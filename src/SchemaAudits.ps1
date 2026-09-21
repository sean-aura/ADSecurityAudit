#region Schema & Persistence-Tampering Audit
#
# PingCastle-comparable check(s): S-ADRegistrationSchema
# (PossSuperiorComputer/PossSuperiorUser, CVE-2021-34470
# msExchStorageGroup), P-DisplaySpecifier. Semperis "Default security
# descriptor schema changes in the last 90 days", "Changes to AD Display
# Specifiers in the past 90 days". See
# files/15-schema-persistence-tampering.md.
#
# Three related, rarely-audited persistence/tampering vectors, all
# sharing the same theme (an attacker with prior admin access modifies a
# rarely-touched AD structure to create a durable, hard-to-notice
# backdoor): vulnerable schema superior-class configuration,
# defaultSecurityDescriptor tampering on schema classes, and AD Display
# Specifier (adminContextMenu) tampering. The fourth check in the same
# feature request (AdminSDHolder inheritance re-enabled) lives in
# AdminSDAudits.ps1 instead, alongside the existing AdminSDHolder
# ACL/deny-ACE checks it reuses the ACL read from.
#
# DETECTION ONLY: every check here is a pure Configuration/Schema
# partition attribute read. No schema write, no exploitation, no PoC
# traffic of any kind.

# Reference table of Microsoft-documented defaultSecurityDescriptor
# values (as SDDL) for the classes most relevant to privilege
# escalation. INTENTIONALLY LEFT EMPTY at authoring time: unlike the
# per-OS-build/fixed-UBR tables elsewhere in this project (which cite a
# single, independently verifiable source per entry), the correct
# defaultSecurityDescriptor SDDL string is long, forest-functional-level-
# and OS-version-dependent, and easy to get subtly wrong from memory or a
# secondary source. Populate this table by reading
# defaultSecurityDescriptor directly from a known-clean, unmodified
# schema (a fresh lab forest at the same functional level as the target
# environment, or Microsoft's own current schema reference) before
# relying on this check - the check below deliberately SKIPS any class
# with no entry here rather than comparing against a guessed value, to
# avoid a false sense of security from an unverified reference table.
# Maintain this the same way KnownVulnAudits.ps1's CVE fix-date table is
# maintained: one inline citation per entry, re-verified periodically.
$Script:SchemaDefaultSecurityDescriptors = @{
    # 'user'               = 'D:...'  # populate from a verified reference schema
    # 'computer'           = 'D:...'
    # 'group'              = 'D:...'
    # 'organizationalUnit' = 'D:...'
}

function Test-ADSchemaIntegrity {
    <#
    .SYNOPSIS
        Audits AD schema classes and Display Specifiers for persistence-
        tampering indicators.
    .DESCRIPTION
        Three independent, read-only checks:
          1. Vulnerable Schema Class Allows Arbitrary Object Creation -
             a schema class whose possSuperiors includes computer/user
             while itself inheriting (directly or transitively) from
             container, plus an explicit check for the documented
             msExchStorageGroup/CVE-2021-34470 variant regardless of the
             general condition.
          2. Schema defaultSecurityDescriptor Modified - compares each
             enumerated class's defaultSecurityDescriptor against a
             maintained reference table of Microsoft-documented defaults
             (see $Script:SchemaDefaultSecurityDescriptors above; classes
             with no reference entry are skipped, never guessed).
          3. AD Display Specifier Tampered - a DisplaySpecifier object's
             adminContextMenu attribute points to a script/COM object
             outside the SYSVOL policies path.

        Detection only - pure Configuration/Schema partition attribute
        reads, no schema write, no exploitation.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting Schema & Persistence-Tampering audit..."
    $findings = @()
    $__adServer = Get-ADSecurityAuditTargetServerValue

    $schemaContext = $null
    $configContext = $null
    try {
        $schemaContext = Get-ADRootDSEValue -Property schemaNamingContext -Server $__adServer
        $configContext = Get-ADRootDSEValue -Property configurationNamingContext -Server $__adServer
    }
    catch {
        Write-Warning "Test-ADSchemaIntegrity: could not resolve Schema/Configuration naming contexts: $_"
        return $findings
    }

    # -------------------------------------------------------------------
    # Enumerate schema classes once, shared by Checks 1 and 2.
    # -------------------------------------------------------------------
    $classSchemas = @()
    try {
        $classSchemas = @(Invoke-ADQueryWithRetry -OperationName 'Get classSchema objects (schema integrity audit)' -Query {
            Get-ADObject -SearchBase $schemaContext -SearchScope OneLevel -Filter "objectClass -eq 'classSchema'" `
                -Properties lDAPDisplayName, possSuperiors, subClassOf, defaultSecurityDescriptor -Server $__adServer -ErrorAction Stop
        })
    }
    catch {
        Write-Warning "Test-ADSchemaIntegrity: could not enumerate schema classes: $_"
    }

    if ($classSchemas.Count -eq 0) {
        Write-Verbose "Test-ADSchemaIntegrity: no schema classes enumerated; skipping Checks 1 and 2."
    }
    else {
        # subClassOf lookup for transitive resolution.
        $subClassOfByName = @{}
        foreach ($c in $classSchemas) {
            if ($c.lDAPDisplayName) { $subClassOfByName[$c.lDAPDisplayName] = $c.subClassOf }
        }

        function Test-ADSchemaClassResolvesToContainer {
            param([string]$ClassName, [hashtable]$Lookup, [int]$Depth = 0)
            if (-not $ClassName -or $Depth -gt 20) { return $false }
            if ($ClassName -eq 'container') { return $true }
            if (-not $Lookup.ContainsKey($ClassName)) { return $false }
            $parent = $Lookup[$ClassName]
            if (-not $parent -or $parent -eq $ClassName) { return $false }
            return Test-ADSchemaClassResolvesToContainer -ClassName $parent -Lookup $Lookup -Depth ($Depth + 1)
        }

        # ---------------------------------------------------------------
        # Check 1: Vulnerable Schema Class Allows Arbitrary Object
        # Creation (PossSuperiorComputer/PossSuperiorUser,
        # msExchStorageGroup/CVE-2021-34470)
        # ---------------------------------------------------------------
        $vulnerableClasses = @()
        foreach ($c in $classSchemas) {
            $possSuperiors = @($c.possSuperiors)
            $isExplicitMsExchVariant = ($c.lDAPDisplayName -eq 'msExchStorageGroup')

            $hasRiskyPossSuperior = [bool]($possSuperiors -contains 'computer' -or $possSuperiors -contains 'user')
            $resolvesToContainer  = Test-ADSchemaClassResolvesToContainer -ClassName $c.subClassOf -Lookup $subClassOfByName

            if (($hasRiskyPossSuperior -and $resolvesToContainer) -or $isExplicitMsExchVariant) {
                $vulnerableClasses += [PSCustomObject]@{
                    ClassName            = $c.lDAPDisplayName
                    DistinguishedName    = $c.DistinguishedName
                    PossSuperiors        = $possSuperiors
                    SubClassOf           = $c.subClassOf
                    IsMsExchStorageGroup = $isExplicitMsExchVariant
                }
            }
        }

        if ($vulnerableClasses.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Schema Integrity'
            $finding.Issue = 'Vulnerable Schema Class Allows Arbitrary Object Creation'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = (($vulnerableClasses | ForEach-Object { $_.ClassName }) -join ', ')
            $finding.Description = "$($vulnerableClasses.Count) schema class(es) allow computer/user objects to be added as a container beneath them, or match the documented msExchStorageGroup/CVE-2021-34470 variant: $(($vulnerableClasses | ForEach-Object { $_.ClassName }) -join ', ')."
            $finding.Impact = "Any computer or user object that can request creation of one of these classes can be added as a container, then create arbitrary, unrestricted child objects underneath it - a documented AD persistence/privilege-escalation technique (PossSuperiorComputer/PossSuperiorUser). msExchStorageGroup (CVE-2021-34470) is independently exploitable even in environments where Exchange has been fully decommissioned, since the schema extension itself persists."
            $finding.Remediation = "Review each listed class's possSuperiors and subClassOf configuration. For msExchStorageGroup specifically, apply Microsoft's documented CVE-2021-34470 mitigation (removing the vulnerable ACE/permission path) even if Exchange is fully decommissioned in this environment."
            $finding.EstimatedEffort = 'Medium - schema changes require Schema Admins and are forest-wide, so validate the change in a lab before applying, and confirm no legitimate application depends on the current (vulnerable) configuration.'
            $finding.KnownRisks = 'Schema modifications are forest-wide and cannot be easily reverted (schema attributes/classes can be deactivated but not fully deleted) - test any corrective change thoroughly in a lab first.'
            $finding.BackupRollback = 'Difficult - schema changes are effectively permanent (classes/attributes can be deactivated, not removed); a system state backup of a schema-master DC before changing anything is the only real rollback path.'
            $finding.Details = @{
                VulnerableClasses = @($vulnerableClasses)
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADSchemaIntegrity: no vulnerable schema class configuration found."
        }

        # ---------------------------------------------------------------
        # Check 2: Schema defaultSecurityDescriptor Modified
        # ---------------------------------------------------------------
        if ($Script:SchemaDefaultSecurityDescriptors.Count -eq 0) {
            Write-Verbose "Test-ADSchemaIntegrity: `$Script:SchemaDefaultSecurityDescriptors reference table is empty (not yet populated against a verified source); skipping defaultSecurityDescriptor comparison rather than guessing at defaults."
        }
        else {
            $modifiedClasses = @()
            foreach ($c in $classSchemas) {
                if (-not $c.lDAPDisplayName) { continue }
                if (-not $Script:SchemaDefaultSecurityDescriptors.ContainsKey($c.lDAPDisplayName)) { continue }

                $expectedSddl = $Script:SchemaDefaultSecurityDescriptors[$c.lDAPDisplayName]
                $actualSddl   = "$($c.defaultSecurityDescriptor)"
                if ($actualSddl -and $expectedSddl -and ($actualSddl -ne $expectedSddl)) {
                    $modifiedClasses += [PSCustomObject]@{
                        ClassName         = $c.lDAPDisplayName
                        DistinguishedName = $c.DistinguishedName
                        ExpectedSddl      = $expectedSddl
                        ActualSddl        = $actualSddl
                    }
                }
            }

            if ($modifiedClasses.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Schema Integrity'
                $finding.Issue = 'Schema defaultSecurityDescriptor Modified'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = (($modifiedClasses | ForEach-Object { $_.ClassName }) -join ', ')
                $finding.Description = "$($modifiedClasses.Count) schema class(es) have a defaultSecurityDescriptor differing from the documented Microsoft default: $(($modifiedClasses | ForEach-Object { $_.ClassName }) -join ', ')."
                $finding.Impact = "Every future object of a modified class inherits the altered ACL at creation time - a forest-wide backdoor affecting objects that don't exist yet, and one of the least-audited AD persistence techniques since it requires no ongoing action once set."
                $finding.Remediation = "Review the actual vs. expected SDDL for each listed class and restore Microsoft's documented default unless the deviation is confirmed intentional and documented."
                $finding.EstimatedEffort = 'Medium - schema changes require Schema Admins and are forest-wide; validate the corrected SDDL in a lab before applying to production.'
                $finding.KnownRisks = 'Restoring the default defaultSecurityDescriptor does not retroactively fix already-created objects that inherited the modified ACL at creation time - those objects need to be separately identified and remediated.'
                $finding.BackupRollback = 'Difficult - schema attribute value changes are not easily reverted once objects have been created under the modified default; back up the current value and plan for a separate remediation pass on already-affected objects.'
                $finding.Details = @{
                    ModifiedClasses = @($modifiedClasses)
                }
                $findings += $finding
            }
            else {
                Write-Verbose "Test-ADSchemaIntegrity: no defaultSecurityDescriptor deviation found against the populated reference table."
            }
        }
    }

    # -------------------------------------------------------------------
    # Check 3: AD Display Specifier Tampered
    # -------------------------------------------------------------------
    # REWORKED TWICE (v1.30.1):
    #
    # (1) The original version flagged any command NOT under a SYSVOL
    #     policies path. That was wrong - Microsoft ships plenty of
    #     built-in adminContextMenu entries that point at local system
    #     consoles/executables (e.g. the Remote Storage feature's own
    #     remoteStorageServicePoint class legitimately registers
    #     RsAdmin.msc, a stock Windows MMC console under
    #     %SystemRoot%\System32), which is the normal, healthy default
    #     state of a domain - not evidence of tampering. Reworked to flag
    #     only PLACEMENT PATTERNS that are themselves inherently
    #     suspicious, regardless of what ships by default: a URL, a UNC
    #     path outside SYSVOL\<domain>\Policies\, or a per-user-writable
    #     location. A bare filename (Microsoft's own common registration
    #     style for built-in consoles) or a local path rooted under
    #     %SystemRoot%/%ProgramFiles% is treated as safe, since writing
    #     there already requires local admin rights on that machine.
    #
    # (2) Reported false positive fixed, then two further changes made
    #     based on published community guidance rather than this
    #     project's own invented heuristics:
    #       - Added a second, INDEPENDENT signal: the referenced command
    #         names a binary from the LOLBAS (Living Off The Land
    #         Binaries And Scripts) project's own well-established "most
    #         commonly abused" set - certutil, mshta, regsvr32, rundll32,
    #         wscript/cscript, bitsadmin, msiexec, installutil, msbuild,
    #         cmstp, forfiles, wmic, powershell/pwsh - matching MITRE
    #         ATT&CK T1218 (System Binary Proxy Execution) and T1216
    #         (System Script Proxy Execution). This fires REGARDLESS of
    #         placement, since referencing one of these as a static
    #         admin-console command at all is itself unusual (Microsoft's
    #         own built-in registrations are consoles/executables
    #         specific to that object class, not general-purpose
    #         dual-use proxy binaries).
    #       - Added a third signal: the referenced file's extension is a
    #         script/direct-execution type (.hta/.vbs/.vbe/.js/.jse/
    #         .wsf/.wsh/.scr/.ps1/.psm1/.chm/.hlp) - Microsoft's own
    #         static registrations are essentially always .msc or .exe,
    #         never a raw script, so this is a low-false-positive signal
    #         independent of location.
    #       - Split what used to be ONE aggregated finding (every
    #         suspicious entry across the whole domain joined into a
    #         single long Description string) into ONE FINDING PER
    #         SUSPICIOUS ENTRY, matching this project's own established
    #         one-finding-per-affected-object convention used everywhere
    #         else (see e.g. UserAudits.ps1) - a long comma-joined string
    #         is hard to read/triage and doesn't sort/filter per-object
    #         the way the rest of this project's output does.
    #       - Added an explicit, prominent statement that THIS CHECK DOES
    #         NOT VALIDATE WHETHER THE REFERENCED FILE OR URL IS ACTUALLY
    #         MALICIOUS - it only flags a placement or naming pattern
    #         that published guidance associates with higher risk (see
    #         LOLBAS project maintainers' own framing: "None of them is a
    #         vulnerability... the line between legitimate administration
    #         and attack does not sit in the file; it sits in the
    #         context" - this project has no way to evaluate that
    #         context from an LDAP-only read).
    #
    # Sources: LOLBAS project (lolbas-project.github.io); MITRE ATT&CK
    # T1218 (System Binary Proxy Execution) / T1216 (System Script Proxy
    # Execution) / T1059 (Command and Scripting Interpreter).
    $Script:AdminContextMenuLolbasBinaries = @(
        'certutil', 'mshta', 'regsvr32', 'rundll32', 'wscript', 'cscript',
        'bitsadmin', 'msiexec', 'installutil', 'msbuild', 'cmstp',
        'forfiles', 'wmic', 'powershell', 'pwsh', 'regsvcs', 'regasm',
        'msdt', 'odbcconf', 'control'
    )
    $Script:AdminContextMenuRiskyExtensions = @(
        '.hta', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.scr',
        '.ps1', '.psm1', '.chm', '.hlp'
    )

    try {
        $displaySpecifiersContainer = "CN=DisplaySpecifiers,$configContext"
        $displaySpecifierObjects = @(Invoke-ADQueryWithRetry -OperationName 'Get DisplaySpecifier objects (schema integrity audit)' -Query {
            Get-ADObject -SearchBase $displaySpecifiersContainer -SearchScope Subtree -Filter "objectClass -eq 'displaySpecifier'" `
                -Properties adminContextMenu -Server $__adServer -ErrorAction Stop
        })

        foreach ($ds in $displaySpecifierObjects) {
            $menuValues = @($ds.adminContextMenu | Where-Object { $_ })
            foreach ($menuValue in $menuValues) {
                # Per Microsoft's documented adminContextMenu formats, this
                # single multi-valued attribute mixes two different
                # registration shapes that must NOT be evaluated the same
                # way:
                #   - COM object registration: "<order number>,<CLSID>"
                #     (2 fields) - the CLSID is a GUID resolved via COM on
                #     the administrator's own machine, not a filesystem
                #     path recorded in AD at all. This is the common,
                #     default, benign shape and must be SKIPPED here.
                #   - Static context menu item: "<order number>,<menu
                #     text>,<command>" (3 fields) - <command> is the
                #     actual program/file/URL invoked via ShellExecute.
                $parts = $menuValue -split ','
                if ($parts.Count -eq 2) {
                    # COM object registration (order,CLSID) - not evaluated.
                    continue
                }
                if ($parts.Count -lt 3) {
                    # Malformed/unrecognized value shape - nothing to
                    # evaluate confidently; skip rather than guess.
                    continue
                }
                $path = ($parts[2..($parts.Count - 1)] -join ',').Trim()
                if (-not $path) { continue }

                $reasons = [System.Collections.ArrayList]::new()

                if ($path -match '(?i)^(https?|ftp|file)://') {
                    [void]$reasons.Add('References a URL (ShellExecute-invokable), not a standard static file/console registration.')
                }
                elseif ($path -match '^\\\\') {
                    # UNC path - suspicious unless it's specifically the
                    # SYSVOL policies path GPO-deployed extensions use.
                    if ($path -notmatch '(?i)\\sysvol\\.*\\policies\\') {
                        [void]$reasons.Add('UNC path outside SYSVOL\<domain>\Policies\ - a network share GPO-deployed admin extensions are not meant to live on.')
                    }
                }
                elseif ($path -match '(?i)(\\users\\|%temp%|%tmp%|%appdata%|%localappdata%|%userprofile%|\\appdata\\|\\windows\\temp\\)') {
                    [void]$reasons.Add('Path is under a per-user-writable or temp location - any authenticated user, not just an admin, can write there.')
                }
                # Otherwise: a bare filename (no path separators - the
                # common built-in-console registration style), a
                # drive-letter/%SystemRoot%/%ProgramFiles%-rooted local
                # path, or a SYSVOL policies path - none flagged on
                # placement alone.

                # Independent signal: a well-known LOLBAS dual-use binary
                # referenced as the command itself, regardless of path.
                $fileNameOnly = $null
                $fileBaseName = $null
                $fileExtension = $null
                try {
                    $fileNameOnly = ($path -split '[\\/]')[-1]
                    $fileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($fileNameOnly)
                    $fileExtension = [System.IO.Path]::GetExtension($fileNameOnly)
                }
                catch {
                    # A malformed/unusual value shouldn't abort evaluation
                    # of the rest of this DisplaySpecifier's other menu
                    # values - the placement-pattern reasons above (if
                    # any) still apply; only the filename-based signals
                    # are skipped for this one value.
                    Write-Verbose "Test-ADSchemaIntegrity: could not parse filename/extension from adminContextMenu value '$menuValue': $_"
                }
                if ($fileBaseName -and ($Script:AdminContextMenuLolbasBinaries -icontains $fileBaseName)) {
                    [void]$reasons.Add("References '$fileNameOnly', a binary on the LOLBAS (Living Off The Land Binaries And Scripts) project's list of commonly-abused dual-use Windows binaries (MITRE ATT&CK T1218/T1216) - unusual as a static admin-console command regardless of where it's located.")
                }

                # Independent signal: a script/direct-execution extension,
                # a shape Microsoft's own built-in registrations don't use
                # (those are always .msc/.exe).
                if ($fileExtension -and ($Script:AdminContextMenuRiskyExtensions -icontains $fileExtension)) {
                    [void]$reasons.Add("File extension '$fileExtension' is a script/direct-execution type Microsoft's own built-in adminContextMenu registrations do not use (those are always .msc or .exe).")
                }

                if ($reasons.Count -eq 0) { continue }

                # One finding per suspicious entry (not aggregated across
                # the whole domain into a single long string) - matches
                # this project's established one-finding-per-affected-
                # object convention.
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Schema Integrity'
                $finding.Issue = 'AD Display Specifier Tampered'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $ds.DistinguishedName
                $finding.Description = "DisplaySpecifier '$($ds.DistinguishedName)' has an adminContextMenu entry referencing '$path' that matches known higher-risk pattern(s): $($reasons -join ' ')"
                $finding.Impact = "adminContextMenu entries run in the administrator's own UI context whenever triggered from the Active Directory management console (ADUC, etc.), so a persistence mechanism placed here waits for an administrator to trigger it rather than requiring further attacker action. IMPORTANT: THIS CHECK DOES NOT VALIDATE WHETHER THE REFERENCED FILE OR URL IS ACTUALLY MALICIOUS. It only flags a placement or naming pattern that published guidance (the LOLBAS project, MITRE ATT&CK) associates with elevated risk for this kind of registration - as the LOLBAS project's own maintainers put it, 'none of these binaries is a vulnerability... the line between legitimate administration and attack sits in the context, not the file,' and this LDAP-only read has no way to evaluate that context. Manually confirm this is not a legitimate, currently-used administrative tool before treating it as confirmed tampering."
                $finding.Remediation = "Confirm whether this entry is a currently-used, legitimate administrative extension. If not, remove it. If it is legitimate but points at a user-writable or non-SYSVOL network location, move the target to a location only administrators can write to (SYSVOL, or a local path under %SystemRoot%/%ProgramFiles% on every DC/admin workstation)."
                $finding.EstimatedEffort = 'Low - removing a single attribute value on this DisplaySpecifier object, but confirm the referenced tool isn''t a legitimate (if unusually placed or named) admin console extension before removing.'
                $finding.KnownRisks = 'Removing a legitimate admin console extension (if one happens to be configured this way) will break that specific right-click context-menu action for administrators - confirm before removing. This check only flags a specific set of published, inherently-suspicious patterns (placement, LOLBAS binary names, script extensions); it cannot and does not confirm actual malicious intent or behavior, and a malicious entry placed inside an otherwise-protected system directory with an otherwise-unremarkable name would not be caught by this LDAP-only check.'
                $finding.BackupRollback = 'Easy - record the current adminContextMenu value before removing it; effective immediately, no data loss.'
                $finding.Details = @{
                    DistinguishedName          = $ds.DistinguishedName
                    MenuValue                  = $menuValue
                    Path                       = $path
                    MatchedReasons             = @($reasons)
                    MaliciousnessNotValidated  = $true
                    Sources                    = 'LOLBAS project (lolbas-project.github.io); MITRE ATT&CK T1218/T1216/T1059'
                }
                $findings += $finding
            }
        }

        if (-not ($findings | Where-Object { $_.Issue -eq 'AD Display Specifier Tampered' })) {
            Write-Verbose "Test-ADSchemaIntegrity: no DisplaySpecifier adminContextMenu tampering found."
        }
    }
    catch {
        Write-Verbose "Test-ADSchemaIntegrity: could not enumerate DisplaySpecifier objects (may not be present/accessible): $_"
    }

    Write-Verbose "Schema & Persistence-Tampering audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
