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
    try {
        $displaySpecifiersContainer = "CN=DisplaySpecifiers,$configContext"
        $displaySpecifierObjects = @(Invoke-ADQueryWithRetry -OperationName 'Get DisplaySpecifier objects (schema integrity audit)' -Query {
            Get-ADObject -SearchBase $displaySpecifiersContainer -SearchScope Subtree -Filter "objectClass -eq 'displaySpecifier'" `
                -Properties adminContextMenu -Server $__adServer -ErrorAction Stop
        })

        $tamperedSpecifiers = @()
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
                #     default, benign shape (built-in AD snap-in
                #     extensions typically register this way) and must be
                #     SKIPPED here, not flagged - checking a GUID against
                #     a SYSVOL-path pattern would always "fail" and flood
                #     every healthy environment with false positives.
                #   - Static context menu item: "<order number>,<menu
                #     text>,<command>" (3 fields) - <command> is the
                #     actual program/file/URL invoked via ShellExecute.
                #     THIS is the shape the tampering check cares about:
                #     a <command> pointing outside SYSVOL is the anomaly.
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
                $path = ($parts[2..($parts.Count - 1)] -join ',')
                if ($path -and ($path -notmatch '(?i)\\sysvol\\.*\\policies\\')) {
                    $tamperedSpecifiers += [PSCustomObject]@{
                        DistinguishedName = $ds.DistinguishedName
                        MenuValue         = $menuValue
                        Path              = $path
                    }
                }
            }
        }

        if ($tamperedSpecifiers.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Schema Integrity'
            $finding.Issue = 'AD Display Specifier Tampered'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = (($tamperedSpecifiers | ForEach-Object { $_.DistinguishedName }) -join '; ')
            $finding.Description = "$($tamperedSpecifiers.Count) DisplaySpecifier adminContextMenu entrie(s) reference a script/COM object outside the SYSVOL policies path: $(($tamperedSpecifiers | ForEach-Object { "$($_.DistinguishedName) -> $($_.Path)" }) -join '; ')."
            $finding.Impact = "adminContextMenu entries run in the administrator's own UI context whenever triggered from the Active Directory management console (ADUC, etc.). A value pointing outside SYSVOL is either leftover from a decommissioned legitimate tool or - more concerning - a persistence mechanism waiting for an administrator to trigger it."
            $finding.Remediation = "Review each listed adminContextMenu value; remove any that are not a confirmed, currently-used legitimate administrative extension referencing a SYSVOL-hosted script/COM object."
            $finding.EstimatedEffort = 'Low - removing a single attribute value per affected DisplaySpecifier object, but confirm the referenced tool isn''t a legitimate (if unusually placed) admin console extension before removing.'
            $finding.KnownRisks = 'Removing a legitimate admin console extension (if one happens to be configured this way) will break that specific right-click context-menu action for administrators - confirm before removing.'
            $finding.BackupRollback = 'Easy - record the current adminContextMenu value before removing it; effective immediately, no data loss.'
            $finding.Details = @{
                TamperedDisplaySpecifiers = @($tamperedSpecifiers)
            }
            $findings += $finding
        }
        else {
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
