#region Domain Hardening Flags Audit
#
# Audits domain-wide settings with a large blast radius that are invisible
# to most tools: the dSHeuristics attribute, membership of the built-in
# "Pre-Windows 2000 Compatible Access" group, whether anonymous LDAP /
# RootDSE binding is permitted, and whether null-session (unauthenticated)
# access to named pipes/shares is permitted. PingCastle-comparable check(s):
# A-DsHeuristicsAnonymous, A-DsHeuristicsAllowAnonNSPI,
# A-DsHeuristicsLDAPSecurity, P-DsHeuristicsDoListObject,
# P-DsHeuristicsAdminSDExMask, A-PreWin2000Anonymous,
# A-PreWin2000AuthenticatedUsers, A-RootDseAnonBinding, A-NullSession.
#
# Snapshot-aware for the dSHeuristics and Pre-Windows 2000 checks (see
# Get-ADSnapshot's DsHeuristics / PreWin2000Members keys). The anonymous
# RootDSE bind probe and the null-session pipe/share check are both live
# operations with no point-in-time snapshot representation, so - consistent
# with the -FromSnapshot contract of performing NO live AD/network access -
# both are only attempted when this function is called WITHOUT -Snapshot
# (i.e. from the live audit path, not from Invoke-ADRuleSet /
# Start-ADSecurityAudit -FromSnapshot).
#
# The null-session check (RestrictNullSessAccess / NullSessionPipes /
# NullSessionShares) follows the same GPO-linked-policy-then-live-per-DC-
# registry-fallback pattern LegacyAuthAudits.ps1 already uses for
# SMBv1/SMB-signing/LmCompatibilityLevel, reusing that module's
# Get-ADLinkedGposOrdered / Get-ADPolicyRegistryValue plus the shared
# Get-ADLiveRegistryValuePerDc helper in Common.ps1, rather than
# re-implementing GPO-link resolution here.
#
# DETECTION ONLY: attribute reads, group-membership reads, a strictly
# read-only anonymous bind probe (refusal = secure, no finding), and
# GPO-linked/direct registry value reads for the null-session check (no
# live SMB/null-session connection is ever attempted). No exploitation,
# coercion, relay, or PoC traffic of any kind.

# Well-known SIDs that make "Pre-Windows 2000 Compatible Access" membership
# dangerous when present (grants broad, unauthenticated-adjacent, read
# access to user/group attributes domain-wide).
$Script:PreWin2000DangerousSids = @{
    'S-1-5-11' = 'Authenticated Users'
    'S-1-1-0'  = 'Everyone'
    'S-1-5-7'  = 'ANONYMOUS LOGON'
}

function Test-ADDomainHardeningFlags {
    <#
    .SYNOPSIS
        Audits domain-wide hardening flags: dSHeuristics, Pre-Windows 2000
        Compatible Access membership, and anonymous LDAP/RootDSE binding.
    .DESCRIPTION
        Three independent, read-only checks:
          1. dSHeuristics - positionally parsed for dangerous settings:
             anonymous access (7th character = '2'), List Object security
             mode (1st character = '1'), and AdminSDHolder exclusion mask
             weakening (16th character present and non-zero).
          2. Pre-Windows 2000 Compatible Access - flags membership by broad
             principals (Authenticated Users, Everyone, ANONYMOUS LOGON).
          3. Anonymous LDAP/RootDSE binding - a strictly read-only
             anonymous DirectoryEntry bind against RootDSE, attempted
             against EVERY Domain Controller in the domain (via
             `Get-ADSecurityAuditDomainController`, Common.ps1 - correctly
             domain-scoped, unlike a bare `Get-ADDomainController -Filter *`
             which is forest-wide regardless of -Server) rather than a
             single discovered/overridden DC. Success on any DC is the
             finding; a refusal (exception) on a given DC is that DC's
             secure state. This live probe is skipped when -Snapshot is
             supplied, since offline re-analysis must perform no live
             AD/network access.
          4. Null-session pipe/share access - `RestrictNullSessAccess`
             (Security Options: "Network access: Restrict anonymous access
             to Named Pipes and Shares") read as disabled (0), checking
             GPOs linked to the Domain Controllers OU then the domain root,
             falling back to a direct per-DC registry read if no linked GPO
             defines it. Registry-value read only - no live SMB/null-session
             connection is attempted. Skipped when -Snapshot is supplied.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        DsHeuristics and PreWin2000Members are read from it instead of
        live AD queries, and the anonymous-bind network probe and the
        null-session pipe/share check (both live-only) are skipped.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Domain Hardening Flags audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Check 1: dSHeuristics
    # -------------------------------------------------------------------
    try {
        $dsHeuristics = $null
        $dsServiceDN = $null

        if ($Snapshot -and $Snapshot.ContainsKey('DsHeuristics')) {
            Write-Verbose "Test-ADDomainHardeningFlags: using snapshot data for dSHeuristics."
            $dsHeuristics = $Snapshot.DsHeuristics
            $dsServiceDN = if ($Snapshot.ContainsKey('DsHeuristicsDN')) { $Snapshot.DsHeuristicsDN } else { 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration' }
        }
        else {
            $configNC = Get-ADRootDSEValue -Property configurationNamingContext
            $dsServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            $dsServiceObject = Invoke-ADQueryWithRetry -OperationName 'Get-ADObject dSHeuristics' -Query {
                Get-ADObject -Identity $dsServiceDN -Properties dSHeuristics -ErrorAction Stop
            }
            if ($dsServiceObject) {
                $dsHeuristics = $dsServiceObject.dSHeuristics
            }
        }

        if ($null -ne $dsHeuristics -and $dsHeuristics -ne '') {
            $flagIssues = [System.Collections.ArrayList]::new()
            $chars = $dsHeuristics.ToCharArray()

            # 1st character ('1' = List Object security mode enabled forest-wide).
            if ($chars.Length -ge 1 -and $chars[0] -eq '1') {
                [void]$flagIssues.Add(@{
                    Position = 1
                    Character = $chars[0]
                    Setting  = 'List Object security mode (fDoListObject)'
                    Detail   = "Character 1 of dSHeuristics is '1', enabling List Object security mode forest-wide. This changes how visibility of objects/containers is evaluated and can hide or reveal objects in unexpected ways for delegated read permissions."
                })
            }

            # 7th character ('2' = anonymous access, incl. NSPI, granted).
            if ($chars.Length -ge 7 -and $chars[6] -eq '2') {
                [void]$flagIssues.Add(@{
                    Position = 7
                    Character = $chars[6]
                    Setting  = 'Anonymous access / Allow Anonymous NSPI (fAnonymousAccess)'
                    Detail   = "Character 7 of dSHeuristics is '2', granting anonymous connections the same directory access as the Pre-Windows 2000 Compatible Access anonymous grant (including anonymous NSPI/address-book access), regardless of the Pre-Windows 2000 group's own membership."
                })
            }

            # 16th character (present and not '0'/blank) = AdminSDHolder
            # exclusion mask weakened: one or more protected groups are
            # excluded from automatic SDProp ACL enforcement.
            if ($chars.Length -ge 16 -and $chars[15] -notin @('0', ' ', "`0")) {
                [void]$flagIssues.Add(@{
                    Position = 16
                    Character = $chars[15]
                    Setting  = 'AdminSDHolder exclusion mask (dwAdminSDExMask)'
                    Detail   = "Character 16 of dSHeuristics is '$($chars[15])' (non-zero), meaning one or more protected/Tier-0 groups have been excluded from automatic AdminSDHolder ACL enforcement (SDProp). Excluded groups no longer have their permissions periodically reset to the secure default, allowing unauthorized ACL changes on them to persist."
                })
            }

            if ($flagIssues.Count -gt 0) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Domain Hardening'
                $finding.Issue = 'Dangerous dsHeuristics Flag Set'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $dsServiceDN
                # BUGFIX: was a single semicolon-joined run-on sentence;
                # rendered as one bullet per flag instead for readability.
                $flagBullets = ($flagIssues | ForEach-Object { "- $($_.Setting)" }) -join "`n"
                $finding.Description = "The dSHeuristics attribute on the Directory Service object contains $($flagIssues.Count) dangerous flag(s):`n$flagBullets"
                $finding.Impact = "dSHeuristics settings apply forest-wide and can silently weaken anonymous-access restrictions, object-visibility security, or AdminSDHolder ACL enforcement without touching any individual object's permissions, making the change easy to miss in routine ACL reviews."
                $finding.Remediation = "Review each flagged position against Microsoft's documented dSHeuristics semantics and reset it to the secure default (character removed or '0') unless there is a specific, documented business reason for the current value: `Set-ADObject -Identity '$dsServiceDN' -Replace @{dSHeuristics='<corrected-value>'}`."
                $finding.Details = @{
                    DistinguishedName = $dsServiceDN
                    RawValue          = $dsHeuristics
                    FlaggedPositions  = @($flagIssues)
                }
                $findings += $finding
            }
            else {
                Write-Verbose "Test-ADDomainHardeningFlags: dSHeuristics present but no dangerous positions set."
            }
        }
        else {
            Write-Verbose "Test-ADDomainHardeningFlags: dSHeuristics not set (secure default); no finding."
        }
    }
    catch {
        Write-Warning "Test-ADDomainHardeningFlags: error auditing dSHeuristics: $_"
    }

    # -------------------------------------------------------------------
    # Check 2: Pre-Windows 2000 Compatible Access membership
    # -------------------------------------------------------------------
    try {
        $broadPrincipals = [System.Collections.ArrayList]::new()
        $groupDN = $null

        if ($Snapshot -and $Snapshot.ContainsKey('PreWin2000Members')) {
            Write-Verbose "Test-ADDomainHardeningFlags: using snapshot data for Pre-Windows 2000 Compatible Access."
            $groupDN = if ($Snapshot.ContainsKey('PreWin2000GroupDN')) { $Snapshot.PreWin2000GroupDN } else { 'Pre-Windows 2000 Compatible Access' }

            foreach ($memberDN in @($Snapshot.PreWin2000Members)) {
                if (-not $memberDN) { continue }
                foreach ($sid in $Script:PreWin2000DangerousSids.Keys) {
                    if ($memberDN -match "CN=$sid,") {
                        [void]$broadPrincipals.Add($Script:PreWin2000DangerousSids[$sid])
                    }
                }
            }
        }
        else {
            $group = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroup Pre-Windows 2000 Compatible Access' -Query {
                Get-ADGroup -Filter "Name -eq 'Pre-Windows 2000 Compatible Access'" -ErrorAction Stop
            }

            if ($group) {
                $groupDN = $group.DistinguishedName
                $members = Invoke-ADQueryWithRetry -OperationName 'Get-ADGroupMember Pre-Windows 2000 Compatible Access' -Query {
                    Get-ADGroupMember -Identity $group -ErrorAction Stop
                }

                foreach ($member in @($members)) {
                    $sidValue = if ($member.SID) { $member.SID.Value } else { $null }
                    if ($sidValue -and $Script:PreWin2000DangerousSids.ContainsKey($sidValue)) {
                        [void]$broadPrincipals.Add($Script:PreWin2000DangerousSids[$sidValue])
                    }
                }
            }
            else {
                Write-Verbose "Test-ADDomainHardeningFlags: 'Pre-Windows 2000 Compatible Access' group not found."
            }
        }

        if ($broadPrincipals.Count -gt 0) {
            $uniquePrincipals = @($broadPrincipals | Select-Object -Unique)

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Hardening'
            $finding.Issue = 'Broad Membership in Pre-Windows 2000 Compatible Access'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $groupDN
            $finding.Description = "The built-in 'Pre-Windows 2000 Compatible Access' group contains the following broad principal(s): $($uniquePrincipals -join ', ')."
            $finding.Impact = "Members of this group are granted Read access to most user and group attributes domain-wide (a legacy compatibility grant for pre-Windows 2000 systems). Including Authenticated Users, Everyone, or ANONYMOUS LOGON effectively exposes that attribute-level read access to anyone who can reach the domain, aiding reconnaissance (e.g. user enumeration, password-policy discovery) and tools such as null-session enumeration."
            $finding.Remediation = "Remove the broad principal(s) from 'Pre-Windows 2000 Compatible Access' and replace with only the specific legacy service accounts or systems that genuinely require this compatibility access, if any: `Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members '<principal>'`."
            $finding.Details = @{
                DistinguishedName = $groupDN
                BroadPrincipals   = $uniquePrincipals
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADDomainHardeningFlags: no broad principals found in Pre-Windows 2000 Compatible Access."
        }
    }
    catch {
        Write-Warning "Test-ADDomainHardeningFlags: error auditing Pre-Windows 2000 Compatible Access membership: $_"
    }

    # -------------------------------------------------------------------
    # Check 3: Anonymous LDAP / RootDSE binding (live probe only)
    # -------------------------------------------------------------------
    if (-not $Snapshot) {
        try {
            # Fixed: previously resolved a single DC via
            # Get-ADTargetDomainController (either the -Discover result or,
            # if a -Server override was active, that one overridden
            # host) and probed only that one DC. That meant the finding -
            # and even whether the probe errored at all - depended on
            # whichever single DC happened to be picked that run, not on
            # the domain's actual anonymous-bind posture: a domain with a
            # mix of hardened and non-hardened DCs could show a finding on
            # one run and none on the next, and a single unreachable
            # override host could error out the whole check even though
            # every other DC was reachable. Now enumerates every DC in the
            # TARGET DOMAIN via Get-ADSecurityAuditDomainController (see
            # Common.ps1 - a bare `Get-ADDomainController -Filter *` is
            # forest-wide regardless of -Server, which would have silently
            # probed other domains' DCs too) and probes each independently.
            $anonDomainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (anonymous-bind probe)' -Query {
                Get-ADSecurityAuditDomainController
            })

            if (-not $anonDomainControllers -or $anonDomainControllers.Count -eq 0) {
                Write-Verbose "Test-ADDomainHardeningFlags: no Domain Controllers found; skipping anonymous-bind probe."
            }
            else {
                $anonBindResults = [System.Collections.ArrayList]::new()

                foreach ($dc in $anonDomainControllers) {
                    $dcHost = if ($dc.HostName) { $dc.HostName } else { $dc.Name }
                    $probePath = "LDAP://$dcHost/RootDSE"
                    $anonBindSucceeded = $false
                    $anonEntry = $null

                    try {
                        $anonEntry = New-Object System.DirectoryServices.DirectoryEntry(
                            $probePath, $null, $null, [System.DirectoryServices.AuthenticationTypes]::Anonymous
                        )
                        # ADSI binds lazily; force the actual network bind
                        # by touching a property. An exception here means
                        # the anonymous bind was refused (the secure
                        # state) - or, less commonly, that this specific
                        # DC could not be reached at all; either way, no
                        # anonymous read was achieved against it.
                        [void]$anonEntry.Properties['currentTime']
                        [void]$anonEntry.NativeObject
                        $anonBindSucceeded = $true
                    }
                    catch {
                        Write-Verbose "Test-ADDomainHardeningFlags: anonymous RootDSE bind against '$dcHost' refused or failed (treated as secure for this DC): $_"
                        $anonBindSucceeded = $false
                    }
                    finally {
                        if ($anonEntry) { $anonEntry.Dispose() }
                    }

                    [void]$anonBindResults.Add([PSCustomObject]@{
                        DomainController  = $dcHost
                        AnonBindSucceeded = $anonBindSucceeded
                        ProbePath         = $probePath
                    })
                }

                $vulnerableDCs = @($anonBindResults | Where-Object { $_.AnonBindSucceeded } | ForEach-Object { $_.DomainController })

                if ($vulnerableDCs.Count -gt 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Hardening'
                    $finding.Issue = 'Anonymous LDAP / RootDSE Binding Permitted'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = ($vulnerableDCs -join ', ')
                    $finding.Description = "An anonymous (unauthenticated) LDAP bind to RootDSE succeeded against $($vulnerableDCs.Count) of $($anonDomainControllers.Count) Domain Controller(s): $($vulnerableDCs -join ', ')."
                    $finding.Impact = "Anonymous LDAP binding is a null-session indicator: it lets unauthenticated clients enumerate directory-service metadata (naming contexts, supported capabilities, schema/config paths) without any credentials, aiding reconnaissance ahead of further attacks. Because this was observed on only some Domain Controllers, exposure is inconsistent across the environment rather than a single domain-wide setting - see PerDomainControllerResults for which DCs still refuse the bind."
                    $finding.Remediation = "Restrict anonymous LDAP operations via dSHeuristics (character 7) and/or the 'Network access: Let Everyone permissions apply to anonymous users' and related null-session security policy settings, ensuring the policy is applied consistently to every Domain Controller listed above, then re-test."
                    $finding.Details = @{
                        DomainControllersTested     = $anonDomainControllers.Count
                        VulnerableDomainControllers = $vulnerableDCs
                        PerDomainControllerResults  = @($anonBindResults)
                    }
                    $findings += $finding
                }
                else {
                    Write-Verbose "Test-ADDomainHardeningFlags: anonymous RootDSE binding refused on all $($anonDomainControllers.Count) Domain Controller(s); no finding (secure)."
                }
            }
        }
        catch {
            Write-Warning "Test-ADDomainHardeningFlags: error during anonymous-bind probe: $_"
        }
    }
    else {
        Write-Verbose "Test-ADDomainHardeningFlags: -Snapshot supplied; skipping live anonymous-bind network probe (offline mode performs no live AD/network access)."
        Add-ADOfflineSkipNote -Test 'DomainHardeningFlags' -Check 'Anonymous LDAP bind probe' `
            -Reason 'A live network probe against a DC, not an AD attribute. Run this check live (without -Snapshot) if you need this coverage.'
    }

    # -------------------------------------------------------------------
    # Check 4: Null-Session Pipe/Share Access Permitted (GPO + live
    # fallback; registry-value read only, no live SMB/null-session
    # connection is attempted).
    #
    # Reuses LegacyAuthAudits.ps1's existing GPO-then-live-fallback
    # registry resolver (Get-ADLinkedGposOrdered, Get-ADPolicyRegistryValue,
    # and the now-shared Get-ADLiveRegistryValuePerDc in Common.ps1) instead
    # of duplicating that logic here.
    # -------------------------------------------------------------------
    if (-not $Snapshot) {
        try {
            Import-Module GroupPolicy -ErrorAction Stop

            $nsDomain = Get-ADDomain -ErrorAction Stop
            # Get-ADSecurityAuditDomainController, not a bare
            # Get-ADDomainController -Filter * - the latter is forest-wide
            # regardless of -Server; see Common.ps1 for why.
            $nsDomainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADSecurityAuditDomainController (null-session audit)' -Query {
                Get-ADSecurityAuditDomainController
            })

            if (-not $nsDomainControllers -or $nsDomainControllers.Count -eq 0) {
                Write-Verbose "Test-ADDomainHardeningFlags: no Domain Controllers found; cannot evaluate null-session pipe/share access."
            }
            else {
                # Discover the actual Domain Controllers OU from a real DC's
                # parent container, same approach as Test-ADLegacyAuthSurface,
                # so this still resolves correctly if that OU was renamed/moved.
                $nsDcOuDn = $null
                try {
                    $firstDcDn = $nsDomainControllers[0].ComputerObjectDN
                    if ($firstDcDn -and $firstDcDn -match '^CN=[^,]+,(.+)$') {
                        $nsDcOuDn = $Matches[1]
                    }
                }
                catch {
                    Write-Verbose "Test-ADDomainHardeningFlags: could not derive Domain Controllers OU for null-session check: $_"
                }
                if (-not $nsDcOuDn) {
                    $nsDcOuDn = "OU=Domain Controllers,$($nsDomain.DistinguishedName)"
                    Write-Verbose "Test-ADDomainHardeningFlags: falling back to default Domain Controllers OU path '$nsDcOuDn' for null-session check."
                }

                # DC OU precedence first (most specific to the DCs being
                # evaluated), domain root as fallback - same ordering as
                # Test-ADLegacyAuthSurface's $dcScopeGpos.
                $nsDcOuGpos   = Get-ADLinkedGposOrdered -TargetDn $nsDcOuDn
                $nsDomainGpos = Get-ADLinkedGposOrdered -TargetDn $nsDomain.DistinguishedName
                $nsScopeGpos  = @($nsDcOuGpos + $nsDomainGpos)

                $restrictTarget = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'RestrictNullSessAccess' }
                $pipesTarget    = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'NullSessionPipes' }
                $sharesTarget   = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'NullSessionShares' }

                $restrictPolicy = Get-ADPolicyRegistryValue -Gpos $nsScopeGpos -Key $restrictTarget.Key -ValueName $restrictTarget.ValueName

                $restrictDisabled = $false
                $source = $null
                $detail = @{}

                if ($restrictPolicy) {
                    $restrictDisabled = ([int]$restrictPolicy.Value -eq 0)
                    $source = "GPO: $($restrictPolicy.Source)"
                    $detail.RestrictNullSessAccess = [int]$restrictPolicy.Value
                    $detail.Source = $source
                }
                else {
                    $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $nsDomainControllers -Key $restrictTarget.Key -ValueName $restrictTarget.ValueName
                    $disabledDCs = @($perDc | Where-Object { $null -ne $_.Value -and [int]$_.Value -eq 0 } | ForEach-Object { $_.DomainController })
                    # No enforcing GPO and no live value observed at all
                    # (fully unset) is left as-is - unlike LmCompatibilityLevel,
                    # RestrictNullSessAccess has no single documented
                    # universally-secure OS default to fall back on across
                    # Windows Server versions, so only an explicitly
                    # observed 0 is flagged, not the mere absence of a
                    # value (same "unset is not itself a finding" posture
                    # LmCompatibilityLevel already applies).
                    $restrictDisabled = $disabledDCs.Count -gt 0
                    $source = 'No enforcing GPO found; observed via direct per-DC registry read'
                    $detail.Source = $source
                    $detail.AffectedDomainControllers = $disabledDCs
                    $detail.PerDomainControllerState = @($perDc)
                }

                if ($restrictDisabled) {
                    # RestrictNullSessAccess is disabled - this is the
                    # primary signal and is sufficient on its own to raise
                    # the finding. Also fetch the pipe/share allow-lists
                    # purely to enrich the finding with how much surface is
                    # exposed; a lookup failure here doesn't block the
                    # primary finding from being raised.
                    $nullSessionPipes  = @()
                    $nullSessionShares = @()
                    try {
                        $pipesPolicy = Get-ADPolicyRegistryValue -Gpos $nsScopeGpos -Key $pipesTarget.Key -ValueName $pipesTarget.ValueName
                        if ($pipesPolicy) {
                            $nullSessionPipes = @($pipesPolicy.Value)
                        }
                        else {
                            $pipesPerDc = Get-ADLiveRegistryValuePerDc -DomainControllers $nsDomainControllers -Key $pipesTarget.Key -ValueName $pipesTarget.ValueName
                            $firstWithValue = $pipesPerDc | Where-Object { $_.Value } | Select-Object -First 1
                            if ($firstWithValue) { $nullSessionPipes = @($firstWithValue.Value) }
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADDomainHardeningFlags: could not read NullSessionPipes for null-session finding detail: $_"
                    }
                    try {
                        $sharesPolicy = Get-ADPolicyRegistryValue -Gpos $nsScopeGpos -Key $sharesTarget.Key -ValueName $sharesTarget.ValueName
                        if ($sharesPolicy) {
                            $nullSessionShares = @($sharesPolicy.Value)
                        }
                        else {
                            $sharesPerDc = Get-ADLiveRegistryValuePerDc -DomainControllers $nsDomainControllers -Key $sharesTarget.Key -ValueName $sharesTarget.ValueName
                            $firstWithValue = $sharesPerDc | Where-Object { $_.Value } | Select-Object -First 1
                            if ($firstWithValue) { $nullSessionShares = @($firstWithValue.Value) }
                        }
                    }
                    catch {
                        Write-Verbose "Test-ADDomainHardeningFlags: could not read NullSessionShares for null-session finding detail: $_"
                    }

                    $nullSessionPipes  = @($nullSessionPipes  | Where-Object { $_ })
                    $nullSessionShares = @($nullSessionShares | Where-Object { $_ })

                    $listSummary = if ($nullSessionPipes.Count -gt 0 -or $nullSessionShares.Count -gt 0) {
                        " Configured allow-list(s): $($nullSessionPipes.Count) named pipe(s), $($nullSessionShares.Count) share(s)."
                    }
                    else {
                        ''
                    }

                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Hardening'
                    $finding.Issue = 'Null-Session Pipe/Share Access Permitted'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = if ($restrictPolicy) { $nsDcOuDn } else { ($detail.AffectedDomainControllers -join ', ') }
                    $finding.Description = "`RestrictNullSessAccess` ('Network access: Restrict anonymous access to Named Pipes and Shares') is disabled ($source).$listSummary"
                    $finding.Impact = "With this restriction disabled, an unauthenticated (null-session) client can access the named pipes and shares listed in `NullSessionPipes`/`NullSessionShares` without any credentials - the SMB/named-pipe equivalent of the anonymous LDAP bind exposure above, aiding reconnaissance (e.g. share/pipe enumeration, IPC`$ access) and, depending on which pipes/shares are exposed, further attacks."
                    $finding.Remediation = "Set 'Network access: Restrict anonymous access to Named Pipes and Shares' (`RestrictNullSessAccess`) to Enabled (value 1) via a GPO enforced on Domain Controllers (and ideally all member servers), and review the `NullSessionPipes`/`NullSessionShares` allow-lists to remove any entries not genuinely required for legacy compatibility."
                    $detail.NullSessionPipes  = $nullSessionPipes
                    $detail.NullSessionShares = $nullSessionShares
                    $finding.Details = $detail
                    $findings += $finding
                }
                else {
                    Write-Verbose "Test-ADDomainHardeningFlags: null-session pipe/share access is restricted (policy-enforced, observed live, or unset/default)."
                }
            }
        }
        catch {
            Write-Warning "Test-ADDomainHardeningFlags: error evaluating null-session pipe/share access: $_"
        }
    }
    else {
        Write-Verbose "Test-ADDomainHardeningFlags: -Snapshot supplied; skipping live GPO-linked/per-DC null-session registry check (offline mode performs no live AD/network access)."
        Add-ADOfflineSkipNote -Test 'DomainHardeningFlags' -Check 'Null-session pipe/share access (RestrictNullSessAccess/NullSessionPipes/NullSessionShares)' `
            -Reason 'GPO-linked registry policy state and per-DC registry reads have no AD-schema/snapshot equivalent. Run this check live (without -Snapshot) if you need this coverage.'
    }

    Write-Verbose "Domain Hardening Flags audit complete. Found $($findings.Count) issues."
    return $findings
}

#endregion
