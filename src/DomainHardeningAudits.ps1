#region Domain Hardening Flags Audit
#
# Audits domain-wide settings with a large blast radius that are invisible
# to most tools: the dSHeuristics attribute, membership of the built-in
# "Pre-Windows 2000 Compatible Access" group, and whether anonymous LDAP /
# RootDSE binding is permitted. PingCastle-comparable check(s): A-DsHeuristicsAnonymous,
# A-DsHeuristicsAllowAnonNSPI, A-DsHeuristicsLDAPSecurity,
# P-DsHeuristicsDoListObject, P-DsHeuristicsAdminSDExMask,
# A-PreWin2000Anonymous, A-PreWin2000AuthenticatedUsers,
# A-RootDseAnonBinding, A-NullSession.
#
# Snapshot-aware for the dSHeuristics and Pre-Windows 2000 checks (see
# Get-ADSnapshot's DsHeuristics / PreWin2000Members keys). The anonymous
# RootDSE bind probe is a live network operation and cannot be represented
# by a point-in-time snapshot, so - consistent with the -FromSnapshot
# contract of performing NO live AD/network access - it is only attempted
# when this function is called WITHOUT -Snapshot (i.e. from the live audit
# path, not from Invoke-ADRuleSet / Start-ADSecurityAudit -FromSnapshot).
#
# DETECTION ONLY: attribute reads, group-membership reads, and a strictly
# read-only anonymous bind probe (refusal = secure, no finding). No
# exploitation, coercion, relay, or PoC traffic of any kind.

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
          3. Anonymous LDAP/RootDSE binding - a single, strictly read-only
             anonymous DirectoryEntry bind against RootDSE. Success is the
             finding; a refusal (exception) is the secure state and no
             finding is raised. This live probe is skipped when -Snapshot
             is supplied, since offline re-analysis must perform no live
             AD/network access.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        DsHeuristics and PreWin2000Members are read from it instead of
        live AD queries, and the anonymous-bind network probe is skipped.
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
            $configNC = ([ADSI]"LDAP://RootDSE").configurationNamingContext
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
                $finding.Description = "The dSHeuristics attribute on the Directory Service object contains $($flagIssues.Count) dangerous flag(s): " + (($flagIssues | ForEach-Object { $_.Setting }) -join '; ') + "."
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
            $targetDC = $null
            try {
                $targetDC = (Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Discover (anon bind target)' -Query {
                    Get-ADDomainController -Discover -ErrorAction Stop
                }).HostName
            }
            catch {
                Write-Verbose "Test-ADDomainHardeningFlags: DC discovery for anonymous-bind probe failed: $_"
            }

            if (-not $targetDC) {
                Write-Verbose "Test-ADDomainHardeningFlags: no target DC available; skipping anonymous-bind probe."
            }
            else {
                $anonBindSucceeded = $false
                $probePath = "LDAP://$targetDC/RootDSE"

                try {
                    $anonEntry = New-Object System.DirectoryServices.DirectoryEntry(
                        $probePath, $null, $null, [System.DirectoryServices.AuthenticationTypes]::Anonymous
                    )
                    # ADSI binds lazily; force the actual network bind by
                    # touching a property. An exception here means the
                    # anonymous bind was refused (the secure state).
                    [void]$anonEntry.Properties['currentTime']
                    [void]$anonEntry.NativeObject
                    $anonBindSucceeded = $true
                }
                catch {
                    Write-Verbose "Test-ADDomainHardeningFlags: anonymous RootDSE bind refused (secure): $_"
                    $anonBindSucceeded = $false
                }
                finally {
                    if ($anonEntry) { $anonEntry.Dispose() }
                }

                if ($anonBindSucceeded) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Domain Hardening'
                    $finding.Issue = 'Anonymous LDAP / RootDSE Binding Permitted'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $targetDC
                    $finding.Description = "An anonymous (unauthenticated) LDAP bind to RootDSE on '$targetDC' succeeded."
                    $finding.Impact = "Anonymous LDAP binding is a null-session indicator: it lets unauthenticated clients enumerate directory-service metadata (naming contexts, supported capabilities, schema/config paths) without any credentials, aiding reconnaissance ahead of further attacks."
                    $finding.Remediation = "Restrict anonymous LDAP operations via dSHeuristics (character 7) and/or the 'Network access: Let Everyone permissions apply to anonymous users' and related null-session security policy settings, then re-test."
                    $finding.Details = @{
                        DomainController = $targetDC
                        ProbePath        = $probePath
                    }
                    $findings += $finding
                }
                else {
                    Write-Verbose "Test-ADDomainHardeningFlags: anonymous RootDSE binding refused; no finding (secure)."
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

    Write-Verbose "Domain Hardening Flags audit complete. Found $($findings.Count) issues."
    return $findings
}

#endregion
