#region Domain Admin Equivalence Audit

function Test-ADDomainAdminEquivalence {
    <#
    .SYNOPSIS
        Correlates ACLs, group membership, delegation, and attribute-level
        signals to detect principals with effective Domain Admin-equivalent
        control, even without explicit group membership.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        every sub-check reads from the snapshot instead of live AD: per-
        computer ACLs and adminCount=1 user ACLs (Snapshot.Computers[].Access
        / Snapshot.PrivilegedUserAcls), a shadow-credentials presence flag
        (HasShadowCredentials, never the raw msDS-KeyCredentialLink value),
        scriptPath, SIDHistory (already collected since v1.18.2),
        TrustedToAuthForDelegation/HasRbcdConfigured (from the
        ConstrainedDelegation offline-parity step), and the existing
        Snapshot.ACLs.DomainRoot/.AdminSDHolder/.DomainControllersOU
        targets. No live AD access is performed. Added in v1.19.0 - the
        last of the 12 offline-parity retrofits in this release.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Admin Equivalence Audit"
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ADDomainAdminEquivalence: running from snapshot (no live AD access)."

        $domainDN = if ($Snapshot.Domain) { $Snapshot.Domain.DistinguishedName } else { $null }
        $domainName = if ($Snapshot.Domain) { $Snapshot.Domain.DNSRoot } else { $null }
        $netBIOSName = if ($Snapshot.Domain) { $Snapshot.Domain.NetBIOSName } else { $null }
        $domainSID = if ($Snapshot.Domain) { "$($Snapshot.Domain.DomainSID)" } else { $null }

        $legitimatePrincipals = @(
            'NT AUTHORITY\SYSTEM',
            'BUILTIN\Administrators'
        )
        if ($netBIOSName) {
            $legitimatePrincipals += @(
                "$netBIOSName\Administrators",
                "$netBIOSName\Domain Admins",
                "$netBIOSName\Enterprise Admins",
                "$netBIOSName\Schema Admins",
                "$netBIOSName\Domain Controllers",
                "$netBIOSName\Enterprise Domain Controllers",
                "$netBIOSName\Read-only Domain Controllers"
            )
        }

        $sensitiveGroupNames = @(
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Backup Operators', 'Account Operators', 'DNSAdmins', 'Print Operators', 'Server Operators'
        )

        $principalEvidence = @{}
        function Add-SnapshotEvidence {
            param([string]$Principal, [string]$Reason, [hashtable]$Context)
            if (-not $Principal) { return }
            if (-not $principalEvidence.ContainsKey($Principal)) {
                $principalEvidence[$Principal] = [System.Collections.ArrayList]::new()
            }
            [void]$principalEvidence[$Principal].Add([PSCustomObject]@{ Reason = $Reason; Context = $Context })
        }

        $groupsByName = @{}
        if ($Snapshot.ContainsKey('Groups')) {
            foreach ($g in @($Snapshot.Groups)) { if ($g -and $g.Name) { $groupsByName[$g.Name] = $g } }
        }
        $usersByDN = @{}
        $usersBySam = @{}
        if ($Snapshot.ContainsKey('Users')) {
            foreach ($u in @($Snapshot.Users)) {
                if ($u -and $u.DistinguishedName) { $usersByDN[$u.DistinguishedName] = $u }
                if ($u -and $u.SamAccountName) { $usersBySam[$u.SamAccountName] = $u }
            }
        }

        # DC names, for the delegation-to-DC cross-reference below.
        $dcNames = @()
        if ($Snapshot.ContainsKey('DomainControllers')) {
            $dcNames = @(@($Snapshot.DomainControllers) | ForEach-Object { $_.Name })
        }
        $dcComputerDNsForRbcd = @()
        if ($Snapshot.ContainsKey('Computers') -and $Snapshot.ContainsKey('DomainControllers')) {
            $dcNameSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$dcNames)
            $dcComputerDNsForRbcd = @(@($Snapshot.Computers) | Where-Object { $dcNameSet.Contains($_.Name) })
        }

        # Recursive protected-group membership (reuses step 18's helper).
        $protectedMembersDNs = [System.Collections.Generic.HashSet[string]]::new()
        $sensitivePrincipals = @{}
        foreach ($groupName in $sensitiveGroupNames) {
            $group = $groupsByName[$groupName]
            if (-not $group) { continue }
            $members = @(Resolve-ADSnapshotGroupMember -Snapshot $Snapshot -GroupDistinguishedName $group.DistinguishedName)
            foreach ($m in $members) {
                if ($m.DistinguishedName) { [void]$protectedMembersDNs.Add($m.DistinguishedName) }
                if ($m.objectClass -eq 'user' -and $m.SamAccountName -and -not $sensitivePrincipals.ContainsKey($m.SamAccountName)) {
                    $sensitivePrincipals[$m.SamAccountName] = $m.DistinguishedName
                }
            }
        }

        # 1. AdminSDHolder "ghost" accounts (adminCount=1, not in any protected group)
        Write-Verbose "Test-ADDomainAdminEquivalence: analyzing AdminSDHolder ghost accounts..."
        if ($Snapshot.ContainsKey('Users')) {
            $adminCountUsers = @($Snapshot.Users | Where-Object { $_.adminCount -eq 1 })
            foreach ($user in $adminCountUsers) {
                if (-not $protectedMembersDNs.Contains($user.DistinguishedName) -and $user.SamAccountName -ne 'krbtgt') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'AdminSDHolder Ghost Account'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp."
                    $finding.Impact = "The account's ACL inheritance remains disabled and its permissions frozen even though it's no longer in a protected group, which can mask a persistence mechanism or leave stale, overly-permissive rights in place unnoticed."
                    $finding.Remediation = "Clear the 'adminCount' attribute (set to 0) and enable permission inheritance on the object. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    $finding.Details = @{ UserDN = $user.DistinguishedName; Domain = $domainName }
                    $findings += $finding
                }
            }
        }

        # 2. Shadow Credentials presence (Users + Computers with HasShadowCredentials)
        Write-Verbose "Test-ADDomainAdminEquivalence: scanning for Shadow Credentials presence..."
        foreach ($collectionKey in @('Users', 'Computers')) {
            if (-not $Snapshot.ContainsKey($collectionKey)) { continue }
            foreach ($obj in @($Snapshot[$collectionKey] | Where-Object { $_.HasShadowCredentials })) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Admin Equivalence'
                $finding.Issue = 'Shadow Credentials Detected'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $obj.Name
                $finding.Description = "Object has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover."
                $finding.Impact = "An attacker with this key credential can authenticate as the object via PKINIT without knowing (or changing) its password, giving silent, persistent account takeover that survives a password reset."
                $finding.Remediation = "Investigate the 'msDS-KeyCredentialLink' attribute. If not legitimate WHfB, clear the attribute immediately. Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8"
                $finding.Details = @{
                    ObjectDN    = $obj.DistinguishedName
                    ObjectClass = if ($collectionKey -eq 'Users') { 'user' } else { 'computer' }
                    Domain      = $domainName
                }
                $findings += $finding
            }
        }

        # 3. Shadow Credentials write access on computers (per-computer ACLs)
        Write-Verbose "Test-ADDomainAdminEquivalence: checking Shadow Credentials write access on computers..."
        $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        if ($Snapshot.ContainsKey('Computers')) {
            foreach ($computer in @($Snapshot.Computers)) {
                foreach ($ace in @($computer.Access)) {
                    $principal = $ace.IdentityReference
                    if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                    if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                        $aceGuid = "$($ace.ObjectType)".ToLower()
                        if ($aceGuid -eq '00000000-0000-0000-0000-000000000000' -or $aceGuid -eq $keyCredLinkGuid) {
                            Add-SnapshotEvidence -Principal $principal -Reason "Shadow Credentials write access on computer '$($computer.Name)' - allows authentication as the computer account" -Context @{
                                Target = 'Shadow Credentials'; ComputerName = $computer.Name; DistinguishedName = $computer.DistinguishedName
                                OperatingSystem = $computer.OperatingSystem; Rights = "$($ace.ActiveDirectoryRights)"
                                AttackPath = 'Write msDS-KeyCredentialLink -> Request TGT as computer -> Compromise system'
                            }
                        }
                    }
                }
            }
        }

        # 4. Shadow Credentials write access + WriteSPN on privileged (adminCount=1) users
        Write-Verbose "Test-ADDomainAdminEquivalence: checking Shadow Credentials/WriteSPN write access on privileged users..."
        $privilegedUserAclsByDN = @{}
        if ($Snapshot.ContainsKey('PrivilegedUserAcls')) {
            foreach ($pua in @($Snapshot.PrivilegedUserAcls)) {
                if ($pua -and $pua.DistinguishedName) { $privilegedUserAclsByDN[$pua.DistinguishedName] = $pua }
            }
        }
        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value
            $pua = $privilegedUserAclsByDN[$dn]
            if (-not $pua) { continue }
            foreach ($ace in @($pua.Access)) {
                $principal = $ace.IdentityReference
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    $aceGuid = "$($ace.ObjectType)".ToLower()
                    if ($aceGuid -eq '00000000-0000-0000-0000-000000000000' -or $aceGuid -eq $keyCredLinkGuid) {
                        Add-SnapshotEvidence -Principal $principal -Reason "Shadow Credentials write access on privileged user '$sam' - direct account takeover" -Context @{
                            Target = 'Shadow Credentials (Privileged User)'; Account = $sam; DistinguishedName = $dn
                            Rights = "$($ace.ActiveDirectoryRights)"; AttackPath = 'Write msDS-KeyCredentialLink -> Authenticate as user -> Full compromise'
                        }
                    }
                    if ($aceGuid -eq '00000000-0000-0000-0000-000000000000' -or $aceGuid -eq $spnGuid) {
                        Add-SnapshotEvidence -Principal $principal -Reason "WriteSPN on privileged account '$sam' - enables targeted Kerberoasting" -Context @{
                            Target = 'WriteSPN'; Account = $sam; DistinguishedName = $dn
                            Rights = "$($ace.ActiveDirectoryRights)"; AttackPath = 'Add fake SPN -> Request service ticket -> Offline password cracking'
                        }
                    }
                }
            }
        }

        # 5. SID History Injection (already-collected Snapshot.Users.SIDHistory)
        Write-Verbose "Test-ADDomainAdminEquivalence: scanning for SID History Injection..."
        if ($Snapshot.ContainsKey('Users')) {
            foreach ($user in @($Snapshot.Users | Where-Object { @($_.SIDHistory).Count -gt 0 })) {
                foreach ($sidStr in @($user.SIDHistory)) {
                    if ($domainSID -and $sidStr -like "$domainSID*") {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Admin Equivalence'
                        $finding.Issue = 'SID History Injection (Same Domain)'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $user.SamAccountName
                        $finding.Description = "User contains a SID from the CURRENT domain in its SID History ($sidStr). This is a definitive sign of a Golden Ticket or SID History injection attack."
                        $finding.Impact = "The account carries privileges from the injected SID in addition to its normal group memberships, effectively granting hidden, unauthorized access that standard group-membership reviews will not reveal."
                        $finding.Remediation = "Immediate Incident Response required. Reset the account and investigate origin. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                        $finding.Details = @{ UserDN = $user.DistinguishedName; InjectedSID = $sidStr; Domain = $domainName }
                        $findings += $finding
                    }
                    if ($sidStr -match '-(500|512|519)$') {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Admin Equivalence'
                        $finding.Issue = 'Privileged SID in History'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $user.SamAccountName
                        $finding.Description = "User has a highly privileged SID ($sidStr) in their SID History. They possess Domain Admin rights regardless of group membership."
                        $finding.Impact = "The account has effective Domain Admin (or equivalent) rights that won't show up in any group-membership audit, since the privilege comes from SID History rather than an actual group the account belongs to."
                        $finding.Remediation = "Clear the sIDHistory attribute immediately unless this is a verified migration account. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                        $finding.Details = @{ UserDN = $user.DistinguishedName; PrivilegedSID = $sidStr; Domain = $domainName }
                        $findings += $finding
                    }
                }
            }
        }

        # 6. Legacy logon scripts (new scriptPath field)
        Write-Verbose "Test-ADDomainAdminEquivalence: scanning for legacy logon script abuse..."
        if ($Snapshot.ContainsKey('Users')) {
            foreach ($user in @($Snapshot.Users | Where-Object { $_.scriptPath })) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Legacy Attack Vector'
                $finding.Issue = 'Legacy Logon Script Defined'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has a legacy logon script defined: '$($user.scriptPath)'. Attackers can modify this file to achieve code execution upon user logon."
                $finding.Impact = "Anyone able to write to the referenced script file gains code execution as every user the script runs for at their next logon, a low-effort persistence and lateral-movement foothold."
                $finding.Remediation = "Migrate to Group Policy Preferences and clear the 'scriptPath' attribute. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues"
                $finding.Details = @{ UserDN = $user.DistinguishedName; ScriptPath = $user.scriptPath; Domain = $domainName }
                $findings += $finding
            }
        }

        # 7. Direct control of Domain Root / AdminSDHolder / DC OU
        Write-Verbose "Test-ADDomainAdminEquivalence: checking direct control of Domain Root/AdminSDHolder/DC OU..."
        $controlTargets = @(
            @{ Name = 'Domain Root'; AclKey = 'DomainRoot' },
            @{ Name = 'AdminSDHolder'; AclKey = 'AdminSDHolder' },
            @{ Name = 'Domain Controllers OU'; AclKey = 'DomainControllersOU' }
        )
        foreach ($target in $controlTargets) {
            if (-not ($Snapshot.ACLs -and $Snapshot.ACLs.ContainsKey($target.AclKey))) {
                Write-Verbose "Test-ADDomainAdminEquivalence: snapshot has no ACLs.$($target.AclKey) entry; skipping '$($target.Name)' control check."
                continue
            }
            $targetAcl = $Snapshot.ACLs[$target.AclKey]
            foreach ($ace in @($targetAcl.Access)) {
                $principal = $ace.IdentityReference
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-SnapshotEvidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target = $target.Name; DistinguishedName = $targetAcl.DistinguishedName
                        Rights = "$($ace.ActiveDirectoryRights)"; AccessControlType = "$($ace.AccessControlType)"
                        Inheritance = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        # 8. AdminSDHolder ACL analysis (dedicated finding, mirrors live's separate check)
        Write-Verbose "Test-ADDomainAdminEquivalence: performing AdminSDHolder ACL analysis..."
        if ($Snapshot.ACLs -and $Snapshot.ACLs.ContainsKey('AdminSDHolder')) {
            foreach ($ace in @($Snapshot.ACLs['AdminSDHolder'].Access)) {
                $principal = $ace.IdentityReference
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'AdminSDHolder ACL Compromise'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = 'AdminSDHolder'
                    $finding.Description = "Principal '$principal' has dangerous rights ($($ace.ActiveDirectoryRights)) on AdminSDHolder. This grants persistent Domain Admin rights via SDProp."
                    $finding.Impact = "Because SDProp periodically re-applies AdminSDHolder's ACL to every protected (Tier-0) account and group, this principal effectively controls the DACL of every Domain Admin, Enterprise Admin, and other protected object in the domain - a single ACE here compromises the entire tier."
                    $finding.Remediation = "Remove the ACE immediately and check all protected groups for 'adminCount=1' users. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    $finding.Details = @{ Principal = $principal; Rights = "$($ace.ActiveDirectoryRights)"; Domain = $domainName }
                    $findings += $finding
                }
            }
        }

        # 9. Constrained delegation to Domain Controllers
        Write-Verbose "Test-ADDomainAdminEquivalence: checking constrained delegation to Domain Controllers..."
        foreach ($collectionKey in @('Users', 'Computers')) {
            if (-not $Snapshot.ContainsKey($collectionKey)) { continue }
            foreach ($obj in @($Snapshot[$collectionKey] | Where-Object { @($_.'msDS-AllowedToDelegateTo').Count -gt 0 })) {
                foreach ($targetSPN in @($obj.'msDS-AllowedToDelegateTo')) {
                    $targetHost = ($targetSPN -split '/')[1]
                    if (-not $targetHost) { continue }
                    if ($targetHost -match ':') { $targetHost = ($targetHost -split ':')[0] }
                    $targetHostShort = ($targetHost -split '\.')[0]

                    if ($targetHostShort -in $dcNames) {
                        Add-SnapshotEvidence -Principal $(if ($obj.SamAccountName) { $obj.SamAccountName } else { $obj.Name }) -Reason "Admin Equivalence Edge: AllowedToDelegate (Constrained Delegation) to Domain Controller $targetHostShort" -Context @{
                            Target = $targetHostShort; SPN = $targetSPN; Attack = 'Impersonate users to DC via S4U2Proxy'
                        }
                    }

                    if ($obj.TrustedToAuthForDelegation) {
                        $targets = @(@($obj.'msDS-AllowedToDelegateTo') | ForEach-Object {
                            $parts = $_ -split '/'
                            if ($parts.Count -ge 2) { $parts[1] } else { $_ }
                        })
                        Add-SnapshotEvidence -Principal $obj.SamAccountName -Reason "Constrained delegation WITH protocol transition on '$($obj.SamAccountName)' - allows impersonation to sensitive services" -Context @{
                            Target = 'Constrained Delegation + Protocol Transition'; Account = $obj.SamAccountName
                            DistinguishedName = $obj.DistinguishedName; AllowedToDelegate = ($obj.'msDS-AllowedToDelegateTo' -join '; ')
                            TargetHosts = ($targets -join '; '); AttackPath = 'S4U2Self allows impersonation of ANY user to delegated services without authentication'
                        }
                    }
                }
            }
        }

        # 10. RBCD on Domain Controllers (presence flag from step 24)
        Write-Verbose "Test-ADDomainAdminEquivalence: checking RBCD on Domain Controllers..."
        foreach ($dc in @($dcComputerDNsForRbcd | Where-Object { $_.HasRbcdConfigured })) {
            Add-SnapshotEvidence -Principal $dc.Name -Reason "Admin Equivalence Edge: RBCD (AllowedToActOnBehalfOfOtherIdentity) configured on Domain Controller $($dc.Name)" -Context @{
                Target = $dc.Name; Attack = 'Compromise DC via RBCD impersonation'
            }
        }

        # 11. Dangerous built-in group membership (direct members only)
        Write-Verbose "Test-ADDomainAdminEquivalence: checking dangerous built-in group membership..."
        foreach ($groupName in @('Print Operators', 'Server Operators', 'Backup Operators', 'Account Operators', 'DnsAdmins')) {
            $group = $groupsByName[$groupName]
            if (-not $group) { continue }
            foreach ($memberDN in @($group.Members)) {
                $memberUser = $usersByDN[$memberDN]
                if (-not $memberUser) { continue }
                Add-SnapshotEvidence -Principal $memberUser.SamAccountName -Reason "Membership in dangerous built-in group '$groupName' - provides privilege escalation paths" -Context @{
                    Group = $groupName; Member = $memberUser.SamAccountName; MemberDN = $memberDN
                    AttackPath = switch ($groupName) {
                        'Print Operators' { 'Load printer drivers on DCs -> Execute code as SYSTEM' }
                        'Server Operators' { 'Modify services on DCs -> Execute code as SYSTEM' }
                        'Backup Operators' { 'Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise' }
                        'Account Operators' { 'Modify non-protected accounts -> Add to privileged groups' }
                        'DnsAdmins' { 'Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM' }
                        default { 'Privilege escalation via built-in group rights' }
                    }
                }
            }
        }

        # Build findings from evidence (same aggregation as the live path)
        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = @($evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync|Domain Controller|Privileged account|PKI|Unconstrained|AllowedToDelegate|AllowedToAct|ReadLAPSPassword|ReadGMSAPassword|WriteGPLink|Shadow Credentials|Certificate|Constrained Delegation|RBCD|LAPS password|DNS zone|Exchange|WriteSPN' })

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Admin Equivalence'
            $finding.Issue = 'Domain Admin Equivalent Access Detected'
            $finding.Severity = $severity
            $finding.SeverityLevel = $severityLevel
            $finding.AffectedObject = $principal
            $finding.Description = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control: $($evidence.Reason -join '; ')."
            $finding.Impact = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, PKI infrastructure, or perform DCSync.'
            $finding.Remediation = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control.
2. Lock down AD CS/PKI containers in the Configuration Partition.
3. Audit and remove Unconstrained Delegation from non-DC computers.
4. Restrict control over DNSAdmins and Print Operators.
5. Remove Constrained/RBCD delegation paths to Domain Controllers.
6. Audit LAPS and GMSA password read permissions.
7. Restrict WriteGPLink permissions on Domain and OU objects.
8. Clear adminCount attribute for 'ghost' accounts.
9. Remove Shadow Credentials if not using Windows Hello for Business.
10. Clear SID History injection entries.
"@
            $finding.Details = @{ Evidence = $evidence; Domain = $domainName }
            $findings += $finding
        }

        Write-Verbose "Admin Equivalence audit complete (snapshot mode). Found $($findings.Count) issues."
        return $findings
    }

    try {
        $domain = Get-ADDomain
        $domainDN = $domain.DistinguishedName
        $domainSID = $domain.DomainSID.Value
        $netBIOSName = $domain.NetBIOSName
        $configContext = (Get-ADRootDSE).ConfigurationNamingContext
        
        # Explicitly trusted principals that normally require broad control
        $legitimatePrincipals = @(
            'NT AUTHORITY\SYSTEM',
            'BUILTIN\Administrators',
            "$netBIOSName\Administrators",
            "$netBIOSName\Domain Admins",
            "$netBIOSName\Enterprise Admins",
            "$netBIOSName\Schema Admins",
            "$netBIOSName\Domain Controllers",
            "$netBIOSName\Enterprise Domain Controllers",
            "$netBIOSName\Read-only Domain Controllers"
        )

        $broadPrincipals = @(
            'NT AUTHORITY\Authenticated Users',
            'NT AUTHORITY\INTERACTIVE',
            'NT AUTHORITY\NETWORK',
            'Everyone',
            "$netBIOSName\Domain Users"
        )

        $principalEvidence = @{}
        $computerExposure = @()

        $sensitiveGroupNames = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Backup Operators',
            'Account Operators',
            'DNSAdmins',
            'Print Operators',
            'Server Operators'
        )

        $domainControllersContainer = $domain.DomainControllersContainer
        $sensitivePrincipals = @{}

        # Property GUIDs (normalized to lowercase for consistent comparison)
        $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
        $spnGuid = 'f3a64788-5306-11d1-a9c5-0000f80367c1'
        $rbcdGuid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
        $memberAttributeGuid = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
        $passwordResetGuid = '00299570-246d-11d0-a768-00aa006e0529'
        $gpLinkGuid = 'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
        $lapsGuid = 'ba19577d-37b2-4921-a637-429a1d99da82'
        $lapsPasswordGuid = '9a9a021e-4a5b-11d1-a9c3-0000f80367c1'
        $lapsPasswordExpGuid = 'e362ed86-b728-0842-b27d-2dea7a9df218'

        # Get DC computers EARLY - before any code that references it
        Write-Verbose "Enumerating Domain Controllers..."
        $dcComputers = $null
        try {
            $dcComputers = Get-ADComputer -Filter "primaryGroupID -eq 516" -Properties nTSecurityDescriptor, OperatingSystem -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to enumerate Domain Controllers: $_"
        }
        $dcNames = @()
        if ($dcComputers) {
            $dcNames = $dcComputers | ForEach-Object { $_.Name }
        }

        function Add-Evidence {
            param(
                [string]$Principal,
                [string]$Reason,
                [hashtable]$Context
            )

            if (-not $principalEvidence.ContainsKey($Principal)) {
                $principalEvidence[$Principal] = [System.Collections.ArrayList]::new()
            }

            $entry = [PSCustomObject]@{
                Reason  = $Reason
                Context = $Context
            }

            [void]$principalEvidence[$Principal].Add($entry)
        }

        # Helper function for consistent GUID comparison
        function Test-GuidMatch {
            param(
                [string]$AceObjectType,
                [string]$TargetGuid
            )
            
            if ([string]::IsNullOrEmpty($AceObjectType)) { return $false }
            
            $aceGuid = $AceObjectType.ToString().ToLower()
            $targetLower = $TargetGuid.ToLower()
            
            # Check for empty GUID (all properties)
            if ($aceGuid -eq '00000000-0000-0000-0000-000000000000') { return $true }
            
            return $aceGuid -eq $targetLower
        }

        Write-Verbose "Collecting sensitive principals for equivalence correlation..."
        foreach ($groupName in $sensitiveGroupNames) {
            $group = $null
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get group '$groupName': $_"
            }
            if (-not $group) { continue }

            $members = $null
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
            }
            catch {
                Write-Verbose "Failed to get members of group '$groupName': $_"
            }

            foreach ($member in $members) {
                if (-not $sensitivePrincipals.ContainsKey($member.SamAccountName)) {
                    $sensitivePrincipals[$member.SamAccountName] = $member.DistinguishedName
                }
            }
        }

        Write-Verbose "Analyzing AdminSDHolder 'Ghost' accounts..."
        
        # Get all protected members recursively
        $protectedMembers = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($groupName in $sensitiveGroupNames) {
            $group = $null
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get protected group '$groupName': $_"
            }
            if ($group) {
                $members = $null
                try {
                    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Failed to get protected group members for '$groupName': $_"
                }
                if ($members) {
                    foreach ($m in $members) { [void]$protectedMembers.Add($m.DistinguishedName) }
                }
            }
        }

        # Find users with adminCount=1
        $adminCountUsers = $null
        try {
            $adminCountUsers = Get-ADUser -LDAPFilter "(adminCount=1)" -Properties adminCount, nTSecurityDescriptor -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to enumerate adminCount users: $_"
        }

        foreach ($user in $adminCountUsers) {
            if (-not $protectedMembers.Contains($user.DistinguishedName) -and $user.SamAccountName -ne "krbtgt") {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Admin Equivalence'
                $finding.Issue = 'AdminSDHolder Ghost Account'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has 'adminCount=1' but is not a member of any protected group. This may indicate a leftover administrative account or a persistence backdoor where ACLs are frozen by SDProp."
                $finding.Impact = "The account's ACL inheritance remains disabled and its permissions frozen even though it's no longer in a protected group, which can mask a persistence mechanism or leave stale, overly-permissive rights in place unnoticed."
                $finding.Remediation = "Clear the 'adminCount' attribute (set to 0) and enable permission inheritance on the object. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                $finding.Details = @{
                    UserDN = $user.DistinguishedName
                    Domain = $domain.DNSRoot
                }
                $findings += $finding
            }
        }

        Write-Verbose "Scanning for Shadow Credentials (msDS-KeyCredentialLink)..."

        $shadowCreds = $null
        try {
            $shadowCreds = Get-ADObject -LDAPFilter "(msDS-KeyCredentialLink=*)" -Properties msDS-KeyCredentialLink, samAccountName, objectClass -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to scan for Shadow Credentials: $_"
        }

        foreach ($obj in $shadowCreds) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Admin Equivalence'
            $finding.Issue = 'Shadow Credentials Detected'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $obj.Name
            $finding.Description = "Object has 'msDS-KeyCredentialLink' populated. Unless Windows Hello for Business is deployed, this indicates a potential 'Shadow Credentials' attack (Whisker/Certipy) allowing account takeover."
            $finding.Impact = "An attacker with this key credential can authenticate as the object via PKINIT without knowing (or changing) its password, giving silent, persistent account takeover that survives a password reset."
            $finding.Remediation = "Investigate the 'msDS-KeyCredentialLink' attribute. If not legitimate WHfB, clear the attribute immediately. Reference: https://posts.specterops.io/shadow-credentials-abusing-key-credential-link-translation-to-en-9d8f9fb12be8"
            $finding.Details = @{
                ObjectDN    = $obj.DistinguishedName
                ObjectClass = $obj.objectClass -join ', '
                Domain      = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Detecting Shadow Credentials attack surface (msDS-KeyCredentialLink write access)..."

        $criticalComputers = $null
        try {
            $criticalComputers = Get-ADComputer -Filter * -Properties nTSecurityDescriptor, OperatingSystem -ResultPageSize 500 -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to enumerate computers for Shadow Credentials check: $_"
        }

        foreach ($computer in $criticalComputers) {
            if (-not $computer.nTSecurityDescriptor) { continue }
            
            foreach ($ace in $computer.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on computer '$($computer.Name)' - allows authentication as the computer account" -Context @{
                            Target            = 'Shadow Credentials'
                            ComputerName      = $computer.Name
                            DistinguishedName = $computer.DistinguishedName
                            OperatingSystem   = $computer.OperatingSystem
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Request TGT as computer -> Compromise system'
                        }
                    }
                }
            }
        }

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = $null
            try {
                $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get user '$sam' for Shadow Credentials check: $_"
            }
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $keyCredLinkGuid) {
                        Add-Evidence -Principal $principal -Reason "Shadow Credentials write access on privileged user '$sam' - direct account takeover" -Context @{
                            Target            = 'Shadow Credentials (Privileged User)'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Write msDS-KeyCredentialLink -> Authenticate as user -> Full compromise'
                        }
                    }
                }
            }
        }

        Write-Verbose "Checking for WriteSPN permissions (targeted Kerberoasting attack)..."

        foreach ($kvp in $sensitivePrincipals.GetEnumerator()) {
            $sam = $kvp.Key
            $dn = $kvp.Value

            $user = $null
            try {
                $user = Get-ADUser -Identity $dn -Properties nTSecurityDescriptor -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get user '$sam' for WriteSPN check: $_"
            }
            if (-not $user -or -not $user.nTSecurityDescriptor) { continue }

            foreach ($ace in $user.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll') {
                    if (Test-GuidMatch -AceObjectType $ace.ObjectType -TargetGuid $spnGuid) {
                        Add-Evidence -Principal $principal -Reason "WriteSPN on privileged account '$sam' - enables targeted Kerberoasting" -Context @{
                            Target            = 'WriteSPN'
                            Account           = $sam
                            DistinguishedName = $dn
                            Rights            = $ace.ActiveDirectoryRights.ToString()
                            AttackPath        = 'Add fake SPN -> Request service ticket -> Offline password cracking'
                        }
                    }
                }
            }
        }

        Write-Verbose "Scanning for SID History Injection..."

        $sidHistoryUsers = $null
        try {
            $sidHistoryUsers = Get-ADUser -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to scan for SID History Injection: $_"
        }

        foreach ($user in $sidHistoryUsers) {
            foreach ($sid in $user.sIDHistory) {
                $sidStr = $sid.ToString()
                
                if ($sidStr -like "$domainSID*") {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'SID History Injection (Same Domain)'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User contains a SID from the CURRENT domain in its SID History ($sidStr). This is a definitive sign of a Golden Ticket or SID History injection attack."
                    $finding.Impact = "The account carries privileges from the injected SID in addition to its normal group memberships, effectively granting hidden, unauthorized access that standard group-membership reviews will not reveal."
                    $finding.Remediation = "Immediate Incident Response required. Reset the account and investigate origin. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        InjectedSID  = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }
                
                if ($sidStr -match '-(500|512|519)$') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'Privileged SID in History'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has a highly privileged SID ($sidStr) in their SID History. They possess Domain Admin rights regardless of group membership."
                    $finding.Impact = "The account has effective Domain Admin (or equivalent) rights that won't show up in any group-membership audit, since the privilege comes from SID History rather than an actual group the account belongs to."
                    $finding.Remediation = "Clear the sIDHistory attribute immediately unless this is a verified migration account. Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-sidhistory"
                    $finding.Details = @{
                        UserDN       = $user.DistinguishedName
                        PrivilegedSID = $sidStr
                        Domain       = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Scanning for legacy Logon Script abuse..."

        $scriptUsers = $null
        try {
            $scriptUsers = Get-ADUser -LDAPFilter "(scriptPath=*)" -Properties scriptPath -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to scan for legacy Logon Scripts: $_"
        }
        foreach ($user in $scriptUsers) {
            $path = $user.scriptPath
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Attack Vector'
            $finding.Issue = 'Legacy Logon Script Defined'
            $finding.Severity = 'Low'
            $finding.SeverityLevel = 1
            $finding.AffectedObject = $user.SamAccountName
            $finding.Description = "User has a legacy logon script defined: '$path'. Attackers can modify this file to achieve code execution upon user logon."
            $finding.Impact = "Anyone able to write to the referenced script file gains code execution as every user the script runs for at their next logon, a low-effort persistence and lateral-movement foothold."
            $finding.Remediation = "Migrate to Group Policy Preferences and clear the 'scriptPath' attribute. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/logon-script-issues"
            $finding.Details = @{
                UserDN     = $user.DistinguishedName
                ScriptPath = $path
                Domain     = $domain.DNSRoot
            }
            $findings += $finding
        }

        # Check direct control over the domain naming context and AdminSDHolder
        $controlTargets = @(
            @{ Name = 'Domain Root'; DistinguishedName = $domainDN; RiskType = 'DomainRootControl' },
            @{ Name = 'AdminSDHolder'; DistinguishedName = "CN=AdminSDHolder,CN=System,$domainDN"; RiskType = 'AdminSDHolderControl' }
        )

        if ($domainControllersContainer) {
            $controlTargets += @{ Name = 'Domain Controllers OU'; DistinguishedName = $domainControllersContainer; RiskType = 'DomainControllersContainerControl' }
        }

        foreach ($target in $controlTargets) {
            $object = $null
            try {
                $object = Get-ADObject -Identity $target.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get control target '$($target.Name)': $_"
            }
            if (-not $object -or -not $object.nTSecurityDescriptor) { continue }

            foreach ($ace in $object.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value

                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }

                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights') {
                    Add-Evidence -Principal $principal -Reason "$($target.Name) control via $($ace.ActiveDirectoryRights)" -Context @{
                        Target             = $target.Name
                        DistinguishedName  = $target.DistinguishedName
                        Rights             = $ace.ActiveDirectoryRights.ToString()
                        AccessControlType  = $ace.AccessControlType.ToString()
                        Inheritance        = if ($ace.IsInherited) { 'Inherited' } else { 'Explicit' }
                    }
                }
            }
        }

        Write-Verbose "Performing AdminSDHolder ACL Analysis..."
        $adminSdHolder = $null
        try {
            $adminSdHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$domainDN" -Properties nTSecurityDescriptor -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to get AdminSDHolder: $_"
        }
        if ($adminSdHolder -and $adminSdHolder.nTSecurityDescriptor) {
            foreach ($ace in $adminSdHolder.nTSecurityDescriptor.Access) {
                $principal = $ace.IdentityReference.Value
                if ($ace.IsInherited -or $principal -in $legitimatePrincipals) { continue }
                
                if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Admin Equivalence'
                    $finding.Issue = 'AdminSDHolder ACL Compromise'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = 'AdminSDHolder'
                    $finding.Description = "Principal '$principal' has dangerous rights ($($ace.ActiveDirectoryRights)) on AdminSDHolder. This grants persistent Domain Admin rights via SDProp."
                    $finding.Impact = "Because SDProp periodically re-applies AdminSDHolder's ACL to every protected (Tier-0) account and group, this principal effectively controls the DACL of every Domain Admin, Enterprise Admin, and other protected object in the domain - a single ACE here compromises the entire tier."
                    $finding.Remediation = "Remove the ACE immediately and check all protected groups for 'adminCount=1' users. Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/adminsdholder-protected-accounts-and-groups"
                    $finding.Details = @{
                        Principal = $principal
                        Rights    = $ace.ActiveDirectoryRights.ToString()
                        Domain    = $domain.DNSRoot
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Checking Constrained Delegation to Domain Controllers..."

        $delegationRisk = $null
        try {
            $delegationRisk = Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo, samAccountName -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to check Constrained Delegation: $_"
        }

        foreach ($obj in $delegationRisk) {
            foreach ($targetSPN in $obj.'msDS-AllowedToDelegateTo') {
                $targetHost = ($targetSPN -split '/')[1]
                if ($targetHost -match ':') { $targetHost = ($targetHost -split ':')[0] }
                $targetHostShort = ($targetHost -split '\.')[0]

                if ($targetHostShort -in $dcNames) {
                    Add-Evidence -Principal $obj.Name -Reason "Admin Equivalence Edge: AllowedToDelegate (Constrained Delegation) to Domain Controller $targetHostShort" -Context @{
                        Target = $targetHostShort
                        SPN = $targetSPN
                        Attack = "Impersonate users to DC via S4U2Proxy"
                    }
                }
            }
        }

        Write-Verbose "Checking constrained delegation with protocol transition (S4U2Self abuse)..."
        $constrainedDelegation = $null
        try {
            $constrainedDelegation = Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo, servicePrincipalName, samAccountName, objectClass -ErrorAction Stop
        }
        catch {
            Write-Verbose "Failed to check constrained delegation with protocol transition: $_"
        }

        foreach ($delegator in $constrainedDelegation) {
            $allowedServices = $delegator.'msDS-AllowedToDelegateTo'
            $delegatorDetails = $null
            try {
                $delegatorDetails = Get-ADObject -Identity $delegator.DistinguishedName -Properties TrustedToAuthForDelegation -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get delegator details for '$($delegator.samAccountName)': $_"
            }
            $hasProtocolTransition = $delegatorDetails.TrustedToAuthForDelegation

            if ($hasProtocolTransition) {
                $targets = $allowedServices | ForEach-Object {
                    $parts = $_ -split '/'
                    if ($parts.Count -ge 2) { $parts[1] } else { $_ }
                }

                Add-Evidence -Principal $delegator.samAccountName -Reason "Constrained delegation WITH protocol transition on '$($delegator.samAccountName)' - allows impersonation to sensitive services" -Context @{
                    Target               = 'Constrained Delegation + Protocol Transition'
                    Account              = $delegator.samAccountName
                    DistinguishedName    = $delegator.DistinguishedName
                    ObjectClass          = $delegator.objectClass -join ', '
                    AllowedToDelegate    = $allowedServices -join '; '
                    TargetHosts          = $targets -join '; '
                    AttackPath           = 'S4U2Self allows impersonation of ANY user to delegated services without authentication'
                }
            }
        }

        Write-Verbose "Checking RBCD (AllowedToActOnBehalfOfOtherIdentity) on Domain Controllers..."
        foreach ($dc in $dcComputers) {
            $dcObj = $null
            try {
                $dcObj = Get-ADComputer -Identity $dc.DistinguishedName -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get RBCD info for DC '$($dc.Name)': $_"
            }

            if ($dcObj -and $dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
                try {
                    $sdBytes = $dcObj.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    if ($sdBytes) {
                        $rawSD = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)
                        foreach ($ace in $rawSD.DiscretionaryAcl) {
                            $sid = $ace.SecurityIdentifier.Value
                            try { $principal = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value } catch { $principal = $sid }
                            
                            if ($principal -notin $legitimatePrincipals) {
                                Add-Evidence -Principal $principal -Reason "Admin Equivalence Edge: AllowedToAct (RBCD) on Domain Controller $($dc.Name)" -Context @{
                                    Target = $dc.Name
                                    Attack = "Compromise DC via RBCD impersonation"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Failed to parse RBCD SD for $($dc.Name): $_"
                }
            }
        }

        Write-Verbose "Checking for auditing high-privilege built-in groups..."
        foreach ($groupName in @('Print Operators', 'Server Operators', 'Backup Operators', 'Account Operators', 'DnsAdmins')) {
            $group = $null
            try {
                $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get built-in group '$groupName': $_"
            }
            if (-not $group) { continue }

            $members = $null
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
            }
            catch {
                Write-Verbose "Failed to get members of built-in group '$groupName': $_"
            }

            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    Add-Evidence -Principal $member.SamAccountName -Reason "Membership in dangerous built-in group '$groupName' - provides privilege escalation paths" -Context @{
                        Group      = $groupName
                        Member     = $member.SamAccountName
                        MemberDN   = $member.DistinguishedName
                        AttackPath = switch ($groupName) {
                            'Print Operators' { 'Load printer drivers on DCs -> Execute code as SYSTEM' }
                            'Server Operators' { 'Modify services on DCs -> Execute code as SYSTEM' }
                            'Backup Operators' { 'Backup SAM/SYSTEM -> Extract credentials -> Full domain compromise' }
                            'Account Operators' { 'Modify non-protected accounts -> Add to privileged groups' }
                            'DnsAdmins' { 'Load arbitrary DLL in DNS service on DC -> Execute as SYSTEM' }
                            default { 'Privilege escalation via built-in group rights' }
                        }
                    }
                }
            }
        }

        # Build findings from evidence
        foreach ($principal in $principalEvidence.Keys) {
            $evidence = $principalEvidence[$principal]
            $criticalEvidence = $evidence | Where-Object { $_.Reason -match 'Domain Root|AdminSDHolder|DCSync|Domain Controller|Privileged account|PKI|Unconstrained|AllowedToDelegate|AllowedToAct|ReadLAPSPassword|ReadGMSAPassword|WriteGPLink|Shadow Credentials|Certificate|Constrained Delegation|RBCD|LAPS password|DNS zone|Exchange|WriteSPN' }

            $severity = if ($criticalEvidence.Count -gt 0) { 'Critical' } else { 'High' }
            $severityLevel = if ($severity -eq 'Critical') { 4 } else { 3 }

            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Domain Admin Equivalence'
            $finding.Issue = 'Domain Admin Equivalent Access Detected'
            $finding.Severity = $severity
            $finding.SeverityLevel = $severityLevel
            $finding.AffectedObject = $principal
            $finding.Description = "Principal '$principal' holds permissions that provide Domain Admin-equivalent control: $($evidence.Reason -join '; ')."
            $finding.Impact = 'Compromise of this principal would allow attackers to seize control of protected groups, the domain naming context, PKI infrastructure, or perform DCSync.'
            $finding.Remediation = @"
Review and remove the excessive permissions listed in the evidence:
1. Restrict Domain Naming Context and AdminSDHolder control.
2. Lock down AD CS/PKI containers in the Configuration Partition.
3. Audit and remove Unconstrained Delegation from non-DC computers.
4. Restrict control over DNSAdmins and Print Operators.
5. Remove Constrained/RBCD delegation paths to Domain Controllers.
6. Audit LAPS and GMSA password read permissions.
7. Restrict WriteGPLink permissions on Domain and OU objects.
8. Clear adminCount attribute for 'ghost' accounts.
9. Remove Shadow Credentials if not using Windows Hello for Business.
10. Clear SID History injection entries.
"@
            $finding.Details = @{
                Evidence = $evidence
                Domain   = $domain.DNSRoot
            }
            $findings += $finding
        }

        Write-Verbose "Audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during equivalence audit: $_"
        throw
    }
}

#endregion
