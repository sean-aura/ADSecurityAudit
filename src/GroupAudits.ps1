#region Group and Privilege Audits

function Test-ADPrivilegedGroups {
    <#
    .SYNOPSIS
        Audits privileged/protected group membership for excessive size,
        nested groups, and disabled users.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        group membership is resolved entirely in-memory via
        Resolve-ADSnapshotGroupMember against Snapshot.Groups/Users/Computers -
        no live AD access is performed. Added in v1.19.0.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$AdditionalGroups = @(),

        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting privileged group audit..."
    $findings = @()

    $groupsToCheck = $Script:ProtectedGroups + $AdditionalGroups

    if ($Snapshot) {
        Write-Verbose "Test-ADPrivilegedGroups: running from snapshot (no live AD access)."

        if (-not $Snapshot.ContainsKey('Groups')) {
            Write-Verbose "Test-ADPrivilegedGroups: snapshot has no 'Groups' key; no findings."
            return $findings
        }

        $groupsByName = @{}
        foreach ($g in @($Snapshot.Groups)) {
            if ($g -and $g.Name) { $groupsByName[$g.Name] = $g }
        }

        $criticalGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')

        foreach ($groupName in $groupsToCheck) {
            $group = $groupsByName[$groupName]
            if (-not $group) {
                Write-Verbose "Test-ADPrivilegedGroups: group '$groupName' not found in snapshot."
                continue
            }

            $recursiveMembers = @(Resolve-ADSnapshotGroupMember -Snapshot $Snapshot -GroupDistinguishedName $group.DistinguishedName)
            $directMembers = @(Resolve-ADSnapshotGroupMember -Snapshot $Snapshot -GroupDistinguishedName $group.DistinguishedName -DirectOnly)

            # Check for excessive membership (using recursive count)
            $memberCount = $recursiveMembers.Count
            $threshold = if ($groupName -in $criticalGroups) { $Script:ThresholdCriticalGroupSize } else { $Script:ThresholdStandardGroupSize }

            if ($memberCount -gt $threshold) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Privileged Groups'
                $finding.Issue = 'Excessive Privileged Group Membership'
                $finding.Severity = if ($groupName -in $criticalGroups) { 'Critical' } else { 'High' }
                $finding.SeverityLevel = if ($groupName -in $criticalGroups) { 4 } else { 3 }
                $finding.AffectedObject = $groupName
                $finding.Description = "The '$groupName' group has $memberCount members, exceeding the recommended threshold of $threshold."
                $finding.Impact = "Over-privileged accounts increase the attack surface and make it harder to maintain accountability."
                $finding.Remediation = "Review and reduce membership. Remove unnecessary accounts and implement role-based access with custom delegated groups. Use temporary privileged access where possible."
                $finding.Details = @{
                    GroupDN = $group.DistinguishedName
                    MemberCount = $memberCount
                    Members = ($recursiveMembers | Select-Object -ExpandProperty SamAccountName) -join '; '
                }
                $findings += $finding
            }

            # Check for nested groups in critical groups (using direct members)
            $nestedGroups = @($directMembers | Where-Object { $_.objectClass -eq 'group' })
            if ($nestedGroups.Count -gt 0 -and $groupName -in $criticalGroups) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Privileged Groups'
                $finding.Issue = 'Nested Groups in Critical Privileged Group'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $groupName
                $finding.Description = "The critical group '$groupName' contains $($nestedGroups.Count) nested group(s), which complicates access management."
                $finding.Impact = "Nested groups create choke points and can lead to unintentional privileged access. They make it difficult to audit who has access."
                $finding.Remediation = "Remove nested groups and add users directly, or create custom delegated groups instead. Nested groups: $($nestedGroups.SamAccountName -join ', ')"
                $finding.Details = @{
                    GroupDN = $group.DistinguishedName
                    NestedGroups = ($nestedGroups | Select-Object @{N='Name';E={$_.SamAccountName}}, DistinguishedName)
                }
                $findings += $finding
            }

            # Check for disabled users in privileged groups
            $usersByDN = @{}
            if ($Snapshot.ContainsKey('Users')) {
                foreach ($u in @($Snapshot.Users)) {
                    if ($u -and $u.DistinguishedName) { $usersByDN[$u.DistinguishedName] = $u }
                }
            }
            $userMembers = @($recursiveMembers | Where-Object { $_.objectClass -eq 'user' })
            foreach ($member in $userMembers) {
                $userDetails = $usersByDN[$member.DistinguishedName]
                if (-not $userDetails) {
                    Write-Verbose "Test-ADPrivilegedGroups: could not find user details for '$($member.DistinguishedName)' in snapshot."
                    continue
                }

                if ($userDetails.Enabled -eq $false) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Privileged Groups'
                    $finding.Issue = 'Disabled User in Privileged Group'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = "$groupName - $($userDetails.SamAccountName)"
                    $finding.Description = "Disabled user '$($userDetails.SamAccountName)' is still a member of privileged group '$groupName'."
                    $finding.Impact = "Disabled accounts in privileged groups should be removed to maintain clean access control."
                    $finding.Remediation = "Remove the disabled user: Remove-ADGroupMember -Identity '$groupName' -Members '$($userDetails.SamAccountName)' -Confirm:`$false"
                    $finding.Details = @{
                        UserDN = $userDetails.DistinguishedName
                        GroupDN = $group.DistinguishedName
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "Privileged group audit complete (snapshot mode). Found $($findings.Count) issues."
        return $findings
    }

    try {
        $groupCount = $groupsToCheck.Count
        $currentGroup = 0
        $forestRootOnlyGroups = @('Enterprise Admins', 'Schema Admins')
        
        foreach ($groupName in $groupsToCheck) {
            $currentGroup++
            Write-Progress -Activity "Scanning Privileged Groups" -Status "Processing $groupName" `
                -PercentComplete (($currentGroup / $groupCount) * 100)
            
            try {
                $group = $null
                try {
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Properties Members, MemberOf -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Failed to get group '$groupName': $_"
                }

                if (-not $group -and $groupName -in $forestRootOnlyGroups) {
                    # Enterprise Admins/Schema Admins exist ONLY in the
                    # forest root domain - a lookup scoped to a child
                    # domain (via the active -Server override) correctly
                    # finds nothing there, and previously that meant this
                    # group was silently skipped for every non-root domain
                    # audited, with no finding and no indication why.
                    # Resolve the forest root explicitly and re-query
                    # there instead.
                    try {
                        $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
                        if ($forestRootDomain) {
                            Write-Verbose "Test-ADPrivilegedGroups: '$groupName' not found in the target domain (expected - it's forest-root-only); re-querying against the forest root '$forestRootDomain' instead."
                            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $forestRootDomain -Properties Members, MemberOf -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Verbose "Failed to resolve '$groupName' via the forest root domain: $_"
                    }
                }

                if (-not $group) {
                    continue
                }

                # The domain the group object ITSELF actually landed in -
                # normally the audited domain, but the forest root for
                # Enterprise Admins/Schema Admins per the fallback above.
                # Get-ADGroupMember is called with -Identity $group below,
                # which binds it to this same domain regardless of the
                # ambient -Server default, so member lookups stay
                # consistent with wherever the group actually is.
                $groupDomainDN = if ($group.DistinguishedName -match '(DC=.+)$') { $matches[1] } else { $null }

                # Get recursive members for total count and user analysis
                $recursiveMembers = $null
                try {
                    $recursiveMembers = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Failed to get recursive members of '$groupName': $_"
                }

                # Get direct members separately to detect nested groups
                # (Get-ADGroupMember -Recursive only returns leaf objects, not groups)
                $directMembers = $null
                try {
                    $directMembers = Get-ADGroupMember -Identity $group -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Failed to get direct members of '$groupName': $_"
                }

                if (-not $recursiveMembers -and -not $directMembers) {
                    continue
                }

                # --- Cross-domain membership visibility -----------------
                # Get-ADGroupMember -Recursive can return members from a
                # DIFFERENT domain than the group itself (a universal group,
                # or - in a multi-domain forest where the auditor's own
                # machine is joined to a different domain than the one
                # being audited - membership resolved via a Global Catalog
                # can legitimately include full objects from other domains
                # too). Neither case is inherently wrong, but it was
                # previously invisible: nothing recorded which domain a
                # member actually belonged to. This doesn't change the
                # membership counts/thresholds below (a cross-domain member
                # is still a real member) - it only adds visibility.
                if ($groupDomainDN -and $recursiveMembers) {
                    $membershipSplit = Split-ADObjectByTargetDomain -InputObject @($recursiveMembers) -TargetDomainDN $groupDomainDN
                    if (@($membershipSplit.Foreign).Count -gt 0) {
                        Write-Warning "Test-ADPrivilegedGroups: '$groupName' has $(@($membershipSplit.Foreign).Count) member(s) from a domain other than the group's own ($groupDomainDN). If this domain wasn't the one you intended to audit, verify -Server/DNS resolution - see the 'Cross-Domain Privileged Group Membership' finding for the affected accounts."
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Privileged Groups'
                        $finding.Issue = 'Cross-Domain Privileged Group Membership'
                        # 'Low', not a true Info bucket - Export-ADSecurityReportHTML
                        # only renders Critical/High/Medium/Low sections, so an
                        # 'Info' severity here would be counted in JSON/CSV but
                        # invisible in the HTML report itself, defeating the
                        # point of surfacing it. Low keeps its scoring impact
                        # minimal while still making it visible where an
                        # operator will actually see it.
                        $finding.Severity = 'Low'
                        $finding.SeverityLevel = 1
                        $finding.AffectedObject = $groupName
                        $finding.Description = "The '$groupName' group (domain: $groupDomainDN) has $(@($membershipSplit.Foreign).Count) member(s) whose own DistinguishedName belongs to a different domain."
                        $finding.Impact = "This can be legitimate (a universal group, or intentional cross-domain nesting in this forest) - but if this domain was not the one you intended to audit (-Server), it can also indicate the audit is unexpectedly reading data from another domain in the forest."
                        $finding.Remediation = "Review the listed accounts' domains. If this is unintentional, verify -Server was resolved to the intended domain (check the run's 'Server override:' console/verbose output) and that DNS for the target domain resolves correctly from this machine."
                        $finding.Details = @{
                            GroupDN         = $group.DistinguishedName
                            ForeignDomains  = @($membershipSplit.Foreign | ForEach-Object { if ($_.DistinguishedName -match '(DC=.+)$') { $matches[1] } }) | Select-Object -Unique
                            ForeignMembers  = ($membershipSplit.Foreign | Select-Object -ExpandProperty SamAccountName) -join '; '
                        }
                        $findings += $finding
                    }
                }
                
                # Check for excessive membership (using recursive count)
                $memberCount = ($recursiveMembers | Measure-Object).Count
                
                $criticalGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                $threshold = if ($groupName -in $criticalGroups) { $Script:ThresholdCriticalGroupSize } else { $Script:ThresholdStandardGroupSize }
                
                if ($memberCount -gt $threshold) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Privileged Groups'
                    $finding.Issue = 'Excessive Privileged Group Membership'
                    $finding.Severity = if ($groupName -in $criticalGroups) { 'Critical' } else { 'High' }
                    $finding.SeverityLevel = if ($groupName -in $criticalGroups) { 4 } else { 3 }
                    $finding.AffectedObject = $groupName
                    $finding.Description = "The '$groupName' group has $memberCount members, exceeding the recommended threshold of $threshold."
                    $finding.Impact = "Over-privileged accounts increase the attack surface and make it harder to maintain accountability."
                    $finding.Remediation = "Review and reduce membership. Remove unnecessary accounts and implement role-based access with custom delegated groups. Use temporary privileged access where possible."
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        MemberCount = $memberCount
                        Members = ($recursiveMembers | Select-Object -ExpandProperty SamAccountName) -join '; '
                    }
                    $findings += $finding
                }
                
                # Check for nested groups in critical groups (using direct members)
                $nestedGroups = $directMembers | Where-Object { $_.objectClass -eq 'group' }
                if ($nestedGroups -and $groupName -in $criticalGroups) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Privileged Groups'
                    $finding.Issue = 'Nested Groups in Critical Privileged Group'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $groupName
                    $finding.Description = "The critical group '$groupName' contains $($nestedGroups.Count) nested group(s), which complicates access management."
                    $finding.Impact = "Nested groups create choke points and can lead to unintentional privileged access. They make it difficult to audit who has access."
                    $finding.Remediation = "Remove nested groups and add users directly, or create custom delegated groups instead. Nested groups: $($nestedGroups.Name -join ', ')"
                    $finding.Details = @{
                        GroupDN = $group.DistinguishedName
                        NestedGroups = ($nestedGroups | Select-Object Name, DistinguishedName)
                    }
                    $findings += $finding
                }
                
                # Check for disabled or inactive users in privileged groups
                $userMembers = $recursiveMembers | Where-Object { $_.objectClass -eq 'user' }
                foreach ($member in $userMembers) {
                    $userDetails = $null
                    try {
                        $userDetails = Get-ADUser -Identity $member -Properties Enabled, LastLogonDate -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Failed to get user details for '$($member.SamAccountName)': $_"
                    }

                    if (-not $userDetails) {
                        continue
                    }
                    
                    if ($userDetails.Enabled -eq $false) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Privileged Groups'
                        $finding.Issue = 'Disabled User in Privileged Group'
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = "$groupName - $($userDetails.SamAccountName)"
                        $finding.Description = "Disabled user '$($userDetails.SamAccountName)' is still a member of privileged group '$groupName'."
                        $finding.Impact = "Disabled accounts in privileged groups should be removed to maintain clean access control."
                        $finding.Remediation = "Remove the disabled user: Remove-ADGroupMember -Identity '$groupName' -Members '$($userDetails.SamAccountName)' -Confirm:`$false"
                        $finding.Details = @{
                            UserDN = $userDetails.DistinguishedName
                            GroupDN = $group.DistinguishedName
                        }
                        $findings += $finding
                    }
                }
                
            }
            catch {
                Write-Warning "Could not audit group '$groupName': $_"
            }
        }
        
        Write-Progress -Activity "Scanning Privileged Groups" -Completed
        Write-Verbose "Privileged group audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during privileged group audit: $_"
        throw
    }
}

#endregion
