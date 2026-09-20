#region Replication and DCSync Audit

function Test-ADReplicationSecurity {
    <#
    .SYNOPSIS
        Audits DCSync-enabling replication rights and privileged-operations
        group membership.
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Starting replication security audit (DCSync detection)..."
    $findings = @()

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue
        $domain = Get-ADDomain -Server $__adServer
        $domainDN = $domain.DistinguishedName
        
        # Get the domain object with ACL
        $domainObject = Get-ADObject -Identity $domainDN -Properties nTSecurityDescriptor -Server $__adServer
        $acl = $domainObject.nTSecurityDescriptor
        
        # Define legitimate replication principals
        $legitimateReplicators = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            "$($domain.NetBIOSName)\Domain Controllers"
            "$($domain.NetBIOSName)\Enterprise Domain Controllers"
            "$($domain.NetBIOSName)\Domain Admins"
            "$($domain.NetBIOSName)\Enterprise Admins"
            "$($domain.NetBIOSName)\Read-only Domain Controllers"
        )
        
        $dcsyncRights = @{
            'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-All' = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
        }
        
        # A trustee's DCSync capability can come from more than one ACE
        # (e.g. one ACE granting DS-Replication-Get-Changes and a separate
        # ACE granting DS-Replication-Get-Changes-All) - these combine to
        # grant full DCSync capability just as a single GenericAll ACE
        # would, so aggregate ALL rights a given identity holds across
        # every one of its ACEs into ONE finding (also resolving the
        # principal's object class only once per identity instead of once
        # per ACE), rather than reporting each ACE's single right as its
        # own finding with a generic Description that doesn't name the
        # specific right - which looked like an exact duplicate.
        $__dcSyncByIdentity = [ordered]@{}

        # Check each ACE for dangerous replication rights
        foreach ($ace in $acl.Access) {
            $identityReference = $ace.IdentityReference.Value
            
            # Skip inherited ACEs and legitimate replicators
            if ($ace.IsInherited -or $identityReference -in $legitimateReplicators) {
                continue
            }
            
            # Check for DCSync-enabling rights
            $rightsFound = @()
            
            if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -or 
                $ace.ActiveDirectoryRights -match 'GenericAll') {
                
                # Check ObjectType GUID
                $objectTypeGuid = $ace.ObjectType.ToString().ToLower()
                
                foreach ($rightName in $dcsyncRights.Keys) {
                    if ($objectTypeGuid -eq $dcsyncRights[$rightName].ToLower() -or 
                        $ace.ActiveDirectoryRights -match 'GenericAll') {
                        $rightsFound += $rightName
                    }
                }
            }
            
            if ($rightsFound.Count -eq 0) { continue }

            if (-not $__dcSyncByIdentity.Contains($identityReference)) {
                $__dcSyncByIdentity[$identityReference] = @{
                    Rights                = [System.Collections.ArrayList]::new()
                    ActiveDirectoryRights = [System.Collections.ArrayList]::new()
                    ObjectTypes           = [System.Collections.ArrayList]::new()
                }
            }
            $entry = $__dcSyncByIdentity[$identityReference]
            foreach ($r in $rightsFound) { if ($r -notin $entry.Rights) { [void]$entry.Rights.Add($r) } }
            $__adRightsStr = $ace.ActiveDirectoryRights.ToString()
            if ($__adRightsStr -notin $entry.ActiveDirectoryRights) { [void]$entry.ActiveDirectoryRights.Add($__adRightsStr) }
            $__objTypeStr = $ace.ObjectType.ToString()
            if ($__objTypeStr -notin $entry.ObjectTypes) { [void]$entry.ObjectTypes.Add($__objTypeStr) }
        }

        foreach ($identityReference in $__dcSyncByIdentity.Keys) {
            $entry = $__dcSyncByIdentity[$identityReference]

            # Resolve the identity to determine if it's a user or group -
            # once per identity, not once per contributing ACE.
            $principal = $null
            $principalClass = 'Unknown'
            
            try {
                # First try to translate the identity reference to a SID
                $sid = $null
                
                # Check if it's already a SID string
                if ($identityReference -match '^S-1-') {
                    $sid = $identityReference
                }
                else {
                    # Try to translate account name to SID
                    try {
                        $ntAccount = New-Object System.Security.Principal.NTAccount($identityReference)
                        $sidObj = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
                        $sid = $sidObj.Value
                    }
                    catch {
                        Write-Verbose "Could not translate '$identityReference' to SID: $_"
                    }
                }
                
                # If we have a SID, look up the AD object
                if ($sid) {
                    $principal = $null
                    try {
                        $principal = Get-ADObject -Filter "objectSid -eq '$sid'" -Properties objectClass -Server $__adServer -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Could not resolve SID '$sid': $_"
                    }
                    if ($principal) {
                        $principalClass = $principal.objectClass
                    }
                }
            }
            catch {
                Write-Verbose "Could not resolve principal: $identityReference - $_"
            }
            
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Replication Security'
            $finding.Issue = 'Unauthorized DCSync Permissions'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = $identityReference
            $finding.Description = "Non-standard principal '$identityReference' has DCSync replication rights on the domain ($($entry.Rights -join ', '))."
            $finding.Impact = "This principal can perform DCSync attacks to retrieve password hashes for any account, including KRBTGT and Domain Admins. Attackers can then create Golden Tickets for persistent, unrestricted domain access."
            $finding.Remediation = "Remove replication rights immediately: `$acl = Get-Acl 'AD:\$domainDN'; Find and remove the ACE for '$identityReference'; Set-Acl -Path 'AD:\$domainDN' -AclObject `$acl"
            $finding.EstimatedEffort = 'Low - removing two specific extended-right ACEs (Replicating Directory Changes / Replicating Directory Changes All) from one object, a well-scoped ACE change.'
            $finding.KnownRisks = 'Legitimate DCSync-capable accounts are normally limited to Domain Controllers, Domain/Enterprise Admins, and directory-sync tools like Azure AD Connect; removing an unauthorized grant has no legitimate compatibility impact unless it turns out to be an undocumented, currently-in-use sync or identity-governance tool, so confirm no such tool depends on it.'
            $finding.BackupRollback = 'Moderate - export the domain object''s ACL before removing the specific extended-right ACEs so they can be restored if a legitimate sync tool is affected; changes follow normal AD replication.'
            $finding.Details = @{
                Identity = $identityReference
                ObjectClass = $principalClass
                ActiveDirectoryRights = ($entry.ActiveDirectoryRights -join ', ')
                Rights = ($entry.Rights -join ', ')
                ObjectType = ($entry.ObjectTypes -join ', ')
            }
            $findings += $finding
        }
        
        # Check for accounts with explicit DCSync-enabling group memberships
        Write-Verbose "Checking for suspicious group memberships..."
        
        # Get members of groups that might have replication rights
        $suspiciousGroups = @('Backup Operators', 'Account Operators', 'Server Operators')
        
        foreach ($groupName in $suspiciousGroups) {
            try {
                $group = $null
                try {
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Could not get group '$groupName': $_"
                }
                if ($group) {
                    $members = $null
                    try {
                        $members = Get-ADGroupMember -Identity $group -Server $__adServer -ErrorAction Stop
                    }
                    catch {
                        Write-Verbose "Could not get members of group '$groupName': $_"
                    }

                    if ($members) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Replication Security'
                        $finding.Issue = "Membership in Privileged Operations Group"
                        $finding.Severity = 'Medium'
                        $finding.SeverityLevel = 2
                        $finding.AffectedObject = $groupName
                        $finding.Description = "Group '$groupName' has $($members.Count) member(s). These groups have powerful rights that could be leveraged for privilege escalation or data exfiltration."
                        $finding.Impact = "Members of this group may have rights that can be leveraged for privilege escalation or data exfiltration."
                        $finding.Remediation = "Review membership and remove unnecessary accounts. Members: $($members.SamAccountName -join ', ')"
                        $finding.EstimatedEffort = 'Medium - reviewing each member of the operations group (e.g. Backup/Server/Account/Print Operators) for actual ongoing need, rather than a single mechanical change.'
                        $finding.KnownRisks = 'Removing a member who still has a legitimate operational need for the group''s rights will break their ability to perform that work until re-added, so confirm with each member or their manager first.'
                        $finding.BackupRollback = 'Easy - re-add any member whose need is confirmed; effective on next Kerberos ticket refresh, no data loss.'
                        $finding.Details = @{
                            GroupDN = $group.DistinguishedName
                            Members = ($members | Select-Object Name, SamAccountName, DistinguishedName)
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Warning "Could not check group '$groupName': $_"
            }
        }
        
        Write-Verbose "Replication security audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during replication security audit: $_"
        throw
    }
}

#endregion
