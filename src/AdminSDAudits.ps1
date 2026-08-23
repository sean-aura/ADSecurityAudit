#region AdminSDHolder Audit

function Test-AdminSDHolder {
    <#
    .SYNOPSIS
        Audits the AdminSDHolder object's ACL and orphaned adminCount=1 accounts.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied, both
        checks run entirely from Snapshot.ACLs.AdminSDHolder and
        Snapshot.Users/.Groups (via Resolve-ADSnapshotGroupMember) - no live
        AD access is performed. Added in v1.19.0.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot,

        # Defense-in-depth for multi-domain forests: when this function is
        # called standalone (not via Start-ADSecurityAudit -Server, which
        # already installs a session-wide override before this ever runs),
        # there was previously no way to target a domain other than the
        # one the calling session ambiently resolves to. Passing -Server
        # here installs the same Set-ADSecurityAuditTargetServer override
        # Start-ADSecurityAudit uses, for the duration of this call only,
        # and only if one isn't ALREADY active - so calling this from
        # within a Start-ADSecurityAudit -Server run is unaffected.
        [Parameter()]
        [string]$Server
    )

    $__adAuditServerAlreadyActive = [bool](Get-ADSecurityAuditActiveServerOverride)
    if ($Server -and -not $__adAuditServerAlreadyActive) {
        Set-ADSecurityAuditTargetServer -Server (Resolve-ADSecurityAuditTargetServer -Server $Server)
    }
    # Resolved once, explicitly passed to every live AD call below - not
    # relying on the $PSDefaultParameterValues injection alone. $null when
    # no override is active, which Get-AD* cmdlets treat identically to
    # -Server being omitted entirely.
    $__adServer = Get-ADSecurityAuditActiveServerOverride

    try {
    Write-Verbose "Starting AdminSDHolder audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-AdminSDHolder: running from snapshot (no live AD access)."

        $acceptableTrustees = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            'NT AUTHORITY\SELF'
        )
        if ($Snapshot.Domain -and $Snapshot.Domain.NetBIOSName) {
            $acceptableTrustees += "$($Snapshot.Domain.NetBIOSName)\Domain Admins"
            $acceptableTrustees += "$($Snapshot.Domain.NetBIOSName)\Enterprise Admins"
        }

        if ($Snapshot.ACLs -and $Snapshot.ACLs.ContainsKey('AdminSDHolder')) {
            $adminSDHolderAcl = $Snapshot.ACLs['AdminSDHolder']

            foreach ($ace in @($adminSDHolderAcl.Access)) {
                $identityReference = $ace.IdentityReference

                if ($ace.IsInherited) { continue }

                if ($identityReference -notin $acceptableTrustees -and
                    $identityReference -notmatch '^S-1-5-32-544$') {

                    $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty')
                    $hasRiskyPermission = $false
                    foreach ($right in $dangerousRights) {
                        if ($ace.ActiveDirectoryRights -match $right) {
                            $hasRiskyPermission = $true
                            break
                        }
                    }

                    if ($hasRiskyPermission -or $ace.ActiveDirectoryRights -match 'ExtendedRight') {
                        $severity = 'Critical'
                        $severityLevel = 4
                        if ($identityReference -match 'BUILTIN\\' -or $identityReference -match 'NT AUTHORITY\\') {
                            $severity = 'Medium'
                            $severityLevel = 2
                        }

                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'AdminSDHolder'
                        $finding.Issue = 'Non-Standard Permissions on AdminSDHolder'
                        $finding.Severity = $severity
                        $finding.SeverityLevel = $severityLevel
                        $finding.AffectedObject = "AdminSDHolder - $identityReference"
                        $finding.Description = "Non-standard trustee '$identityReference' has '$($ace.ActiveDirectoryRights)' rights on AdminSDHolder."
                        $finding.Impact = "Attackers who compromise this principal can modify AdminSDHolder ACL to grant persistent domain-wide rights, create shadow admins, or bypass privilege escalation controls. SDProp will propagate these malicious permissions every 60 minutes."
                        $finding.Remediation = "Review and remove unauthorized ACE. Use: `$acl = Get-Acl 'AD:\`$adminSDHolderDN'; Review `$acl.Access; Remove unauthorized entries using Set-Acl."
                        $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but AdminSDHolder''s SDProp mechanism propagates the corrected ACL to every protected (Tier-0) object domain-wide, so confirm the trustee isn''t a legitimate delegated Tier-0 management tool first.'
                        $finding.KnownRisks = 'Procedural - confirm the trustee isn''t an intentional, currently-used Tier-0 delegation before removing; there is no realistic legitimate compatibility break otherwise.'
                        $finding.BackupRollback = 'Moderate - export the current ACL first; full effect across every protected object depends on SDProp''s next propagation cycle, not just AD replication.'
                        $finding.Details = @{
                            Identity = $identityReference
                            AccessControlType = $ace.AccessControlType
                            ActiveDirectoryRights = $ace.ActiveDirectoryRights
                            InheritanceType = $ace.InheritanceType
                            ObjectType = $ace.ObjectType
                            InheritedObjectType = $ace.InheritedObjectType
                        }
                        $findings += $finding
                    }
                }

                if ($ace.AccessControlType -eq 'Deny') {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'AdminSDHolder'
                    $finding.Issue = 'Deny ACE on AdminSDHolder'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = "AdminSDHolder - $identityReference"
                    $finding.Description = "Deny ACE found on AdminSDHolder for '$identityReference'."
                    $finding.Impact = "Deny ACEs on AdminSDHolder are unusual and may cause unexpected permission issues for protected accounts."
                    $finding.Remediation = "Review the deny ACE and determine if it's intentional. Remove if unnecessary."
                    $finding.EstimatedEffort = 'Low - removing a single unexpected Deny ACE from one object.'
                    $finding.KnownRisks = 'Low technical risk removing an unexpected deny entry, but confirm it wasn''t intentionally placed to block a specific known-compromised or decommissioned account before removing it, since that would re-permit whatever it was blocking.'
                    $finding.BackupRollback = 'Moderate - export the AdminSDHolder ACL before changing it; the removal only reaches every protected object after SDProp''s next propagation cycle.'
                    $finding.Details = @{
                        Identity = $identityReference
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights
                    }
                    $findings += $finding
                }
            }
        }
        else {
            Write-Verbose "Test-AdminSDHolder: snapshot has no ACLs.AdminSDHolder entry; skipping ACL checks."
        }

        # Orphaned adminCount check
        if ($Snapshot.ContainsKey('Users')) {
            $protectedUsers = @($Snapshot.Users | Where-Object { $_.adminCount -eq 1 })

            $protectedGroupMembers = @{}
            if ($Snapshot.ContainsKey('Groups')) {
                $groupsByName = @{}
                foreach ($g in @($Snapshot.Groups)) {
                    if ($g -and $g.Name) { $groupsByName[$g.Name] = $g }
                }
                foreach ($groupName in $Script:ProtectedGroups) {
                    $group = $groupsByName[$groupName]
                    if (-not $group) { continue }
                    $members = @(Resolve-ADSnapshotGroupMember -Snapshot $Snapshot -GroupDistinguishedName $group.DistinguishedName)
                    foreach ($member in $members) {
                        if ($member.objectClass -eq 'user' -and $member.SamAccountName) {
                            $protectedGroupMembers[$member.SamAccountName] = $true
                        }
                    }
                }
            }

            foreach ($user in $protectedUsers) {
                $isInProtectedGroup = $protectedGroupMembers.ContainsKey($user.SamAccountName)
                if (-not $isInProtectedGroup) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'AdminSDHolder'
                    $finding.Issue = 'Orphaned adminCount Attribute'
                    $finding.Severity = 'Medium'
                    $finding.SeverityLevel = 2
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User has adminCount=1 but is not a member of any protected group."
                    $finding.Impact = "User retains AdminSDHolder permissions after being removed from protected groups, potentially granting unintended privileges."
                    $finding.Remediation = "Clear adminCount and fix ACL: Set-ADUser -Identity '$($user.SamAccountName)' -Clear adminCount; Then manually review and reset the user's ACL to remove AdminSDHolder permissions."
                    $finding.EstimatedEffort = 'Low - reset a single attribute and re-enable inheritance on one object.'
                    $finding.KnownRisks = 'Low technical risk; confirm the object isn''t intentionally kept protected for an undocumented reason before clearing.'
                    $finding.BackupRollback = 'Easy - reset adminCount and inheritance back if needed; effective immediately, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        AdminCount = $user.adminCount
                    }
                    $findings += $finding
                }
            }
        }

        Write-Verbose "AdminSDHolder audit complete (snapshot mode). Found $($findings.Count) issues."
        return $findings
    }

    try {
        # Get the domain DN
        $domain = if ($__adServer) { Get-ADDomain -Server $__adServer } else { Get-ADDomain }
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
        
        Write-Verbose "Checking AdminSDHolder at: $adminSDHolderDN"
        
        # Get AdminSDHolder object with ACL
        $adminSDHolder = if ($__adServer) {
            Get-ADObject -Identity $adminSDHolderDN -Server $__adServer -Properties nTSecurityDescriptor
        }
        else {
            Get-ADObject -Identity $adminSDHolderDN -Properties nTSecurityDescriptor
        }
        $acl = $adminSDHolder.nTSecurityDescriptor
        
        $acceptableTrustees = @(
            'NT AUTHORITY\SYSTEM'
            'BUILTIN\Administrators'
            "$($domain.NetBIOSName)\Domain Admins"
            "$($domain.NetBIOSName)\Enterprise Admins"
            'NT AUTHORITY\SELF'
        )
        
        # Check each ACE
        foreach ($ace in $acl.Access) {
            $identityReference = $ace.IdentityReference.Value
            
            # Skip inherited ACEs
            if ($ace.IsInherited) {
                continue
            }
            
            # Check for non-standard trustees with dangerous rights
            if ($identityReference -notin $acceptableTrustees -and 
                $identityReference -notmatch '^S-1-5-32-544$') { # BUILTIN\Administrators SID
                
                $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'WriteProperty')
                $hasRiskyPermission = $false
                
                foreach ($right in $dangerousRights) {
                    if ($ace.ActiveDirectoryRights -match $right) {
                        $hasRiskyPermission = $true
                        break
                    }
                }
                
                if ($hasRiskyPermission -or $ace.ActiveDirectoryRights -match 'ExtendedRight') {
                    $severity = 'Critical'
                    $severityLevel = 4
                    
                    # Lower severity for some built-in groups
                    if ($identityReference -match 'BUILTIN\\' -or 
                        $identityReference -match 'NT AUTHORITY\\') {
                        $severity = 'Medium'
                        $severityLevel = 2
                    }
                    
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'AdminSDHolder'
                    $finding.Issue = 'Non-Standard Permissions on AdminSDHolder'
                    $finding.Severity = $severity
                    $finding.SeverityLevel = $severityLevel
                    $finding.AffectedObject = "AdminSDHolder - $identityReference"
                    $finding.Description = "Non-standard trustee '$identityReference' has '$($ace.ActiveDirectoryRights)' rights on AdminSDHolder."
                    $finding.Impact = "Attackers who compromise this principal can modify AdminSDHolder ACL to grant persistent domain-wide rights, create shadow admins, or bypass privilege escalation controls. SDProp will propagate these malicious permissions every 60 minutes."
                    $finding.Remediation = "Review and remove unauthorized ACE. Use: `$acl = Get-Acl 'AD:\$adminSDHolderDN'; Review `$acl.Access; Remove unauthorized entries using Set-Acl."
                    $finding.EstimatedEffort = 'Medium - a single-object ACE removal, but AdminSDHolder''s SDProp mechanism propagates the corrected ACL to every protected (Tier-0) object domain-wide, so confirm the trustee isn''t a legitimate delegated Tier-0 management tool first.'
                    $finding.KnownRisks = 'Procedural - confirm the trustee isn''t an intentional, currently-used Tier-0 delegation before removing; there is no realistic legitimate compatibility break otherwise.'
                    $finding.BackupRollback = 'Moderate - export the current ACL first; full effect across every protected object depends on SDProp''s next propagation cycle, not just AD replication.'
                    $finding.Details = @{
                        Identity = $identityReference
                        AccessControlType = $ace.AccessControlType.ToString()
                        ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                        InheritanceType = $ace.InheritanceType.ToString()
                        ObjectType = $ace.ObjectType.ToString()
                        InheritedObjectType = $ace.InheritedObjectType.ToString()
                    }
                    $findings += $finding
                }
            }
            
            # Check for Deny ACEs (unusual and potentially problematic)
            if ($ace.AccessControlType -eq 'Deny') {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'AdminSDHolder'
                $finding.Issue = 'Deny ACE on AdminSDHolder'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = "AdminSDHolder - $identityReference"
                $finding.Description = "Deny ACE found on AdminSDHolder for '$identityReference'."
                $finding.Impact = "Deny ACEs on AdminSDHolder are unusual and may cause unexpected permission issues for protected accounts."
                $finding.Remediation = "Review the deny ACE and determine if it's intentional. Remove if unnecessary."
                $finding.EstimatedEffort = 'Low - removing a single unexpected Deny ACE from one object.'
                $finding.KnownRisks = 'Low technical risk removing an unexpected deny entry, but confirm it wasn''t intentionally placed to block a specific known-compromised or decommissioned account before removing it, since that would re-permit whatever it was blocking.'
                $finding.BackupRollback = 'Moderate - export the AdminSDHolder ACL before changing it; the removal only reaches every protected object after SDProp''s next propagation cycle.'
                $finding.Details = @{
                    Identity = $identityReference
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                }
                $findings += $finding
            }
        }
        
        # Check for accounts with adminCount=1 that shouldn't have it
        Write-Verbose "Checking for orphaned adminCount attributes..."
        $protectedUsers = if ($__adServer) {
            Get-ADUser -Filter 'adminCount -eq 1' -Server $__adServer -Properties adminCount, MemberOf, SamAccountName, DistinguishedName
        }
        else {
            Get-ADUser -Filter 'adminCount -eq 1' -Properties adminCount, MemberOf, SamAccountName, DistinguishedName
        }
        
        # Build a list of all members of protected groups (using recursive membership)
        $protectedGroupMembers = @{}
        foreach ($groupName in $Script:ProtectedGroups) {
            try {
                $group = $null
                try {
                    $group = if ($__adServer) {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -Server $__adServer -ErrorAction Stop
                    }
                    else {
                        Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction Stop
                    }
                }
                catch {
                    Write-Verbose "Failed to get protected group '$groupName': $_"
                }
                if ($group) {
                    $members = $null
                    try {
                        $members = if ($__adServer) {
                            Get-ADGroupMember -Identity $group -Recursive -Server $__adServer -ErrorAction Stop
                        }
                        else {
                            Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Verbose "Failed to get members of protected group '$groupName': $_"
                    }
                    if ($members) {
                        foreach ($member in $members) {
                            if ($member.objectClass -eq 'user') {
                                $protectedGroupMembers[$member.SamAccountName] = $true
                            }
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not enumerate members of '$groupName': $_"
            }
        }
        
        foreach ($user in $protectedUsers) {
            # Check if user is in ANY protected group (using our pre-built hashtable)
            $isInProtectedGroup = $protectedGroupMembers.ContainsKey($user.SamAccountName)
            
            if (-not $isInProtectedGroup) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'AdminSDHolder'
                $finding.Issue = 'Orphaned adminCount Attribute'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User has adminCount=1 but is not a member of any protected group."
                $finding.Impact = "User retains AdminSDHolder permissions after being removed from protected groups, potentially granting unintended privileges."
                $finding.Remediation = "Clear adminCount and fix ACL: Set-ADUser -Identity '$($user.SamAccountName)' -Clear adminCount; Then manually review and reset the user's ACL to remove AdminSDHolder permissions."
                $finding.EstimatedEffort = 'Low - reset a single attribute and re-enable inheritance on one object.'
                $finding.KnownRisks = 'Low technical risk; confirm the object isn''t intentionally kept protected for an undocumented reason before clearing.'
                $finding.BackupRollback = 'Easy - reset adminCount and inheritance back if needed; effective immediately, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AdminCount = $user.adminCount
                }
                $findings += $finding
            }
        }
        
        Write-Verbose "AdminSDHolder audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during AdminSDHolder audit: $_"
        throw
    }
    }
    finally {
        if ($Server -and -not $__adAuditServerAlreadyActive) {
            Clear-ADSecurityAuditTargetServer
        }
    }
}

#endregion
