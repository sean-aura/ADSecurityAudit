#region GPO Audit

function Test-ADGroupPolicies {
    <#
    .SYNOPSIS
        Audits GPO permissions, link scope, and SYSVOL file-share permissions.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        the over-permissioned-GPO, DC-OU-linked-weak-permissions, and
        unlinked-GPO checks run from Snapshot.GPOs (.Permissions/.LinkedTo).
        The SYSVOL file-share ACL check has no AD-schema equivalent and is
        SKIPPED entirely under -Snapshot (with a Write-Warning), consistent
        with Test-ADCoercionAndRelayExposure's/Test-ADLegacyAuthSurface's
        live-only sub-checks - it never falls back to live I/O. Added in
        v1.19.0; the skip-instead-of-live-fallback behavior was corrected
        in v1.19.1 (it briefly fell back to a live SYSVOL read in v1.19.0,
        which contradicted -Snapshot's "no live AD access" contract).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Group Policy audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ADGroupPolicies: running GPO permission/link checks from snapshot (no live AD access for those checks)."

        if ($Snapshot.ContainsKey('GPOs')) {
            foreach ($gpo in @($Snapshot.GPOs)) {
                $gpoPermissions = @($gpo.Permissions)
                $linkedTo = @($gpo.LinkedTo)

                foreach ($permission in $gpoPermissions) {
                    $isDangerous = $false
                    $dangerousRight = ""
                    if ($permission.Permission -match 'GpoEditDeleteModifySecurity') {
                        $isDangerous = $true
                        $dangerousRight = "Full Control (GpoEditDeleteModifySecurity)"
                    }
                    elseif ($permission.Permission -match 'GpoEdit') {
                        $isDangerous = $true
                        $dangerousRight = "Edit Settings (GpoEdit)"
                    }

                    if ($isDangerous) {
                        $trustee = $permission.Trustee
                        $isPrivilegedTrustee = $Script:ProtectedGroups | Where-Object { $trustee -match $_ }

                        if (-not $isPrivilegedTrustee -and
                            $trustee -notmatch 'SYSTEM' -and
                            $trustee -notmatch 'Domain Admins' -and
                            $trustee -notmatch 'Enterprise Admins') {

                            $finding = [ADSecurityFinding]::new()
                            $finding.Category = 'Group Policy'
                            $finding.Issue = 'Over-Permissioned GPO'
                            $finding.Severity = 'High'
                            $finding.SeverityLevel = 3
                            $finding.AffectedObject = $gpo.DisplayName
                            $finding.Description = "GPO '$($gpo.DisplayName)' grants '$dangerousRight' to non-privileged principal '$trustee'."
                            $finding.Impact = "Low-privileged users or groups can modify the GPO, leading to privilege escalation, malware deployment, or persistence mechanisms."
                            $finding.Remediation = "Remove dangerous permission: Set-GPPermission -Guid $($gpo.Id) -TargetName '$trustee' -TargetType User -PermissionLevel None"
                            $finding.Details = @{
                                GPOID = $gpo.Id
                                Trustee = $trustee
                                Permission = $permission.Permission
                            }
                            $findings += $finding
                        }
                    }
                }

                $dcOuLinks = @($linkedTo | Where-Object { $_ -match 'OU=Domain Controllers' })
                if ($dcOuLinks.Count -gt 0) {
                    $nonAdminEditRights = @($gpoPermissions | Where-Object {
                        $_.Permission -match 'Edit' -and
                        $_.Trustee -notmatch 'Domain Admins' -and
                        $_.Trustee -notmatch 'Enterprise Admins' -and
                        $_.Trustee -notmatch 'SYSTEM'
                    })

                    if ($nonAdminEditRights.Count -gt 0) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'GPO Linked to Domain Controllers with Weak Permissions'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' is linked to Domain Controllers OU but has edit rights granted to non-admin principals."
                        $finding.Impact = "Attackers can deploy malicious packages or configurations to Domain Controllers with SYSTEM-level rights, leading to full domain compromise."
                        $finding.Remediation = "Restrict GPO permissions to only Domain Admins and Enterprise Admins. Remove all non-admin edit rights immediately."
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            LinkedOU = ($dcOuLinks -join '; ')
                            NonAdminTrustees = ($nonAdminEditRights.Trustee -join '; ')
                        }
                        $findings += $finding
                    }
                }

                if ($linkedTo.Count -eq 0) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Group Policy'
                    $finding.Issue = 'Unlinked GPO'
                    $finding.Severity = 'Low'
                    $finding.SeverityLevel = 1
                    $finding.AffectedObject = $gpo.DisplayName
                    $finding.Description = "GPO '$($gpo.DisplayName)' is not linked to any OU or domain."
                    $finding.Impact = "Unlinked GPOs create clutter and may contain misconfigurations that could cause issues if accidentally linked."
                    $finding.Remediation = "Review the GPO and delete if no longer needed: Remove-GPO -Guid $($gpo.Id)"
                    $finding.Details = @{
                        GPOID = $gpo.Id
                        CreatedDate = $gpo.CreationTime
                        ModifiedDate = $gpo.ModificationTime
                    }
                    $findings += $finding
                }
            }
        }
        else {
            Write-Verbose "Test-ADGroupPolicies: snapshot has no 'GPOs' key; skipping GPO permission/link checks."
        }

        # SYSVOL file-share ACL check has no AD-schema equivalent. Fixed in
        # v1.19.1: this used to fall back to a live SMB read against SYSVOL,
        # which contradicted -Snapshot's "no live AD access" contract and
        # was inconsistent with how every other partially-offline module in
        # this codebase (Test-ADCoercionAndRelayExposure,
        # Test-ADLegacyAuthSurface, Test-ADDnsSecurity,
        # Test-ADKerberosHardening, Test-ADKnownDCVulnerabilities) actually
        # handles a live-only sub-check under -Snapshot: skip it entirely
        # and say so, never fall back to live I/O. This check is now
        # skipped the same way.
        Write-Warning "Test-ADGroupPolicies: -Snapshot supplied; skipping the SYSVOL file-share ACL check (no AD-schema equivalent; offline mode performs no live AD/network access)."
        Add-ADOfflineSkipNote -Test 'GroupPolicies' -Check 'SYSVOL file-share ACL permissions' `
            -Reason 'No AD-schema equivalent - a file-share ACL is not an AD attribute. Run this check live (without -Snapshot) if you need this coverage.'

        Write-Verbose "Group Policy audit complete (snapshot mode, SYSVOL check skipped). Found $($findings.Count) issues."
        return $findings
    }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $allGPOs = Get-GPO -All
        $domain = Get-ADDomain
        
        Write-Verbose "Analyzing $($allGPOs.Count) GPOs..."
        
        $gpoCount = $allGPOs.Count
        $currentGpo = 0
        
        foreach ($gpo in $allGPOs) {
            $currentGpo++
            Write-Progress -Activity "Scanning Group Policies" -Status "Processing $($gpo.DisplayName)" `
                -PercentComplete (($currentGpo / $gpoCount) * 100)
            
            # Get GPO permissions
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All
            
            # Check for dangerous permissions granted to non-admin users/groups
            foreach ($permission in $gpoPermissions) {
                $isDangerous = $false
                $dangerousRight = ""
                
                if ($permission.Permission -match 'GpoEditDeleteModifySecurity') {
                    $isDangerous = $true
                    $dangerousRight = "Full Control (GpoEditDeleteModifySecurity)"
                }
                elseif ($permission.Permission -match 'GpoEdit') {
                    $isDangerous = $true
                    $dangerousRight = "Edit Settings (GpoEdit)"
                }
                
                if ($isDangerous) {
                    # Check if trustee is a privileged group
                    $trustee = $permission.Trustee.Name
                    $isPrivilegedTrustee = $Script:ProtectedGroups | Where-Object { $trustee -match $_ }
                    
                    if (-not $isPrivilegedTrustee -and 
                        $trustee -notmatch 'SYSTEM' -and 
                        $trustee -notmatch 'Domain Admins' -and
                        $trustee -notmatch 'Enterprise Admins') {
                        
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'Over-Permissioned GPO'
                        $finding.Severity = 'High'
                        $finding.SeverityLevel = 3
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' grants '$dangerousRight' to non-privileged principal '$trustee'."
                        $finding.Impact = "Low-privileged users or groups can modify the GPO, leading to privilege escalation, malware deployment, or persistence mechanisms."
                        $finding.Remediation = "Remove dangerous permission: Set-GPPermission -Guid $($gpo.Id) -TargetName '$trustee' -TargetType User -PermissionLevel None"
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            GPOPath = $gpo.Path
                            Trustee = $trustee
                            Permission = $permission.Permission
                        }
                        $findings += $finding
                    }
                }
            }
            
            # Check for GPOs linked to sensitive OUs
            $gpoLinks = Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink, DistinguishedName
            
            foreach ($link in $gpoLinks) {
                # Check if linked to Domain Controllers OU
                if ($link.DistinguishedName -match 'OU=Domain Controllers') {
                    # Verify this GPO has restricted permissions
                    $nonAdminEditRights = $gpoPermissions | Where-Object {
                        $_.Permission -match 'Edit' -and
                        $_.Trustee.Name -notmatch 'Domain Admins' -and
                        $_.Trustee.Name -notmatch 'Enterprise Admins' -and
                        $_.Trustee.Name -notmatch 'SYSTEM'
                    }
                    
                    if ($nonAdminEditRights) {
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'GPO Linked to Domain Controllers with Weak Permissions'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = $gpo.DisplayName
                        $finding.Description = "GPO '$($gpo.DisplayName)' is linked to Domain Controllers OU but has edit rights granted to non-admin principals."
                        $finding.Impact = "Attackers can deploy malicious packages or configurations to Domain Controllers with SYSTEM-level rights, leading to full domain compromise."
                        $finding.Remediation = "Restrict GPO permissions to only Domain Admins and Enterprise Admins. Remove all non-admin edit rights immediately."
                        $finding.Details = @{
                            GPOID = $gpo.Id
                            LinkedOU = $link.DistinguishedName
                            NonAdminTrustees = ($nonAdminEditRights.Trustee.Name -join '; ')
                        }
                        $findings += $finding
                    }
                }
            }
            
            # Check for unlinked GPOs (security hygiene)
            if (-not $gpoLinks) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Group Policy'
                $finding.Issue = 'Unlinked GPO'
                $finding.Severity = 'Low'
                $finding.SeverityLevel = 1
                $finding.AffectedObject = $gpo.DisplayName
                $finding.Description = "GPO '$($gpo.DisplayName)' is not linked to any OU or domain."
                $finding.Impact = "Unlinked GPOs create clutter and may contain misconfigurations that could cause issues if accidentally linked."
                $finding.Remediation = "Review the GPO and delete if no longer needed: Remove-GPO -Guid $($gpo.Id)"
                $finding.Details = @{
                    GPOID = $gpo.Id
                    CreatedDate = $gpo.CreationTime
                    ModifiedDate = $gpo.ModificationTime
                }
                $findings += $finding
            }
        }
        
        Write-Progress -Activity "Scanning Group Policies" -Completed
        
        # Check SYSVOL permissions
        Write-Verbose "Checking SYSVOL permissions..."
        $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)"
        
        if (Test-Path $sysvolPath) {
            try {
                $sysvolAcl = Get-Acl $sysvolPath -ErrorAction Stop
                
                foreach ($ace in $sysvolAcl.Access) {
                    # Check for write/modify rights granted to non-admin groups
                    if ($ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                        $ace.AccessControlType -eq 'Allow' -and
                        $ace.IdentityReference -notmatch 'SYSTEM' -and
                        $ace.IdentityReference -notmatch 'Administrators' -and
                        $ace.IdentityReference -notmatch 'Domain Admins' -and
                        $ace.IdentityReference -notmatch 'Enterprise Admins' -and
                        $ace.IdentityReference -notmatch 'CREATOR OWNER') {
                        
                        $finding = [ADSecurityFinding]::new()
                        $finding.Category = 'Group Policy'
                        $finding.Issue = 'Insecure SYSVOL Permissions'
                        $finding.Severity = 'Critical'
                        $finding.SeverityLevel = 4
                        $finding.AffectedObject = "SYSVOL - $($ace.IdentityReference)"
                        $finding.Description = "SYSVOL has write permissions granted to '$($ace.IdentityReference)'."
                        $finding.Impact = "Attackers can tamper with GPO files, scripts, and policies that apply to all domain members, leading to widespread compromise."
                        $finding.Remediation = "Restrict SYSVOL permissions. Remove write access for non-admin principals. Only Domain Admins and SYSTEM should have write access."
                        $finding.Details = @{
                            Path = $sysvolPath
                            Identity = $ace.IdentityReference
                            FileSystemRights = $ace.FileSystemRights
                            AccessControlType = $ace.AccessControlType
                        }
                        $findings += $finding
                    }
                }
            }
            catch {
                Write-Warning "Could not access SYSVOL ACL: $_"
            }
        }
        else {
            Write-Warning "SYSVOL path not accessible at expected location: $sysvolPath"
        }
        
        Write-Verbose "Group Policy audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during Group Policy audit: $_"
        throw
    }
}

#endregion

