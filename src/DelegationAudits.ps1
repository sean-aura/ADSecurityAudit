#region Constrained Delegation Audits

function Test-ConstrainedDelegation {
    <#
    .SYNOPSIS
        Audits constrained delegation (including protocol transition) and
        Resource-Based Constrained Delegation (RBCD).
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        filters Snapshot.Users/.Computers in-memory instead of live
        -Filter queries; TrustedToAuthForDelegation and HasRbcdConfigured
        are read directly. RBCD offline coverage is scoped to computer
        objects (matching real-world usage) - added in v1.19.0.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting constrained delegation security audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ConstrainedDelegation: running from snapshot (no live AD access)."

        if ($Snapshot.ContainsKey('Users')) {
            $usersWithConstrainedDelegation = @($Snapshot.Users | Where-Object { @($_.'msDS-AllowedToDelegateTo').Count -gt 0 })
            foreach ($user in $usersWithConstrainedDelegation) {
                if ($user.TrustedToAuthForDelegation -eq $true) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Kerberos Delegation'
                    $finding.Issue = 'User Account with Protocol Transition (T2A4D)'
                    $finding.Severity = 'Critical'
                    $finding.SeverityLevel = 4
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation with protocol transition enabled (TrustedToAuthForDelegation)."
                    $finding.Impact = "Can impersonate ANY user to specified services without requiring their credentials. Highly exploitable for privilege escalation."
                    $finding.Remediation = "Disable protocol transition if not absolutely required. If needed, ensure the account has a very strong password (30+ characters) and is closely monitored. Consider migrating to Group Managed Service Accounts."
                    $finding.EstimatedEffort = 'Medium — a single-attribute change, but confirm whether the impersonation capability is still required before removing it; migrating to a Group Managed Service Account (as the remediation suggests) is a larger, separate project.'
                    $finding.KnownRisks = 'Protocol transition on a user account is a highly consequential but sometimes legitimate impersonation mechanism, so removing it can break the specific service still relying on it.'
                    $finding.BackupRollback = 'Easy — restore the TrustedToAuthForDelegation flag and delegation list on the account; effective at next Kerberos ticket request, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                        TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
                        Enabled = $user.Enabled
                    }
                    $findings += $finding
                }
                else {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Kerberos Delegation'
                    $finding.Issue = 'User Account with Constrained Delegation'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $user.SamAccountName
                    $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation configured to specific services."
                    $finding.Impact = "Can impersonate authenticated users to specified services. Less risky than unconstrained delegation but still requires strong security controls."
                    $finding.Remediation = "Verify this configuration is necessary. Ensure strong password policy and monitoring. Review delegated services: $($user.'msDS-AllowedToDelegateTo' -join ', ')"
                    $finding.EstimatedEffort = 'Medium — a single-attribute change, but confirm the specific service-to-service authentication flow it supports is no longer required, or is otherwise reconfigured, before removing it.'
                    $finding.KnownRisks = 'Removing constrained delegation can break the specific service-to-service authentication flow it was configured for if still in active use.'
                    $finding.BackupRollback = 'Easy — restore the msDS-AllowedToDelegateTo attribute to its prior list of SPNs; effective at next Kerberos ticket request, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $user.DistinguishedName
                        AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                        Enabled = $user.Enabled
                    }
                    $findings += $finding
                }
            }
        }

        if ($Snapshot.ContainsKey('Computers')) {
            $computersWithConstrainedDelegation = @($Snapshot.Computers | Where-Object { @($_.'msDS-AllowedToDelegateTo').Count -gt 0 })
            foreach ($computer in $computersWithConstrainedDelegation) {
                if ($computer.TrustedToAuthForDelegation -eq $true) {
                    $finding = [ADSecurityFinding]::new()
                    $finding.Category = 'Kerberos Delegation'
                    $finding.Issue = 'Computer Account with Protocol Transition (T2A4D)'
                    $finding.Severity = 'High'
                    $finding.SeverityLevel = 3
                    $finding.AffectedObject = $computer.Name
                    $finding.Description = "Computer account '$($computer.Name)' has constrained delegation with protocol transition enabled."
                    $finding.Impact = "If compromised, attackers can impersonate any user to specified services. Common on Exchange servers but requires securing the host."
                    $finding.Remediation = "Verify this configuration is required (common for Exchange/IIS). Ensure the computer is hardened, patched, and monitored. Services: $($computer.'msDS-AllowedToDelegateTo' -join ', ')"
                    $finding.EstimatedEffort = 'Medium — a single-object attribute change, but confirm with the application owner (classically Exchange/IIS) whether protocol transition is still genuinely required before removing it.'
                    $finding.KnownRisks = 'Protocol transition (TrustedToAuthForDelegation) is legitimately used by some application servers to impersonate users without their credentials, so removing it can break that application''s functionality if still in use.'
                    $finding.BackupRollback = 'Easy — re-enable protocol transition and restore the msDS-AllowedToDelegateTo list on the computer object; effective at next Kerberos ticket request, no data loss.'
                    $finding.Details = @{
                        DistinguishedName = $computer.DistinguishedName
                        AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                        TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
                        Enabled = $computer.Enabled
                    }
                    $findings += $finding
                }
            }

            # RBCD: presence-flag only, scoped to computer objects (see
            # Get-ADSnapshot's HasRbcdConfigured collection note).
            $rbcdComputers = @($Snapshot.Computers | Where-Object { $_.HasRbcdConfigured })
            foreach ($object in $rbcdComputers) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'Resource-Based Constrained Delegation Configured'
                $finding.Severity = 'Medium'
                $finding.SeverityLevel = 2
                $finding.AffectedObject = $object.Name
                $finding.Description = "Object '$($object.Name)' has Resource-Based Constrained Delegation (RBCD) configured, allowing other accounts to impersonate users to this resource."
                $finding.Impact = "RBCD can be exploited if an attacker can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute or compromise accounts listed in it."
                $finding.Remediation = "Review RBCD configuration and ensure only necessary accounts are allowed. Monitor for unauthorized changes to this attribute."
                $finding.EstimatedEffort = 'Medium — a single-attribute change on the resource object, but confirm with the resource owner whether the delegation is an intentional, still-needed configuration.'
                $finding.KnownRisks = 'RBCD is commonly used intentionally for modern constrained delegation without protocol transition, so removing it can break a legitimate service-to-service delegation scenario it was set up for.'
                $finding.BackupRollback = 'Easy — restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to its prior value; effective at next Kerberos ticket request, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $object.DistinguishedName
                    ObjectClass = 'computer'
                }
                $findings += $finding
            }
        }

        Write-Verbose "Constrained delegation audit complete (snapshot mode). Found $($findings.Count) issues."
        return $findings
    }

    try {
        $__adServer = Get-ADSecurityAuditTargetServerValue
        # Check user accounts with constrained delegation
        $usersWithConstrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled -Server $__adServer
        
        foreach ($user in $usersWithConstrainedDelegation) {
            # Check for protocol transition (most dangerous)
            if ($user.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation with protocol transition enabled (TrustedToAuthForDelegation)."
                $finding.Impact = "Can impersonate ANY user to specified services without requiring their credentials. Highly exploitable for privilege escalation."
                $finding.Remediation = "Disable protocol transition if not absolutely required. If needed, ensure the account has a very strong password (30+ characters) and is closely monitored. Consider migrating to Group Managed Service Accounts."
                $finding.EstimatedEffort = 'Medium — a single-attribute change, but confirm whether the impersonation capability is still required before removing it; migrating to a Group Managed Service Account (as the remediation suggests) is a larger, separate project.'
                $finding.KnownRisks = 'Protocol transition on a user account is a highly consequential but sometimes legitimate impersonation mechanism, so removing it can break the specific service still relying on it.'
                $finding.BackupRollback = 'Easy — restore the TrustedToAuthForDelegation flag and delegation list on the account; effective at next Kerberos ticket request, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
            else {
                # Standard constrained delegation
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'User Account with Constrained Delegation'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $user.SamAccountName
                $finding.Description = "User account '$($user.SamAccountName)' has constrained delegation configured to specific services."
                $finding.Impact = "Can impersonate authenticated users to specified services. Less risky than unconstrained delegation but still requires strong security controls."
                $finding.Remediation = "Verify this configuration is necessary. Ensure strong password policy and monitoring. Review delegated services: $($user.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.EstimatedEffort = 'Medium — a single-attribute change, but confirm the specific service-to-service authentication flow it supports is no longer required, or is otherwise reconfigured, before removing it.'
                $finding.KnownRisks = 'Removing constrained delegation can break the specific service-to-service authentication flow it was configured for if still in active use.'
                $finding.BackupRollback = 'Easy — restore the msDS-AllowedToDelegateTo attribute to its prior list of SPNs; effective at next Kerberos ticket request, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $user.DistinguishedName
                    AllowedToDelegateTo = $user.'msDS-AllowedToDelegateTo' -join '; '
                    Enabled = $user.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check computer accounts with constrained delegation
        $computersWithConstrainedDelegation = Get-ADComputer -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled -Server $__adServer
        
        foreach ($computer in $computersWithConstrainedDelegation) {
            if ($computer.TrustedToAuthForDelegation -eq $true) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Delegation'
                $finding.Issue = 'Computer Account with Protocol Transition (T2A4D)'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = $computer.Name
                $finding.Description = "Computer account '$($computer.Name)' has constrained delegation with protocol transition enabled."
                $finding.Impact = "If compromised, attackers can impersonate any user to specified services. Common on Exchange servers but requires securing the host."
                $finding.Remediation = "Verify this configuration is required (common for Exchange/IIS). Ensure the computer is hardened, patched, and monitored. Services: $($computer.'msDS-AllowedToDelegateTo' -join ', ')"
                $finding.EstimatedEffort = 'Medium — a single-object attribute change, but confirm with the application owner (classically Exchange/IIS) whether protocol transition is still genuinely required before removing it.'
                $finding.KnownRisks = 'Protocol transition (TrustedToAuthForDelegation) is legitimately used by some application servers to impersonate users without their credentials, so removing it can break that application''s functionality if still in use.'
                $finding.BackupRollback = 'Easy — re-enable protocol transition and restore the msDS-AllowedToDelegateTo list on the computer object; effective at next Kerberos ticket request, no data loss.'
                $finding.Details = @{
                    DistinguishedName = $computer.DistinguishedName
                    AllowedToDelegateTo = $computer.'msDS-AllowedToDelegateTo' -join '; '
                    TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
                    Enabled = $computer.Enabled
                }
                $findings += $finding
            }
        }
        
        # Check for Resource-Based Constrained Delegation (RBCD)
        $objectsWithRBCD = Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} `
            -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, objectClass, Name -Server $__adServer
        
        foreach ($object in $objectsWithRBCD) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Delegation'
            $finding.Issue = 'Resource-Based Constrained Delegation Configured'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $object.Name
            $finding.Description = "Object '$($object.Name)' has Resource-Based Constrained Delegation (RBCD) configured, allowing other accounts to impersonate users to this resource."
            $finding.Impact = "RBCD can be exploited if an attacker can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute or compromise accounts listed in it."
            $finding.Remediation = "Review RBCD configuration and ensure only necessary accounts are allowed. Monitor for unauthorized changes to this attribute."
            $finding.EstimatedEffort = 'Medium — a single-attribute change on the resource object, but confirm with the resource owner whether the delegation is an intentional, still-needed configuration.'
            $finding.KnownRisks = 'RBCD is commonly used intentionally for modern constrained delegation without protocol transition, so removing it can break a legitimate service-to-service delegation scenario it was set up for.'
            $finding.BackupRollback = 'Easy — restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to its prior value; effective at next Kerberos ticket request, no data loss.'
            $finding.Details = @{
                DistinguishedName = $object.DistinguishedName
                ObjectClass = $object.objectClass
            }
            $findings += $finding
        }
        
        Write-Verbose "Constrained delegation audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during constrained delegation audit: $_"
        throw
    }
}

#endregion

