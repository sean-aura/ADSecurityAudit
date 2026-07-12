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
        # Check user accounts with constrained delegation
        $usersWithConstrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like '*'} `
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
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
            -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalNames, Enabled
        
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
            -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, objectClass, Name
        
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

