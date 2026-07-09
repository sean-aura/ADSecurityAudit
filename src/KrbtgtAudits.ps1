#region KRBTGT Account Audits

function Test-KRBTGTAccount {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MaxPasswordAgeDays = 180,

        # Added in v1.3.0 (collect-once snapshot contract, see
        # docs/features/02-domain-snapshot.md). Optional and backward
        # compatible: when omitted, this function queries AD live exactly as
        # before.
        [Parameter()]
        [hashtable]$Snapshot
    )
    
    Write-Verbose "Starting KRBTGT account security audit..."
    $findings = @()
    
    try {
        # Get KRBTGT account - from the snapshot's Users collection when one
        # was supplied, otherwise via a live query (unchanged behaviour).
        if ($Snapshot -and $Snapshot.ContainsKey('Users')) {
            Write-Verbose "Test-KRBTGTAccount: using snapshot data."
            $krbtgtAccount = $Snapshot.Users | Where-Object { $_.SamAccountName -eq 'krbtgt' } | Select-Object -First 1
            if (-not $krbtgtAccount) {
                throw "krbtgt account not found in snapshot Users collection."
            }
        }
        else {
            $krbtgtAccount = Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties PasswordLastSet, Enabled, Description -ErrorAction Stop
        }
        
        if ($krbtgtAccount.PasswordLastSet) {
            # PasswordLastSet may come back as a [string] after a JSON
            # round-trip (-ToJson / -FromSnapshot); coerce explicitly so the
            # subtraction below is always DateTime - DateTime.
            $passwordLastSet = if ($krbtgtAccount.PasswordLastSet -is [datetime]) {
                $krbtgtAccount.PasswordLastSet
            }
            else {
                [datetime]$krbtgtAccount.PasswordLastSet
            }
            $passwordAge = (Get-Date) - $passwordLastSet
            
            # Critical finding if KRBTGT password is too old
            if ($passwordAge.Days -gt $MaxPasswordAgeDays) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Age Exceeds Recommended Threshold'
                $finding.Severity = 'Critical'
                $finding.SeverityLevel = 4
                $finding.AffectedObject = 'krbtgt'
                $finding.Description = "The KRBTGT account password has not been changed in $($passwordAge.Days) days. Microsoft recommends changing it every 180 days."
                $finding.Impact = "An old KRBTGT password increases the window for Golden Ticket attacks. If compromised, attackers can forge Kerberos tickets with arbitrary privileges indefinitely."
                $finding.Remediation = "Reset the KRBTGT password twice (with appropriate intervals) using the official Microsoft script. WARNING: This is a sensitive operation that requires careful planning."
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                    RecommendedMaxAgeDays = $MaxPasswordAgeDays
                }
                $findings += $finding
            }
            elseif ($passwordAge.Days -gt 90) {
                $finding = [ADSecurityFinding]::new()
                $finding.Category = 'Kerberos Security'
                $finding.Issue = 'KRBTGT Password Approaching Rotation Threshold'
                $finding.Severity = 'High'
                $finding.SeverityLevel = 3
                $finding.AffectedObject = 'krbtgt'
                $finding.Description = "The KRBTGT account password is $($passwordAge.Days) days old and approaching the recommended rotation threshold."
                $finding.Impact = "Regular KRBTGT password rotation limits the window for Golden Ticket attacks."
                $finding.Remediation = "Plan to reset the KRBTGT password twice using the official Microsoft script before it exceeds 180 days."
                $finding.Details = @{
                    DistinguishedName = $krbtgtAccount.DistinguishedName
                    PasswordLastSet = $krbtgtAccount.PasswordLastSet
                    PasswordAgeDays = $passwordAge.Days
                }
                $findings += $finding
            }
        }
        else {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Kerberos Security'
            $finding.Issue = 'KRBTGT Password Last Set Date Unknown'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = 'krbtgt'
            $finding.Description = "Unable to determine when the KRBTGT password was last changed."
            $finding.Impact = "Cannot assess risk of Golden Ticket attacks without knowing KRBTGT password age."
            $finding.Remediation = "Investigate why PasswordLastSet is not populated and reset the KRBTGT password."
            $finding.Details = @{
                DistinguishedName = $krbtgtAccount.DistinguishedName
            }
            $findings += $finding
        }
        
        Write-Verbose "KRBTGT account audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during KRBTGT audit: $_"
        throw
    }
}

#endregion

