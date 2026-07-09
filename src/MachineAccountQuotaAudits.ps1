#region Machine Account Quota Audit
#
# Checks the domain-wide ms-DS-MachineAccountQuota attribute. By default,
# every authenticated domain user may join up to 10 computer accounts to the
# domain (the classic AD default), and any value greater than 0 lets
# unprivileged users create machine accounts they own. Self-service machine
# accounts are commonly abused as a foothold for resource-based constrained
# delegation (RBCD) relay attacks and SamAccountName-spoofing techniques
# (e.g. CVE-2021-42278/42287, "noPac") that escalate a low-privilege user to
# Domain Admin equivalence.
#
# Snapshot-aware per the v1.3.0 collection contract (docs/features/
# 02-domain-snapshot.md): reads $Snapshot.MachineAccountQuota when supplied,
# falling back to a live Get-ADObject read of the domain root's
# ms-DS-MachineAccountQuota attribute (Get-ADDomain does not expose this
# attribute directly).
#
# DETECTION ONLY: this is a single read-only LDAP attribute read. Nothing
# here creates, joins, or modifies any computer account.

function Test-ADMachineAccountQuota {
    <#
    .SYNOPSIS
        Audits the domain's ms-DS-MachineAccountQuota attribute.
    .DESCRIPTION
        Flags a non-zero machine account quota, distinguishing between the
        unmodified default of 10 (Critical/High risk - never reviewed) and a
        lowered-but-still-non-zero value (Medium risk - still self-service).
        A quota of 0 (hardened: computer joins must be explicitly delegated)
        produces no finding.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied and
        it contains a 'MachineAccountQuota' key, that value is used instead
        of a live AD query.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Machine Account Quota audit..."
    $findings = @()

    try {
        $quota = $null
        $domainDN = $null

        if ($Snapshot -and $Snapshot.ContainsKey('MachineAccountQuota') -and $null -ne $Snapshot.MachineAccountQuota) {
            Write-Verbose "Test-ADMachineAccountQuota: using snapshot data."
            $quota = $Snapshot.MachineAccountQuota
            if ($Snapshot.ContainsKey('Domain')) {
                $domainDN = $Snapshot.Domain.DistinguishedName
            }
        }
        else {
            $domain = Get-ADDomain -ErrorAction Stop
            $domainDN = $domain.DistinguishedName
            $domainObject = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
            $quota = $domainObject.'ms-DS-MachineAccountQuota'
        }

        if ($null -eq $quota) {
            Write-Verbose "Test-ADMachineAccountQuota: could not determine ms-DS-MachineAccountQuota; skipping."
            return $findings
        }

        # May arrive as [string] after a JSON round-trip (-ToJson / -FromSnapshot).
        $quotaValue = [int]$quota

        if ($quotaValue -eq 10) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Machine Account Quota'
            $finding.Issue = 'Default Machine Account Quota Not Restricted'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $domainDN
            $finding.Description = "ms-DS-MachineAccountQuota is set to the unmodified Active Directory default of 10, allowing every authenticated domain user to join up to 10 computer accounts to the domain."
            $finding.Impact = "Any authenticated user - including low-privilege accounts - can create and own machine accounts without any delegated permission. This is commonly abused as a foothold for resource-based constrained delegation (RBCD) relay attacks and SamAccountName-spoofing privilege escalation (e.g. CVE-2021-42278/42287, 'noPac'), letting an attacker escalate from any domain account to Domain Admin equivalence."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0 on the domain object (Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}) and explicitly delegate computer-join rights (Create/Delete Computer Objects) on the relevant OUs to only the specific groups or provisioning accounts that need them."
            $finding.Details = @{
                DistinguishedName   = $domainDN
                MachineAccountQuota = $quotaValue
                DefaultValue        = 10
            }
            $findings += $finding
        }
        elseif ($quotaValue -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Machine Account Quota'
            $finding.Issue = 'Non-Zero Machine Account Quota'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $domainDN
            $finding.Description = "ms-DS-MachineAccountQuota is set to $quotaValue, allowing every authenticated domain user to join up to $quotaValue computer account(s) to the domain."
            $finding.Impact = "Even at a reduced value, self-service computer joins remain available to any authenticated user, which still expands the attack surface for RBCD-based privilege escalation and SamAccountName-spoofing attacks."
            $finding.Remediation = "Set ms-DS-MachineAccountQuota to 0 and delegate computer-join rights explicitly to the specific groups or service accounts that require them, rather than relying on a domain-wide self-service quota."
            $finding.Details = @{
                DistinguishedName   = $domainDN
                MachineAccountQuota = $quotaValue
                DefaultValue        = 10
            }
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADMachineAccountQuota: ms-DS-MachineAccountQuota is 0 (hardened); no finding."
        }

        Write-Verbose "Machine Account Quota audit complete. Found $($findings.Count) issues."
        return $findings
    }
    catch {
        Write-Error "Error during Machine Account Quota audit: $_"
        throw
    }
}

#endregion
