#region Read-Only Domain Controller Security Posture Audit
#
# Audits Read-Only Domain Controllers (RODCs) for the specific escalation
# paths they introduce: Tier-0/privileged secrets already cached or allowed
# to be cached on a lower-trust DC, password replication policy (PRP) gaps
# (an allowed list that is too broad or a denied list missing the standard
# privileged groups), and orphaned RODC-specific krbtgt_* accounts left
# behind after an RODC was demoted or removed. PingCastle-comparable check(s):
# P-RODCAdminRevealed, P-RODCAllowedGroup, P-RODCDeniedGroup,
# P-RODCNeverReveal, P-RODCRevealOnDemand, P-RODCKrbtgtOrphan.
#
# DETECTION ONLY: every determination here is a read of RODC computer-object
# attributes (msDS-RevealedUsers, msDS-RevealOnDemandGroup,
# msDS-NeverRevealGroup, msDS-KrbTgtLink) and a krbtgt_* account inventory
# cross-referenced against current RODC computer objects. This module never
# modifies a PRP list, forges a ticket, or sends any exploitation/coercion/
# PoC traffic to any host.

# Well-known broad principals that should never appear in an RODC's allowed
# (msDS-RevealOnDemandGroup) password replication list - if they do, the
# RODC will cache secrets for essentially anyone who authenticates through it.
$Script:RodcBroadAllowedPrincipalNames = @(
    'Authenticated Users'
    'Domain Users'
    'Everyone'
    'ANONYMOUS LOGON'
)

# The core Tier-0 groups that a well-formed RODC deployment denies via
# msDS-NeverRevealGroup (in addition to the built-in Denied RODC Password
# Replication Group, which itself is seeded with most of these). Used only
# to flag an RODC whose denied list is missing expected coverage - it is not
# an exhaustive Tier-0 definition (Get-ADTier0Principal remains that).
$Script:RodcExpectedDeniedGroupNames = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
    'Cert Publishers'
    'Denied RODC Password Replication Group'
)

function Get-RodcPrincipalNameFromDN {
    <#
    .SYNOPSIS
        Best-effort extraction of a display/CN name from a DN-ish string.
    .DESCRIPTION
        msDS-RevealedUsers, msDS-RevealOnDemandGroup, and msDS-NeverRevealGroup
        values are DNs (msDS-RevealedUsers may carry additional packed
        metadata ahead of the DN on some AD versions). This pulls out the
        leading CN= component for matching/reporting without assuming a
        single exact wire format - a read-only, best-effort parse, consistent
        with the other pattern-based parsing used elsewhere in this module
        (e.g. GPP cpassword / script-credential detection).
    #>
    param([string]$RawValue)

    if (-not $RawValue) { return $null }

    $match = [regex]::Match($RawValue, 'CN=([^,]+)', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }

    # Fall back to the raw value itself (e.g. already a bare SamAccountName).
    return $RawValue
}

function Get-RodcDNFromRawValue {
    <#
    .SYNOPSIS
        Best-effort extraction of the DN portion from a possibly-packed
        msDS-RevealedUsers value.
    #>
    param([string]$RawValue)

    if (-not $RawValue) { return $null }

    $match = [regex]::Match($RawValue, '(CN=.+)$', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }

    return $RawValue
}

function Test-ADRodcSecurity {
    <#
    .SYNOPSIS
        Audits Read-Only Domain Controller (RODC) security posture.
    .DESCRIPTION
        Enumerates RODCs and, for each, reads msDS-RevealedUsers (secrets
        already cached), msDS-RevealOnDemandGroup (the allowed password
        replication list), msDS-NeverRevealGroup (the denied list), and
        msDS-KrbTgtLink (the RODC's dedicated krbtgt_* account). Flags:

          - Privileged Account Revealed to RODC (Critical): a Tier-0
            principal (per Get-ADTier0Principal) is already revealed to, or
            sits in the allowed list of, an RODC.
          - RODC Password Replication Policy Misconfigured (High): the
            allowed list contains a broad principal (Authenticated Users,
            Domain Users, Everyone, ANONYMOUS LOGON), or the denied list is
            missing one or more of the expected core privileged groups.
          - Orphaned RODC krbtgt Account (Medium): a krbtgt_* account exists
            with no current RODC linking back to it via msDS-KrbTgtLink,
            i.e. left behind after the owning RODC was demoted/removed.

        Exits cleanly (no findings) when the domain has no RODCs.

        Detection only: reads RODC computer-object attributes and the
        krbtgt_* account inventory. Never modifies a PRP list, forges a
        Kerberos ticket, or sends any exploitation/coercion/PoC traffic to
        any host.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). When supplied,
        the RODC list is taken from Snapshot.DomainControllers (filtered to
        IsReadOnly) and the krbtgt_* account inventory is taken from
        Snapshot.Users, avoiding a live DC/user enumeration pass. The
        per-RODC msDS-RevealedUsers / msDS-RevealOnDemandGroup /
        msDS-NeverRevealGroup / msDS-KrbTgtLink reads are not part of the
        current snapshot schema and are always performed live, consistent
        with the other live-only sub-checks elsewhere in this module (e.g.
        Test-ADGpoDeployedSecrets' SYSVOL reads, Test-ADDnsSecurity's
        zone-level reads).
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Read-Only Domain Controller security posture audit..."
    $findings = @()

    # -------------------------------------------------------------------
    # Resolve the RODC list - from the snapshot's DC inventory when
    # supplied, otherwise a live, read-only DC enumeration.
    # -------------------------------------------------------------------
    $rodcs = @()

    if ($Snapshot -and $Snapshot.ContainsKey('DomainControllers') -and $Snapshot.DomainControllers) {
        Write-Verbose "Test-ADRodcSecurity: using RODC list from snapshot DomainControllers."
        $rodcs = @($Snapshot.DomainControllers | Where-Object { $_.IsReadOnly -eq $true -or "$($_.IsReadOnly)" -eq 'True' })
    }
    else {
        try {
            $rodcs = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController RODCs' -Query {
                Get-ADDomainController -Filter { IsReadOnly -eq $true } -ErrorAction Stop
            })
        }
        catch {
            Write-Error "Test-ADRodcSecurity: failed to enumerate RODCs: $_"
            return $findings
        }
    }

    if (-not $rodcs -or $rodcs.Count -eq 0) {
        Write-Verbose "Test-ADRodcSecurity: no RODCs found in the domain; clean exit."
        return $findings
    }

    Write-Verbose "Test-ADRodcSecurity: found $($rodcs.Count) RODC(s)."

    # Tier-0/privileged principal set, for cross-referencing revealed/
    # allowed principals. Works with or without -Snapshot.
    $tier0 = @()
    try {
        $tier0 = @(Get-ADTier0Principal -Snapshot $Snapshot)
    }
    catch {
        Write-Verbose "Test-ADRodcSecurity: Get-ADTier0Principal unavailable: $_"
    }

    $tier0ByDN = @{}
    $tier0ByName = @{}
    foreach ($p in $tier0) {
        if ($p.DistinguishedName) { $tier0ByDN[$p.DistinguishedName.ToLowerInvariant()] = $p }
        if ($p.SamAccountName) { $tier0ByName[$p.SamAccountName.ToLowerInvariant()] = $p }
    }

    # -------------------------------------------------------------------
    # Per-RODC live attribute reads (not part of the current snapshot
    # schema, so always live regardless of -Snapshot - consistent with
    # other live-only sub-checks in this module).
    # -------------------------------------------------------------------
    $rodcDetails = [System.Collections.ArrayList]::new()
    $linkedKrbtgtDNs = New-Object System.Collections.Generic.HashSet[string]

    foreach ($rodc in $rodcs) {
        $computerObjectDN = $rodc.ComputerObjectDN
        if (-not $computerObjectDN) { $computerObjectDN = $rodc.DistinguishedName }
        $rodcName = if ($rodc.Name) { $rodc.Name } elseif ($rodc.HostName) { $rodc.HostName } else { "$computerObjectDN" }

        if (-not $computerObjectDN) {
            Write-Verbose "Test-ADRodcSecurity: RODC '$rodcName' has no resolvable computer object DN; skipping attribute read."
            continue
        }

        try {
            $rodcObject = Invoke-ADQueryWithRetry -OperationName "Get-ADObject RODC attributes ($rodcName)" -Query {
                Get-ADObject -Identity $computerObjectDN -Properties `
                    'msDS-RevealedUsers', 'msDS-RevealOnDemandGroup', 'msDS-NeverRevealGroup', `
                    'msDS-KrbTgtLink' -ErrorAction Stop
            }
        }
        catch {
            Write-Verbose "Test-ADRodcSecurity: could not read attributes for RODC '$rodcName' ($computerObjectDN): $_"
            continue
        }

        if (-not $rodcObject) { continue }

        foreach ($krbtgtLink in @($rodcObject.'msDS-KrbTgtLink')) {
            if ($krbtgtLink) { [void]$linkedKrbtgtDNs.Add("$krbtgtLink".ToLowerInvariant()) }
        }

        [void]$rodcDetails.Add([PSCustomObject]@{
            Name              = $rodcName
            ComputerObjectDN  = $computerObjectDN
            RevealedRaw       = @($rodcObject.'msDS-RevealedUsers')
            AllowedDNs        = @($rodcObject.'msDS-RevealOnDemandGroup')
            DeniedDNs         = @($rodcObject.'msDS-NeverRevealGroup')
        })
    }

    # -------------------------------------------------------------------
    # Finding: Privileged Account Revealed to RODC
    # -------------------------------------------------------------------
    foreach ($detail in $rodcDetails) {
        $hits = [System.Collections.ArrayList]::new()

        foreach ($raw in $detail.RevealedRaw) {
            $dn = Get-RodcDNFromRawValue -RawValue $raw
            $name = Get-RodcPrincipalNameFromDN -RawValue $raw
            $tier0Match = $null
            if ($dn -and $tier0ByDN.ContainsKey($dn.ToLowerInvariant())) { $tier0Match = $tier0ByDN[$dn.ToLowerInvariant()] }
            elseif ($name -and $tier0ByName.ContainsKey($name.ToLowerInvariant())) { $tier0Match = $tier0ByName[$name.ToLowerInvariant()] }

            if ($tier0Match) {
                [void]$hits.Add([PSCustomObject]@{ Source = 'msDS-RevealedUsers (already cached)'; PrincipalName = $name; PrincipalDN = $dn })
            }
        }

        foreach ($dn in $detail.AllowedDNs) {
            $name = Get-RodcPrincipalNameFromDN -RawValue $dn
            $tier0Match = $null
            if ($dn -and $tier0ByDN.ContainsKey("$dn".ToLowerInvariant())) { $tier0Match = $tier0ByDN["$dn".ToLowerInvariant()] }
            elseif ($name -and $tier0ByName.ContainsKey($name.ToLowerInvariant())) { $tier0Match = $tier0ByName[$name.ToLowerInvariant()] }

            if ($tier0Match) {
                [void]$hits.Add([PSCustomObject]@{ Source = 'msDS-RevealOnDemandGroup (allowed list)'; PrincipalName = $name; PrincipalDN = $dn })
            }
        }

        foreach ($hit in $hits) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Read-Only Domain Controller Security Posture'
            $finding.Issue = 'Privileged Account Revealed to RODC'
            $finding.Severity = 'Critical'
            $finding.SeverityLevel = 4
            $finding.AffectedObject = "$($detail.Name) - $($hit.PrincipalName)"
            $finding.Description = "The RODC '$($detail.Name)' has the Tier-0/privileged principal '$($hit.PrincipalName)' present via $($hit.Source). RODCs are deployed in lower-trust locations (branch offices, perimeter sites) specifically because a compromise of the RODC itself is considered more likely; a Tier-0 account's secrets being revealed to (or eligible to be revealed to) an RODC defeats that trust boundary."
            $finding.Impact = "An attacker who compromises this RODC (physically or remotely) can extract the cached credential material for '$($hit.PrincipalName)', a privileged/Tier-0 account, enabling full domain compromise from what was intended to be a lower-trust, disposable DC."
            $finding.Remediation = "Remove '$($hit.PrincipalName)' from the RODC's allowed password replication list (or, if already revealed, reset its password/credentials and add it to the Denied RODC Password Replication Group / msDS-NeverRevealGroup going forward). Tier-0 principals should never be allowed to authenticate through, or have secrets cached on, an RODC."
            $finding.Details = @{
                RODC              = $detail.Name
                ComputerObjectDN  = $detail.ComputerObjectDN
                PrincipalName     = $hit.PrincipalName
                PrincipalDN       = $hit.PrincipalDN
                Source            = $hit.Source
            }
            $findings += $finding
        }
    }

    # -------------------------------------------------------------------
    # Finding: RODC Password Replication Policy Misconfigured
    # -------------------------------------------------------------------
    foreach ($detail in $rodcDetails) {
        $issues = [System.Collections.ArrayList]::new()

        $allowedNames = @($detail.AllowedDNs | ForEach-Object { Get-RodcPrincipalNameFromDN -RawValue $_ })
        foreach ($broadName in $Script:RodcBroadAllowedPrincipalNames) {
            if ($allowedNames -contains $broadName) {
                [void]$issues.Add("Allowed list includes the broad principal '$broadName'")
            }
        }

        $deniedNames = @($detail.DeniedDNs | ForEach-Object { Get-RodcPrincipalNameFromDN -RawValue $_ })
        $missingDenied = @($Script:RodcExpectedDeniedGroupNames | Where-Object { $deniedNames -notcontains $_ })
        if ($missingDenied.Count -gt 0) {
            [void]$issues.Add("Denied list is missing expected privileged group(s): $($missingDenied -join ', ')")
        }

        if ($issues.Count -gt 0) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Read-Only Domain Controller Security Posture'
            $finding.Issue = 'RODC Password Replication Policy Misconfigured'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $detail.Name
            $finding.Description = "The RODC '$($detail.Name)' has a password replication policy (PRP) gap: $($issues -join '; ')."
            $finding.Impact = "A too-broad allowed list lets a much larger set of accounts have their secrets cached on this lower-trust DC than intended; a denied list missing core privileged groups relies solely on the allowed list being correct, with no defense-in-depth if that list is later widened by mistake."
            $finding.Remediation = "Scope msDS-RevealOnDemandGroup (the allowed list) down to only the specific accounts/groups that legitimately need to authenticate through this RODC, and ensure msDS-NeverRevealGroup (the denied list) explicitly includes Domain Admins, Enterprise Admins, Schema Admins, built-in Administrators, Cert Publishers, and the built-in Denied RODC Password Replication Group."
            $finding.Details = @{
                RODC             = $detail.Name
                ComputerObjectDN = $detail.ComputerObjectDN
                AllowedListRaw   = $detail.AllowedDNs
                DeniedListRaw    = $detail.DeniedDNs
                Issues           = @($issues)
            }
            $findings += $finding
        }
    }

    # -------------------------------------------------------------------
    # Finding: Orphaned RODC krbtgt Account
    # -------------------------------------------------------------------
    $krbtgtUsers = @()
    try {
        if ($Snapshot -and $Snapshot.ContainsKey('Users') -and $Snapshot.Users) {
            Write-Verbose "Test-ADRodcSecurity: sourcing krbtgt_* accounts from snapshot Users."
            $krbtgtUsers = @($Snapshot.Users | Where-Object { $_.SamAccountName -like 'krbtgt_*' })
        }
        else {
            $krbtgtUsers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADUser krbtgt_* accounts' -Query {
                Get-ADUser -Filter "SamAccountName -like 'krbtgt_*'" -Properties DistinguishedName, SamAccountName -ErrorAction Stop
            })
        }
    }
    catch {
        Write-Verbose "Test-ADRodcSecurity: could not enumerate krbtgt_* accounts: $_"
    }

    foreach ($krbtgtUser in $krbtgtUsers) {
        $dn = "$($krbtgtUser.DistinguishedName)".ToLowerInvariant()
        if (-not $linkedKrbtgtDNs.Contains($dn)) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Read-Only Domain Controller Security Posture'
            $finding.Issue = 'Orphaned RODC krbtgt Account'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $krbtgtUser.SamAccountName
            $finding.Description = "The RODC-specific account '$($krbtgtUser.SamAccountName)' exists but no current RODC links back to it via msDS-KrbTgtLink. This typically means the RODC it was provisioned for has since been demoted or removed without its dedicated krbtgt account being cleaned up."
            $finding.Impact = "Orphaned krbtgt_* accounts are unused attack surface: stale privileged-flavoured service accounts that add to hygiene debt and are easy to overlook during account reviews, and their continued presence can also mask genuine RODC decommissioning gaps."
            $finding.Remediation = "Confirm the corresponding RODC no longer exists (or, if it does, that its msDS-KrbTgtLink is correctly set), then disable and remove the orphaned '$($krbtgtUser.SamAccountName)' account following Microsoft's documented RODC krbtgt cleanup guidance."
            $finding.Details = @{
                SamAccountName    = $krbtgtUser.SamAccountName
                DistinguishedName = $krbtgtUser.DistinguishedName
                CurrentRodcCount  = $rodcs.Count
            }
            $findings += $finding
        }
    }

    Write-Verbose "Completed Read-Only Domain Controller security posture audit. Findings: $($findings.Count)"
    return $findings
}

#endregion
