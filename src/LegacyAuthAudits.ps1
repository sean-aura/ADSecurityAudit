#region Legacy Auth & Name-Poisoning Surface Audit
#
# Detects legacy/weak authentication and name-resolution poisoning surface
# that is enforced (or left unenforced) via GPO/registry: SMBv1, SMB signing
# not required, LM/NTLMv1 authentication permitted, LLMNR not disabled, and
# WSUS delivered over HTTP. PingCastle-comparable check(s): S-SMB-v1,
# A-SMB2SignatureNotEnabled, A-SMB2SignatureNotRequired, A-LMHashAuthorized,
# S-OldNtlm, A-NoGPOLLMNR, S-WSUS-HTTP.
#
# DETECTION ONLY: this module reads GPO-linked registry policy values (via
# `Get-GPRegistryValue` against each linked GPO's registry.pol) and, only
# when no linked GPO defines a setting, falls back to a direct per-DC
# registry read (remote registry / `Invoke-Command`) so an unmanaged/local
# value is not silently missed. It never sets, clears, or otherwise modifies
# any policy or registry value, and performs no exploitation, coercion,
# relay, ticket forging, or PoC traffic (e.g. it never triggers Responder-
# style poisoning or an SMB relay). Per the -FromSnapshot contract of
# performing NO live AD/network access, and because GPO-linked registry
# policy state is not part of the current snapshot schema, ALL checks in
# this module are live-only and are skipped entirely when invoked with
# -Snapshot (consistent with Test-ADCoercionAndRelayExposure and the
# anonymous-bind probe in Test-ADDomainHardeningFlags).

# Registry locations/value names probed by this module. Centralised here so
# the GPO-lookup and live-fallback code paths always agree on exactly what
# they are reading.
$Script:LegacyAuthRegistryTargets = @{
    Smb1 = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        ValueName = 'SMB1'
    }
    SmbSigning = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        ValueName = 'RequireSecuritySignature'
    }
    LmCompatibilityLevel = @{
        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        ValueName = 'LmCompatibilityLevel'
    }
    Llmnr = @{
        Key       = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        ValueName = 'EnableMulticast'
    }
    WsusServer = @{
        Key       = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        ValueName = 'WUServer'
    }
}

# Resolves the GPOs linked to a given AD container, ordered so that the
# link Get-GPInheritance considers highest-precedence (i.e. the one that
# would win once Enforced/Block Inheritance are accounted for) is checked
# first. Read-only (GroupPolicy module queries against SYSVOL/AD); never
# creates, links, or edits a GPO.
function Get-ADLinkedGposOrdered {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetDn
    )

    try {
        $inheritance = Get-GPInheritance -Target $TargetDn -ErrorAction Stop
        return @($inheritance.GpoLinks |
            Sort-Object -Property Order |
            ForEach-Object {
                try { Get-GPO -Guid $_.GpoId -ErrorAction Stop } catch { $null }
            } |
            Where-Object { $_ })
    }
    catch {
        Write-Verbose "Get-ADLinkedGposOrdered: could not resolve GPO links for '$TargetDn': $_"
        return @()
    }
}

# Walks a precedence-ordered list of GPOs looking for a specific registry
# value in each GPO's registry.pol. Returns the first (highest-precedence)
# hit, tagged with the source GPO's display name, or $null if no linked GPO
# sets the value (in which case the caller should treat it as policy-unset
# and, if appropriate, fall back to a live read to see the effective state).
function Get-ADPolicyRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Gpos,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$ValueName
    )

    foreach ($gpo in $Gpos) {
        try {
            $regValue = Get-GPRegistryValue -Guid $gpo.Id -Key $Key -ValueName $ValueName -ErrorAction Stop
            if ($regValue -and $null -ne $regValue.Value) {
                return [PSCustomObject]@{
                    Value  = $regValue.Value
                    Source = $gpo.DisplayName
                }
            }
        }
        catch {
            Write-Verbose "Get-ADPolicyRegistryValue: '$Key\$ValueName' not set in GPO '$($gpo.DisplayName)': $_"
        }
    }

    return $null
}

function Test-ADLegacyAuthSurface {
    <#
    .SYNOPSIS
        Audits legacy/weak authentication and name-resolution poisoning
        surface enforced (or left unenforced) via GPO/registry: SMBv1, SMB
        signing, LM/NTLMv1, LLMNR, and WSUS-over-HTTP.
    .DESCRIPTION
        Five checks, each distinguishing a policy-enforced value (naming the
        source GPO) from an unset/local one:
          1. SMBv1 Enabled / Not Disabled by Policy - LanmanServer `SMB1`.
          2. SMB Signing Not Required - LanmanServer `RequireSecuritySignature`.
          3. LM/NTLMv1 Authentication Permitted - LSA `LmCompatibilityLevel` < 3.
          4. LLMNR Not Disabled by Policy - DNSClient `EnableMulticast`.
          5. WSUS Delivered over HTTP - WindowsUpdate `WUServer` is http://.

        For the Domain-Controller-scoped settings (SMBv1, SMB signing,
        LM/NTLMv1), GPOs linked to the Domain Controllers OU are checked
        first, then GPOs linked to the domain root, so the value actually
        enforced on DCs is preferred. If no linked GPO defines a setting,
        this falls back to a live per-DC registry read so a locally
        configured (non-GPO) value is still detected; the resulting finding
        notes whether the observed value came from a GPO or from a direct
        registry read with no enforcing policy found.

        LLMNR and WSUS are evaluated against GPOs linked to the domain root
        (and the Domain Controllers OU) only; this module does not attempt
        to enumerate every OU in the domain, so a policy linked exclusively
        to some other OU will not be seen. If no linked GPO is found, LLMNR
        falls back to a live per-DC read (fail-open assumption -
        LLMNR-poisoning risk is flagged unless a disabling GPO is
        confirmed), and WSUS falls back to a live per-DC read of the same
        registry location.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot). GPO-linked
        registry policy state is not part of the current snapshot schema
        and every check here requires live AD/GPO/registry access, so -
        consistent with the -FromSnapshot contract of performing NO live
        AD/network access - this entire function is skipped (returns no
        findings) when invoked with -Snapshot.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Legacy Auth & Name-Poisoning Surface audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ADLegacyAuthSurface: -Snapshot supplied; GPO-linked registry policy state and live per-DC registry reads are not part of the snapshot schema, so this audit is skipped entirely (offline mode performs no live AD/network access)."
        Add-ADOfflineSkipNote -Test 'LegacyAuthSurface' -Check 'Entire test: GPO-linked and per-DC registry policy state' `
            -Reason 'Live GPO-linked registry policy and per-DC registry reads with no AD-schema equivalent. Run this check live (without -Snapshot) if you need this coverage.'
        return $findings
    }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: GroupPolicy module not available; cannot evaluate GPO-linked policy state: $_"
        return $findings
    }

    try {
        $domain = Get-ADDomain -ErrorAction Stop
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: failed to query domain: $_"
        return $findings
    }

    $domainControllers = @()
    try {
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Filter * (legacy-auth audit)' -Query {
            Get-ADDomainController -Filter * -ErrorAction Stop
        })
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADLegacyAuthSurface: no Domain Controllers found; cannot evaluate DC-scoped or live-fallback checks."
        return $findings
    }

    # Discover the actual Domain Controllers OU from a real DC's parent
    # container rather than assuming the default 'OU=Domain Controllers'
    # path, so this still resolves correctly if that OU was renamed/moved.
    $dcOuDn = $null
    try {
        $firstDcDn = $domainControllers[0].ComputerObjectDN
        if ($firstDcDn -and $firstDcDn -match '^CN=[^,]+,(.+)$') {
            $dcOuDn = $Matches[1]
        }
    }
    catch {
        Write-Verbose "Test-ADLegacyAuthSurface: could not derive Domain Controllers OU from a DC computer object: $_"
    }
    if (-not $dcOuDn) {
        $dcOuDn = "OU=Domain Controllers,$($domain.DistinguishedName)"
        Write-Verbose "Test-ADLegacyAuthSurface: falling back to default Domain Controllers OU path '$dcOuDn'."
    }

    $dcOuGpos   = Get-ADLinkedGposOrdered -TargetDn $dcOuDn
    $domainGpos = Get-ADLinkedGposOrdered -TargetDn $domain.DistinguishedName
    # DC OU precedence first (most specific to the DCs being evaluated),
    # domain root as fallback.
    $dcScopeGpos = @($dcOuGpos + $domainGpos)

    # -------------------------------------------------------------------
    # Live per-DC registry fallback helper. Only invoked for settings that
    # no linked GPO defines, so a locally configured (non-policy) value is
    # still caught rather than silently skipped.
    # -------------------------------------------------------------------
    function Get-ADLiveRegistryValuePerDc {
        param(
            [array]$DomainControllers,
            [string]$Key,
            [string]$ValueName
        )
        $results = [System.Collections.ArrayList]::new()
        $regPath = "Registry::$Key"
        foreach ($dc in $DomainControllers) {
            $dcName = if ($dc.HostName) { $dc.HostName } else { $dc.Name }
            try {
                $value = Invoke-ADQueryWithRetry -OperationName "Read '$Key\$ValueName' on $dcName" -Query {
                    Invoke-Command -ComputerName $dcName -ErrorAction Stop -ScriptBlock {
                        param($p, $vn)
                        (Get-ItemProperty -Path $p -Name $vn -ErrorAction SilentlyContinue).$vn
                    } -ArgumentList $regPath, $ValueName
                }
                [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $value; Error = $null })
            }
            catch {
                Write-Verbose "Get-ADLiveRegistryValuePerDc: could not read '$Key\$ValueName' on '$dcName': $_"
                [void]$results.Add([PSCustomObject]@{ DomainController = $dcName; Value = $null; Error = "$_" })
            }
        }
        return $results
    }

    # -------------------------------------------------------------------
    # Check 1: SMBv1 Enabled / Not Disabled by Policy
    # -------------------------------------------------------------------
    try {
        $target = $Script:LegacyAuthRegistryTargets.Smb1
        $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

        $isEnabled  = $false
        $source     = $null
        $detail     = @{}

        if ($policy) {
            $isEnabled = ([int]$policy.Value -ne 0)
            $source    = "GPO: $($policy.Source)"
            $detail    = @{ EnforcedValue = [int]$policy.Value; Source = $source }
        }
        else {
            $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
            $notDisabledDCs = @($perDc | Where-Object { $null -eq $_.Value -or [int]$_.Value -ne 0 } | ForEach-Object { $_.DomainController })
            $isEnabled = $notDisabledDCs.Count -gt 0
            $source    = 'No enforcing GPO found; observed via direct per-DC registry read'
            $detail    = @{ Source = $source; AffectedDomainControllers = $notDisabledDCs; PerDomainControllerState = @($perDc) }
        }

        if ($isEnabled) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Auth & Name Poisoning'
            $finding.Issue = 'SMBv1 Enabled / Not Disabled by Policy'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = if ($policy) { $dcOuDn } else { ($detail.AffectedDomainControllers -join ', ') }
            $finding.Description = "SMBv1 is permitted ($source)."
            $finding.Impact = "SMBv1 is an obsolete, unauthenticated-by-default protocol with known remote code execution vulnerabilities (e.g. EternalBlue/MS17-010) and no protection against relay/MITM. Its continued availability materially increases the blast radius of any foothold on the network."
            $finding.Remediation = "Disable the SMBv1 server (and client) component (`Set-SmbServerConfiguration -EnableSMB1Protocol $false`, or the 'Configure SMBv1 client/server' GPO setting) and confirm via a GPO enforced on Domain Controllers and workstations alike."
            $finding.Details = $detail
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADLegacyAuthSurface: SMBv1 is disabled (policy-enforced or observed live)."
        }
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: error evaluating SMBv1 state: $_"
    }

    # -------------------------------------------------------------------
    # Check 2: SMB Signing Not Required
    # -------------------------------------------------------------------
    try {
        $target = $Script:LegacyAuthRegistryTargets.SmbSigning
        $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

        $notRequired = $false
        $source      = $null
        $detail      = @{}

        if ($policy) {
            $notRequired = ([int]$policy.Value -eq 0)
            $source      = "GPO: $($policy.Source)"
            $detail      = @{ EnforcedValue = [int]$policy.Value; Source = $source }
        }
        else {
            $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
            $notRequiredDCs = @($perDc | Where-Object { $null -eq $_.Value -or [int]$_.Value -eq 0 } | ForEach-Object { $_.DomainController })
            $notRequired = $notRequiredDCs.Count -gt 0
            $source      = 'No enforcing GPO found; observed via direct per-DC registry read'
            $detail      = @{ Source = $source; AffectedDomainControllers = $notRequiredDCs; PerDomainControllerState = @($perDc) }
        }

        if ($notRequired) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Auth & Name Poisoning'
            $finding.Issue = 'SMB Signing Not Required'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = if ($policy) { $dcOuDn } else { ($detail.AffectedDomainControllers -join ', ') }
            $finding.Description = "SMB server signing is not required ($source)."
            $finding.Impact = "Without required SMB signing, a coerced or captured NTLM authentication can be relayed to SMB on this host to execute commands or access shares as the relayed identity - the classic coerce-then-relay-to-SMB path."
            $finding.Remediation = "Enable and enforce 'Microsoft network server: Digitally sign communications (always)' (`RequireSecuritySignature` = 1) via a GPO linked to the Domain Controllers OU (and ideally domain-wide)."
            $finding.Details = $detail
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADLegacyAuthSurface: SMB signing is required (policy-enforced or observed live)."
        }
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: error evaluating SMB signing state: $_"
    }

    # -------------------------------------------------------------------
    # Check 3: LM/NTLMv1 Authentication Permitted (LmCompatibilityLevel < 3)
    # -------------------------------------------------------------------
    try {
        $target = $Script:LegacyAuthRegistryTargets.LmCompatibilityLevel
        $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

        $isWeak = $false
        $source = $null
        $detail = @{}

        if ($policy) {
            $isWeak = ([int]$policy.Value -lt 3)
            $source = "GPO: $($policy.Source)"
            $detail = @{ EnforcedValue = [int]$policy.Value; Source = $source }
        }
        else {
            $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
            # A missing value with no enforcing GPO is left as the OS
            # default (3 - "Send NTLMv2 response only" on Vista/2008+), so
            # only explicitly weak values are flagged; unset is not treated
            # as a finding to avoid false positives from the modern default.
            $weakDCs = @($perDc | Where-Object { $null -ne $_.Value -and [int]$_.Value -lt 3 } | ForEach-Object { $_.DomainController })
            $isWeak  = $weakDCs.Count -gt 0
            $source  = 'No enforcing GPO found; observed via direct per-DC registry read'
            $detail  = @{ Source = $source; AffectedDomainControllers = $weakDCs; PerDomainControllerState = @($perDc) }
        }

        if ($isWeak) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Auth & Name Poisoning'
            $finding.Issue = 'LM/NTLMv1 Authentication Permitted'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = if ($policy) { $dcOuDn } else { ($detail.AffectedDomainControllers -join ', ') }
            $finding.Description = "`LmCompatibilityLevel` permits sending LM and/or NTLMv1 authentication ($source)."
            $finding.Impact = "LM and NTLMv1 use weak, crackable hashing and are vulnerable to well-known downgrade, relay, and offline cracking attacks (e.g. via Responder). Permitting them anywhere in the domain undermines NTLMv2-only defences elsewhere."
            $finding.Remediation = "Set 'Network security: LAN Manager authentication level' (`LmCompatibilityLevel`) to 5 (Send NTLMv2 response only, refuse LM & NTLM) via a GPO, after confirming no legacy clients/applications still require LM/NTLMv1."
            $finding.Details = $detail
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADLegacyAuthSurface: LmCompatibilityLevel does not permit LM/NTLMv1 (policy-enforced, observed live, or unset/default)."
        }
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: error evaluating LmCompatibilityLevel: $_"
    }

    # -------------------------------------------------------------------
    # Check 4: LLMNR Not Disabled by Policy
    # -------------------------------------------------------------------
    try {
        $target = $Script:LegacyAuthRegistryTargets.Llmnr
        # LLMNR is a computer-wide client setting normally rolled out
        # domain-wide, so only the domain root and DC OU links are
        # consulted; a policy linked exclusively to some other OU will not
        # be seen by this check (see function help).
        $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

        $isEnabled = $true
        $source    = $null
        $detail    = @{}

        if ($policy) {
            $isEnabled = ([int]$policy.Value -ne 0)
            $source    = "GPO: $($policy.Source)"
            $detail    = @{ EnforcedValue = [int]$policy.Value; Source = $source }
        }
        else {
            # Fail-open: if no GPO could be confirmed to disable LLMNR,
            # treat it as not disabled by policy (the same fail-open
            # semantics as PingCastle's comparable A-NoGPOLLMNR check - the
            # finding is the absence of a disabling policy).
            $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
            $isEnabled = $true
            $source    = 'No enforcing (disabling) GPO found linked at the domain root or Domain Controllers OU'
            $detail    = @{ Source = $source; PerDomainControllerState = @($perDc) }
        }

        if ($isEnabled) {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Auth & Name Poisoning'
            $finding.Issue = 'LLMNR Not Disabled by Policy'
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
            $finding.AffectedObject = $domain.DNSRoot
            $finding.Description = "No GPO could be confirmed to disable LLMNR ($source)."
            $finding.Impact = "LLMNR (and, typically alongside it, NBT-NS) answers name-resolution requests for names that don't exist in DNS, allowing an attacker on the local network to spoof responses and capture/relay NTLM authentication attempts (Responder-style poisoning)."
            $finding.Remediation = "Disable 'Turn off Multicast Name Resolution' setting to Enabled (which sets `EnableMulticast` = 0) via a GPO linked at the domain root (or broadly enough to cover all workstations and servers), and disable NBT-NS via DHCP options or NetBIOS settings as a complementary control."
            $finding.Details = $detail
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADLegacyAuthSurface: LLMNR is disabled by a linked GPO."
        }
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: error evaluating LLMNR policy state: $_"
    }

    # -------------------------------------------------------------------
    # Check 5: WSUS Delivered over HTTP
    # -------------------------------------------------------------------
    try {
        $target = $Script:LegacyAuthRegistryTargets.WsusServer
        $policy = Get-ADPolicyRegistryValue -Gpos $dcScopeGpos -Key $target.Key -ValueName $target.ValueName

        $wuServer = $null
        $source   = $null
        $detail   = @{}

        if ($policy) {
            $wuServer = "$($policy.Value)"
            $source   = "GPO: $($policy.Source)"
            $detail   = @{ WUServer = $wuServer; Source = $source }
        }
        else {
            $perDc = Get-ADLiveRegistryValuePerDc -DomainControllers $domainControllers -Key $target.Key -ValueName $target.ValueName
            $firstWithValue = $perDc | Where-Object { $_.Value } | Select-Object -First 1
            if ($firstWithValue) {
                $wuServer = "$($firstWithValue.Value)"
                $source   = 'No enforcing GPO found; observed via direct per-DC registry read'
                $detail   = @{ WUServer = $wuServer; Source = $source; PerDomainControllerState = @($perDc) }
            }
        }

        if ($wuServer -and $wuServer -match '^(?i)http://') {
            $finding = [ADSecurityFinding]::new()
            $finding.Category = 'Legacy Auth & Name Poisoning'
            $finding.Issue = 'WSUS Delivered over HTTP'
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
            $finding.AffectedObject = $wuServer
            $finding.Description = "WSUS is configured to deliver updates over unencrypted HTTP ($source): $wuServer."
            $finding.Impact = "Updates delivered over plain HTTP can be intercepted and swapped for attacker-supplied packages by an on-path attacker (WSUS package-injection MITM, e.g. WSUXploit/WSUSpect), leading to SYSTEM-level code execution on every client that checks in against this WSUS server."
            $finding.Remediation = "Reconfigure WSUS for HTTPS (`WUServer`/`WUStatusServer` set to an https:// URL backed by a valid certificate) via the 'Specify intranet Microsoft update service location' GPO setting, and reissue the policy to all managed clients."
            $finding.Details = $detail
            $findings += $finding
        }
        else {
            Write-Verbose "Test-ADLegacyAuthSurface: WSUS is not configured over HTTP (or WSUS is not configured/found)."
        }
    }
    catch {
        Write-Warning "Test-ADLegacyAuthSurface: error evaluating WSUS delivery protocol: $_"
    }

    Write-Verbose "Legacy Auth & Name-Poisoning Surface audit complete. Found $($findings.Count) issue(s)."
    return $findings
}

#endregion
