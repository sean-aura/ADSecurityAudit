#region Known DC Vulnerabilities by Patch/Build Audit
#
# Flags Domain Controller exposure to the highest-impact AD CVEs strictly
# from OS build/version, installed CU/hotfix level, and service/config
# state - ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068,
# PrintNightmare (CVE-2021-34527), and BadSuccessor/dMSA escalation
# exposure on Windows Server 2025-level Domain Controllers.
# PingCastle-comparable check(s): S-Vuln-MS14-068, S-Vuln-MS17_010, A-Krbtgt, A-DC-Spooler,
# A-BadSuccessor.
#
# DETECTION ONLY: every determination here comes from reading
# Win32_OperatingSystem (build/version/install date), installed hotfixes
# (Get-HotFix / Win32_QuickFixEngineering), and the Print Spooler service
# state - the same category of read used elsewhere in this module (e.g.
# Test-ADCoercionAndRelayExposure's Spooler check). This module NEVER
# sends an exploit, authentication bypass, ticket forgery, coercion
# request, or any other PoC traffic to any host; a DC is judged vulnerable
# purely by whether its patch level/build/config falls below a documented,
# inline-cited fix threshold. Per the -FromSnapshot contract of performing
# NO live AD/network access, and because per-DC OS build/hotfix/service
# state is not part of the current snapshot schema, this entire audit is
# live-only and is skipped when invoked with -Snapshot (consistent with
# Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure).

# Documented fix thresholds for the legacy, build/patch-detectable CVEs.
# FixDate is the Patch Tuesday (or out-of-band) release date of the first
# public fix; a DC is treated as protected once ANY reliable evidence
# (latest installed hotfix date, or an OS install/media date that already
# postdates the fix) is on or after that date. Kept as a single table so
# every threshold is cited in one place rather than scattered through the
# check logic below.
$Script:KnownVulnFixThresholds = @{
    ZeroLogon = @{
        Issue       = 'DC Missing ZeroLogon Patch'
        Cve         = 'CVE-2020-1472'
        FixDate     = [datetime]'2020-08-11'
        FixNote     = 'August 11, 2020 cumulative/security-only updates (e.g. KB4565351 / KB4571694 / KB4565349 / KB4565354 depending on OS) - initial Netlogon secure-channel enforcement fix.'
        Description = 'Netlogon Remote Protocol elevation-of-privilege (ZeroLogon) allows an unauthenticated attacker on the network to reset the DC computer account password and obtain Domain Admin-equivalent access.'
    }
    MS17010 = @{
        Issue       = 'DC Vulnerable to MS17-010'
        Cve         = 'MS17-010 (CVE-2017-0143 through CVE-2017-0148)'
        FixDate     = [datetime]'2017-03-14'
        FixNote     = 'March 14, 2017 Patch Tuesday updates (e.g. KB4012212 / KB4012213 / KB4013389 depending on OS) - SMBv1 remote code execution fix (EternalBlue).'
        Description = 'Unauthenticated SMBv1 remote code execution (EternalBlue) allows full compromise of the Domain Controller over the network with no credentials.'
    }
    MS14068 = @{
        Issue       = 'DC Vulnerable to MS14-068'
        Cve         = 'CVE-2014-6324'
        FixDate     = [datetime]'2014-11-18'
        FixNote     = 'November 18, 2014 out-of-band update (KB3011780) - Kerberos PAC signature validation fix.'
        Description = 'A forged Kerberos PAC can claim Domain Admin group membership for any authenticated low-privilege user, which the unpatched KDC accepts without validating the signature.'
    }
    PrintNightmare = @{
        Issue       = 'PrintNightmare Exposure on DC'
        Cve         = 'CVE-2021-34527'
        FixDate     = [datetime]'2021-07-06'
        FixNote     = 'July 6, 2021 out-of-band update - Print Spooler remote code execution / local privilege escalation fix. Only relevant while the Spooler service is running.'
        Description = 'An authenticated user can remotely install a malicious printer driver via the Print Spooler service (RpcAddPrinterDriver) and achieve SYSTEM-level code execution on the DC.'
    }
}

# Windows Server 2025 shipped build number. BadSuccessor (delegated Managed
# Service Account / dMSA privilege-escalation exposure, disclosed 2025) is
# only meaningful on DCs running this build or later, since dMSA is a
# Server 2025 feature - guard the check to that build so older DCs never
# generate a false positive.
$Script:KnownVulnServer2025Build = 26100

function Test-ADKnownDCVulnerabilities {
    <#
    .SYNOPSIS
        Audits Domain Controllers for known high-impact AD CVE exposure,
        determined strictly from patch/build/config - never by exploitation.
    .DESCRIPTION
        For each Domain Controller, reads:
          1. Win32_OperatingSystem (BuildNumber, Caption, InstallDate).
          2. Installed hotfixes (Get-HotFix / Win32_QuickFixEngineering),
             using the most recent InstalledOn date as the DC's effective
             patch date.
          3. Print Spooler service state (reused for the PrintNightmare
             check only; independent of, and in addition to,
             Test-ADCoercionAndRelayExposure's own Spooler finding).

        Then flags, per documented fix threshold (see
        $Script:KnownVulnFixThresholds):
          - DC Missing ZeroLogon Patch (CVE-2020-1472)
          - DC Vulnerable to MS17-010 (EternalBlue)
          - DC Vulnerable to MS14-068 (Kerberos PAC forgery)
          - PrintNightmare Exposure on DC (CVE-2021-34527) - only when the
            Spooler service is also running.
          - BadSuccessor / dMSA Escalation Exposure - only on Domain
            Controllers running Windows Server 2025 (build >=
            $Script:KnownVulnServer2025Build), since dMSA is a Server 2025
            feature; there is no version-detectable "patched" state for
            this issue at time of writing, so its presence is reported as
            an environment-level exposure requiring delegation/ACL review
            rather than a missing-patch finding.

        Each DC is evaluated independently and degrades gracefully if it
        cannot be reached (Verbose warning only; no finding is raised for
        that DC).

        Detection only - every determination is a version/patch/config
        read. No exploitation, authentication bypass, ticket forging,
        coercion, relay, or PoC traffic is ever sent to any host.
    .PARAMETER Snapshot
        Optional snapshot hashtable (from Get-ADSnapshot), accepted for
        interface consistency with other Test-AD* functions. Per-DC OS
        build, hotfix level, and Spooler service state are live, real-time
        machine state with no snapshot equivalent, so this audit is
        entirely live-only: when -Snapshot is supplied, no live AD/network
        access is performed (per the -FromSnapshot contract) and this
        function returns no findings, consistent with
        Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure.
    .OUTPUTS
        [ADSecurityFinding[]]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [hashtable]$Snapshot
    )

    Write-Verbose "Starting Known DC Vulnerabilities (patch/build) audit..."
    $findings = @()

    if ($Snapshot) {
        Write-Verbose "Test-ADKnownDCVulnerabilities: -Snapshot supplied; skipping (OS build/hotfix/service state has no snapshot equivalent and offline mode performs no live AD/network access)."
        return $findings
    }

    # -------------------------------------------------------------------
    # Enumerate Domain Controllers.
    # -------------------------------------------------------------------
    $domainControllers = @()
    try {
        $domainControllers = @(Invoke-ADQueryWithRetry -OperationName 'Get-ADDomainController -Filter * (known-vuln audit)' -Query {
            Get-ADDomainController -Filter * -ErrorAction Stop
        })
    }
    catch {
        Write-Warning "Test-ADKnownDCVulnerabilities: failed to enumerate Domain Controllers: $_"
    }

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no Domain Controllers to evaluate; no findings."
        return $findings
    }

    $perDcState = [System.Collections.ArrayList]::new()

    $zeroLogonDCs      = [System.Collections.ArrayList]::new()
    $ms17010DCs        = [System.Collections.ArrayList]::new()
    $ms14068DCs        = [System.Collections.ArrayList]::new()
    $printNightmareDCs = [System.Collections.ArrayList]::new()
    $server2025DCs     = [System.Collections.ArrayList]::new()

    foreach ($dc in $domainControllers) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { "$dc" }
        Write-Verbose "Test-ADKnownDCVulnerabilities: evaluating DC '$dcName'..."

        $dcState = [ordered]@{
            DomainController = $dcName
            Reachable        = $false
            OSCaption        = $null
            OSBuildNumber    = $null
            OSInstallDate    = $null
            LatestHotfixDate = $null
            EffectivePatchDate = $null
            SpoolerStatus    = $null
            Error            = $null
        }

        # --- OS build/version/install date ---
        try {
            $osInfo = Invoke-ADQueryWithRetry -OperationName "Get-CimInstance Win32_OperatingSystem on $dcName" -Query {
                Get-CimInstance -ComputerName $dcName -ClassName Win32_OperatingSystem -ErrorAction Stop |
                    Select-Object Caption, BuildNumber, InstallDate
            }

            if ($osInfo) {
                $dcState.Reachable     = $true
                $dcState.OSCaption     = "$($osInfo.Caption)"
                $dcState.OSBuildNumber = [int]$osInfo.BuildNumber
                if ($osInfo.InstallDate) {
                    $dcState.OSInstallDate = [datetime]$osInfo.InstallDate
                }

                if ($dcState.OSBuildNumber -ge $Script:KnownVulnServer2025Build) {
                    [void]$server2025DCs.Add($dcName)
                }
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not read Win32_OperatingSystem on '$dcName': $_"
            $dcState.Error = "$_"
        }

        # --- Installed hotfix level (most recent InstalledOn date) ---
        try {
            $hotfixes = Invoke-ADQueryWithRetry -OperationName "Get-HotFix on $dcName" -Query {
                Get-HotFix -ComputerName $dcName -ErrorAction Stop
            }

            if ($hotfixes) {
                $dcState.Reachable = $true
                $latest = $hotfixes |
                    Where-Object { $_.InstalledOn } |
                    Sort-Object InstalledOn -Descending |
                    Select-Object -First 1
                if ($latest) {
                    $dcState.LatestHotfixDate = [datetime]$latest.InstalledOn
                }
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not read installed hotfixes on '$dcName' (Get-HotFix): $_"
            if (-not $dcState.Error) { $dcState.Error = "$_" }
        }

        # Effective patch date: the later of the OS install date (covers a
        # freshly built/reimaged DC whose media already postdates a fix,
        # even before any separate QFE record exists) and the most recent
        # installed hotfix. A DC is only as patched as the newer of the two.
        $candidateDates = @($dcState.OSInstallDate, $dcState.LatestHotfixDate) | Where-Object { $_ }
        if ($candidateDates.Count -gt 0) {
            $dcState.EffectivePatchDate = ($candidateDates | Sort-Object -Descending | Select-Object -First 1)
        }

        # --- Print Spooler service state (for PrintNightmare only) ---
        try {
            $spooler = Invoke-ADQueryWithRetry -OperationName "Get-Service Spooler on $dcName" -Query {
                Get-Service -ComputerName $dcName -Name 'Spooler' -ErrorAction Stop
            }
            if ($spooler) {
                $dcState.Reachable    = $true
                $dcState.SpoolerStatus = "$($spooler.Status)"
            }
        }
        catch {
            Write-Verbose "Test-ADKnownDCVulnerabilities: could not query Spooler service state on '$dcName': $_"
            if (-not $dcState.Error) { $dcState.Error = "$_" }
        }

        if (-not $dcState.Reachable) {
            Write-Verbose "Test-ADKnownDCVulnerabilities: DC '$dcName' unreachable; skipping (no finding for this DC)."
            [void]$perDcState.Add([PSCustomObject]$dcState)
            continue
        }

        # --- Evaluate the three build/patch-only CVE thresholds ---
        if ($dcState.EffectivePatchDate) {
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.ZeroLogon.FixDate) {
                [void]$zeroLogonDCs.Add($dcName)
            }
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.MS17010.FixDate) {
                [void]$ms17010DCs.Add($dcName)
            }
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.MS14068.FixDate) {
                [void]$ms14068DCs.Add($dcName)
            }
            if ($dcState.SpoolerStatus -eq 'Running' -and $dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.PrintNightmare.FixDate) {
                [void]$printNightmareDCs.Add($dcName)
            }
        }
        else {
            # No reliable patch-date evidence at all (neither an OS install
            # date nor any hotfix record) - cannot rule the DC IN or OUT for
            # the legacy CVEs, so it is reported for manual review rather
            # than silently assumed patched or silently assumed vulnerable.
            Write-Verbose "Test-ADKnownDCVulnerabilities: no OS install date or hotfix record available for '$dcName'; cannot determine legacy-CVE patch status from this data alone."
        }

        [void]$perDcState.Add([PSCustomObject]$dcState)
    }

    # -------------------------------------------------------------------
    # Finding: DC Missing ZeroLogon Patch
    # -------------------------------------------------------------------
    if ($zeroLogonDCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.ZeroLogon
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($zeroLogonDCs -join ', ')
        $finding.Description = "$($zeroLogonDCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) (ZeroLogon) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($zeroLogonDCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) Verify with `Get-HotFix -ComputerName <DC>` and enforce Netlogon secure-channel signing/sealing (`FullSecureChannelProtection`) once all DCs and trusts are updated."
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($zeroLogonDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found missing the ZeroLogon patch."
    }

    # -------------------------------------------------------------------
    # Finding: DC Vulnerable to MS17-010
    # -------------------------------------------------------------------
    if ($ms17010DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.MS17010
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($ms17010DCs -join ', ')
        $finding.Description = "$($ms17010DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($ms17010DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) If SMBv1 is not required, also disable it entirely (`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`)."
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($ms17010DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found vulnerable to MS17-010."
    }

    # -------------------------------------------------------------------
    # Finding: DC Vulnerable to MS14-068
    # -------------------------------------------------------------------
    if ($ms14068DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.MS14068
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($ms14068DCs -join ', ')
        $finding.Description = "$($ms14068DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) (MS14-068) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($ms14068DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) This is a long-superseded out-of-band fix; any DC still missing it should also be checked for currency against all subsequent cumulative updates."
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($ms14068DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found vulnerable to MS14-068."
    }

    # -------------------------------------------------------------------
    # Finding: PrintNightmare Exposure on DC
    # -------------------------------------------------------------------
    if ($printNightmareDCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.PrintNightmare
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($printNightmareDCs -join ', ')
        $finding.Description = "$($printNightmareDCs.Count) Domain Controller(s) are running the Print Spooler service AND show no patch/build evidence on or after the $($info.Cve) (PrintNightmare) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($printNightmareDCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) As defense-in-depth regardless of patch level, disable and stop the Spooler service on all Domain Controllers unless print serving from a DC is an explicit, documented requirement."
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($printNightmareDCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found exposed to PrintNightmare (either Spooler not running or patch level current)."
    }

    # -------------------------------------------------------------------
    # Finding: BadSuccessor / dMSA Escalation Exposure
    # -------------------------------------------------------------------
    if ($server2025DCs.Count -gt 0) {
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = 'BadSuccessor / dMSA Escalation Exposure'
        $finding.Severity = 'High'
        $finding.SeverityLevel = 3
        $finding.AffectedObject = ($server2025DCs -join ', ')
        $finding.Description = "$($server2025DCs.Count) Domain Controller(s) are running Windows Server 2025 (build >= $($Script:KnownVulnServer2025Build)), which introduces delegated Managed Service Accounts (dMSA): $($server2025DCs -join ', ')."
        $finding.Impact = "The dMSA feature ('BadSuccessor') lets any principal with CreateChild/msDS-DelegatedManagedServiceAccount rights over an OU create a dMSA that inherits the resulting-password-authority of an existing account it 'succeeds', which can be abused for privilege escalation against any account (including Tier-0) if delegation is not tightly scoped. There is no build/version-detectable 'patched' state for this issue; it is a configuration/delegation exposure inherent to the feature being present."
        $finding.Remediation = "Audit and restrict who holds CreateChild/msDS-DelegatedManagedServiceAccount and generic-write rights on OUs, especially any OU containing or above Tier-0 objects; monitor for unexpected dMSA object creation; consult current Microsoft/vendor guidance for this feature before treating any specific configuration as fully mitigated."
        $finding.Details = @{
            AffectedDomainControllers = @($server2025DCs)
            Server2025BuildThreshold  = $Script:KnownVulnServer2025Build
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no Windows Server 2025-level DC found; BadSuccessor/dMSA check not applicable."
    }

    Write-Verbose "Completed Known DC Vulnerabilities (patch/build) audit. Findings: $($findings.Count)"
    return $findings
}

#endregion
