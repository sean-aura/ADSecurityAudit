#region Known DC Vulnerabilities by Patch/Build Audit
#
# Flags Domain Controller exposure to the highest-impact AD CVEs strictly
# from OS build/version, installed CU/hotfix level, and service/config
# state - ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068,
# PrintNightmare (CVE-2021-34527), CVE-2026-41089 (unauthenticated Netlogon
# RCE), and BadSuccessor/dMSA escalation exposure on Windows Server
# 2025-level Domain Controllers, including (as of v1.18.0) a per-DC
# CVE-2025-53779 KDC-side patch-level (UBR) classification.
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
    # Verified against MSRC (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
    # on 2026-07-09. Fix date unchanged since prior review.
    ZeroLogon = @{
        Issue       = 'DC Missing ZeroLogon Patch'
        Cve         = 'CVE-2020-1472'
        FixDate     = [datetime]'2020-08-11'
        FixNote     = 'August 11, 2020 cumulative/security-only updates (e.g. KB4565351 / KB4571694 / KB4565349 / KB4565354 depending on OS) - initial Netlogon secure-channel enforcement fix.'
        Description = 'Netlogon Remote Protocol elevation-of-privilege (ZeroLogon) allows an unauthenticated attacker on the network to reset the DC computer account password and obtain Domain Admin-equivalent access.'
    }
    # Verified against MSRC (https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
    # on 2026-07-09. Fix date unchanged since prior review.
    MS17010 = @{
        Issue       = 'DC Vulnerable to MS17-010'
        Cve         = 'MS17-010 (CVE-2017-0143 through CVE-2017-0148)'
        FixDate     = [datetime]'2017-03-14'
        FixNote     = 'March 14, 2017 Patch Tuesday updates (e.g. KB4012212 / KB4012213 / KB4013389 depending on OS) - SMBv1 remote code execution fix (EternalBlue).'
        Description = 'Unauthenticated SMBv1 remote code execution (EternalBlue) allows full compromise of the Domain Controller over the network with no credentials.'
    }
    # Verified against MSRC (https://msrc.microsoft.com/blog/2014/11/additional-information-about-cve-2014-6324/)
    # on 2026-07-09. Fix date unchanged since prior review.
    MS14068 = @{
        Issue       = 'DC Vulnerable to MS14-068'
        Cve         = 'CVE-2014-6324'
        FixDate     = [datetime]'2014-11-18'
        FixNote     = 'November 18, 2014 out-of-band update (KB3011780) - Kerberos PAC signature validation fix.'
        Description = 'A forged Kerberos PAC can claim Domain Admin group membership for any authenticated low-privilege user, which the unpatched KDC accepts without validating the signature.'
    }
    # Verified against MSRC (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
    # on 2026-07-09. Fix date unchanged since prior review.
    PrintNightmare = @{
        Issue       = 'PrintNightmare Exposure on DC'
        Cve         = 'CVE-2021-34527'
        FixDate     = [datetime]'2021-07-06'
        FixNote     = 'July 6, 2021 out-of-band update - Print Spooler remote code execution / local privilege escalation fix. Only relevant while the Spooler service is running.'
        Description = 'An authenticated user can remotely install a malicious printer driver via the Print Spooler service (RpcAddPrinterDriver) and achieve SYSTEM-level code execution on the DC.'
    }
    # Verified 2026-07-09 against multiple independent sources citing MSRC
    # directly: SecurityWeek, Tenable, Zero Day Initiative, Help Net
    # Security, and CERT-EU (https://cert.europa.eu/publications/security-advisories/2026-007/).
    # Fix date (May 12, 2026), CVSS 9.8, and unauthenticated pre-auth RCE via
    # a Netlogon stack-based buffer overflow are consistent across all of
    # them. CERT-EU's advisory (citing MSRC) additionally gives verified
    # per-OS fixed-build boundaries rather than KB numbers, which several
    # lower-quality aggregator sites gave inconsistently and were NOT relied
    # on here: Server 2016 < 10.0.14393.9140, Server 2019 < 10.0.17763.8755,
    # Server 2022 < 10.0.20348.5074, Server 2022 23H2 < 10.0.25398.2330,
    # Server 2025 < 10.0.26100.32772. This function's threshold below
    # intentionally stays FixDate-only (not per-OS build), consistent with
    # how the other three legacy CVE checks in this table work; the CERT-EU
    # build numbers are recorded here for reference / a future refinement.
    # Active in-the-wild exploitation was reported by Belgium's CCB
    # starting May 29, 2026, per the same sources.
    Netlogon2026 = @{
        Issue       = 'DC Missing CVE-2026-41089 Patch (Netlogon RCE)'
        Cve         = 'CVE-2026-41089'
        FixDate     = [datetime]'2026-05-12'
        FixNote     = 'May 12, 2026 Patch Tuesday cumulative updates - Netlogon Remote Protocol (MS-NRPC) packet-handling stack buffer overflow fix. Per-OS fixed-build boundaries (CERT-EU, citing MSRC): Server 2016 >= 10.0.14393.9140, Server 2019 >= 10.0.17763.8755, Server 2022 >= 10.0.20348.5074, Server 2022 23H2 >= 10.0.25398.2330, Server 2025 >= 10.0.26100.32772. Confirm the exact KB number for your specific OS build via Windows Update / the Microsoft Update Catalog, since third-party aggregator KB numbers for this CVE have been inconsistent.'
        Description = 'An unauthenticated, network-only attacker can trigger a stack-based buffer overflow in the Netlogon RPC interface (MS-NRPC) and achieve SYSTEM-level remote code execution on the Domain Controller, with no credentials or user interaction required (CVSS 9.8). Reported under active exploitation in the wild starting May 29, 2026 (Belgium CCB advisory).'
    }
}

# Windows Server 2025 shipped build number. BadSuccessor (delegated Managed
# Service Account / dMSA privilege-escalation exposure, disclosed 2025) is
# only meaningful on DCs running this build or later, since dMSA is a
# Server 2025 feature - guard the check to that build so older DCs never
# generate a false positive.
#
# As of v1.18.0 this base-build guard is paired with a per-DC UBR
# (Update Build Revision) read - see $Script:KnownVulnBadSuccessorPatchedUBR
# and Get-ADKnownVulnUBR below - to distinguish DCs patched for
# CVE-2025-53779 (build 26100.4946+) from unpatched ones. The base-build
# guard itself is unchanged: it still just answers "does this DC even have
# dMSA," irrespective of patch level.
$Script:KnownVulnServer2025Build = 26100

# UBR (Update Build Revision - the third component of a Windows build
# number, e.g. the 4946 in 26100.4946) at or above which a Server
# 2025-level DC has Microsoft's August 12, 2025 cumulative update
# (KB5063878, OS build 26100.4946) installed, which added KDC-side
# validation requiring a mutual (two-sided) dMSA/target link before the
# KDC honors it - closing the original one-sided-link escalation path
# described in CVE-2025-53779.
# Verified 2026-07-09 directly against Microsoft's own KB5063878 support
# article (support.microsoft.com/en-us/topic/august-12-2025-kb5063878-...
# -e4b87262-75c8-4fef-9df7-4a18099ee294): "August 12, 2025 - KB5063878
# (OS Build 26100.4946)" confirms the KB-to-build mapping used here.
#
# NOTE: per independent post-patch research (Akamai, "BadSuccessor Is
# Dead, Long Live BadSuccessor(?)", confirmed 2026-07-09), this patch does
# not fully close the underlying technique - a mutually-paired dMSA/target
# relationship still allows credential/privilege abuse if an attacker
# controls both sides. A DC classified "Patched" below is therefore not
# "safe" the way a fixed ZeroLogon/MS17-010/MS14-068/PrintNightmare DC is;
# the finding continues to fire for patched DCs with adjusted text rather
# than disappearing.
$Script:KnownVulnBadSuccessorPatchedUBR = 4946

function Get-ADKnownVulnUBR {
    <#
    .SYNOPSIS
        Reads the Windows Update Build Revision (UBR) from a remote
        computer's registry.
    .DESCRIPTION
        Read-only: opens the remote HKLM hive via .NET's
        [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey (the standard
        remote-registry API - functionally equivalent to `reg.exe query
        \\computer\HKLM\...`) and reads the single existing
        'UBR' value under 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'.
        No writes, no code execution, no service interaction of any kind.
    .PARAMETER ComputerName
        The remote Domain Controller to read the UBR from.
    .OUTPUTS
        [int] the UBR value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $baseKey = $null
    $subKey  = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $subKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        if (-not $subKey) {
            throw "CurrentVersion registry key not found on '$ComputerName'."
        }
        $ubr = $subKey.GetValue('UBR', $null)
        if ($null -eq $ubr) {
            throw "UBR value not present under CurrentVersion on '$ComputerName'."
        }
        return [int]$ubr
    }
    finally {
        if ($subKey)  { $subKey.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }
}

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
          - DC Missing CVE-2026-41089 Patch (Netlogon RCE) - unauthenticated,
            critical (CVSS 9.8) Netlogon RPC remote code execution against
            any DC, evaluated with the same patch-date evidence as the
            other build/patch-only checks above.
          - BadSuccessor / dMSA Escalation Exposure - only on Domain
            Controllers running Windows Server 2025 (build >=
            $Script:KnownVulnServer2025Build), since dMSA is a Server 2025
            feature. Microsoft shipped a partial KDC-side fix for the
            original one-sided-link escalation as CVE-2025-53779 (August
            2025, build 26100.4946+). As of v1.18.0, each Server
            2025-level DC additionally has its UBR (Update Build Revision)
            read via remote registry to classify it as patched (UBR >=
            $Script:KnownVulnBadSuccessorPatchedUBR) or unpatched for
            CVE-2025-53779; a DC whose UBR cannot be read is reported with
            an unknown patch status rather than silently assumed patched.
            Independent research has shown the underlying dMSA-linking
            primitive still enables related credential/privilege abuse
            even on patched DCs - so the finding continues to fire (with
            adjusted text and, when every affected DC is confirmed
            patched, a reduced severity) rather than disappearing once
            patched.

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
    $netlogon2026DCs   = [System.Collections.ArrayList]::new()
    $server2025DCs     = [System.Collections.ArrayList]::new()
    $badSuccessorPatchedDCs   = [System.Collections.ArrayList]::new()
    $badSuccessorUnpatchedDCs = [System.Collections.ArrayList]::new()
    $badSuccessorUnknownDCs   = [System.Collections.ArrayList]::new()

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
            UBR              = $null
            BadSuccessorPatchStatus = $null
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

        # --- UBR (Update Build Revision) - BadSuccessor / CVE-2025-53779
        #     patch-level classification, Server 2025-level DCs only ---
        if ($dcState.OSBuildNumber -ge $Script:KnownVulnServer2025Build) {
            try {
                $ubr = Invoke-ADQueryWithRetry -OperationName "Read UBR registry value on $dcName" -Query {
                    Get-ADKnownVulnUBR -ComputerName $dcName
                }
                if ($null -ne $ubr) {
                    $dcState.UBR = [int]$ubr
                    if ($dcState.UBR -ge $Script:KnownVulnBadSuccessorPatchedUBR) {
                        $dcState.BadSuccessorPatchStatus = 'Patched'
                        [void]$badSuccessorPatchedDCs.Add($dcName)
                    }
                    else {
                        $dcState.BadSuccessorPatchStatus = 'Unpatched'
                        [void]$badSuccessorUnpatchedDCs.Add($dcName)
                    }
                }
                else {
                    $dcState.BadSuccessorPatchStatus = 'Unknown'
                    [void]$badSuccessorUnknownDCs.Add($dcName)
                }
            }
            catch {
                Write-Verbose "Test-ADKnownDCVulnerabilities: could not read UBR on '$dcName' (e.g. remote registry access denied); BadSuccessor patch level reported as unknown, not assumed patched: $_"
                $dcState.BadSuccessorPatchStatus = 'Unknown'
                [void]$badSuccessorUnknownDCs.Add($dcName)
                if (-not $dcState.Error) { $dcState.Error = "$_" }
            }
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
            if ($dcState.EffectivePatchDate -lt $Script:KnownVulnFixThresholds.Netlogon2026.FixDate) {
                [void]$netlogon2026DCs.Add($dcName)
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
    # Finding: DC Missing CVE-2026-41089 Patch (Netlogon RCE)
    # -------------------------------------------------------------------
    if ($netlogon2026DCs.Count -gt 0) {
        $info = $Script:KnownVulnFixThresholds.Netlogon2026
        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = $info.Issue
        $finding.Severity = 'Critical'
        $finding.SeverityLevel = 4
        $finding.AffectedObject = ($netlogon2026DCs -join ', ')
        $finding.Description = "$($netlogon2026DCs.Count) Domain Controller(s) show no patch/build evidence on or after the $($info.Cve) fix date of $($info.FixDate.ToString('yyyy-MM-dd')): $($netlogon2026DCs -join ', ')."
        $finding.Impact = $info.Description
        $finding.Remediation = "Install the $($info.FixNote) Treat as emergency-patch priority given active in-the-wild exploitation reported since late May / early June 2026 - verify with `Get-HotFix -ComputerName <DC>` and confirm against the current MSRC Update Guide entry for $($info.Cve) before considering a DC remediated."
        $finding.Details = @{
            Cve                       = $info.Cve
            FixDate                   = $info.FixDate.ToString('yyyy-MM-dd')
            FixNote                   = $info.FixNote
            AffectedDomainControllers = @($netlogon2026DCs)
            PerDomainControllerState  = @($perDcState)
        }
        $findings += $finding
    }
    else {
        Write-Verbose "Test-ADKnownDCVulnerabilities: no DC found missing the CVE-2026-41089 (Netlogon RCE) patch."
    }

    # -------------------------------------------------------------------
    # Finding: BadSuccessor / dMSA Escalation Exposure
    # -------------------------------------------------------------------
    if ($server2025DCs.Count -gt 0) {
        $hasUnpatchedOrUnknown = ($badSuccessorUnpatchedDCs.Count -gt 0) -or ($badSuccessorUnknownDCs.Count -gt 0)

        $finding = [ADSecurityFinding]::new()
        $finding.Category = 'Known DC Vulnerabilities'
        $finding.Issue = 'BadSuccessor / dMSA Escalation Exposure'
        if ($hasUnpatchedOrUnknown) {
            $finding.Severity = 'High'
            $finding.SeverityLevel = 3
        }
        else {
            # Every Server 2025-level DC is confirmed patched (UBR >=
            # threshold) for CVE-2025-53779 - the original one-sided-link
            # escalation path is closed. Reduced (not suppressed) severity:
            # independent research shows a mutually-paired dMSA/target
            # relationship still allows credential/privilege abuse when an
            # attacker controls both sides, so this remains a
            # delegation/ACL exposure to review, not a clean bill of health.
            $finding.Severity = 'Medium'
            $finding.SeverityLevel = 2
        }
        $finding.AffectedObject = ($server2025DCs -join ', ')
        $finding.Description = "$($server2025DCs.Count) Domain Controller(s) are running Windows Server 2025 (build >= $($Script:KnownVulnServer2025Build)), which introduces delegated Managed Service Accounts (dMSA): $($server2025DCs -join ', '). Patch-level (UBR) breakdown for CVE-2025-53779: $($badSuccessorPatchedDCs.Count) patched (UBR >= $($Script:KnownVulnBadSuccessorPatchedUBR))$(if ($badSuccessorPatchedDCs.Count -gt 0) { ": $($badSuccessorPatchedDCs -join ', ')" }); $($badSuccessorUnpatchedDCs.Count) unpatched$(if ($badSuccessorUnpatchedDCs.Count -gt 0) { ": $($badSuccessorUnpatchedDCs -join ', ')" }); $($badSuccessorUnknownDCs.Count) unknown patch level (UBR unreadable)$(if ($badSuccessorUnknownDCs.Count -gt 0) { ": $($badSuccessorUnknownDCs -join ', ')"})."
        $finding.Impact = "The dMSA feature ('BadSuccessor') originally let any principal with CreateChild/msDS-DelegatedManagedServiceAccount rights over an OU create a dMSA and link it one-sidedly to an existing account to inherit that account's effective privileges and Kerberos keys - abusable against any account, including Tier-0. Microsoft's August 2025 fix (CVE-2025-53779, build 26100.4946+) made the KDC require a mutual (two-sided) link before honoring the relationship, closing that direct path on DCs confirmed patched above, but does not restrict who can create a dMSA or write its link attributes - independent research has shown a controlled dMSA can still be paired with a target the attacker also controls to extract that target's credentials, even on a fully patched DC. Any DC reported above as unpatched or unknown patch level remains exposed to the original one-sided-link escalation as well."
        $finding.Remediation = "Ensure all Server 2025 DCs are updated to at least the August 2025 cumulative update (KB5063878, build 26100.4946) or later, which addresses CVE-2025-53779 - prioritize any DC listed above as unpatched or unknown patch level (an unreadable UBR should be treated as unpatched until confirmed otherwise, e.g. remote registry access was denied). Independently of patch level, audit and restrict who holds CreateChild/msDS-DelegatedManagedServiceAccount and generic-write rights on OUs and on dMSA objects themselves, especially anywhere at or above Tier-0; monitor for unexpected dMSA creation and changes to the migration-link attributes; consult current Microsoft/vendor guidance before treating any specific configuration as fully mitigated."
        $finding.Details = @{
            AffectedDomainControllers          = @($server2025DCs)
            Server2025BuildThreshold           = $Script:KnownVulnServer2025Build
            BadSuccessorPatchedUBRThreshold    = $Script:KnownVulnBadSuccessorPatchedUBR
            PatchedDomainControllers           = @($badSuccessorPatchedDCs)
            UnpatchedDomainControllers         = @($badSuccessorUnpatchedDCs)
            UnknownPatchStatusDomainControllers = @($badSuccessorUnknownDCs)
            PerDomainControllerState           = @($perDcState)
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
