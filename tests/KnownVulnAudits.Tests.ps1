#Requires -Modules Pester
<#
    Unit tests for Test-ADKnownDCVulnerabilities (features 16 and 17).

    Test-ADKnownDCVulnerabilities is live-only (no -Snapshot equivalent for
    per-DC OS build/hotfix/UBR/service state), so every test here shadows
    Get-ADDomainController, Get-CimInstance, Get-HotFix, Get-Service, and
    Get-ADKnownVulnUBR with local functions - no real AD module,
    connectivity, or remote registry access is required.

    Run from the repo root:  Invoke-Pester ./tests/KnownVulnAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/KnownVulnAudits.ps1')
}

Describe 'Test-ADKnownDCVulnerabilities (-Snapshot contract)' {
    It 'returns no findings and performs no live access when -Snapshot is supplied' {
        $findings = Test-ADKnownDCVulnerabilities -Snapshot @{ Domain = 'placeholder' }
        $findings.Count | Should -Be 0
    }
}

Describe 'Test-ADKnownDCVulnerabilities / CVE-2026-41089 (Netlogon RCE)' {
    BeforeEach {
        function Get-ADDomainController { param($Filter) @([PSCustomObject]@{ HostName = 'dc1.contoso.com' }) }
        function Get-Service { param($ComputerName, $Name) [PSCustomObject]@{ Status = 'Stopped' } }
        function Get-ADKnownVulnUBR { param($ComputerName) $null }
    }

    It 'flags a DC whose latest hotfix predates the May 12, 2026 fix date' {
        function Get-CimInstance { param($ComputerName, $ClassName) [PSCustomObject]@{ Caption = 'Windows Server 2022'; BuildNumber = '20348'; InstallDate = (Get-Date '2024-01-01') } }
        function Get-HotFix { param($ComputerName) @([PSCustomObject]@{ InstalledOn = (Get-Date '2026-03-01') }) }

        $findings = Test-ADKnownDCVulnerabilities
        $netlogonFinding = $findings | Where-Object { $_.Issue -eq 'DC Missing CVE-2026-41089 Patch (Netlogon RCE)' }
        $netlogonFinding | Should -Not -BeNullOrEmpty
        $netlogonFinding.Severity | Should -Be 'Critical'
        $netlogonFinding.Details.AffectedDomainControllers | Should -Contain 'dc1.contoso.com'
    }

    It 'does not flag a DC whose latest hotfix is on/after the fix date' {
        function Get-CimInstance { param($ComputerName, $ClassName) [PSCustomObject]@{ Caption = 'Windows Server 2022'; BuildNumber = '20348'; InstallDate = (Get-Date '2024-01-01') } }
        function Get-HotFix { param($ComputerName) @([PSCustomObject]@{ InstalledOn = (Get-Date '2026-05-12') }) }

        $findings = Test-ADKnownDCVulnerabilities
        ($findings | Where-Object { $_.Issue -eq 'DC Missing CVE-2026-41089 Patch (Netlogon RCE)' }) | Should -BeNullOrEmpty
    }

    It 'is unaffected by, and does not affect, the existing ZeroLogon/MS17-010/MS14-068 checks' {
        function Get-CimInstance { param($ComputerName, $ClassName) [PSCustomObject]@{ Caption = 'Windows Server 2016'; BuildNumber = '14393'; InstallDate = (Get-Date '2015-01-01') } }
        function Get-HotFix { param($ComputerName) @([PSCustomObject]@{ InstalledOn = (Get-Date '2015-01-01') }) }

        $findings = Test-ADKnownDCVulnerabilities
        ($findings | Where-Object { $_.Issue -eq 'DC Missing ZeroLogon Patch' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'DC Vulnerable to MS17-010' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'DC Vulnerable to MS14-068' }) | Should -Not -BeNullOrEmpty
        ($findings | Where-Object { $_.Issue -eq 'DC Missing CVE-2026-41089 Patch (Netlogon RCE)' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-ADKnownDCVulnerabilities / BadSuccessor UBR patch-level classification' {
    BeforeEach {
        function Get-ADDomainController { param($Filter) @([PSCustomObject]@{ HostName = 'dc1.contoso.com' }) }
        function Get-HotFix { param($ComputerName) @([PSCustomObject]@{ InstalledOn = (Get-Date '2026-06-01') }) }
        function Get-Service { param($ComputerName, $Name) [PSCustomObject]@{ Status = 'Stopped' } }
        function Get-CimInstance { param($ComputerName, $ClassName) [PSCustomObject]@{ Caption = 'Windows Server 2025'; BuildNumber = '26100'; InstallDate = (Get-Date '2026-06-01') } }
    }

    It 'classifies a DC at the exact patch boundary (UBR 4946) as Patched' {
        function Get-ADKnownVulnUBR { param($ComputerName) 4946 }
        $findings = Test-ADKnownDCVulnerabilities
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f.Details.PatchedDomainControllers | Should -Contain 'dc1.contoso.com'
        $f.Details.UnpatchedDomainControllers | Should -BeNullOrEmpty
    }

    It 'classifies a DC below the patch boundary (UBR 4945) as Unpatched' {
        function Get-ADKnownVulnUBR { param($ComputerName) 4945 }
        $findings = Test-ADKnownDCVulnerabilities
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f.Details.UnpatchedDomainControllers | Should -Contain 'dc1.contoso.com'
        $f.Details.PatchedDomainControllers | Should -BeNullOrEmpty
    }

    It 'classifies a DC well above the patch boundary (UBR 6584) as Patched' {
        function Get-ADKnownVulnUBR { param($ComputerName) 6584 }
        $findings = Test-ADKnownDCVulnerabilities
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f.Details.PatchedDomainControllers | Should -Contain 'dc1.contoso.com'
    }

    It 'reports Unknown (not Patched) when the UBR registry read fails, and does not silently misclassify' {
        function Get-ADKnownVulnUBR { param($ComputerName) throw 'Access is denied' }
        $findings = Test-ADKnownDCVulnerabilities -WarningAction SilentlyContinue
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f.Details.UnknownPatchStatusDomainControllers | Should -Contain 'dc1.contoso.com'
        $f.Details.PatchedDomainControllers | Should -BeNullOrEmpty
        $f.Details.UnpatchedDomainControllers | Should -BeNullOrEmpty
    }

    It 'reduces (but does not suppress) severity to Medium once every Server 2025 DC is confirmed patched' {
        function Get-ADKnownVulnUBR { param($ComputerName) 5000 }
        $findings = Test-ADKnownDCVulnerabilities
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity | Should -Be 'Medium'
    }

    It 'keeps High severity when at least one Server 2025 DC is unpatched or unknown' {
        function Get-ADKnownVulnUBR { param($ComputerName) 1000 }
        $findings = Test-ADKnownDCVulnerabilities
        $f = $findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }
        $f.Severity | Should -Be 'High'
    }

    It 'does not read UBR at all for a pre-Server-2025 DC (base-build guard unaffected)' {
        function Get-CimInstance { param($ComputerName, $ClassName) [PSCustomObject]@{ Caption = 'Windows Server 2022'; BuildNumber = '20348'; InstallDate = (Get-Date '2026-06-01') } }
        function Get-ADKnownVulnUBR { param($ComputerName) throw 'should not be called' }
        $findings = Test-ADKnownDCVulnerabilities
        ($findings | Where-Object { $_.Issue -eq 'BadSuccessor / dMSA Escalation Exposure' }) | Should -BeNullOrEmpty
    }
}
