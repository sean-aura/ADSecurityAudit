#Requires -Modules Pester
<#
    Unit tests for Test-ADCSChaseFallback (CVE-2026-54121 / "Certighost"
    CA chase-fallback exposure), added as a new sibling function in
    src/CertificateServicesExtendedAudits.ps1.

    Like the existing ESC8 check, this is live-only: it reads a registry
    value (policy\EditFlags) on the CA host itself via Invoke-Command. These
    tests shadow every live cmdlet it touches: Get-ADRootDSE (via
    Get-ADRootDSEValue), Get-ADObject, and Invoke-Command. No real Active
    Directory, CA host, or network access is used - Invoke-Command's
    -ScriptBlock is invoked directly against a fake registry-shaped object
    rather than actually running remotely.

    Run from the repo root:  Invoke-Pester ./tests/ADCSChaseFallback.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')
}

Describe 'Test-ADCSChaseFallback (CVE-2026-54121 / Certighost)' {
    BeforeEach {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, [string]$Server)
            [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
        }
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Properties, $Server, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    Name              = 'CONTOSO-CA'
                    DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    dNSHostName       = 'ca01.contoso.com'
                }
            )
        }
    }

    It 'produces no finding when EDITF_ENABLECHASECLIENTDC is not set' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # EditFlags with only EDITF_ATTRIBUTESUBJECTALTNAME2 (0x40000) set -
            # chase-client-dc bit (0x100000) absent.
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x40000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        ($findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }) | Should -BeNullOrEmpty
    }

    It 'fires Critical when EDITF_ENABLECHASECLIENTDC is set, naming the CA and citing the CVE' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            # EDITF_ENABLECHASECLIENTDC (0x100000) set, alongside other
            # unrelated flags - matches a realistic EditFlags value.
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x15014e -bor 0x100000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $finding = $findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Category | Should -Be 'Certificate Services'
        $finding.Severity | Should -Be 'Critical'
        $finding.SeverityLevel | Should -Be 4
        $finding.AffectedObject | Should -Match 'CONTOSO-CA'
        $finding.AffectedObject | Should -Match 'ca01.contoso.com'
        $finding.Description | Should -Match 'EDITF_ENABLECHASECLIENTDC'
        $finding.Impact | Should -Match 'CVE-2026-54121'
        $finding.Remediation | Should -Match 'certutil'
        $finding.Remediation | Should -Match 'July 14, 2026'
        $finding.Details.CVE | Should -Be 'CVE-2026-54121'
        $finding.Details.CAHost | Should -Be 'ca01.contoso.com'
    }

    It 'still fires when the flag is set even if the CA host reports no error (patched-but-still-flagged case)' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $true; EditFlags = 0x100000; Error = $null }
        }

        $findings = Test-ADCSChaseFallback
        $finding = $findings | Where-Object { $_.Issue -eq 'CA Chase-Fallback Enabled (CVE-2026-54121 / Certighost Exposure)' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Impact | Should -Match 'independent of the CA''s patch level'
    }

    It 'skips a CA with no dNSHostName without throwing' {
        function Get-ADObject {
            param($SearchBase, $SearchScope, $Filter, $Properties, $Server, [switch]$ErrorAction)
            @(
                [PSCustomObject]@{
                    Name              = 'CONTOSO-CA'
                    DistinguishedName = 'CN=CONTOSO-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=com'
                    dNSHostName       = $null
                }
            )
        }
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            throw "should not be called - CA has no dNSHostName"
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'produces no finding and does not throw when the registry read fails/errors on the CA host' {
        function Invoke-Command {
            param($ComputerName, [switch]$ErrorAction, $ScriptBlock, $ArgumentList)
            [PSCustomObject]@{ EditFlagsRead = $false; EditFlags = $null; Error = 'CertSvc policy module registry key not found.' }
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }

    It 'returns no findings when AD CS is not installed (live path)' {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, [string]$Server)
            throw "AD CS not present"
        }

        { Test-ADCSChaseFallback } | Should -Not -Throw
        $findings = Test-ADCSChaseFallback
        $findings | Should -BeNullOrEmpty
    }
}
