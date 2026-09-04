#Requires -Modules Pester
<#
    Unit tests for the two new forest-level findings added to
    Test-ADDomainSecurity in src/DomainSecurityAudits.ps1:
      - "Outdated Forest Functional Level"
      - "Short Tombstone Lifetime"

    These tests shadow every live AD cmdlet the function touches:
    Get-ADDomain, Get-ADDefaultDomainPasswordPolicy, Get-ADForest,
    Get-ADRootDSE, Get-ADObject, Get-ADOptionalFeature, Get-ADComputer. No
    real Active Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/DomainSecurityAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainSecurityAudits.ps1')
}

Describe 'Test-ADDomainSecurity (Outdated Forest Functional Level / Short Tombstone Lifetime)' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com'; DomainMode = 'Windows2016Domain'; NetBIOSName = 'CONTOSO'; DomainSID = 'S-1-5-21-1-2-3'; Forest = 'contoso.com' }
        }
        function Get-ADDefaultDomainPasswordPolicy {
            param($Server)
            [PSCustomObject]@{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false }
        }
        function Get-ADForest {
            param($Server)
            [PSCustomObject]@{ ForestMode = 'Windows2016Forest' }
        }
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com' }
        }
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            [PSCustomObject]@{ tombstoneLifetime = 180 }
        }
        function Get-ADOptionalFeature {
            param($Filter, $Server)
            [PSCustomObject]@{ EnabledScopes = @('CN=Configuration,DC=contoso,DC=com') }
        }
        function Get-ADComputer {
            param($Filter, $Properties, $LDAPFilter, $Server)
            @()
        }
    }

    It 'fires Outdated Forest Functional Level live when the forest mode is deprecated' {
        function Get-ADForest { param($Server) [PSCustomObject]@{ ForestMode = 'Windows2012R2Forest' } }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Outdated Forest Functional Level' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.CurrentLevel | Should -Be 'Windows2012R2Forest'
    }

    It 'fires Short Tombstone Lifetime live when the Directory Service object has no explicit value (60-day default)' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            [PSCustomObject]@{ tombstoneLifetime = $null }
        }

        $findings = Test-ADDomainSecurity
        $finding = $findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.Details.CurrentValueDays | Should -Be 60
    }

    It 'does not throw and produces no tombstone finding if the Directory Service object read fails' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            throw "access denied"
        }

        { Test-ADDomainSecurity } | Should -Not -Throw
        $findings = Test-ADDomainSecurity
        ($findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }) | Should -BeNullOrEmpty
    }
}
