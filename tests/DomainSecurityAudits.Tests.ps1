#Requires -Modules Pester
<#
    Unit tests for the two new forest-level findings added to
    Test-ADDomainSecurity in src/DomainSecurityAudits.ps1:
      - "Outdated Forest Functional Level"
      - "Short Tombstone Lifetime"

    Snapshot-mode tests exercise Snapshot.Forest.ForestMode and
    Snapshot.TombstoneLifetimeDays directly. Live-mode tests shadow every
    live AD cmdlet the function touches: Get-ADDomain,
    Get-ADDefaultDomainPasswordPolicy, Get-ADForest, Get-ADRootDSE,
    Get-ADObject, Get-ADOptionalFeature, Get-ADComputer. No real Active
    Directory access is used.

    Run from the repo root:  Invoke-Pester ./tests/DomainSecurityAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainSecurityAudits.ps1')
}

Describe 'Test-ADDomainSecurity (Outdated Forest Functional Level / Short Tombstone Lifetime) - Snapshot mode' {
    function New-BaseSnapshot {
        @{
            PasswordPolicy      = @{ MinPasswordLength = 14; ComplexityEnabled = $true; ReversibleEncryptionEnabled = $false }
            Domain              = [PSCustomObject]@{ DomainMode = 'Windows2016Domain' }
            Forest              = @{ ForestMode = 'Windows2016Forest' }
            RecycleBinEnabled   = $true
            TombstoneLifetimeDays = 180
        }
    }

    It 'produces no forest-functional-level finding for a current forest mode' {
        $snapshot = New-BaseSnapshot
        $findings = Test-ADDomainSecurity -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Outdated Forest Functional Level' }) | Should -BeNullOrEmpty
    }

    It 'fires Medium when the forest functional level is deprecated, independent of a current domain level' {
        $snapshot = New-BaseSnapshot
        $snapshot.Forest.ForestMode = 'Windows2008R2Forest'
        $findings = Test-ADDomainSecurity -Snapshot $snapshot
        $finding = $findings | Where-Object { $_.Issue -eq 'Outdated Forest Functional Level' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Category | Should -Be 'Domain Security'
        $finding.Severity | Should -Be 'Medium'
        $finding.SeverityLevel | Should -Be 2
        $finding.Details.CurrentLevel | Should -Be 'Windows2008R2Forest'
        # Domain-level finding must NOT also fire - domain mode is current in this fixture
        ($findings | Where-Object { $_.Issue -eq 'Outdated Domain Functional Level' }) | Should -BeNullOrEmpty
    }

    It 'produces no tombstone-lifetime finding at exactly the 180-day recommended minimum' {
        $snapshot = New-BaseSnapshot
        $snapshot.TombstoneLifetimeDays = 180
        $findings = Test-ADDomainSecurity -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }) | Should -BeNullOrEmpty
    }

    It 'fires Low when tombstone lifetime is the legacy 60-day default' {
        $snapshot = New-BaseSnapshot
        $snapshot.TombstoneLifetimeDays = 60
        $findings = Test-ADDomainSecurity -Snapshot $snapshot
        $finding = $findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Low'
        $finding.SeverityLevel | Should -Be 1
        $finding.Details.CurrentValueDays | Should -Be 60
        $finding.Details.RecommendedMinimumDays | Should -Be 180
    }

    It 'skips the tombstone-lifetime check without throwing when the snapshot predates this field' {
        $snapshot = New-BaseSnapshot
        $snapshot.Remove('TombstoneLifetimeDays')
        { Test-ADDomainSecurity -Snapshot $snapshot } | Should -Not -Throw
        $findings = Test-ADDomainSecurity -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Short Tombstone Lifetime' }) | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDomainSecurity (Outdated Forest Functional Level / Short Tombstone Lifetime) - Live mode' {
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
