#Requires -Modules Pester
<#
    Unit tests for Test-ADMachineAccountQuota (feature 03).

    The snapshot-mode tests do NOT touch Active Directory. The live-mode
    tests shadow Get-ADDomain / Get-ADObject with local functions so no real
    AD module or connectivity is required.

    Run from the repo root:  Invoke-Pester ./tests/MachineAccountQuota.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/MachineAccountQuotaAudits.ps1')
}

Describe 'Test-ADMachineAccountQuota (snapshot mode)' {
    It 'flags the unmodified default quota of 10 as High' {
        $snapshot = @{
            Domain              = [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' }
            MachineAccountQuota = 10
        }
        $findings = Test-ADMachineAccountQuota -Snapshot $snapshot
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Default Machine Account Quota Not Restricted'
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Details.MachineAccountQuota | Should -Be 10
    }

    It 'flags a lowered but non-zero quota as Medium' {
        $snapshot = @{
            Domain              = [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' }
            MachineAccountQuota = 3
        }
        $findings = Test-ADMachineAccountQuota -Snapshot $snapshot
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Non-Zero Machine Account Quota'
        $findings[0].Severity | Should -Be 'Medium'
    }

    It 'produces no finding when the quota is hardened to 0' {
        $snapshot = @{
            Domain              = [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' }
            MachineAccountQuota = 0
        }
        $findings = Test-ADMachineAccountQuota -Snapshot $snapshot
        $findings.Count | Should -Be 0
    }

    It 'coerces a string quota value from a JSON round-trip' {
        $snapshot = @{
            Domain              = [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' }
            MachineAccountQuota = '10'
        }
        $findings = Test-ADMachineAccountQuota -Snapshot $snapshot
        $findings[0].Details.MachineAccountQuota | Should -Be 10
    }

    It 'falls back to a live query when the snapshot has no MachineAccountQuota key' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 10 } }

        $findings = Test-ADMachineAccountQuota -Snapshot @{ Domain = $null }
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'High'
    }
}

Describe 'Test-ADMachineAccountQuota (live mode)' {
    It 'queries AD directly when no snapshot is supplied' {
        function Get-ADDomain { [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com' } }
        function Get-ADObject { param($Identity, $Properties) [PSCustomObject]@{ 'ms-DS-MachineAccountQuota' = 0 } }

        $findings = Test-ADMachineAccountQuota
        $findings.Count | Should -Be 0
    }
}
