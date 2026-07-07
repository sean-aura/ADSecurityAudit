#Requires -Modules Pester
<#
    Unit tests for Test-ADDomainHardeningFlags (feature 04).

    All tests run in snapshot mode, which never touches Active Directory
    and never performs the live anonymous-bind network probe (that probe is
    intentionally skipped whenever -Snapshot is supplied - see the
    -FromSnapshot "no live AD/network access" contract in Snapshot.ps1).

    Run from the repo root:  Invoke-Pester ./tests/DomainHardeningFlags.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainHardeningAudits.ps1')
}

Describe 'Test-ADDomainHardeningFlags (dSHeuristics)' {
    It 'flags anonymous access when character 7 is 2' {
        $snapshot = @{
            DsHeuristics      = '0000002'
            PreWin2000Members = @()
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Dangerous dsHeuristics Flag Set'
        $findings[0].Severity | Should -Be 'High'
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 7 }).Count | Should -Be 1
    }

    It 'flags List Object mode when character 1 is 1' {
        $snapshot = @{
            DsHeuristics      = '1'
            PreWin2000Members = @()
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 1
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 1 }).Count | Should -Be 1
    }

    It 'flags AdminSDHolder exclusion mask weakening when character 16 is non-zero' {
        $snapshot = @{
            DsHeuristics      = '000000000000000f'
            PreWin2000Members = @()
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 1
        ($findings[0].Details.FlaggedPositions | Where-Object { $_.Position -eq 16 }).Count | Should -Be 1
    }

    It 'produces no finding for a benign dsHeuristics value' {
        $snapshot = @{
            DsHeuristics      = '0000000'
            PreWin2000Members = @()
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 0
    }

    It 'produces no finding when dSHeuristics is not set' {
        $snapshot = @{
            DsHeuristics      = $null
            PreWin2000Members = @()
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 0
    }
}

Describe 'Test-ADDomainHardeningFlags (Pre-Windows 2000 Compatible Access)' {
    It 'flags Authenticated Users membership as High' {
        $snapshot = @{
            DsHeuristics      = $null
            PreWin2000GroupDN = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=contoso,DC=com'
            PreWin2000Members = @('CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com')
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 1
        $findings[0].Issue | Should -Be 'Broad Membership in Pre-Windows 2000 Compatible Access'
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Details.BroadPrincipals | Should -Contain 'Authenticated Users'
    }

    It 'does not fire for narrow/legitimate members' {
        $snapshot = @{
            DsHeuristics      = $null
            PreWin2000GroupDN = 'CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=contoso,DC=com'
            PreWin2000Members = @('CN=legacy-svc,OU=ServiceAccounts,DC=contoso,DC=com')
        }
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings.Count | Should -Be 0
    }
}

Describe 'Test-ADDomainHardeningFlags (offline mode skips the anonymous-bind probe)' {
    It 'never attempts the live anonymous-bind probe when -Snapshot is supplied' {
        # No Get-ADDomainController shadow function is defined, so if the
        # function attempted the live probe it would throw (or a warning
        # would surface). Passing a Snapshot must short-circuit that path.
        $snapshot = @{
            DsHeuristics      = '0000000'
            PreWin2000Members = @()
        }
        { Test-ADDomainHardeningFlags -Snapshot $snapshot } | Should -Not -Throw
        $findings = Test-ADDomainHardeningFlags -Snapshot $snapshot
        $findings | Where-Object { $_.Issue -eq 'Anonymous LDAP / RootDSE Binding Permitted' } | Should -BeNullOrEmpty
    }
}
