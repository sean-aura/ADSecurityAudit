#Requires -Modules Pester
<#
    Unit tests for Invoke-ADRuleSet's test-coverage tracking
    (Add-ADTestCoverageEntry / Get-ADTestCoverageTracker / Reset-ADTestCoverageTracker
    in Common.ps1).

    Reported gap: -FromSnapshot mode dispatches tests through
    Invoke-ADRuleSet, a completely separate code path from Main.ps1's live
    test loop (which is what originally got Test Coverage tracking). The
    $testCoverage variable Main.ps1 passes to Export-ADSecurityReportHTML
    was simply never assigned on the -FromSnapshot branch - an undefined
    PowerShell variable reads as $null, and passing that as -TestCoverage
    hit the documented "@($null) has Count 1" quirk (see
    ConvertTo-ADFlatFindingsArray's own docs): the Test Coverage section's
    gate (Count -gt 0) came out true, while its actual per-row data (built
    via Sort-Object, which silently drops a $null element) came out
    empty - rendering a nonsensical "0 check(s) tracked: 0 passed clean,
    0 found issue(s), and 0 untested" box on every single -FromSnapshot
    report.

    Fixed by having Invoke-ADRuleSet itself record each test's outcome via
    the same tracker pattern already used for Offline-Skip-Notes
    (Add-ADOfflineSkipNote/Get-ADOfflineSkipNotes/Reset-ADOfflineSkipNotes),
    and having Main.ps1's -FromSnapshot branch read it back into
    $testCoverage after calling Invoke-ADRuleSet.

    These tests replace $Script:ADTestFunctionRegistry with a small fake
    registry (of locally-defined fake Test-* functions) so the coverage-
    tracking LOGIC can be verified without touching real Active Directory
    or the real 28-test registry.

    Run from the repo root:  Invoke-Pester ./tests/InvokeADRuleSet.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Snapshot.ps1')

    function Test-CoverageFixtureClean { param($Snapshot) return @([PSCustomObject]@{ Category = 'X'; Issue = 'Found something'; Severity = 'Low'; SeverityLevel = 1 }) }
    function Test-CoverageFixtureEmpty { param($Snapshot) return @() }
    function Test-CoverageFixtureFails { param($Snapshot) throw 'Simulated failure' }
    function Test-CoverageFixtureNoSnapshotParam { param($NotSnapshot) return @() }

    $script:FakeRegistry = [ordered]@{
        'FixtureFound'      = 'Test-CoverageFixtureClean'
        'FixtureClean'      = 'Test-CoverageFixtureEmpty'
        'FixtureFails'      = 'Test-CoverageFixtureFails'
        'FixtureNoSnapshot' = 'Test-CoverageFixtureNoSnapshotParam'
        'FixtureExcluded'   = 'Test-CoverageFixtureEmpty'
    }
}

Describe 'Invoke-ADRuleSet - test coverage tracking' {
    BeforeEach {
        $Script:ADTestFunctionRegistry = $script:FakeRegistry
        Reset-ADTestCoverageTracker
        Reset-ADOfflineSkipNotes
    }

    It 'records every registered test, not just the ones that ran' {
        Invoke-ADRuleSet -Snapshot @{} -ExcludeTests @('FixtureExcluded') -WarningAction SilentlyContinue | Out-Null
        $coverage = Get-ADTestCoverageTracker
        $coverage.Count | Should -Be 5
        ($coverage.TestName | Sort-Object) | Should -Be @('FixtureClean', 'FixtureExcluded', 'FixtureFails', 'FixtureFound', 'FixtureNoSnapshot')
    }

    It 'marks a test that ran and found something as Completed with the right FindingCount' {
        Invoke-ADRuleSet -Snapshot @{} -IncludeTests @('FixtureFound') -WarningAction SilentlyContinue | Out-Null
        $entry = (Get-ADTestCoverageTracker) | Where-Object TestName -eq 'FixtureFound'
        $entry.Status | Should -Be 'Completed'
        $entry.FindingCount | Should -Be 1
        $entry.ErrorMessage | Should -BeNullOrEmpty
    }

    It 'marks a test that ran clean (no findings) as Completed with FindingCount 0 - not Excluded' {
        Invoke-ADRuleSet -Snapshot @{} -IncludeTests @('FixtureClean') -WarningAction SilentlyContinue | Out-Null
        $entry = (Get-ADTestCoverageTracker) | Where-Object TestName -eq 'FixtureClean'
        $entry.Status | Should -Be 'Completed'
        $entry.FindingCount | Should -Be 0
    }

    It 'marks a test that threw an exception as Failed, with the error captured' {
        Invoke-ADRuleSet -Snapshot @{} -IncludeTests @('FixtureFails') -WarningAction SilentlyContinue | Out-Null
        $entry = (Get-ADTestCoverageTracker) | Where-Object TestName -eq 'FixtureFails'
        $entry.Status | Should -Be 'Failed'
        $entry.ErrorMessage | Should -Match 'Simulated failure'
    }

    It 'marks a test with no -Snapshot parameter as Excluded (not run live by default)' {
        Invoke-ADRuleSet -Snapshot @{} -IncludeTests @('FixtureNoSnapshot') -WarningAction SilentlyContinue | Out-Null
        $entry = (Get-ADTestCoverageTracker) | Where-Object TestName -eq 'FixtureNoSnapshot'
        $entry.Status | Should -Be 'Excluded'
        $entry.ErrorMessage | Should -Match 'no -Snapshot support'
    }

    It 'marks a test excluded via -ExcludeTests as Excluded, without ever attempting to run it' {
        Invoke-ADRuleSet -Snapshot @{} -ExcludeTests @('FixtureExcluded') -WarningAction SilentlyContinue | Out-Null
        $entry = (Get-ADTestCoverageTracker) | Where-Object TestName -eq 'FixtureExcluded'
        $entry.Status | Should -Be 'Excluded'
        $entry.ErrorMessage | Should -Match 'IncludeTests|ExcludeTests'
    }

    It 'produces a real, non-degenerate Test Coverage section when fed into Export-ADSecurityReportHTML (regression for the reported "0 check(s) tracked" bug)' {
        . (Join-Path $root 'src/Scoring.ps1')
        . (Join-Path $root 'src/Reporting.ps1')

        $findings = Invoke-ADRuleSet -Snapshot @{} -ExcludeTests @('FixtureExcluded') -WarningAction SilentlyContinue
        $coverage = Get-ADTestCoverageTracker

        $outPath = Join-Path $TestDrive 'snapshot-coverage.html'
        Export-ADSecurityReportHTML -Findings @($findings) -OutputPath $outPath -Domain 'contoso.com' `
            -Summary @{ Critical = 0; High = 0; Medium = 0; Low = 1 } -Duration ([timespan]::Zero) `
            -RiskScore (Get-ADRiskScore -Findings @($findings)) -RunMode 'Offline (Snapshot)' -TestCoverage $coverage

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match '5 check\(s\) tracked'
        $content | Should -Not -Match '0 check\(s\) tracked'
        $content | Should -Match '1 found issue'
        $content | Should -Match '3 untested'
    }
}
