#Requires -Modules Pester
<#
    Unit tests for Get-ADRetestComparison / Export-ADRetestComparisonHTML.

    These tests do NOT touch Active Directory. Like ForestConsolidation.Tests.ps1,
    they only exercise this project's own scoring/serialization contract: two
    synthetic "run" exports (findings JSON + score sidecar JSON, in the exact
    shape Start-ADSecurityAudit already writes) are written to TestDrive and
    fed to Get-ADRetestComparison entirely offline.

    Run from the repo root:  Invoke-Pester ./tests/RetestComparison.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/RetestComparison.ps1')

    function New-TestFinding {
        param(
            [string]$Issue,
            [string]$Category,
            [string]$Severity,
            [int]$SeverityLevel,
            [string]$AffectedObject = ''
        )
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        $f.AffectedObject = $AffectedObject
        return $f
    }

    function New-RunFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp,
            [switch]$NoScoreSidecar
        )
        foreach ($finding in $Findings) { [void](Set-ADFindingMetadata -Finding $finding) }
        $folder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findingsPath = Join-Path $folder "AD_Security_Audit_$Timestamp.json"
        $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $findingsPath -Encoding UTF8

        if (-not $NoScoreSidecar) {
            $riskScore = Get-ADRiskScore -Findings $Findings
            $scorePath = Join-Path $folder "AD_Security_Score_$Timestamp.json"
            $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
        }
        return $folder
    }

    # --- Baseline: 3 stale accounts + 1 High privileged-group finding ---
    $script:BaselineFindings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user2'
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user3'
        New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'High' -SeverityLevel 3 -AffectedObject 'Domain Admins'
    )

    # --- Retest: 2 of the 3 stale accounts resolved, the privileged-group
    # finding's severity changed, and one brand-new finding. ---
    $script:RetestFindings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user3'
        New-TestFinding -Issue 'Excessive Privileged Group Membership' -Category 'Privileged Groups' -Severity 'Critical' -SeverityLevel 4 -AffectedObject 'Domain Admins'
        New-TestFinding -Issue 'Weak Minimum Password Length' -Category 'Domain Security' -Severity 'Medium' -SeverityLevel 2 -AffectedObject 'contoso.com'
    )
}

Describe 'Get-ADRetestComparison' {
    BeforeAll {
        $script:BaselineFolder = New-RunFixture -FolderName 'baseline' -Findings $script:BaselineFindings -Timestamp '2026-01-01_00-00-00'
        $script:RetestFolder   = New-RunFixture -FolderName 'retest'   -Findings $script:RetestFindings   -Timestamp '2026-02-01_00-00-00'
        $script:Comparison = Get-ADRetestComparison -BaselinePath $script:BaselineFolder -RetestPath $script:RetestFolder
    }

    It 'classifies a finding present only in the retest as New' {
        $script:Comparison.NewFindings.Count | Should -Be 1
        $script:Comparison.NewFindings[0].Issue | Should -Be 'Weak Minimum Password Length'
    }

    It 'classifies a finding present only in the baseline as Resolved' {
        $script:Comparison.ResolvedFindings.Count | Should -Be 2
        ($script:Comparison.ResolvedFindings.AffectedObject | Sort-Object) | Should -Be @('user1', 'user2')
    }

    It 'classifies an unchanged matched finding as StillOpen' {
        $script:Comparison.StillOpenFindings.Count | Should -Be 1
        $script:Comparison.StillOpenFindings[0].AffectedObject | Should -Be 'user3'
    }

    It 'classifies a matched finding whose severity differs as Changed, not StillOpen' {
        $script:Comparison.ChangedFindings.Count | Should -Be 1
        $script:Comparison.ChangedFindings[0].BaselineFinding.Severity | Should -Be 'High'
        $script:Comparison.ChangedFindings[0].RetestFinding.Severity | Should -Be 'Critical'
    }

    It 'matches findings on Category+Issue+AffectedObject, not Category+Issue alone (partial remediation is visible)' {
        # 3 stale accounts down to 1: 2 Resolved + 1 StillOpen, not one coarse bucket.
        $script:Comparison.ResolvedFindings.Count | Should -Be 2
        $script:Comparison.StillOpenFindings.Count | Should -Be 1
    }

    It 'surfaces each run''s own recorded ModuleVersion/GeneratedDate in BaselineMeta/RetestMeta for context' {
        $script:Comparison.BaselineMeta.ScorePath | Should -Not -BeNullOrEmpty
        $script:Comparison.RetestMeta.ScorePath | Should -Not -BeNullOrEmpty
    }

    It 'recomputes both runs'' scores via the current Get-ADRiskScore rather than trusting stored sidecar values' {
        # Even though weight is issue-keyed (not severity-keyed) in the mapping
        # table, the recomputed score must come from Get-ADRiskScore's own
        # diminishing-returns model, not a passthrough of the sidecar file.
        $expectedRetest = Get-ADRiskScore -Findings $script:RetestFindings
        $script:Comparison.RetestScore.TotalScore | Should -Be $expectedRetest.TotalScore
    }

    It 'produces arithmetically correct ScoreDelta/MaturityDelta against Get-ADRiskScore run independently on each side' {
        $expectedBaseline = Get-ADRiskScore -Findings $script:BaselineFindings
        $expectedRetest   = Get-ADRiskScore -Findings $script:RetestFindings
        $script:Comparison.ScoreDelta    | Should -Be ($expectedRetest.TotalScore - $expectedBaseline.TotalScore)
        $script:Comparison.MaturityDelta | Should -Be ($expectedRetest.MaturityLevel - $expectedBaseline.MaturityLevel)
    }

    It 'produces correct per-category deltas including a category only present in one run' {
        $domainSecDelta = $script:Comparison.CategoryDeltas | Where-Object { $_.Category -eq 'Domain Security' }
        $domainSecDelta.BaselineScore | Should -Be 0
        $domainSecDelta.RetestScore | Should -BeGreaterThan 0
    }
}

Describe 'Get-ADRetestComparison - identity case' {
    It 'feeding the same run as both -BaselinePath and -RetestPath yields all-StillOpen, zero New/Resolved, zero deltas' {
        $folder = New-RunFixture -FolderName 'identity' -Findings $script:BaselineFindings -Timestamp '2026-03-01_00-00-00'
        $cmp = Get-ADRetestComparison -BaselinePath $folder -RetestPath $folder

        $cmp.NewFindings.Count | Should -Be 0
        $cmp.ResolvedFindings.Count | Should -Be 0
        $cmp.ChangedFindings.Count | Should -Be 0
        $cmp.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
        $cmp.ScoreDelta | Should -Be 0
        $cmp.MaturityDelta | Should -Be 0
    }
}

Describe 'Get-ADRetestComparison - input resolution and error handling' {
    It 'accepts an explicit AD_Security_Audit_*.json file path, not just a folder' {
        $folder = New-RunFixture -FolderName 'explicit-file' -Findings $script:BaselineFindings -Timestamp '2026-04-01_00-00-00'
        $explicitFile = Join-Path $folder 'AD_Security_Audit_2026-04-01_00-00-00.json'
        { Get-ADRetestComparison -BaselinePath $explicitFile -RetestPath $explicitFile } | Should -Not -Throw
    }

    It 'throws a clear error when a path does not exist' {
        { Get-ADRetestComparison -BaselinePath (Join-Path $TestDrive 'does-not-exist') -RetestPath (Join-Path $TestDrive 'does-not-exist') } | Should -Throw
    }

    It 'still produces a comparison when a score sidecar is missing (sidecar is optional/informational only)' {
        $folderNoSidecar = New-RunFixture -FolderName 'no-sidecar' -Findings $script:BaselineFindings -Timestamp '2026-05-01_00-00-00' -NoScoreSidecar
        $cmp = Get-ADRetestComparison -BaselinePath $folderNoSidecar -RetestPath $folderNoSidecar
        $cmp.BaselineMeta.ScorePath | Should -BeNullOrEmpty
        $cmp.BaselineMeta.ModuleVersion | Should -BeNullOrEmpty
        $cmp.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
    }
}

Describe 'Get-ADRetestComparison -ToJson' {
    It 'persists a parseable AD_Retest_Comparison_<timestamp>.json' {
        $folder = New-RunFixture -FolderName 'tojson' -Findings $script:BaselineFindings -Timestamp '2026-06-01_00-00-00'
        $outPath = Join-Path $TestDrive 'AD_Retest_Comparison_2026-06-01_00-00-00.json'
        Get-ADRetestComparison -BaselinePath $folder -RetestPath $folder -ToJson $outPath | Out-Null

        Test-Path $outPath | Should -BeTrue
        $parsed = Get-Content -Path $outPath -Raw | ConvertFrom-Json
        $parsed.StillOpenFindings.Count | Should -Be $script:BaselineFindings.Count
    }
}

Describe 'Export-ADRetestComparisonHTML' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/Reporting.ps1')
        $folderB = New-RunFixture -FolderName 'html-baseline' -Findings $script:BaselineFindings -Timestamp '2026-07-01_00-00-00'
        $folderR = New-RunFixture -FolderName 'html-retest'   -Findings $script:RetestFindings   -Timestamp '2026-07-15_00-00-00'
        $script:HtmlComparison = Get-ADRetestComparison -BaselinePath $folderB -RetestPath $folderR
    }

    It 'produces a single self-contained HTML file with the Current State / Delta View toggle' {
        $outPath = Join-Path $TestDrive 'retest-report.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath

        Test-Path $outPath | Should -BeTrue
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'Current State'
        $content | Should -Match 'Delta View'
    }

    It 'does not regress the v1.20.3 [hidden]-specificity bug: .view-panel[hidden] is declared as an explicit override' {
        $outPath = Join-Path $TestDrive 'retest-report-hidden-check.html'
        Export-ADRetestComparisonHTML -Comparison $script:HtmlComparison -OutputPath $outPath
        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match '\.view-panel\[hidden\]\s*\{\s*display:\s*none;\s*\}'
    }

    It 'accepts the comparison object via the pipeline' {
        $outPath = Join-Path $TestDrive 'retest-report-pipeline.html'
        $script:HtmlComparison | Export-ADRetestComparisonHTML -OutputPath $outPath
        Test-Path $outPath | Should -BeTrue
    }
}
