#Requires -Modules Pester
<#
    Unit tests for Step 16 - Get-ADForestConsolidation / Export-ADForestConsolidationHTML.

    These tests do NOT touch Active Directory. Like Scoring.Tests.ps1, they only
    exercise this project's own scoring/serialization contract: two synthetic
    "domain" exports (findings JSON + score sidecar JSON, in the exact shape
    Start-ADSecurityAudit already writes) are written to TestDrive and fed to
    Get-ADForestConsolidation entirely offline - matching this feature's own
    "no lab domain needed" test/validation notes.

    Run from the repo root:  Invoke-Pester ./tests/ForestConsolidation.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/ForestConsolidation.ps1')

    function New-TestFinding {
        param([string]$Issue, [string]$Category, [string]$Severity, [int]$SeverityLevel, [string]$AffectedObject = '', [hashtable]$Details = @{})
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        $f.AffectedObject = $AffectedObject
        $f.Details = $Details
        return $f
    }

    function New-DomainFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp = '2026-07-01_00-00-00'
        )
        foreach ($finding in $Findings) { [void](Set-ADFindingMetadata -Finding $finding) }
        $riskScore = Get-ADRiskScore -Findings $Findings

        $domainFolder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $domainFolder -Force | Out-Null

        $findingsPath = Join-Path $domainFolder "AD_Security_Audit_$Timestamp.json"
        $scorePath    = Join-Path $domainFolder "AD_Security_Score_$Timestamp.json"

        $Findings   | ConvertTo-Json -Depth 10 | Out-File -FilePath $findingsPath -Encoding UTF8
        $riskScore  | ConvertTo-Json -Depth 6  | Out-File -FilePath $scorePath -Encoding UTF8

        return $riskScore
    }
}

Describe 'Get-ADForestConsolidation (two-domain fixture, one clearly worse)' {
    BeforeAll {
        # DomainA: two Criticals -> clearly the worse domain.
        $findingsA = @(
            (New-TestFinding 'KRBTGT Password Age Exceeds Recommended Threshold' 'Kerberos Security' 'Critical' 4)
            (New-TestFinding 'Unauthorized DCSync Permissions' 'Replication Security' 'Critical' 4)
            (New-TestFinding 'Bidirectional Domain Trust' 'Domain Trusts' 'Medium' 2 -AffectedObject 'domainb.contoso.com' -Details @{ Target = 'domainb.contoso.com'; Direction = 'Bidirectional' })
            (New-TestFinding 'Forest Trust Without Selective Authentication' 'Domain Trusts' 'High' 3 -AffectedObject 'unknownexternal.example.com' -Details @{ Target = 'unknownexternal.example.com' })
        )
        $script:ScoreA = New-DomainFixture -FolderName 'DomainA' -Findings $findingsA

        # DomainB: only a single Low -> clearly the better domain.
        $findingsB = @(
            (New-TestFinding 'Inactive Enabled Account' 'User Account' 'Low' 1)
        )
        $script:ScoreB = New-DomainFixture -FolderName 'DomainB' -Findings $findingsB -Timestamp '2026-07-01_00-00-00'

        $script:Consolidation = Get-ADForestConsolidation -ReportPath $TestDrive
    }

    It 'discovers both domain report pairs, named from their subfolders' {
        $script:Consolidation.DomainCount | Should -Be 2
        $script:Consolidation.Domains.DomainName | Should -Contain 'DomainA'
        $script:Consolidation.Domains.DomainName | Should -Contain 'DomainB'
    }

    It 'sets the forest score to the worse domain''s score, not an average' {
        $script:Consolidation.ForestScore | Should -Be $script:ScoreA.TotalScore
        $script:Consolidation.ForestScore | Should -Not -Be ([math]::Round((($script:ScoreA.TotalScore + $script:ScoreB.TotalScore) / 2)))
        $script:Consolidation.WorstDomain | Should -Be 'DomainA'
    }

    It 'sets forest maturity to the lowest (worst) maturity level present' {
        $script:Consolidation.ForestMaturityLevel | Should -Be ([math]::Min($script:ScoreA.MaturityLevel, $script:ScoreB.MaturityLevel))
    }

    It 'builds a worst-first domain comparison table' {
        $script:Consolidation.DomainComparison[0].DomainName | Should -Be 'DomainA'
    }

    It 'builds a per-category heatmap using the worst domain per category, not an average' {
        $kerberosRow = $script:Consolidation.CategoryHeatmap | Where-Object Category -eq 'Kerberos Security'
        $kerberosRow.WorstDomain | Should -Be 'DomainA'
    }

    It 'annotates a trust finding whose target domain report is present in the input set' {
        $enriched = $script:Consolidation.TrustRiskEnrichment | Where-Object { $_.TargetDomain -eq 'DomainB' }
        $enriched | Should -Not -BeNullOrEmpty
        $enriched.Annotated | Should -BeTrue
        $enriched.TargetScore | Should -Be $script:ScoreB.TotalScore
    }

    It 'leaves a trust finding unannotated (not an error) when its target domain is absent from the input set' {
        $unmatched = $script:Consolidation.TrustRiskEnrichment | Where-Object { $_.TargetDomain -eq 'unknownexternal.example.com' }
        $unmatched | Should -Not -BeNullOrEmpty
        $unmatched.Annotated | Should -BeFalse
        $unmatched.TargetScore | Should -BeNullOrEmpty
    }

    It 'reports no missing domains when no prior consolidation is supplied' {
        $script:Consolidation.MissingDomains.Count | Should -Be 0
    }
}

Describe 'Get-ADForestConsolidation (missing-domain detection across runs)' {
    BeforeAll {
        $findingsC = @( (New-TestFinding 'Inactive Enabled Account' 'User Account' 'Low' 1) )
        New-DomainFixture -FolderName 'DomainC' -Findings $findingsC -Timestamp '2026-06-01_00-00-00' | Out-Null

        # Prior run saw DomainA, DomainB (from the other Describe's TestDrive... use a
        # fresh, self-contained prior-consolidation JSON instead of relying on order).
        $priorPath = Join-Path $TestDrive 'AD_Forest_Consolidation_prior.json'
        [PSCustomObject]@{
            GeneratedDate = (Get-Date).AddDays(-7)
            Domains       = @(
                [PSCustomObject]@{ DomainName = 'DomainC' }
                [PSCustomObject]@{ DomainName = 'DomainD-not-scanned-this-run' }
            )
        } | ConvertTo-Json -Depth 5 | Out-File -FilePath $priorPath -Encoding UTF8

        $script:Result = Get-ADForestConsolidation -ReportPath (Join-Path $TestDrive 'DomainC') -DomainName 'DomainC' -PriorConsolidationPath $priorPath
    }

    It 'flags a domain present in the prior run but absent from this one as not scanned this run' {
        $script:Result.MissingDomains.DomainName | Should -Contain 'DomainD-not-scanned-this-run'
        ($script:Result.MissingDomains | Where-Object DomainName -eq 'DomainD-not-scanned-this-run').Status | Should -Be 'not scanned this run'
    }

    It 'does not flag a domain that is present in both the prior run and this one' {
        $script:Result.MissingDomains.DomainName | Should -Not -Contain 'DomainC'
    }
}

Describe 'Get-ADForestConsolidation (input validation)' {
    It 'throws a clear error when no matching exports are found' {
        $emptyDir = Join-Path $TestDrive 'Empty'
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        { Get-ADForestConsolidation -ReportPath $emptyDir } | Should -Throw
    }
}
