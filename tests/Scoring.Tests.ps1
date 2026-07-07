#Requires -Modules Pester
<#
    Unit tests for the v1.2.0 scoring / ANSSI maturity / MITRE contract layer.

    These tests do NOT touch Active Directory. They feed a fixed set of
    ADSecurityFinding objects to the scoring functions and assert the computed
    total, per-category sub-scores, and maturity bucket - satisfying the
    "no regression / deterministic scoring" acceptance criteria.

    Run from the repo root:  Invoke-Pester ./tests/Scoring.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')

    function New-TestFinding {
        param([string]$Issue, [string]$Category, [string]$Severity, [int]$SeverityLevel)
        $f = [ADSecurityFinding]::new()
        $f.Issue = $Issue
        $f.Category = $Category
        $f.Severity = $Severity
        $f.SeverityLevel = $SeverityLevel
        return $f
    }

    $script:Fixture = @(
        New-TestFinding 'KRBTGT Password Age Exceeds Recommended Threshold' 'Kerberos Security'   'Critical' 4
        New-TestFinding 'Unauthorized DCSync Permissions'                   'Replication Security' 'Critical' 4
        New-TestFinding 'User Account with SPN (Kerberoasting Risk)'        'User Account'        'Medium'   2
        New-TestFinding 'Password Never Expires'                            'User Account'        'Medium'   2
        New-TestFinding 'Inactive Enabled Account'                          'User Account'        'Low'      1
        New-TestFinding 'Weak Minimum Password Length'                      'Domain Security'     'High'     3
        New-TestFinding 'Unlinked GPO'                                      'Group Policy'        'Info'     0
    )
}

Describe 'Set-ADFindingMetadata' {
    It 'tags a known finding with MITRE, ANSSI, and weight from the central table' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Unauthorized DCSync Permissions'; $f.SeverityLevel = 4
        $tagged = Set-ADFindingMetadata -Finding $f
        $tagged.MitreTechnique | Should -Be 'T1003.006'
        $tagged.AnssiControl   | Should -Be 'vuln1_dcsync'
        $tagged.Weight         | Should -Be 40
    }

    It 'falls back to severity-derived defaults for an unmapped issue' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Some Brand New Check'; $f.SeverityLevel = 3
        $tagged = Set-ADFindingMetadata -Finding $f
        $tagged.Weight       | Should -Be 20
        $tagged.AnssiControl | Should -Match '^vuln2_'
    }

    It 'is idempotent' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Shadow Credentials Detected'; $f.SeverityLevel = 4
        Set-ADFindingMetadata -Finding $f | Out-Null
        $w1 = $f.Weight
        Set-ADFindingMetadata -Finding $f | Out-Null
        $f.Weight | Should -Be $w1
    }
}

Describe 'Get-ADRiskScore (fixed fixture)' {
    BeforeAll { $script:Result = Get-ADRiskScore -Findings $script:Fixture }

    It 'computes the global total as the worst category (PingCastle-style)' {
        $script:Result.TotalScore | Should -Be 40
    }

    It 'computes ANSSI maturity as the lowest level present (1)' {
        $script:Result.MaturityLevel | Should -Be 1
    }

    It 'sums weighted points across all findings' {
        $script:Result.WeightedPoints | Should -Be 125
    }

    It 'computes correct per-category sub-scores' {
        ($script:Result.CategoryScores | Where-Object Category -eq 'User Account').Score        | Should -Be 24
        ($script:Result.CategoryScores | Where-Object Category -eq 'Kerberos Security').Score    | Should -Be 40
        ($script:Result.CategoryScores | Where-Object Category -eq 'Replication Security').Score | Should -Be 40
        ($script:Result.CategoryScores | Where-Object Category -eq 'Group Policy').Score         | Should -Be 1
    }

    It 'aggregates MITRE techniques (T1078.002 appears twice)' {
        ($script:Result.MitreSummary | Where-Object Technique -eq 'T1078.002').Count | Should -Be 2
    }

    It 'caps the total at 0-100' {
        $script:Result.TotalScore | Should -BeGreaterOrEqual 0
        $script:Result.TotalScore | Should -BeLessOrEqual 100
    }
}

Describe 'Get-ADRiskScore (edge cases)' {
    It 'returns score 0 / maturity 5 for an empty environment' {
        $r = Get-ADRiskScore -Findings @()
        $r.TotalScore    | Should -Be 0
        $r.MaturityLevel | Should -Be 5
    }

    It 'tags raw (untagged) findings on the fly' {
        $f = [ADSecurityFinding]::new(); $f.Issue = 'Reversible Password Encryption'; $f.Category = 'User Account'; $f.SeverityLevel = 4
        $r = Get-ADRiskScore -Findings @($f)
        $r.TotalScore | Should -Be 40   # weight 40, capped category
        $f.MitreTechnique | Should -Be 'T1003'
    }
}

Describe 'Mapping table integrity' {
    It 'exposes a clone via Get-ADFindingMetadataMap (does not mutate source)' {
        $map = Get-ADFindingMetadataMap
        $map['Unauthorized DCSync Permissions'].Mitre | Should -Be 'T1003.006'
        $map['__injected__'] = @{ Mitre='X'; Anssi='y'; Weight=1 }
        (Get-ADFindingMetadataMap).ContainsKey('__injected__') | Should -BeFalse
    }

    It 'every ANSSI control encodes a 1-5 maturity level prefix' {
        $map = Get-ADFindingMetadataMap
        foreach ($k in $map.Keys) {
            $map[$k].Anssi | Should -Match '^vuln[1-5]_'
        }
    }
}
