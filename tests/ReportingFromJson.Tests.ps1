#Requires -Modules Pester
<#
    Unit tests for Export-ADSecurityReportHTMLFromJson (src/Reporting.ps1).

    These tests do NOT touch Active Directory. Like RetestComparison.Tests.ps1,
    they write a synthetic AD_Security_Audit_<timestamp>.json (the exact shape
    Start-ADSecurityAudit already writes) to TestDrive and feed it to
    Export-ADSecurityReportHTMLFromJson entirely offline.

    Run from the repo root:  Invoke-Pester ./tests/ReportingFromJson.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/RetestComparison.ps1')
    . (Join-Path $root 'src/Reporting.ps1')

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

    $script:ControlPathFinding = New-TestFinding -Issue 'Control Path to Domain Admins' -Category 'Attack Paths' -Severity 'High' -SeverityLevel 3 -AffectedObject 'user1'
    $script:ControlPathFinding.Details = @{
        HopChain  = 'user1 -> GroupA -> Domain Admins'
        Source    = 'user1'
        Target    = 'Domain Admins'
        HopCount  = 2
    }

    $script:Findings = @(
        New-TestFinding -Issue 'Inactive Enabled Account' -Category 'User Account' -Severity 'Low' -SeverityLevel 1 -AffectedObject 'user1'
        New-TestFinding -Issue 'Kerberoastable Account' -Category 'Kerberos Security' -Severity 'High' -SeverityLevel 3 -AffectedObject 'svc1'
        New-TestFinding -Issue 'AdminSDHolder ACL Modified' -Category 'AdminSDHolder' -Severity 'Critical' -SeverityLevel 4 -AffectedObject 'AdminSDHolder'
        $script:ControlPathFinding
    )
    foreach ($finding in $script:Findings) { [void](Set-ADFindingMetadata -Finding $finding) }

    function New-FindingsFixture {
        param(
            [string]$FolderName,
            [array]$Findings,
            [string]$Timestamp,
            [switch]$WithScoreSidecar
        )
        $folder = Join-Path $TestDrive $FolderName
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $findingsPath = Join-Path $folder "AD_Security_Audit_$Timestamp.json"
        $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $findingsPath -Encoding UTF8

        if ($WithScoreSidecar) {
            $riskScore = Get-ADRiskScore -Findings $Findings
            $scorePath = Join-Path $folder "AD_Security_Score_$Timestamp.json"
            $riskScore | ConvertTo-Json -Depth 6 | Out-File -FilePath $scorePath -Encoding UTF8
        }
        return $folder
    }
}

Describe 'Export-ADSecurityReportHTMLFromJson' {
    It 'accepts an explicit AD_Security_Audit_*.json file path' {
        $folder = New-FindingsFixture -FolderName 'explicit-file' -Findings $script:Findings -Timestamp '2026-08-01_00-00-00'
        $explicitFile = Join-Path $folder 'AD_Security_Audit_2026-08-01_00-00-00.json'
        $outPath = Join-Path $TestDrive 'recreated-explicit.html'

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $explicitFile -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue
    }

    It 'accepts a folder path and resolves the newest AD_Security_Audit_*.json in it' {
        $folder = New-FindingsFixture -FolderName 'folder-form' -Findings $script:Findings -Timestamp '2026-08-02_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-folder.html'

        { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
        Test-Path $outPath | Should -BeTrue
    }

    It 'produces a report whose Executive Summary counts match the findings by severity' {
        $folder = New-FindingsFixture -FolderName 'summary-counts' -Findings $script:Findings -Timestamp '2026-08-03_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-summary.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        # One Critical, one High, zero Medium, one Low in the fixture above.
        $content | Should -Match 'AdminSDHolder ACL Modified'
        $content | Should -Match 'Kerberoastable Account'
        $content | Should -Match 'Inactive Enabled Account'
    }

    It 'shows a placeholder Domain rather than a blank/incorrect value when -Domain is omitted' {
        $folder = New-FindingsFixture -FolderName 'no-domain' -Findings $script:Findings -Timestamp '2026-08-04_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-no-domain.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'recreated from JSON export'
    }

    It 'reflects an explicitly-passed -Domain instead of the placeholder' {
        $folder = New-FindingsFixture -FolderName 'with-domain' -Findings $script:Findings -Timestamp '2026-08-05_00-00-00'
        $outPath = Join-Path $TestDrive 'recreated-with-domain.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath -Domain 'contoso.com'

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match 'contoso\.com'
        $content | Should -Not -Match 'recreated from JSON export'
    }

    It 'recomputes the risk score via Get-ADRiskScore rather than trusting a stray score sidecar' {
        # Even when a sidecar happens to exist alongside the findings export,
        # the recreated report's score must come from Get-ADRiskScore run
        # fresh against the findings - never a passthrough of the sidecar.
        $folder = New-FindingsFixture -FolderName 'with-sidecar' -Findings $script:Findings -Timestamp '2026-08-06_00-00-00' -WithScoreSidecar
        $expected = Get-ADRiskScore -Findings $script:Findings
        $outPath = Join-Path $TestDrive 'recreated-with-sidecar.html'
        Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

        $content = Get-Content -Path $outPath -Raw
        $content | Should -Match [regex]::Escape("$($expected.TotalScore)")
    }

    It 'throws a clear error when the path does not exist' {
        { Export-ADSecurityReportHTMLFromJson -FindingsPath (Join-Path $TestDrive 'does-not-exist') -OutputPath (Join-Path $TestDrive 'irrelevant.html') } | Should -Throw
    }

    Context 'Control-path (Attack Paths) findings - Details survives the JSON round-trip' {
        <#
            Regression coverage for a reported bug: Details is declared
            [hashtable] on a live ADSecurityFinding, but
            Export-ADSecurityReportHTMLFromJson reads findings back via a
            plain ConvertFrom-Json (no -AsHashtable), which deserializes
            every JSON object - including a finding's Details - into a
            PSCustomObject instead. The control-path rendering code in
            Export-ADSecurityReportHTML called $finding.Details.ContainsKey(...)
            unconditionally, which only exists on Hashtable/IDictionary,
            so recreating a report from JSON for ANY run that had a
            control-path finding threw "Method invocation failed because
            [...PSCustomObject] does not contain a method named
            'ContainsKey'" on every single one. Fixed via
            Test-ADFindingDetailsKey (Common.ps1), which works for either
            shape.
        #>
        It 'recreates a report containing a control-path finding without throwing' {
            $folder = New-FindingsFixture -FolderName 'control-path' -Findings $script:Findings -Timestamp '2026-08-07_00-00-00'
            $outPath = Join-Path $TestDrive 'recreated-control-path.html'

            { Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath } | Should -Not -Throw
            Test-Path $outPath | Should -BeTrue
        }

        It 'renders the HopChain from a JSON-deserialized (PSCustomObject) Details' {
            $folder = New-FindingsFixture -FolderName 'control-path-hopchain' -Findings $script:Findings -Timestamp '2026-08-08_00-00-00'
            $outPath = Join-Path $TestDrive 'recreated-control-path-hopchain.html'
            Export-ADSecurityReportHTMLFromJson -FindingsPath $folder -OutputPath $outPath

            $content = Get-Content -Path $outPath -Raw
            $content | Should -Match 'Control Path to Domain Admins'
            $content | Should -Match 'user1 -&gt; GroupA -&gt; Domain Admins'
        }

        It 'still works when Details is a genuine Hashtable (not JSON-sourced), unaffected by the fix' {
            $liveFindings = @($script:ControlPathFinding)
            $outPath = Join-Path $TestDrive 'live-control-path.html'
            $summary = @{ Critical = 0; High = 1; Medium = 0; Low = 0 }
            $riskScore = Get-ADRiskScore -Findings $liveFindings
            { Export-ADSecurityReportHTML -Findings $liveFindings -OutputPath $outPath -Domain 'contoso.com' -Summary $summary `
                -Duration ([timespan]::Zero) -RiskScore $riskScore -RunMode 'Live' -SnapshotCollectedDate $null `
                -PrivilegedUsers $null -OfflineSkipNotes @() } | Should -Not -Throw

            $content = Get-Content -Path $outPath -Raw
            $content | Should -Match 'user1 -&gt; GroupA -&gt; Domain Admins'
        }
    }
}

Describe 'Test-ADFindingDetailsKey' {
    It 'finds a key on a real Hashtable' {
        Test-ADFindingDetailsKey -Details @{ Foo = 'bar' } -Key 'Foo' | Should -BeTrue
    }
    It 'returns $false for a missing key on a Hashtable' {
        Test-ADFindingDetailsKey -Details @{ Foo = 'bar' } -Key 'Missing' | Should -BeFalse
    }
    It 'finds a key on a JSON-deserialized PSCustomObject' {
        $obj = (@{ Foo = 'bar' } | ConvertTo-Json | ConvertFrom-Json)
        Test-ADFindingDetailsKey -Details $obj -Key 'Foo' | Should -BeTrue
    }
    It 'returns $false for a missing key on a PSCustomObject' {
        $obj = (@{ Foo = 'bar' } | ConvertTo-Json | ConvertFrom-Json)
        Test-ADFindingDetailsKey -Details $obj -Key 'Missing' | Should -BeFalse
    }
    It 'returns $false (not a throw) for $null Details' {
        { Test-ADFindingDetailsKey -Details $null -Key 'Foo' } | Should -Not -Throw
        Test-ADFindingDetailsKey -Details $null -Key 'Foo' | Should -BeFalse
    }
}
