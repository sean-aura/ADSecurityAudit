function Export-ADSecurityReportHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter(Mandatory)]
        [string]$Domain,
        
        [Parameter(Mandatory)]
        [hashtable]$Summary,
        
        [Parameter(Mandatory)]
        [timespan]$Duration,
        
        [Parameter()]
        [array]$PrivilegedUsers = $null,

        [Parameter()]
        [PSCustomObject]$RiskScore = $null,

        # Added for the -FromSnapshot offline workflow: 'Live' (default) or
        # 'Offline (Snapshot)'. Surfaced in the report header so a reader
        # can tell at a glance whether findings came from a live AD pass or
        # a previously-collected snapshot, without having to check the
        # generating command.
        [Parameter()]
        [ValidateSet('Live', 'Offline (Snapshot)')]
        [string]$RunMode = 'Live',

        # When -RunMode is 'Offline (Snapshot)', the timestamp the snapshot
        # was originally collected (Get-ADSnapshot's CollectedDate). Shown
        # alongside the report-generation date so a reader can see how
        # stale the underlying data is relative to when the report was run.
        [Parameter()]
        [Nullable[datetime]]$SnapshotCollectedDate = $null
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $isOfflineRun = ($RunMode -eq 'Offline (Snapshot)')
    $runModeBadgeColor = if ($isOfflineRun) { '#e67e22' } else { '#27ae60' }
    $snapshotCollectedDateText = if ($SnapshotCollectedDate) { $SnapshotCollectedDate.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    
    # Group findings by severity
    $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'Critical' } | Sort-Object Category
    $highFindings = $Findings | Where-Object { $_.Severity -eq 'High' } | Sort-Object Category
    $mediumFindings = $Findings | Where-Object { $_.Severity -eq 'Medium' } | Sort-Object Category
    $lowFindings = $Findings | Where-Object { $_.Severity -eq 'Low' } | Sort-Object Category
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD Security Assessment Report - $(HtmlEncode $Domain)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 8px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 20px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: #7f8c8d; font-size: 0.9em; margin-bottom: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { display: block; padding: 25px; border-radius: 8px; color: white; text-align: center; text-decoration: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transition: transform 0.15s ease; }
        .summary-card:hover { transform: translateY(-2px); }
        .summary-card-empty { cursor: default; opacity: 0.85; }
        .summary-card-empty:hover { transform: none; }
        .summary-card .count { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .summary-card .label { font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .critical-card { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .high-card { background: linear-gradient(135deg, #e67e22 0%, #d35400 100%); }
        .medium-card { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .low-card { background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%); }
        .finding { margin-bottom: 15px; padding: 20px; border-radius: 5px; border-left: 5px solid; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .finding.critical { border-left-color: #e74c3c; background: #fef5f5; }
        .finding.high { border-left-color: #e67e22; background: #fef9f5; }
        .finding.medium { border-left-color: #f39c12; background: #fffcf5; }
        .finding.low { border-left-color: #95a5a6; background: #f9fafb; }
        details.finding { padding: 0; }
        details.finding[open] { padding-bottom: 5px; }
        details.finding > summary { list-style: none; cursor: pointer; padding: 20px; }
        details.finding > summary::-webkit-details-marker { display: none; }
        details.finding > summary::before { content: '\25B8'; display: inline-block; margin-right: 10px; color: #7f8c8d; transition: transform 0.15s ease; }
        details.finding[open] > summary::before { transform: rotate(90deg); }
        .finding-body { padding: 0 20px 15px; }
        .section-toolbar { display: flex; justify-content: flex-end; gap: 10px; margin: -8px 0 10px; }
        .toggle-all-btn { background: #ecf0f1; border: 1px solid #d5dbdd; color: #2c3e50; padding: 5px 12px; border-radius: 4px; font-size: 0.85em; cursor: pointer; }
        .toggle-all-btn:hover { background: #dfe4e6; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .finding-title { font-size: 1.3em; font-weight: 600; color: #2c3e50; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .count-badge { display: inline-block; background: #eef1f3; color: #2c3e50; font-size: 0.6em; font-weight: 700; padding: 3px 10px; border-radius: 12px; vertical-align: middle; letter-spacing: 0.3px; }
        .finding-instance-list { list-style: none; border-top: 1px solid #ecf0f1; margin-top: 5px; max-height: 420px; overflow-y: auto; }
        .finding-instance { padding: 10px 0; border-bottom: 1px solid #ecf0f1; }
        .finding-instance:last-child { border-bottom: none; }
        .finding-instance-object { font-weight: 600; color: #2c3e50; font-family: 'Consolas', monospace; font-size: 0.9em; word-break: break-word; }
        .finding-instance-desc { color: #666; margin-top: 4px; line-height: 1.5; }
        .finding-instance-date { color: #95a5a6; font-size: 0.8em; margin-top: 4px; }
        .severity-badge { padding: 6px 15px; border-radius: 20px; font-weight: bold; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .finding-meta { display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9em; color: #7f8c8d; flex-wrap: wrap; }
        .finding-meta span { display: flex; align-items: center; }
        .finding-meta strong { margin-right: 5px; color: #555; }
        .finding-section { margin: 15px 0; padding: 15px; background: white; border-radius: 4px; }
        .finding-section h4 { color: #555; margin-bottom: 10px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding-section p { color: #666; line-height: 1.7; }
        .privileged-users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .privileged-users-table th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        .privileged-users-table tr:nth-child(even) { background: #f8f9fa; }
        .privileged-users-table tr:hover { background: #e8f4f8; }
        .status-enabled { color: #27ae60; font-weight: bold; }
        .status-disabled { color: #e74c3c; font-weight: bold; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; font-size: 0.9em; }
        .warning-box { background: #fff3cd; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #856404; margin: 5px 0; }
        .scoring-grid { display: grid; grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr); gap: 20px; margin: 20px 0; }
        @media (max-width: 700px) { .scoring-grid { grid-template-columns: 1fr; } }
        .score-panel, .maturity-panel { padding: 25px; border-radius: 8px; background: #f8f9fa; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .gauge-wrap { display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .gauge { --pct: 0; --col: #95a5a6; width: 160px; height: 160px; border-radius: 50%;
                 background: radial-gradient(white 58%, transparent 59%),
                 conic-gradient(var(--col) calc(var(--pct) * 1%), #e6e9ec 0);
                 display: flex; align-items: center; justify-content: center; }
        .gauge-inner { text-align: center; }
        .gauge-inner .num { font-size: 2.6em; font-weight: bold; color: #2c3e50; line-height: 1; }
        .gauge-inner .of { font-size: 0.9em; color: #7f8c8d; }
        .score-meta { color: #555; }
        .score-meta .hint { font-size: 0.85em; color: #7f8c8d; margin-top: 8px; }
        .maturity-ladder { display: flex; flex-direction: column-reverse; gap: 6px; margin-top: 10px; }
        .maturity-step { padding: 8px 12px; border-radius: 4px; background: #e6e9ec; color: #7f8c8d; font-size: 0.9em; display: flex; justify-content: space-between; }
        .maturity-step.reached { background: #d5f5e3; color: #1e8449; font-weight: 600; }
        .maturity-step.current { background: #2c3e50; color: white; font-weight: 700; }
        .maturity-head { font-size: 2.2em; font-weight: bold; color: #2c3e50; }
        .maturity-head small { font-size: 0.45em; color: #7f8c8d; font-weight: normal; }
        .mitre-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }
        .mitre-table th { background: #34495e; color: white; padding: 10px; text-align: left; }
        .mitre-table td { padding: 8px 10px; border-bottom: 1px solid #ecf0f1; }
        .mitre-table tr:nth-child(even) { background: #f8f9fa; }
        .mitre-id { font-family: 'Consolas', monospace; color: #2980b9; font-weight: 600; }
        .cat-bar-row { display: grid; grid-template-columns: 200px 1fr 50px; align-items: center; gap: 10px; margin: 6px 0; font-size: 0.9em; }
        .cat-bar-track { display: block; background: #e6e9ec; border-radius: 10px; height: 16px; overflow: hidden; }
        .cat-bar-fill { display: block; height: 100%; border-radius: 10px; }
        .tag-mitre { font-family: 'Consolas', monospace; background: #eaf2f8; color: #2471a3; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        .tag-anssi { font-family: 'Consolas', monospace; background: #f4ecf7; color: #6c3483; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#128737; Active Directory Security Assessment Report <span style="display:inline-block; vertical-align:middle; font-size:0.4em; font-weight:bold; letter-spacing:0.05em; text-transform:uppercase; color:#fff; background:$runModeBadgeColor; padding:4px 10px; border-radius:12px; margin-left:10px;">$(HtmlEncode $RunMode)</span></h1>
        
        <div class="warning-box">
            <p><strong>&#9888; CONFIDENTIAL SECURITY REPORT</strong></p>
            <p>This report contains sensitive security information about your Active Directory environment. Handle with care and share only with authorized personnel.</p>
        </div>
$(if ($isOfflineRun) {
@"
        <div class="warning-box" style="background:#fdf2e3; border-color:#e67e22;">
            <p><strong>&#128190; OFFLINE / SNAPSHOT-BASED REPORT</strong></p>
            <p>This report was generated with <code>-FromSnapshot</code> from a previously collected snapshot - no live Active Directory or Domain Controller connections were made during this run.$(if ($snapshotCollectedDateText) { " The underlying snapshot data was collected on <strong>$snapshotCollectedDateText</strong>" }) Findings reflect the environment's state at collection time and may not include changes made since then. Some checks that have no offline/snapshot support are skipped entirely in this mode (see the run log for the skipped-test list) - for a like-for-like comparison against a live run, cross-reference which tests actually executed.</p>
        </div>
"@
})
        
        <div class="header-info">
            <div><strong>DOMAIN</strong><span style="font-size: 1.2em; color: #2c3e50;">$(HtmlEncode $Domain)</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #2c3e50;">$reportDate</span></div>
            <div><strong>COLLECTION MODE</strong><span style="font-size: 1.2em; color: $runModeBadgeColor; font-weight:bold;">$(HtmlEncode $RunMode)</span></div>
            <div><strong>SCAN DURATION</strong><span style="font-size: 1.2em; color: #2c3e50;">$([math]::Round($Duration.TotalSeconds, 2)) seconds</span></div>
            <div><strong>TOTAL FINDINGS</strong><span style="font-size: 1.2em; color: #2c3e50;">$($Findings.Count)</span></div>
$(if ($isOfflineRun -and $snapshotCollectedDateText) {
"            <div><strong>SNAPSHOT COLLECTED</strong><span style=`"font-size: 1.2em; color: #2c3e50;`">$snapshotCollectedDateText</span></div>"
})
        </div>
        
        <h2>&#128202; Executive Summary</h2>
        <div class="summary-cards">
            <a class="summary-card critical-card$(if (-not $criticalFindings) { ' summary-card-empty' })" href="$(if ($criticalFindings) { '#critical-findings' } else { '#' })">
                <div class="count">$($Summary.Critical)</div>
                <div class="label">Critical</div>
            </a>
            <a class="summary-card high-card$(if (-not $highFindings) { ' summary-card-empty' })" href="$(if ($highFindings) { '#high-findings' } else { '#' })">
                <div class="count">$($Summary.High)</div>
                <div class="label">High</div>
            </a>
            <a class="summary-card medium-card$(if (-not $mediumFindings) { ' summary-card-empty' })" href="$(if ($mediumFindings) { '#medium-findings' } else { '#' })">
                <div class="count">$($Summary.Medium)</div>
                <div class="label">Medium</div>
            </a>
            <a class="summary-card low-card$(if (-not $lowFindings) { ' summary-card-empty' })" href="$(if ($lowFindings) { '#low-findings' } else { '#' })">
                <div class="count">$($Summary.Low)</div>
                <div class="label">Low</div>
            </a>
        </div>
"@

    # --- Risk score, ANSSI maturity & MITRE ATT&CK summary (v1.2.0) ---
    if ($RiskScore) {
        $score = [int]$RiskScore.TotalScore
        # Color the gauge by severity band (higher = worse).
        $gaugeColor = if ($score -ge 75) { '#e74c3c' }
                      elseif ($score -ge 50) { '#e67e22' }
                      elseif ($score -ge 25) { '#f39c12' }
                      else { '#27ae60' }

        $maturityLevel = [int]$RiskScore.MaturityLevel

        $html += @"
        <h2>&#127919; Risk Score &amp; Maturity</h2>
        <div class="scoring-grid">
            <div class="score-panel">
                <h3>Global Risk Score</h3>
                <div class="gauge-wrap">
                    <div class="gauge" style="--pct: $score; --col: $gaugeColor;">
                        <div class="gauge-inner">
                            <div class="num">$score</div>
                            <div class="of">/ 100</div>
                        </div>
                    </div>
                    <div class="score-meta">
                        <p><strong>$($RiskScore.FindingCount)</strong> findings scored.</p>
                        <p>Higher is worse. The global score equals the worst category's score - a category is only ever as strong as its weakest one - similar in spirit to PingCastle's approach.</p>
                        <p class="hint">Each category's score approaches 100 as findings accumulate, using diminishing returns per finding (a single Critical won't max out a category by itself). Raw weighted points across all findings: $($RiskScore.WeightedPoints)</p>
                    </div>
                </div>
            </div>
            <div class="maturity-panel">
                <h3>ANSSI Maturity Level</h3>
                <div class="maturity-head">$maturityLevel <small>/ 5</small></div>
                <p style="color:#555; margin: 6px 0 4px;">$(HtmlEncode $RiskScore.MaturityLabel)</p>
                <div class="maturity-ladder">
"@
        foreach ($lvl in 1..5) {
            $cls = 'maturity-step'
            if ($lvl -eq $maturityLevel) { $cls = 'maturity-step current' }
            elseif ($lvl -lt $maturityLevel) { $cls = 'maturity-step reached' }
            $labelMap = @{
                1 = 'Critical gaps'
                2 = 'Partial hygiene'
                3 = 'Standard hardening'
                4 = 'Advanced hardening'
                5 = 'Optimal'
            }
            $html += @"
                    <div class="$cls"><span>Level $lvl</span><span>$($labelMap[$lvl])</span></div>
"@
        }
        $html += @"
                </div>
                <p class="hint" style="font-size:0.85em; color:#7f8c8d; margin-top:10px;">A single Level&nbsp;1 finding caps maturity at Level&nbsp;1. Lower level = more critical hygiene gaps remain.</p>
            </div>
        </div>
"@

        # Per-category sub-score bars
        if ($RiskScore.CategoryScores -and $RiskScore.CategoryScores.Count -gt 0) {
            $html += @"
        <h3>Risk by Category</h3>
        <div style="margin: 10px 0 20px;">
"@
            foreach ($cat in $RiskScore.CategoryScores) {
                $cScore = [int]$cat.Score
                $cColor = if ($cScore -ge 75) { '#e74c3c' }
                          elseif ($cScore -ge 50) { '#e67e22' }
                          elseif ($cScore -ge 25) { '#f39c12' }
                          else { '#27ae60' }
                $html += @"
            <div class="cat-bar-row">
                <span>$(HtmlEncode $cat.Category) <span style="color:#aaa;">($($cat.Findings))</span></span>
                <span class="cat-bar-track"><span class="cat-bar-fill" style="width: $cScore%; background: $cColor;"></span></span>
                <span style="text-align:right; font-weight:600; color:#555;">$cScore</span>
            </div>
"@
            }
            $html += "        </div>"
        }

        # MITRE ATT&CK technique summary
        if ($RiskScore.MitreSummary -and $RiskScore.MitreSummary.Count -gt 0) {
            $html += @"
        <h3>&#128506; MITRE ATT&amp;CK Technique Summary</h3>
        <div style="overflow-x: auto;">
            <table class="mitre-table">
                <thead><tr><th>Technique</th><th>Name</th><th>Findings</th></tr></thead>
                <tbody>
"@
            foreach ($t in $RiskScore.MitreSummary) {
                $html += @"
                    <tr>
                        <td class="mitre-id">$(HtmlEncode $t.Technique)</td>
                        <td>$(HtmlEncode $t.Name)</td>
                        <td>$($t.Count)</td>
                    </tr>
"@
            }
            $html += @"
                </tbody>
            </table>
        </div>
"@
        }
    }

    if ($PrivilegedUsers -and $PrivilegedUsers.Count -gt 0) {
        $html += @"
        <h2>&#128101; Privileged Users Summary</h2>
        <p style="margin-bottom: 15px; color: #555;">The following $($PrivilegedUsers.Count) user accounts have membership in one or more privileged groups. Review these accounts regularly to ensure appropriate access levels.</p>
        <div style="overflow-x: auto;">
            <table class="privileged-users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Enabled</th>
                        <th>Privileged Groups</th>
                        <th>Password Last Set</th>
                        <th>Last Logon</th>
                        <th>Security Flags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($user in ($PrivilegedUsers | Sort-Object -Property @{Expression={$_.PrivilegedGroups.Count}; Descending=$true}, SamAccountName)) {
            $enabledClass = if ($user.Enabled) { 'status-enabled' } else { 'status-disabled' }
            $enabledText = if ($user.Enabled) { 'Yes' } else { 'No' }
            
            $securityFlags = @()
            if ($user.PasswordNeverExpires) { $securityFlags += 'Pwd Never Expires' }
            if ($user.DoesNotRequirePreAuth) { $securityFlags += 'No PreAuth' }
            if ($user.TrustedForDelegation) { $securityFlags += 'Delegation' }
            if ($user.HasSPN) { $securityFlags += "SPN($($user.SPNCount))" }
            $flagsText = if ($securityFlags.Count -gt 0) { HtmlEncode ($securityFlags -join ', ') } else { '-' }
            
            $passwordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
            
            $html += @"
                    <tr>
                        <td><strong>$(HtmlEncode $user.SamAccountName)</strong></td>
                        <td>$(HtmlEncode $user.DisplayName)</td>
                        <td class="$enabledClass">$enabledText</td>
                        <td style="font-size: 0.85em;">$(HtmlEncode $user.PrivilegedGroupsString)</td>
                        <td>$passwordLastSet</td>
                        <td>$lastLogon</td>
                        <td style="font-size: 0.85em;">$flagsText</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
"@
    }

    # --- Control paths to Tier-0 (v1.16.0) ---
    $controlPathFindings = @($Findings | Where-Object { $_.Category -eq 'Attack Paths' } | Sort-Object -Property @{Expression = { $_.SeverityLevel }; Descending = $true })
    if ($controlPathFindings.Count -gt 0) {
        $html += @"
        <h2>&#128504; Control Paths to Tier-0</h2>
        <p style="color:#555; margin-bottom: 15px;">Chained group-membership, ACL, and ownership relationships that let a non-privileged principal reach a Tier-0 object (Domain Admins/DCs/AdminSDHolder/domain head). No single hop here need look critical on its own - see each finding below for full remediation guidance.</p>
"@
        foreach ($cp in $controlPathFindings) {
            $sevClass = $cp.Severity.ToLower()
            $hopChain = if ($cp.Details -and $cp.Details.ContainsKey('HopChain')) { HtmlEncode "$($cp.Details.HopChain)" } else { HtmlEncode $cp.AffectedObject }
            $html += @"
        <div class="finding $sevClass" style="border-left-width: 5px;">
            <div class="finding-header">
                <div class="finding-title">$(HtmlEncode $cp.Issue)</div>
                <span class="severity-badge severity-$sevClass">$($cp.Severity)</span>
            </div>
            <div class="finding-section">
                <h4>&#128279; Hop Chain</h4>
                <p style="font-family: Consolas, monospace; font-size: 0.9em; word-break: break-word;">$hopChain</p>
            </div>
        </div>
"@
        }
    }

    # Add findings by severity
    if ($criticalFindings) {
        $html += @"
    <h2 id="critical-findings">&#128308; Critical Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('critical-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('critical-findings', false)">Collapse All</button>
    </div>
    <div id="critical-findings-body">
"@
        $groups = @($criticalFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($highFindings) {
        $html += @"
    <h2 id="high-findings">&#128992; High Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('high-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('high-findings', false)">Collapse All</button>
    </div>
    <div id="high-findings-body">
"@
        $groups = @($highFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($mediumFindings) {
        $html += @"
    <h2 id="medium-findings">&#128993; Medium Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('medium-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('medium-findings', false)">Collapse All</button>
    </div>
    <div id="medium-findings-body">
"@
        $groups = @($mediumFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    if ($lowFindings) {
        $html += @"
    <h2 id="low-findings">&#9898; Low Severity Findings</h2>
    <div class="section-toolbar">
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('low-findings', true)">Expand All</button>
        <button type="button" class="toggle-all-btn" onclick="setSectionFindings('low-findings', false)">Collapse All</button>
    </div>
    <div id="low-findings-body">
"@
        $groups = @($lowFindings | Group-Object -Property Category, Issue)
        foreach ($group in $groups) {
            $html += Get-FindingHTML -FindingGroup $group.Group
        }
        $html += "    </div>"
    }
    
    $html += @"
        <div class="footer">
            <p><strong>Generated by ADSecurityAudit Module v$($script:ModuleVersion)</strong></p>
            <p>This report should be treated as confidential and shared only with authorized personnel.</p>
            <p>Review findings, prioritize remediation by severity, and implement security best practices.</p>
        </div>
    </div>
    <script>
        // Expand All / Collapse All toggles a section's <details> elements.
        // Each finding is a native <details>, collapsed by default; this
        // just flips the `open` attribute on every one inside the section.
        function setSectionFindings(sectionId, isOpen) {
            var container = document.getElementById(sectionId + '-body');
            if (!container) { return; }
            var items = container.querySelectorAll('details.finding');
            for (var i = 0; i < items.length; i++) {
                items[i].open = isOpen;
            }
        }
    </script>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Get-FindingHTML {
    [CmdletBinding()]
    param(
        # One or more findings sharing the same Category + Issue (and, since
        # they came from the same severity bucket, the same Severity too).
        # Grouping happens in the caller via `Group-Object -Property
        # Category, Issue`; this function renders either the original
        # single-item layout (Count -eq 1, unchanged from prior versions)
        # or a consolidated layout with one shared Impact/Remediation and a
        # list of every affected object underneath (Count -gt 1), instead
        # of duplicating the same finding once per affected object.
        [Parameter(Mandatory)]
        [array]$FindingGroup
    )
    
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    
    $FindingGroup = @($FindingGroup)
    $first = $FindingGroup[0]
    $count = $FindingGroup.Count

    $severityClass = $first.Severity.ToLower()
    $impact = HtmlEncode $first.Impact
    $remediation = HtmlEncode $first.Remediation
    $issue = HtmlEncode $first.Issue
    $category = HtmlEncode $first.Category

    # Defensive fallback: every field below should be populated by the audit
    # module that raised the finding, but a blank paragraph in the report is
    # confusing, so show an explicit placeholder instead of nothing.
    if ([string]::IsNullOrWhiteSpace($impact))      { $impact      = 'Not specified for this finding.' }
    if ([string]::IsNullOrWhiteSpace($remediation)) { $remediation = 'Not specified for this finding.' }
    $remediation = $remediation -replace "`r`n", '<br>' -replace "`n", '<br>'

    # Optional metadata tags (v1.2.0) - these come from the shared Issue ->
    # MITRE/ANSSI mapping, so they're identical across every item in the
    # group; render once from the first item rather than once per object.
    $metaTags = ''
    if (-not [string]::IsNullOrEmpty($first.MitreTechnique)) {
        $metaTags += "<span><strong>MITRE:</strong> <span class=`"tag-mitre`">$(HtmlEncode $first.MitreTechnique)</span></span>"
    }
    if (-not [string]::IsNullOrEmpty($first.AnssiControl)) {
        $metaTags += "<span><strong>ANSSI:</strong> <span class=`"tag-anssi`">$(HtmlEncode $first.AnssiControl)</span></span>"
    }

    # Rendered as a native <details>/<summary> element so every finding is
    # collapsed by default and expandable with no JS required for the basic
    # interaction; the per-section Expand All/Collapse All buttons toggle the
    # `open` attribute on these elements (see setSectionFindings in the
    # footer script).
    if ($count -eq 1) {
        # Single affected object: same layout used since earlier versions,
        # including the finding's own specific Description text.
        $description = HtmlEncode $first.Description
        $affectedObject = HtmlEncode $first.AffectedObject
        if ([string]::IsNullOrWhiteSpace($description))    { $description = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($affectedObject))  { $affectedObject = 'N/A' }

        return @"
        <details class="finding $severityClass">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$issue</div>
                    <span class="severity-badge severity-$severityClass">$($first.Severity)</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $category</span>
                    <span><strong>Affected Object:</strong> $affectedObject</span>
                    <span><strong>Detected:</strong> $($first.DetectedDate.ToString('yyyy-MM-dd HH:mm'))</span>
                    $metaTags
                </div>
                <div class="finding-section">
                    <h4>&#128221; Description</h4>
                    <p>$description</p>
                </div>
                <div class="finding-section">
                    <h4>&#9888; Impact</h4>
                    <p>$impact</p>
                </div>
                <div class="finding-section">
                    <h4>&#9989; Remediation</h4>
                    <p>$remediation</p>
                </div>
            </div>
        </details>
"@
    }

    # Multiple affected objects for the same Category+Issue: one
    # consolidated block. Impact/Remediation/MITRE/ANSSI are shown once
    # (they're the same for every item, coming from the shared Issue -> 
    # metadata mapping); each object keeps its own specific Description
    # (which typically bakes in the exact principal/SID/rights/etc.) and
    # its own detection timestamp in the list below.
    $instanceItems = foreach ($f in ($FindingGroup | Sort-Object AffectedObject)) {
        $objDesc = HtmlEncode $f.Description
        $objName = HtmlEncode $f.AffectedObject
        if ([string]::IsNullOrWhiteSpace($objDesc)) { $objDesc = 'Not specified for this finding.' }
        if ([string]::IsNullOrWhiteSpace($objName)) { $objName = 'N/A' }
        @"
                    <li class="finding-instance">
                        <div class="finding-instance-object">$objName</div>
                        <div class="finding-instance-desc">$objDesc</div>
                        <div class="finding-instance-date">Detected: $($f.DetectedDate.ToString('yyyy-MM-dd HH:mm'))</div>
                    </li>
"@
    }
    $instanceItemsHtml = $instanceItems -join "`n"

    return @"
        <details class="finding $severityClass">
            <summary>
                <div class="finding-header">
                    <div class="finding-title">$issue <span class="count-badge">$count objects</span></div>
                    <span class="severity-badge severity-$severityClass">$($first.Severity)</span>
                </div>
            </summary>
            <div class="finding-body">
                <div class="finding-meta">
                    <span><strong>Category:</strong> $category</span>
                    $metaTags
                </div>
                <div class="finding-section">
                    <h4>&#9888; Impact</h4>
                    <p>$impact</p>
                </div>
                <div class="finding-section">
                    <h4>&#9989; Remediation</h4>
                    <p>$remediation</p>
                </div>
                <div class="finding-section">
                    <h4>&#128221; Affected Objects ($count)</h4>
                    <ul class="finding-instance-list">
$instanceItemsHtml
                    </ul>
                </div>
            </div>
        </details>
"@
}

#endregion

