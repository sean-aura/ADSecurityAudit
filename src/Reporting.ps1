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
        [Nullable[datetime]]$SnapshotCollectedDate = $null,

        # Added in v1.19.1: the offline-skip-note list (Get-ADOfflineSkipNotes)
        # collected during this run. Each entry is a specific sub-check that
        # either did not run at all under -Snapshot (Mode='Skipped') or ran
        # anyway over a live connection because it has no possible snapshot
        # representation (Mode='StillLive'). Rendered as an explicit
        # "Offline Mode Coverage Notes" section so a reader doesn't have to
        # go dig through the run's transcript to know what this specific
        # report does and doesn't cover.
        [Parameter()]
        [array]$OfflineSkipNotes = @()
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $isOfflineRun = ($RunMode -eq 'Offline (Snapshot)')
    $runModeBadgeColor = if ($isOfflineRun) { '#c8590b' } else { '#1a7f4e' }
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
        :root {
            --font-sans: -apple-system, "Segoe UI", system-ui, Roboto, Helvetica, Arial, sans-serif;
            --bg: #f4f6f8;
            --surface: #ffffff;
            --ink: #1f2937;
            --ink-muted: #5b6472;
            --border: #e2e6ea;
            --brand: #1f4e79;
            --critical: #b3261e;
            --critical-bg: #fdf1f0;
            --high: #c8590b;
            --high-bg: #fdf5ec;
            --medium: #8a6200;
            --medium-bg: #fdf8ec;
            --low: #5b6472;
            --low-bg: #f4f5f6;
            --good: #1a7f4e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: var(--font-sans); line-height: 1.6; color: var(--ink); background: var(--bg); padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: var(--surface); padding: 30px; box-shadow: 0 1px 3px rgba(15,23,42,0.08); border-radius: 8px; border: 1px solid var(--border); }
        h1 { color: var(--ink); border-bottom: 3px solid var(--brand); padding-bottom: 15px; margin-bottom: 20px; font-size: 1.7em; }
        h2 { color: var(--ink); margin-top: 30px; margin-bottom: 15px; padding: 10px 14px; background: var(--bg); border-left: 4px solid var(--brand); }
        h3 { color: var(--ink-muted); margin-top: 20px; margin-bottom: 10px; }
        .header-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 30px; padding: 20px; background: var(--bg); border-radius: 5px; border: 1px solid var(--border); }
        .header-info div { padding: 10px; }
        .header-info strong { display: block; color: var(--ink-muted); font-size: 0.9em; margin-bottom: 5px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { display: block; padding: 22px; border-radius: 8px; text-align: center; text-decoration: none; border: 1px solid var(--border); border-top: 4px solid transparent; background: var(--surface); transition: transform 0.15s ease, box-shadow 0.15s ease; }
        .summary-card:hover { transform: translateY(-2px); box-shadow: 0 4px 10px rgba(15,23,42,0.08); }
        .summary-card-empty { cursor: default; opacity: 0.6; }
        .summary-card-empty:hover { transform: none; box-shadow: none; }
        .summary-card .count { font-size: 2.6em; font-weight: 700; margin-bottom: 6px; color: var(--ink); }
        .summary-card .label { font-size: 0.95em; text-transform: uppercase; letter-spacing: 1px; color: var(--ink-muted); font-weight: 600; }
        .critical-card { border-top-color: var(--critical); }
        .critical-card .count { color: var(--critical); }
        .high-card { border-top-color: var(--high); }
        .high-card .count { color: var(--high); }
        .medium-card { border-top-color: var(--medium); }
        .medium-card .count { color: var(--medium); }
        .low-card { border-top-color: var(--low); }
        .low-card .count { color: var(--low); }
        .finding { margin-bottom: 15px; padding: 20px; border-radius: 5px; border-left: 5px solid; background: var(--surface); border: 1px solid var(--border); border-left-width: 5px; }
        .finding.critical { border-left-color: var(--critical); background: var(--critical-bg); }
        .finding.high { border-left-color: var(--high); background: var(--high-bg); }
        .finding.medium { border-left-color: var(--medium); background: var(--medium-bg); }
        .finding.low { border-left-color: var(--low); background: var(--low-bg); }
        details.finding { padding: 0; }
        details.finding[open] { padding-bottom: 5px; }
        details.finding > summary { list-style: none; cursor: pointer; padding: 20px; }
        details.finding > summary::-webkit-details-marker { display: none; }
        details.finding > summary::before { content: '\25B8'; display: inline-block; margin-right: 10px; color: var(--ink-muted); transition: transform 0.15s ease; }
        details.finding[open] > summary::before { transform: rotate(90deg); }
        .finding-body { padding: 0 20px 15px; }
        .section-toolbar { display: flex; justify-content: flex-end; gap: 10px; margin: -8px 0 10px; }
        .toggle-all-btn { background: var(--bg); border: 1px solid var(--border); color: var(--ink); padding: 5px 12px; border-radius: 4px; font-size: 0.85em; cursor: pointer; }
        .toggle-all-btn:hover { background: #e8ebee; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .finding-title { font-size: 1.3em; font-weight: 600; color: var(--ink); display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .count-badge { display: inline-block; background: var(--bg); color: var(--ink); font-size: 0.6em; font-weight: 700; padding: 3px 10px; border-radius: 12px; vertical-align: middle; letter-spacing: 0.3px; border: 1px solid var(--border); }
        .finding-instance-list { list-style: none; border-top: 1px solid var(--border); margin-top: 5px; max-height: 420px; overflow-y: auto; }
        .finding-instance { padding: 10px 0; border-bottom: 1px solid var(--border); }
        .finding-instance:last-child { border-bottom: none; }
        .finding-instance-object { font-weight: 600; color: var(--ink); font-family: 'Consolas', monospace; font-size: 0.9em; word-break: break-word; }
        .finding-instance-desc { color: var(--ink-muted); margin-top: 4px; line-height: 1.5; }
        .finding-instance-date { color: var(--ink-muted); font-size: 0.8em; margin-top: 4px; }
        .severity-badge { padding: 6px 15px; border-radius: 20px; font-weight: 700; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; color: #fff; }
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--high); }
        .severity-medium { background: var(--medium); }
        .severity-low { background: var(--low); }
        .finding-meta { display: flex; gap: 20px; margin-bottom: 15px; font-size: 0.9em; color: var(--ink-muted); flex-wrap: wrap; }
        .finding-meta span { display: flex; align-items: center; }
        .finding-meta strong { margin-right: 5px; color: var(--ink); }
        .finding-section { margin: 15px 0; padding: 15px; background: var(--surface); border-radius: 4px; border: 1px solid var(--border); }
        .finding-section h4 { color: var(--ink-muted); margin-bottom: 10px; font-size: 1em; text-transform: uppercase; letter-spacing: 0.5px; }
        .finding-section p { color: var(--ink); line-height: 1.7; }
        .privileged-users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .privileged-users-table th { background: var(--brand); color: #fff; padding: 12px; text-align: left; font-weight: 600; }
        .privileged-users-table td { padding: 10px; border-bottom: 1px solid var(--border); }
        .privileged-users-table tr:nth-child(even) { background: var(--bg); }
        .privileged-users-table tr:hover { background: #eaf1f8; }
        .status-enabled { color: var(--good); font-weight: bold; }
        .status-disabled { color: var(--critical); font-weight: bold; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 2px solid var(--border); text-align: center; color: var(--ink-muted); font-size: 0.9em; }
        .warning-box { background: #fdf8ec; border-left: 4px solid var(--medium); padding: 15px; margin: 20px 0; border-radius: 4px; }
        .warning-box p { color: #6b4e00; margin: 5px 0; }

        /* Risk score, maturity & category visuals - inline hand-built SVG, no chart library, no CDN */
        .scoring-grid { display: grid; grid-template-columns: minmax(260px, 1fr) minmax(260px, 1fr); gap: 20px; margin: 20px 0; }
        @media (max-width: 700px) { .scoring-grid { grid-template-columns: 1fr; } }
        .score-panel, .maturity-panel { padding: 25px; border-radius: 8px; background: var(--bg); border: 1px solid var(--border); }
        .gauge-wrap { display: flex; align-items: center; justify-content: center; gap: 20px; flex-wrap: wrap; }
        .gauge-svg-wrap { position: relative; width: 160px; height: 160px; flex: none; }
        .gauge-svg-wrap svg { width: 100%; height: 100%; }
        .gauge-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .gauge-center .num { font-size: 2.3em; font-weight: 700; color: var(--ink); line-height: 1; }
        .gauge-center .of { font-size: 0.85em; color: var(--ink-muted); }
        .score-meta { color: var(--ink); }
        .score-meta .hint { font-size: 0.85em; color: var(--ink-muted); margin-top: 8px; }
        .maturity-stepper { display: flex; gap: 6px; margin-top: 14px; flex-wrap: wrap; }
        .maturity-chip { flex: 1; min-width: 88px; padding: 8px 6px; border-radius: 4px; background: var(--surface); border: 1px solid var(--border); color: var(--ink-muted); font-size: 0.78em; text-align: center; }
        .maturity-chip .lvl { display: block; font-weight: 700; font-size: 1.15em; }
        .maturity-chip.reached { background: #eaf5ef; border-color: var(--good); color: var(--good); }
        .maturity-chip.current { background: var(--brand); border-color: var(--brand); color: #fff; }
        .maturity-head { font-size: 2.2em; font-weight: 700; color: var(--ink); }
        .maturity-head small { font-size: 0.45em; color: var(--ink-muted); font-weight: normal; }
        .mitre-table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }
        .mitre-table th { background: var(--brand); color: #fff; padding: 10px; text-align: left; }
        .mitre-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .mitre-table tr:nth-child(even) { background: var(--bg); }
        .mitre-id { font-family: 'Consolas', monospace; color: var(--brand); font-weight: 600; }
        .mitre-bar-cell { display: flex; align-items: center; gap: 8px; }
        .mitre-bar-track { display: block; width: 100px; height: 10px; background: var(--border); border-radius: 5px; overflow: hidden; flex: none; }
        .mitre-bar-fill { display: block; height: 100%; background: var(--brand); border-radius: 5px; }
        .tag-mitre { font-family: 'Consolas', monospace; background: #eaf2f8; color: #2471a3; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
        .tag-anssi { font-family: 'Consolas', monospace; background: #f4ecf7; color: #6c3483; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }

        /* Prioritized remediation order */
        .priority-list { list-style: none; margin: 15px 0; }
        .priority-item { display: grid; grid-template-columns: 34px 1fr auto; align-items: center; gap: 14px; padding: 12px 14px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 8px; background: var(--surface); }
        .priority-rank { font-weight: 700; color: var(--ink-muted); font-size: 1.2em; text-align: center; }
        .priority-item a { color: var(--ink); text-decoration: none; font-weight: 600; }
        .priority-item a:hover { text-decoration: underline; }
        .priority-cat { color: var(--ink-muted); font-size: 0.85em; font-weight: 400; display: block; margin-top: 2px; }

        /* Control path diagram */
        .control-path-diagram { margin: 10px 0 4px; }
        .control-path-diagram svg { width: 100%; height: auto; max-width: 640px; display: block; }

        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; border: none; }
            .toggle-all-btn { display: none; }
        }
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
    $stillLiveNotes = @($OfflineSkipNotes | Where-Object { $_.Mode -eq 'StillLive' })
    $liveConnectionClaim = if ($stillLiveNotes.Count -gt 0) {
        "$($stillLiveNotes.Count) specific sub-check(s) still performed live, read-only AD/network I/O during this run (listed below) - everything else came from the snapshot with no live connections."
    }
    else {
        "no live Active Directory or Domain Controller connections were made during this run."
    }
@"
        <div class="warning-box" style="background:#fdf5ec; border-color:#c8590b;">
            <p><strong>&#128190; OFFLINE / SNAPSHOT-BASED REPORT</strong></p>
            <p>This report was generated with <code>-FromSnapshot</code> from a previously collected snapshot - $liveConnectionClaim$(if ($snapshotCollectedDateText) { " The underlying snapshot data was collected on <strong>$snapshotCollectedDateText</strong>." }) Findings reflect the environment's state at collection time and may not include changes made since then.</p>
        </div>
$(if (@($OfflineSkipNotes).Count -gt 0) {
@"
        <div class="warning-box" style="background:#fdf8ec; border-color:#8a6200;">
            <p><strong>&#128269; OFFLINE MODE COVERAGE NOTES</strong> - $(@($OfflineSkipNotes).Count) sub-check(s) below were not evaluated from the snapshot, or ran live anyway. This is why an offline report can show different findings than a live run of the same audit against the same domain state.</p>
            <table class="mitre-table">
                <tr><th>Test</th><th>Sub-Check Not Covered From Snapshot</th><th>Status</th><th>Why</th></tr>
$(($OfflineSkipNotes | Sort-Object Test, Check | ForEach-Object {
    $statusBadge = if ($_.Mode -eq 'StillLive') {
        '<span style="background:#b3261e;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">STILL LIVE</span>'
    }
    else {
        '<span style="background:#5b6472;color:#fff;padding:2px 8px;border-radius:10px;font-size:0.85em;">SKIPPED</span>'
    }
    "                <tr><td>$(HtmlEncode $_.Test)</td><td>$(HtmlEncode $_.Check)</td><td>$statusBadge</td><td>$(HtmlEncode $_.Reason)</td></tr>"
}) -join "`n")
            </table>
            <p style="margin-top:10px; font-size:0.9em; color:#5b6472;">"SKIPPED" sub-checks contribute zero findings in this report - a like-for-like comparison against a live run must account for this coverage gap, not just the finding counts. "STILL LIVE" sub-checks ran and can contribute findings, but did so over a live connection despite <code>-FromSnapshot</code>.</p>
        </div>
"@
})
"@
})
        
        <div class="header-info">
            <div><strong>DOMAIN</strong><span style="font-size: 1.2em; color: #1f2937;">$(HtmlEncode $Domain)</span></div>
            <div><strong>REPORT DATE</strong><span style="font-size: 1.2em; color: #1f2937;">$reportDate</span></div>
            <div><strong>COLLECTION MODE</strong><span style="font-size: 1.2em; color: $runModeBadgeColor; font-weight:bold;">$(HtmlEncode $RunMode)</span></div>
            <div><strong>SCAN DURATION</strong><span style="font-size: 1.2em; color: #1f2937;">$([math]::Round($Duration.TotalSeconds, 2)) seconds</span></div>
            <div><strong>TOTAL FINDINGS</strong><span style="font-size: 1.2em; color: #1f2937;">$($Findings.Count)</span></div>
$(if ($isOfflineRun -and $snapshotCollectedDateText) {
"            <div><strong>SNAPSHOT COLLECTED</strong><span style=`"font-size: 1.2em; color: #1f2937;`">$snapshotCollectedDateText</span></div>"
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

    # --- Prioritized Remediation Order ---
    # Presentation-only: sorts the *already computed* findings/category scores;
    # no new scoring logic. Severity first (worst first), then that finding's
    # category sub-score (worst category first) as a tie-breaker, then the
    # number of affected objects. Links each item to its full evidence in the
    # severity-grouped sections below via a stable per-finding anchor id.
    $priorityCategoryScores = if ($RiskScore -and $RiskScore.CategoryScores) { $RiskScore.CategoryScores } else { @() }
    $priorityListHtml = Get-ADPriorityListHTML -Findings $Findings -CategoryScores $priorityCategoryScores -Top 10
    if ($priorityListHtml) {
        $html += @"
        <h2>&#128204; Prioritized Remediation Order</h2>
        <p style="color:#5b6472; margin-bottom: 10px;">The findings below are ranked worst-first - by severity, then by how risky their category is overall - as a starting work order. This is a starting point for planning, not a replacement for reviewing every finding.</p>
$priorityListHtml
"@
    }

    # --- Risk score, ANSSI maturity & MITRE ATT&CK summary (v1.2.0) ---
    if ($RiskScore) {
        $score = [int]$RiskScore.TotalScore
        # Color the gauge by severity band (higher = worse) - same bands used
        # for the category bars below, so the palette only has to be learned once.
        $gaugeColor = if ($score -ge 75) { '#b3261e' }
                      elseif ($score -ge 50) { '#c8590b' }
                      elseif ($score -ge 25) { '#8a6200' }
                      else { '#1a7f4e' }

        $maturityLevel = [int]$RiskScore.MaturityLevel
        $gaugeSvg = Get-ADSvgGauge -Score $score -Color $gaugeColor

        $html += @"
        <h2>&#127919; Risk Score &amp; Maturity</h2>
        <div class="scoring-grid">
            <div class="score-panel">
                <h3>Global Risk Score</h3>
                <div class="gauge-wrap">
                    $gaugeSvg
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
                <p style="color:#1f2937; margin: 6px 0 4px;">$(HtmlEncode $RiskScore.MaturityLabel)</p>
                <div class="maturity-stepper">
"@
        foreach ($lvl in 1..5) {
            $cls = 'maturity-chip'
            if ($lvl -eq $maturityLevel) { $cls = 'maturity-chip current' }
            elseif ($lvl -lt $maturityLevel) { $cls = 'maturity-chip reached' }
            $labelMap = @{
                1 = 'Critical gaps'
                2 = 'Partial hygiene'
                3 = 'Standard hardening'
                4 = 'Advanced hardening'
                5 = 'Optimal'
            }
            $html += @"
                    <div class="$cls"><span class="lvl">$lvl</span><span>$($labelMap[$lvl])</span></div>
"@
        }
        $html += @"
                </div>
                <p class="hint" style="font-size:0.85em; color:#5b6472; margin-top:10px;">A single Level&nbsp;1 finding caps maturity at Level&nbsp;1. Lower level = more critical hygiene gaps remain.</p>
            </div>
        </div>
"@

        # Per-category sub-score bars - rendered as one inline SVG chart
        # (worst category first, same severity-band coloring as the gauge).
        if ($RiskScore.CategoryScores -and $RiskScore.CategoryScores.Count -gt 0) {
            $categoryBarsSvg = Get-ADSvgCategoryBars -CategoryScores $RiskScore.CategoryScores
            $html += @"
        <h3>Risk by Category</h3>
        <div style="margin: 10px 0 20px;">
$categoryBarsSvg
        </div>
"@
        }

        # MITRE ATT&CK technique summary
        if ($RiskScore.MitreSummary -and $RiskScore.MitreSummary.Count -gt 0) {
            $mitreMaxCount = ($RiskScore.MitreSummary | Measure-Object -Property Count -Maximum).Maximum
            if ($mitreMaxCount -le 0) { $mitreMaxCount = 1 }
            $html += @"
        <h3>&#128506; MITRE ATT&amp;CK Technique Summary</h3>
        <div style="overflow-x: auto;">
            <table class="mitre-table">
                <thead><tr><th>Technique</th><th>Name</th><th>Findings</th></tr></thead>
                <tbody>
"@
            foreach ($t in $RiskScore.MitreSummary) {
                $barPct = [math]::Round(($t.Count / $mitreMaxCount) * 100, 0)
                $html += @"
                    <tr>
                        <td class="mitre-id">$(HtmlEncode $t.Technique)</td>
                        <td>$(HtmlEncode $t.Name)</td>
                        <td><div class="mitre-bar-cell"><span class="mitre-bar-track"><span class="mitre-bar-fill" style="width: $barPct%;"></span></span><span>$($t.Count)</span></div></td>
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
        <p style="margin-bottom: 15px; color: #5b6472;">The following $($PrivilegedUsers.Count) user accounts have membership in one or more privileged groups. Review these accounts regularly to ensure appropriate access levels.</p>
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
        <p style="color:#5b6472; margin-bottom: 15px;">Chained group-membership, ACL, and ownership relationships that let a non-privileged principal reach a Tier-0 object (Domain Admins/DCs/AdminSDHolder/domain head). No single hop here need look critical on its own - see each finding below for full remediation guidance.</p>
"@
        foreach ($cp in $controlPathFindings) {
            $sevClass = $cp.Severity.ToLower()
            $hopChain = if ($cp.Details -and $cp.Details.ContainsKey('HopChain')) { HtmlEncode "$($cp.Details.HopChain)" } else { HtmlEncode $cp.AffectedObject }
            $diagramSvg = ''
            if ($cp.Details -and $cp.Details.ContainsKey('Source') -and $cp.Details.ContainsKey('Target')) {
                $diagramColor = if ($sevClass -eq 'critical') { '#b3261e' } else { '#c8590b' }
                $hopCountForDiagram = if ($cp.Details.ContainsKey('HopCount')) { [int]$cp.Details.HopCount } else { 1 }
                $diagramSvg = Get-ADSvgControlPathDiagram -Source "$($cp.Details.Source)" -Target "$($cp.Details.Target)" -HopCount $hopCountForDiagram -Color $diagramColor
            }
            $html += @"
        <div class="finding $sevClass" style="border-left-width: 5px;">
            <div class="finding-header">
                <div class="finding-title">$(HtmlEncode $cp.Issue)</div>
                <span class="severity-badge severity-$sevClass">$($cp.Severity)</span>
            </div>
$diagramSvg
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

#region Report visual components (v1.20.0)
# Presentation-only helpers: each renders an already-computed value
# (RiskScore fields, Finding fields) as inline SVG or HTML. None of these
# perform any new scoring, detection, or AD query - see Feature 16
# (html-report-visual-overhaul) for the design rationale. No chart library
# or external asset is used anywhere in this region.

function Get-ADFindingAnchorId {
    <#
    .SYNOPSIS
        Builds a stable, URL-safe anchor id for a Category+Issue pair so the
        Prioritized Remediation Order list can link straight to a finding's
        full evidence in the severity-grouped sections below it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Issue
    )
    $slug = ("$Category-$Issue").ToLower()
    $slug = [System.Text.RegularExpressions.Regex]::Replace($slug, '[^a-z0-9]+', '-')
    $slug = $slug.Trim('-')
    if ([string]::IsNullOrEmpty($slug)) { $slug = 'finding' }
    return "finding-$slug"
}

function Get-ADSvgGauge {
    <#
    .SYNOPSIS
        Renders a 0-100 score as a self-contained inline SVG ring gauge: two
        <circle> elements (a light track and a colored progress ring) using
        stroke-dasharray for the arc length. No canvas, no chart library.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Score,
        [Parameter(Mandatory)][string]$Color
    )
    $clamped = [math]::Max(0, [math]::Min(100, $Score))
    $radius = 70
    $circumference = [math]::Round(2 * [math]::PI * $radius, 2)
    $dash = [math]::Round($circumference * ($clamped / 100.0), 2)
    $gap = [math]::Round($circumference - $dash, 2)
    return @"
<div class="gauge-svg-wrap">
    <svg viewBox="0 0 160 160" role="img" aria-label="Risk score $clamped out of 100">
        <circle cx="80" cy="80" r="$radius" fill="none" stroke="#e2e6ea" stroke-width="14" />
        <circle cx="80" cy="80" r="$radius" fill="none" stroke="$Color" stroke-width="14"
                stroke-linecap="round" stroke-dasharray="$dash $gap"
                transform="rotate(-90 80 80)" />
    </svg>
    <div class="gauge-center">
        <div class="num">$clamped</div>
        <div class="of">/ 100</div>
    </div>
</div>
"@
}

function Get-ADSvgCategoryBars {
    <#
    .SYNOPSIS
        Renders per-category risk sub-scores (already sorted worst-first by
        the caller) as a single horizontal inline SVG bar chart, using the
        same severity-band coloring as the global gauge.
    .NOTES
        Category name labels are drawn as SVG <text> at a fixed font size and
        are not measured/wrapped - very long category names may visually
        crowd the bar for that row. Acceptable for the category names in use
        today; revisit if a much longer category name is introduced.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$CategoryScores
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    function Get-BandColor([int]$s) {
        if ($s -ge 75) { return '#b3261e' }
        elseif ($s -ge 50) { return '#c8590b' }
        elseif ($s -ge 25) { return '#8a6200' }
        else { return '#1a7f4e' }
    }

    $rowHeight  = 34
    $chartWidth = 700
    $labelWidth = 230
    $barAreaW   = $chartWidth - $labelWidth - 60
    $height     = ($rowHeight * @($CategoryScores).Count) + 10

    $rowsSvg = ''
    $y = 4
    foreach ($cat in $CategoryScores) {
        $score = [int]$cat.Score
        $barW  = [math]::Round(($score / 100.0) * $barAreaW, 1)
        if ($barW -lt 2 -and $score -gt 0) { $barW = 2 }
        $color = Get-BandColor $score
        $label = HtmlEncode "$($cat.Category) ($($cat.Findings))"
        $textY = $y + 20
        $numX  = $labelWidth + $barAreaW + 10
        $rowsSvg += @"
    <text x="0" y="$textY" font-size="12.5" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$label</text>
    <rect x="$labelWidth" y="$y" width="$barAreaW" height="22" rx="4" fill="#e2e6ea" />
    <rect x="$labelWidth" y="$y" width="$barW" height="22" rx="4" fill="$color" />
    <text x="$numX" y="$textY" font-size="13" font-weight="700" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$score</text>

"@
        $y += $rowHeight
    }

    return @"
<svg viewBox="0 0 $chartWidth $height" role="img" aria-label="Risk score by category">
$rowsSvg
</svg>
"@
}

function Get-ADSvgControlPathDiagram {
    <#
    .SYNOPSIS
        Renders a simplified 3-node diagram (source -> N hops -> Tier-0
        target) for a single control-path finding. This is an at-a-glance
        summary, not a replacement for the full hop-by-hop chain, which
        remains available as text (Details.HopChain) directly below it.
    .NOTES
        Source/Target labels are drawn as fixed-size SVG <text> and are not
        measured or truncated - very long object names may overflow their box
        visually. The authoritative text remains the hop-chain paragraph
        below the diagram.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][int]$HopCount,
        [Parameter(Mandatory)][string]$Color
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }
    $srcLabel = HtmlEncode $Source
    $tgtLabel = HtmlEncode $Target
    $hopLabel = if ($HopCount -eq 1) { '1 hop' } else { "$HopCount hops" }

    return @"
        <div class="control-path-diagram">
        <svg viewBox="0 0 640 90" role="img" aria-label="$srcLabel to $tgtLabel via $hopLabel">
            <rect x="4" y="24" width="220" height="42" rx="6" fill="#f4f6f8" stroke="#e2e6ea" />
            <text x="114" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">$srcLabel</text>
            <line x1="228" y1="45" x2="404" y2="45" stroke="$Color" stroke-width="3" />
            <polygon points="404,38 418,45 404,52" fill="$Color" />
            <text x="316" y="34" font-size="12" text-anchor="middle" fill="$Color" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">$hopLabel</text>
            <rect x="418" y="24" width="218" height="42" rx="6" fill="#fdf1f0" stroke="$Color" />
            <text x="527" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">$tgtLabel</text>
        </svg>
        </div>
"@
}

function Get-ADPriorityListHTML {
    <#
    .SYNOPSIS
        Builds the "Prioritized Remediation Order" list: the existing
        findings, grouped and sorted worst-first (by severity, then by that
        finding's category risk score, then by affected-object count), linked
        to their full evidence via Get-ADFindingAnchorId. No new scoring.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [Parameter()][array]$CategoryScores = @(),
        [Parameter()][int]$Top = 10
    )
    function HtmlEncode($text) {
        if ($text) {
            return $text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
        }
        return $text
    }

    if (-not $Findings -or @($Findings).Count -eq 0) { return '' }

    $catScoreMap = @{}
    foreach ($c in $CategoryScores) { $catScoreMap[$c.Category] = [int]$c.Score }

    $groups = @($Findings | Group-Object -Property Category, Issue)
    $ranked = foreach ($g in $groups) {
        $first = $g.Group[0]
        $catScore = if ($catScoreMap.ContainsKey($first.Category)) { $catScoreMap[$first.Category] } else { 0 }
        [PSCustomObject]@{
            Category      = $first.Category
            Issue         = $first.Issue
            Severity      = $first.Severity
            SeverityLevel = [int]$first.SeverityLevel
            CategoryScore = $catScore
            Count         = $g.Count
            AnchorId      = Get-ADFindingAnchorId -Category $first.Category -Issue $first.Issue
        }
    }
    $ranked = @($ranked | Sort-Object -Property SeverityLevel, CategoryScore, Count -Descending | Select-Object -First $Top)
    if ($ranked.Count -eq 0) { return '' }

    $rank = 0
    $items = foreach ($r in $ranked) {
        $rank++
        $sevClass = $r.Severity.ToLower()
        $objWord = if ($r.Count -eq 1) { 'object' } else { 'objects' }
        @"
    <li class="priority-item">
        <span class="priority-rank">$rank</span>
        <a href="#$($r.AnchorId)">$(HtmlEncode $r.Issue)<span class="priority-cat">$(HtmlEncode $r.Category) &middot; $($r.Count) affected $objWord</span></a>
        <span class="severity-badge severity-$sevClass">$($r.Severity)</span>
    </li>
"@
    }
    return @"
<ol class="priority-list">
$($items -join "`n")
</ol>
"@
}

#endregion

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
    $anchorId = Get-ADFindingAnchorId -Category $first.Category -Issue $first.Issue

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
        <details class="finding $severityClass" id="$anchorId">
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
        <details class="finding $severityClass" id="$anchorId">
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

