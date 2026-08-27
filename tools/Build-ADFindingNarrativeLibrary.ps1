<#
.SYNOPSIS
    Regenerates src/FindingNarrativeLibrary.ps1 by extracting the current
    EstimatedEffort/KnownRisks/BackupRollback/OperationalNotes text straight
    out of every finding-generation block in src/*.ps1.
.DESCRIPTION
    src/FindingNarrativeLibrary.ps1 exists to backfill those four
    "supporting information" fields on findings loaded from an older JSON
    export that predates them (or predates a given Issue's current
    wording) - see Merge-ADFindingNarrativeGaps in src/Common.ps1 and
    Export-ADSecurityReportHTMLFromJson in src/Reporting.ps1.

    Rather than hand-maintain a second copy of ~110+ boilerplate strings
    (guaranteed to drift from the real source), this script parses every
    "$finding = [ADSecurityFinding]::new() ... $findings += $finding"
    block across src/*.ps1, extracts Issue + the four fields when
    present, and writes them out keyed by Issue name. Re-run this
    whenever a check's Issue name changes, or its EstimatedEffort/
    KnownRisks/BackupRollback/OperationalNotes wording is edited, and
    commit the regenerated src/FindingNarrativeLibrary.ps1 alongside
    that change - otherwise the library silently keeps serving the OLD
    wording as a "current guidance" backfill for older JSON exports.

    Only string-literal assignments are extracted (single- or
    double-quoted, PowerShell ''-escaped single quotes handled). As of
    this writing every EstimatedEffort/KnownRisks/BackupRollback/
    OperationalNotes assignment in the codebase is a plain literal (no
    per-instance $variable interpolation - these four fields are
    boilerplate risk-communication text, not per-instance data), so this
    captures everything; if a future check ever needs a genuinely
    per-instance value in one of these four fields, that Issue simply
    won't extract cleanly here and will need a manual library entry (or
    to accept that this backfill can't help findings without a
    library entry, which is the existing conservative default in
    Merge-ADFindingNarrativeGaps).

    Where the SAME Issue name is used for more than one distinct finding
    block with different text for these fields (a handful of cases in
    PermissionsAudits.ps1 today - the same Issue populated once for the
    -Snapshot path and once for the live path, worded slightly
    differently), the FIRST occurrence encountered wins and a warning is
    printed - this is a best-effort backfill tool, not an exact
    reproduction of "what the original run would have shown."
.PARAMETER SourceRoot
    Root of the ADSecurityAudit repo (containing src/). Defaults to the
    parent of this script's own folder.
.PARAMETER OutputPath
    Where to write the regenerated library. Defaults to
    src/FindingNarrativeLibrary.ps1 under -SourceRoot.
.EXAMPLE
    ./tools/Build-ADFindingNarrativeLibrary.ps1
.EXAMPLE
    ./tools/Build-ADFindingNarrativeLibrary.ps1 -WhatIf
    # Preview without writing, printing entry count and any conflicts.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),

    [Parameter()]
    [string]$OutputPath
)

if (-not $OutputPath) {
    $OutputPath = Join-Path $SourceRoot 'src/FindingNarrativeLibrary.ps1'
}

$srcDir = Join-Path $SourceRoot 'src'
if (-not (Test-Path $srcDir)) {
    throw "Could not find 'src' under -SourceRoot '$SourceRoot'."
}

function Get-ADQuotedFieldValue {
    <#
    Extracts the value of "$finding.<Field> = '...'" or "= "...""
    from a block of source text, handling PowerShell's doubled-single-
    quote escaping. Returns $null if the field isn't assigned a plain
    string literal in this block (e.g. omitted entirely, or the rare
    interpolated/dynamic case this tool intentionally doesn't handle).
    #>
    param([string]$Block, [string]$Field)

    $singleQuoted = [regex]::Match($Block, "\`$finding\.$Field\s*=\s*'((?:[^']|'')*)'", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($singleQuoted.Success) {
        return $singleQuoted.Groups[1].Value -replace "''", "'"
    }
    $doubleQuoted = [regex]::Match($Block, "\`$finding\.$Field\s*=\s*`"((?:[^`"]|`"`")*)`"", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($doubleQuoted.Success) {
        return $doubleQuoted.Groups[1].Value
    }
    return $null
}

$blockPattern = [regex]::new('\$finding\s*=\s*\[ADSecurityFinding\]::new\(\)(.*?)\$findings\s*\+=\s*\$finding', [System.Text.RegularExpressions.RegexOptions]::Singleline)

$library = [ordered]@{}
$order = [System.Collections.Generic.List[string]]::new()
$conflicts = [System.Collections.Generic.List[string]]::new()
$blocksScanned = 0
$blocksWithEnrichment = 0

Get-ChildItem -Path $srcDir -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
    $text = Get-Content -Path $_.FullName -Raw
    foreach ($match in $blockPattern.Matches($text)) {
        $blocksScanned++
        $block = $match.Groups[1].Value
        $issue = Get-ADQuotedFieldValue -Block $block -Field 'Issue'
        if (-not $issue) { continue }

        $effort   = Get-ADQuotedFieldValue -Block $block -Field 'EstimatedEffort'
        $risks    = Get-ADQuotedFieldValue -Block $block -Field 'KnownRisks'
        $rollback = Get-ADQuotedFieldValue -Block $block -Field 'BackupRollback'
        $opNotes  = Get-ADQuotedFieldValue -Block $block -Field 'OperationalNotes'

        if (-not ($effort -or $risks -or $rollback -or $opNotes)) { continue }
        $blocksWithEnrichment++

        if ($library.Contains($issue)) {
            $prev = $library[$issue]
            if ($prev.EstimatedEffort -ne $effort -or $prev.KnownRisks -ne $risks -or
                $prev.BackupRollback -ne $rollback -or $prev.OperationalNotes -ne $opNotes) {
                $conflicts.Add("'$issue' (in $($_.Name)) - keeping first-seen text, this occurrence differs")
            }
            continue
        }

        $library[$issue] = [PSCustomObject]@{
            EstimatedEffort  = $effort
            KnownRisks       = $risks
            BackupRollback   = $rollback
            OperationalNotes = $opNotes
        }
        $order.Add($issue)
    }
}

Write-Host "Scanned $blocksScanned finding block(s) across $((Get-ChildItem -Path $srcDir -Filter '*.ps1').Count) file(s)."
Write-Host "$blocksWithEnrichment block(s) had at least one of the four fields; $($library.Count) distinct Issue name(s) captured."
if ($conflicts.Count -gt 0) {
    Write-Warning "Same Issue name, different text, in $($conflicts.Count) case(s) - first occurrence wins:"
    $conflicts | ForEach-Object { Write-Warning "  $_" }
}

function ConvertTo-ADPowerShellSingleQuoted {
    param([string]$Value)
    if ($null -eq $Value) { return '$null' }
    return "'" + ($Value -replace "'", "''") + "'"
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('# AUTO-EXTRACTED from src/*.ps1 finding-generation blocks. See')
$lines.Add('# tools/Build-ADFindingNarrativeLibrary.ps1 for how this is generated and')
$lines.Add("# how to regenerate it after adding/editing a check's EstimatedEffort/")
$lines.Add('# KnownRisks/BackupRollback/OperationalNotes text.')
$lines.Add('#')
$lines.Add('# Keyed by Issue name. Used ONLY to backfill these four fields on findings')
$lines.Add('# loaded from an older JSON export that predates them (or predates the')
$lines.Add('# specific Issue''s current wording) - see Merge-ADFindingNarrativeGaps in')
$lines.Add('# Common.ps1. Never overwrites a field the loaded finding already has a')
$lines.Add('# non-blank value for.')
$lines.Add('$Script:ADFindingNarrativeLibrary = @{')
foreach ($key in $order) {
    $e = $library[$key]
    $lines.Add("    $(ConvertTo-ADPowerShellSingleQuoted $key) = @{")
    $lines.Add("        EstimatedEffort  = $(ConvertTo-ADPowerShellSingleQuoted $e.EstimatedEffort)")
    $lines.Add("        KnownRisks       = $(ConvertTo-ADPowerShellSingleQuoted $e.KnownRisks)")
    $lines.Add("        BackupRollback   = $(ConvertTo-ADPowerShellSingleQuoted $e.BackupRollback)")
    $lines.Add("        OperationalNotes = $(ConvertTo-ADPowerShellSingleQuoted $e.OperationalNotes)")
    $lines.Add('    }')
}
$lines.Add('}')

$content = ($lines -join "`n") + "`n"

if ($PSCmdlet.ShouldProcess($OutputPath, 'Write regenerated finding narrative library')) {
    Set-Content -Path $OutputPath -Value $content -Encoding UTF8 -NoNewline
    Write-Host "Wrote $OutputPath ($($library.Count) entries)."
}
else {
    Write-Host "-WhatIf: would write $OutputPath ($($library.Count) entries)."
}
