<#
.SYNOPSIS
    Runs the full ADSecurityAudit pipeline against one of the three tiered
    tests/fixtures/ForcedFail-*pct-Snapshot.json fixtures and drops real
    JSON/CSV/HTML/TestCoverage output next to it, with no live AD access at
    all.
.DESCRIPTION
    Three synthetic -FromSnapshot fixtures, each a fake domain
    ("contoso.local") with a different proportion of its ~23 -Snapshot-
    capable checks deliberately misconfigured:

        -Tier 100  ForcedFail-100pct-Snapshot.json  - every controllable
                    "dirty area" is present (the worst-case report)
        -Tier 60   ForcedFail-60pct-Snapshot.json    - roughly 60% dirty
        -Tier 25   ForcedFail-25pct-Snapshot.json    - roughly 25% dirty

    (5 of the 28 registered checks - KnownDCVulnerabilities,
    GpoDeployedSecrets, LegacyAuthSurface, CoercionAndRelayExposure,
    RodcSecurity - always return zero findings under -FromSnapshot by
    design, regardless of fixture data, since their entire detection logic
    is real-time machine/network state with no AD-schema/snapshot
    equivalent. The percentages above are relative to the 23 checks that
    CAN produce a finding offline - see tests/fixtures/README.md for the
    full explanation and the exact "dirty area" breakdown per tier.)

    This exists so a code change to any check can be smoke-tested end-to-end
    (real JSON -> real CSV -> real HTML, real scoring, real Test Coverage
    tracking) without needing a live domain, a VM, or RSAT tools installed,
    and so you can see what the report looks like at different overall
    severity levels. It complements (does not replace) the Snapshot-mode
    unit tests under tests/ - these fixtures are for eyeballing full report
    output and catching integration-level regressions, not for asserting
    exact per-check behavior.

    IMPORTANT - keeping these fixtures current: whenever a check's
    detection logic changes meaningfully, consider whether the fixtures
    (regenerated via tools/build-forcedfail-fixtures.py, a Python
    maintainer utility - NOT part of the PowerShell module) should be
    updated to exercise it - see the "Maintenance" section in
    tests/fixtures/README.md. A fixture that never changes gradually stops
    testing anything new.
.PARAMETER Tier
    Which fixture to run: 100, 60, or 25. Defaults to 100 (the fullest,
    most illustrative report).
.PARAMETER OutputPath
    Where to write the generated JSON/CSV/HTML/TestCoverage files. Defaults
    to a gitignored 'output' folder next to the fixture so a routine run
    never dirties the repo.
.EXAMPLE
    .\tools\Test-ForcedFailFixture.ps1
    Runs the 100%-tier fixture and writes output under tests/fixtures/output/.
.EXAMPLE
    .\tools\Test-ForcedFailFixture.ps1 -Tier 25 -OutputPath C:\Temp\forcedfail-25
    Runs the 25%-tier fixture and writes output to a specific folder instead.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet(100, 60, 25)]
    [int]$Tier = 100,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$fixturePath = Join-Path $repoRoot "tests/fixtures/ForcedFail-${Tier}pct-Snapshot.json"

if (-not (Test-Path $fixturePath)) {
    Write-Error "Fixture not found at '$fixturePath'. Run this script from a checkout that includes tests/fixtures/ForcedFail-${Tier}pct-Snapshot.json."
    return
}

if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot "tests/fixtures/output/${Tier}pct"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "Loading module from '$repoRoot'..." -ForegroundColor Cyan
Import-Module (Join-Path $repoRoot 'ADSecurityAudit.psd1') -Force

Write-Host "Running Start-ADSecurityAudit -FromSnapshot against the $Tier% ForcedFail fixture (no live AD access)...`n" -ForegroundColor Cyan
Start-ADSecurityAudit -FromSnapshot $fixturePath -ExportPath $OutputPath -Verbose:$false

Write-Host "`nDone. Output written to '$OutputPath'." -ForegroundColor Green
Write-Host "Open the .html file to eyeball the full report, or diff the .json/.csv against a previous run to spot unintended changes." -ForegroundColor Green

