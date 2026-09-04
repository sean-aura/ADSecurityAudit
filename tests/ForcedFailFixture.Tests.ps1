#Requires -Modules Pester
<#
    Full-pipeline smoke test against the three tiered
    tests/fixtures/ForcedFail-*pct-Snapshot.json fixtures - see
    tests/fixtures/README.md for what these are and why they exist.

    Unlike every other *.Tests.ps1 file in this folder (which test one
    function in isolation with hand-built minimal fixtures), this one loads
    the REAL module and runs Invoke-ADRuleSet against the REAL, full
    ForcedFail fixtures - the same code path Start-ADSecurityAudit
    -FromSnapshot uses - then checks:

      1. The pipeline runs to completion with a healthy number of findings
         across multiple categories for each tier (catches "a check now
         throws" / "a check now finds nothing" regressions).
      2. Finding volume decreases monotonically 100% -> 60% -> 25%, i.e.
         the tiers are actually ordered the way their names claim.
      3. The specific duplicate-finding regressions the 100%-tier fixture
         was built to catch (see the "Deliberately duplicated entries"
         table in tests/fixtures/README.md) have NOT reappeared.
      4. The findings still serialize cleanly through
         ConvertTo-ADFindingsCsvRows (the CSV export path) with no errors
         and one row per finding.

    This is intentionally coarser than the other unit tests: it doesn't
    assert exact finding counts per category, because legitimate wording/
    severity changes to existing checks would make it brittle. It asserts
    the things that would actually indicate a real regression: total
    volume, tier ordering, specific known dedup cases, and successful
    serialization.

    Run from the repo root:  Invoke-Pester ./tests/ForcedFailFixture.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot

    # Dot-source every module file directly, in the same order
    # ADSecurityAudit.psm1 itself loads them - NOT Import-Module, since
    # several functions this test needs (ConvertTo-ADHashtable,
    # ConvertTo-ADFindingsCsvRows, Reset-ADTestCoverageTracker,
    # Reset-ADOfflineSkipNotes) are internal helpers, not in the module's
    # public Export-ModuleMember list, and so aren't callable after a
    # normal Import-Module. Dot-sourcing exposes everything, same as every
    # other test file in this folder already does for its own subset of
    # files.
    $moduleScripts = @(
        'src/Common.ps1', 'src/Scoring.ps1', 'src/FindingNarrativeLibrary.ps1', 'src/Snapshot.ps1',
        'src/UserAudits.ps1', 'src/GroupAudits.ps1', 'src/AdminSDAudits.ps1', 'src/GpoAudits.ps1',
        'src/ReplicationAudits.ps1', 'src/DomainSecurityAudits.ps1', 'src/PermissionsAudits.ps1',
        'src/PrivilegedUsers.ps1', 'src/CertificateServicesAudits.ps1', 'src/CertificateServicesExtendedAudits.ps1',
        'src/KrbtgtAudits.ps1', 'src/DomainTrustAudits.ps1', 'src/LapsAudits.ps1', 'src/AuditPolicyAudits.ps1',
        'src/DelegationAudits.ps1', 'src/DomainAdminEquivalence.ps1', 'src/MachineAccountQuotaAudits.ps1',
        'src/DomainHardeningAudits.ps1', 'src/CoercionRelayAudits.ps1', 'src/DnsSecurityAudits.ps1',
        'src/LegacyAuthAudits.ps1', 'src/KerberosHardeningAudits.ps1', 'src/StaleObjectDepthAudits.ps1',
        'src/GpoSecretsAudits.ps1', 'src/KnownVulnAudits.ps1', 'src/ExchangeEscalationAudits.ps1',
        'src/RodcSecurityAudits.ps1', 'src/ControlPaths.ps1', 'src/ForestConsolidation.ps1',
        'src/RetestComparison.ps1', 'src/RemediationState.ps1', 'src/MaturityTrend.ps1',
        'src/Main.ps1', 'src/Reporting.ps1'
    )
    foreach ($ms in $moduleScripts) { . (Join-Path $root $ms) }

    function Get-ForcedFailFindings {
        param([int]$Tier)
        $fixturePath = Join-Path $PSScriptRoot "fixtures/ForcedFail-${Tier}pct-Snapshot.json"
        $rawSnapshot = Get-Content -Path $fixturePath -Raw | ConvertFrom-Json
        $snapshot = ConvertTo-ADHashtable -InputObject $rawSnapshot
        Reset-ADTestCoverageTracker
        Reset-ADOfflineSkipNotes
        return @(Invoke-ADRuleSet -Snapshot $snapshot)
    }

    $script:Findings100 = Get-ForcedFailFindings -Tier 100
    $script:Findings60  = Get-ForcedFailFindings -Tier 60
    $script:Findings25  = Get-ForcedFailFindings -Tier 25
}

Describe 'ForcedFail fixtures - full pipeline smoke test' {
    Context 'Each tier runs cleanly and produces plausible volume' {
        It 'the 100%-tier fixture produces a healthy number of findings across multiple categories' {
            $script:Findings100.Count | Should -BeGreaterThan 20
            @($script:Findings100 | Select-Object -ExpandProperty Category -Unique).Count | Should -BeGreaterThan 8
        }

        It 'the 60%-tier fixture produces fewer findings than the 100%-tier fixture' {
            $script:Findings60.Count | Should -BeLessThan $script:Findings100.Count
            $script:Findings60.Count | Should -BeGreaterThan 5
        }

        It 'the 25%-tier fixture produces fewer findings than the 60%-tier fixture' {
            $script:Findings25.Count | Should -BeLessThan $script:Findings60.Count
        }

        It 'every finding in every tier has the required non-empty fields' {
            foreach ($f in ($script:Findings100 + $script:Findings60 + $script:Findings25)) {
                $f.Category | Should -Not -BeNullOrEmpty
                $f.Issue | Should -Not -BeNullOrEmpty
                $f.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Info')
            }
        }
    }

    # --- Deliberately-duplicated-entry regression checks (100%-tier fixture only - see README.md) ---
    Context 'Duplicate-finding regression coverage (100%-tier fixture)' {
        It 'AdminSDHolder: does not duplicate a finding for a trustee with two same-rights ACEs' {
            $hits = @($script:Findings100 | Where-Object {
                $_.Issue -eq 'Non-Standard Permissions on AdminSDHolder' -and $_.AffectedObject -match 'svc-helpdesk'
            })
            $hits.Count | Should -Be 1
        }

        It 'DCSync: aggregates two different specific rights on one trustee into ONE finding' {
            $hits = @($script:Findings100 | Where-Object {
                $_.Issue -eq 'Unauthorized DCSync Permissions' -and $_.AffectedObject -match 'svc-sync'
            })
            $hits.Count | Should -Be 1
            $hits[0].Description | Should -Match 'DS-Replication-Get-Changes'
        }

        It 'Configuration NC: does not duplicate a finding for a trustee with two same-rights ACEs' {
            $hits = @($script:Findings100 | Where-Object {
                $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' -and $_.AffectedObject -match 'svc-helpdesk'
            })
            $hits.Count | Should -Be 1
        }

        It 'ESC7/Low-Priv CA rights: does not duplicate findings when the CA ACL has repeated ACEs' {
            $esc7 = @($script:Findings100 | Where-Object { $_.Issue -eq 'Overly Permissive CA Permissions (ESC7)' })
            $esc7.Count | Should -Be 1
            $lowPriv = @($script:Findings100 | Where-Object { $_.Issue -eq 'Low-Privilege CA Management Rights' })
            $lowPriv.Count | Should -Be 1
        }

        It 'ESC1: does not list the same low-privilege enrollment principal twice' {
            $esc1 = @($script:Findings100 | Where-Object { $_.Issue -eq 'Certificate Template Allows Subject Alternative Name (ESC1)' })
            $esc1.Count | Should -Be 1
            (($esc1[0].Description -split 'Domain Users').Count - 1) | Should -Be 1
        }

        It 'Domain Admin Equivalence: lists a repeated ACE as one evidence bullet, not two' {
            $hit = $script:Findings100 | Where-Object {
                $_.Issue -eq 'Domain Admin Equivalent Access Detected' -and $_.AffectedObject -eq 'Administrator'
            }
            $hit | Should -Not -BeNullOrEmpty
            @($hit.Details.Evidence).Count | Should -Be 2
        }
    }

    Context 'CSV export fidelity' {
        It 'every finding in the 100%-tier fixture serializes through ConvertTo-ADFindingsCsvRows with no errors' {
            { $script:CsvRows = ConvertTo-ADFindingsCsvRows -Findings $script:Findings100 } | Should -Not -Throw
            $script:CsvRows.Count | Should -Be $script:Findings100.Count
        }

        It 'the CSV Details column preserves nested array data (not just a top-level summary)' {
            $dcSyncRow = $script:CsvRows | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' -and $_.AffectedObject -match 'svc-sync' }
            $dcSyncRow | Should -Not -BeNullOrEmpty
            $dcSyncRow.Details | Should -Match 'DS-Replication-Get-Changes'
        }
    }
}

