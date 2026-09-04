#Requires -Modules Pester
<#
    Regression test for Test-ADDomainTrusts' snapshot-mode "Trust Password
    Not Recently Rotated" check.

    Found via tracing the ForcedFail fixtures (tests/fixtures/) against the
    codebase: Snapshot.Trusts[].Modified can come back as a [string] after
    a JSON round-trip (-ToJson / -FromSnapshot), the same well-documented
    scenario UserAudits.ps1 and KrbtgtAudits.ps1 already defensively handle
    for their own date fields (PasswordLastSet/LastLogonDate) - but
    Test-ADDomainTrusts' snapshot branch did the subtraction
    `(Get-Date) - $trust.Modified` directly with no equivalent [datetime]
    cast, unlike the established pattern elsewhere in this codebase.

    This test constructs a snapshot with Modified as a plain ISO-8601
    string (exactly what ConvertFrom-Json leaves a non-".NET Date(ticks)"
    date string as) and confirms the age-based finding still fires
    correctly rather than throwing or silently failing to evaluate.

    Run from the repo root:  Invoke-Pester ./tests/DomainTrustAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DomainTrustAudits.ps1')
}

Describe 'Test-ADDomainTrusts - Modified date-cast regression (snapshot mode)' {
    It 'still flags an old trust password when Modified is a plain ISO-8601 string, not a [datetime]' {
        $oldIsoString = (Get-Date).AddDays(-400).ToString('yyyy-MM-ddTHH:mm:ss')
        $oldIsoString | Should -BeOfType [string]

        $snapshot = @{
            Domain = [PSCustomObject]@{ DNSRoot = 'contoso.com' }
            Trusts = @(
                [PSCustomObject]@{
                    Target = 'partner.external'; Direction = 'Outbound'; TrustType = 'External'
                    SIDFilteringQuarantined = $true; SelectiveAuthentication = $true
                    Created = $oldIsoString; Modified = $oldIsoString
                }
            )
        }

        { $script:Findings = Test-ADDomainTrusts -Snapshot $snapshot } | Should -Not -Throw

        $hit = $script:Findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' }
        $hit | Should -Not -BeNullOrEmpty
        $hit.Details.DaysSinceModified | Should -BeGreaterThan 30
    }

    It 'does not flag a recently-modified trust, string date or not' {
        $recentIsoString = (Get-Date).AddDays(-5).ToString('yyyy-MM-ddTHH:mm:ss')

        $snapshot = @{
            Domain = [PSCustomObject]@{ DNSRoot = 'contoso.com' }
            Trusts = @(
                [PSCustomObject]@{
                    Target = 'partner.external'; Direction = 'Outbound'; TrustType = 'External'
                    SIDFilteringQuarantined = $true; SelectiveAuthentication = $true
                    Created = $recentIsoString; Modified = $recentIsoString
                }
            )
        }

        $findings = Test-ADDomainTrusts -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' })

        $hits.Count | Should -Be 0
    }

    It 'still works when Modified is already a native [datetime] (no regression for the normal case)' {
        $snapshot = @{
            Domain = [PSCustomObject]@{ DNSRoot = 'contoso.com' }
            Trusts = @(
                [PSCustomObject]@{
                    Target = 'partner.external'; Direction = 'Outbound'; TrustType = 'External'
                    SIDFilteringQuarantined = $true; SelectiveAuthentication = $true
                    Created = (Get-Date).AddDays(-400); Modified = (Get-Date).AddDays(-400)
                }
            )
        }

        $findings = Test-ADDomainTrusts -Snapshot $snapshot
        $hit = $findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' }

        $hit | Should -Not -BeNullOrEmpty
    }

    It 'does not throw and simply skips the age check when Modified is an unparsable string' {
        $snapshot = @{
            Domain = [PSCustomObject]@{ DNSRoot = 'contoso.com' }
            Trusts = @(
                [PSCustomObject]@{
                    Target = 'partner.external'; Direction = 'Outbound'; TrustType = 'External'
                    SIDFilteringQuarantined = $true; SelectiveAuthentication = $true
                    Created = 'not-a-date'; Modified = 'not-a-date'
                }
            )
        }

        { $script:Findings = Test-ADDomainTrusts -Snapshot $snapshot } | Should -Not -Throw
        $hits = @($script:Findings | Where-Object { $_.Issue -eq 'Trust Password Not Recently Rotated' })
        $hits.Count | Should -Be 0
    }
}
