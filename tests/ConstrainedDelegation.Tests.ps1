#Requires -Modules Pester
<#
    Unit tests for Test-ConstrainedDelegation's "Computer Account with
    Unconstrained Delegation" check.

    Found via tracing the ForcedFail fixtures (tests/fixtures/) against the
    codebase: Test-ADUserSecurity already flagged bare, unconstrained
    delegation (TrustedForDelegation=$true, no msDS-AllowedToDelegateTo) on
    USER accounts as "Unconstrained Delegation Enabled" (UserAudits.ps1),
    but no equivalent check existed anywhere for COMPUTER accounts - despite
    unconstrained delegation being overwhelmingly found on computer objects
    in real environments (legacy print/app/file servers), not user
    accounts, and being one of the most consequential, well-known AD
    misconfigurations (a compromised host with this flag can capture and
    replay the TGT of any user who authenticates to it).

    Added as "Computer Account with Unconstrained Delegation" in
    Test-ConstrainedDelegation (DelegationAudits.ps1, the existing home for
    computer-level delegation checks), both snapshot and live branches.
    Domain Controllers are excluded - unconstrained delegation is normal,
    required DC configuration, not a misconfiguration.

    Run from the repo root:  Invoke-Pester ./tests/ConstrainedDelegation.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/DelegationAudits.ps1')
}

Describe 'Test-ConstrainedDelegation - Computer Account with Unconstrained Delegation (snapshot mode)' {
    It 'flags a non-DC computer with TrustedForDelegation=$true' {
        $snapshot = @{
            DomainControllers = @([PSCustomObject]@{ Name = 'DC01' })
            Computers = @(
                [PSCustomObject]@{
                    Name = 'LEGACY-SRV01'; DistinguishedName = 'CN=LEGACY-SRV01,CN=Computers,DC=contoso,DC=com'
                    TrustedForDelegation = $true; 'msDS-AllowedToDelegateTo' = @()
                    TrustedToAuthForDelegation = $false; OperatingSystem = 'Windows Server 2008 R2'
                    ServicePrincipalNames = @('HOST/legacy-srv01.contoso.com'); HasRbcdConfigured = $false
                }
            )
        }

        $findings = Test-ConstrainedDelegation -Snapshot $snapshot
        $hit = $findings | Where-Object { $_.Issue -eq 'Computer Account with Unconstrained Delegation' }

        $hit | Should -Not -BeNullOrEmpty
        $hit.AffectedObject | Should -Be 'LEGACY-SRV01'
        $hit.Severity | Should -Be 'Critical'
    }

    It 'does NOT flag a Domain Controller with TrustedForDelegation=$true (normal, required DC configuration)' {
        $snapshot = @{
            DomainControllers = @([PSCustomObject]@{ Name = 'DC01' }, [PSCustomObject]@{ Name = 'DC02' })
            Computers = @(
                [PSCustomObject]@{
                    Name = 'DC01'; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=contoso,DC=com'
                    TrustedForDelegation = $true; 'msDS-AllowedToDelegateTo' = @()
                    TrustedToAuthForDelegation = $false; OperatingSystem = 'Windows Server 2022'
                    ServicePrincipalNames = @('HOST/dc01.contoso.com'); HasRbcdConfigured = $false
                }
            )
        }

        $findings = Test-ConstrainedDelegation -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Computer Account with Unconstrained Delegation' })

        $hits.Count | Should -Be 0
    }

    It 'does NOT flag a computer with TrustedForDelegation=$false' {
        $snapshot = @{
            DomainControllers = @()
            Computers = @(
                [PSCustomObject]@{
                    Name = 'WEB01'; DistinguishedName = 'CN=WEB01,CN=Computers,DC=contoso,DC=com'
                    TrustedForDelegation = $false; 'msDS-AllowedToDelegateTo' = @()
                    TrustedToAuthForDelegation = $false; OperatingSystem = 'Windows Server 2022'
                    ServicePrincipalNames = @(); HasRbcdConfigured = $false
                }
            )
        }

        $findings = Test-ConstrainedDelegation -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Computer Account with Unconstrained Delegation' })

        $hits.Count | Should -Be 0
    }

    It 'does not double-flag a computer that has BOTH unconstrained delegation and separate constrained-delegation attributes' {
        # A computer with TrustedForDelegation=$true AND a populated
        # msDS-AllowedToDelegateTo is a real, if unusual, edge case (the
        # constrained-delegation attribute is simply ignored while
        # unconstrained delegation is enabled) - it should get the
        # unconstrained-delegation finding, and may also legitimately get
        # a constrained-delegation finding since both attributes are
        # genuinely present; this test only confirms the unconstrained
        # finding itself doesn't appear more than once.
        $snapshot = @{
            DomainControllers = @()
            Computers = @(
                [PSCustomObject]@{
                    Name = 'MIXED01'; DistinguishedName = 'CN=MIXED01,CN=Computers,DC=contoso,DC=com'
                    TrustedForDelegation = $true; 'msDS-AllowedToDelegateTo' = @('HTTP/app.contoso.com')
                    TrustedToAuthForDelegation = $false; OperatingSystem = 'Windows Server 2022'
                    ServicePrincipalNames = @(); HasRbcdConfigured = $false
                }
            )
        }

        $findings = Test-ConstrainedDelegation -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Computer Account with Unconstrained Delegation' -and $_.AffectedObject -eq 'MIXED01' })

        $hits.Count | Should -Be 1
    }
}
