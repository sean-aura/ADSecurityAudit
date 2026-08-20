#Requires -Modules Pester
<#
    Unit tests for the multi-domain/-Server override helpers added to
    Common.ps1: Get-ADSecurityAuditActiveServerOverride and
    Split-ADObjectByTargetDomain.

    These tests do NOT touch Active Directory.

    Run from the repo root:  Invoke-Pester ./tests/CrossDomainHelpers.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
}

Describe 'Get-ADSecurityAuditActiveServerOverride' {
    AfterEach {
        Clear-ADSecurityAuditTargetServer
    }

    It 'returns $null when no override is active' {
        Clear-ADSecurityAuditTargetServer
        Get-ADSecurityAuditActiveServerOverride | Should -BeNullOrEmpty
    }

    It 'returns the active -Server value once Set-ADSecurityAuditTargetServer has run' {
        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        Get-ADSecurityAuditActiveServerOverride | Should -Be 'dc01.domainb.corp.com'
    }

    It 'returns $null again after Clear-ADSecurityAuditTargetServer' {
        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        Clear-ADSecurityAuditTargetServer
        Get-ADSecurityAuditActiveServerOverride | Should -BeNullOrEmpty
    }
}

Describe 'Get-ADSecurityAuditDomainController' {
    <#
        Regression coverage for the forest-wide-DC-enumeration bug:
        Get-ADDomainController's -Filter parameter set queries the
        forest-wide Configuration container and returns every domain's
        DCs regardless of -Server. Every per-DC probe in this module used
        to call it bare and could silently mix in another domain's DCs.
        These tests mock Get-ADDomain/Get-ADDomainController to simulate
        exactly that forest-wide result set and confirm the helper filters
        it down to the target domain only.
    #>
    BeforeAll {
        function Get-ADDomain { }
        function Get-ADDomainController { }
    }

    It 'filters out Domain Controllers belonging to a different domain than the one resolved via Get-ADDomain' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }
        Mock -CommandName Get-ADDomainController -MockWith {
            @(
                [PSCustomObject]@{ HostName = 'dc01.domaina.corp.com'; Domain = 'domaina.corp.com' }
                [PSCustomObject]@{ HostName = 'dc01.domainb.corp.com'; Domain = 'domainb.corp.com' }
                [PSCustomObject]@{ HostName = 'dc02.domainb.corp.com'; Domain = 'domainb.corp.com' }
            )
        }

        $result = Get-ADSecurityAuditDomainController -Server 'domainb.corp.com' -WarningAction SilentlyContinue
        $result.Count | Should -Be 2
        $result | ForEach-Object { $_.Domain | Should -Be 'domainb.corp.com' }
    }

    It 'warns when foreign-domain Domain Controllers are excluded' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }
        Mock -CommandName Get-ADDomainController -MockWith {
            @(
                [PSCustomObject]@{ HostName = 'dc01.domaina.corp.com'; Domain = 'domaina.corp.com' }
                [PSCustomObject]@{ HostName = 'dc01.domainb.corp.com'; Domain = 'domainb.corp.com' }
            )
        }

        $warnings = @()
        Get-ADSecurityAuditDomainController -Server 'domainb.corp.com' -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
        $warnings.Count | Should -BeGreaterThan 0
        $warnings[0] | Should -Match 'excluded 1 Domain Controller'
    }

    It 'does not warn when every returned Domain Controller already belongs to the target domain' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }
        Mock -CommandName Get-ADDomainController -MockWith {
            @(
                [PSCustomObject]@{ HostName = 'dc01.domainb.corp.com'; Domain = 'domainb.corp.com' }
                [PSCustomObject]@{ HostName = 'dc02.domainb.corp.com'; Domain = 'domainb.corp.com' }
            )
        }

        $warnings = @()
        $result = Get-ADSecurityAuditDomainController -Server 'domainb.corp.com' -WarningVariable warnings -WarningAction SilentlyContinue
        $result.Count | Should -Be 2
        $warnings.Count | Should -Be 0
    }

    It 'passes -Filter through to Get-ADDomainController (e.g. an RODC-only filter)' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }
        Mock -CommandName Get-ADDomainController -MockWith {
            @([PSCustomObject]@{ HostName = 'rodc01.domainb.corp.com'; Domain = 'domainb.corp.com'; IsReadOnly = $true })
        } -ParameterFilter { $Filter -ne '*' }

        $result = Get-ADSecurityAuditDomainController -Server 'domainb.corp.com' -Filter { IsReadOnly -eq $true } -WarningAction SilentlyContinue
        $result.Count | Should -Be 1
        Should -Invoke -CommandName Get-ADDomainController -ParameterFilter { $Filter -ne '*' } -Times 1
    }

    It 'does not pass -Server to either inner call when none was given (preserves the ambient $PSDefaultParameterValues override)' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } } -ParameterFilter { -not $Server }
        Mock -CommandName Get-ADDomainController -MockWith {
            @([PSCustomObject]@{ HostName = 'dc01.domainb.corp.com'; Domain = 'domainb.corp.com' })
        } -ParameterFilter { -not $Server }

        $result = Get-ADSecurityAuditDomainController -WarningAction SilentlyContinue
        $result.Count | Should -Be 1
        Should -Invoke -CommandName Get-ADDomain -ParameterFilter { -not $Server } -Times 1
        Should -Invoke -CommandName Get-ADDomainController -ParameterFilter { -not $Server } -Times 1
    }
}

Describe 'Split-ADObjectByTargetDomain' {
    It 'treats an empty/null input as zero in-scope and zero foreign objects' {
        $result = Split-ADObjectByTargetDomain -InputObject @() -TargetDomainDN 'DC=domainb,DC=corp,DC=com'
        @($result.InScope).Count | Should -Be 0
        @($result.Foreign).Count | Should -Be 0
    }

    It 'classifies an object whose DN ends with TargetDomainDN as in-scope' {
        $obj = [PSCustomObject]@{ SamAccountName = 'user1'; DistinguishedName = 'CN=user1,OU=Users,DC=domainb,DC=corp,DC=com' }
        $result = Split-ADObjectByTargetDomain -InputObject @($obj) -TargetDomainDN 'DC=domainb,DC=corp,DC=com'
        @($result.InScope).Count | Should -Be 1
        @($result.Foreign).Count | Should -Be 0
    }

    It 'classifies an object whose DN belongs to a DIFFERENT domain as foreign (the cross-domain-leak case)' {
        # Exactly the reported symptom: a member object whose own domain
        # (domaina - e.g. the machine's own joined domain) differs from the
        # domain actually being audited (domainb).
        $obj = [PSCustomObject]@{ SamAccountName = 'user1'; DistinguishedName = 'CN=user1,OU=Users,DC=domaina,DC=corp,DC=com' }
        $result = Split-ADObjectByTargetDomain -InputObject @($obj) -TargetDomainDN 'DC=domainb,DC=corp,DC=com'
        @($result.InScope).Count | Should -Be 0
        @($result.Foreign).Count | Should -Be 1
        $result.Foreign[0].SamAccountName | Should -Be 'user1'
    }

    It 'is case-insensitive when comparing DNs (AD DNs are case-insensitive)' {
        $obj = [PSCustomObject]@{ SamAccountName = 'user1'; DistinguishedName = 'CN=user1,OU=Users,DC=DomainB,DC=Corp,DC=Com' }
        $result = Split-ADObjectByTargetDomain -InputObject @($obj) -TargetDomainDN 'dc=domainb,dc=corp,dc=com'
        @($result.InScope).Count | Should -Be 1
    }

    It 'treats an object with no DistinguishedName as in-scope rather than silently dropping it' {
        $obj = [PSCustomObject]@{ SamAccountName = 'user1' }
        $result = Split-ADObjectByTargetDomain -InputObject @($obj) -TargetDomainDN 'DC=domainb,DC=corp,DC=com'
        @($result.InScope).Count | Should -Be 1
        @($result.Foreign).Count | Should -Be 0
    }

    It 'correctly splits a mixed set of in-scope and foreign objects' {
        $objs = @(
            [PSCustomObject]@{ SamAccountName = 'a'; DistinguishedName = 'CN=a,DC=domainb,DC=corp,DC=com' }
            [PSCustomObject]@{ SamAccountName = 'b'; DistinguishedName = 'CN=b,DC=domaina,DC=corp,DC=com' }
            [PSCustomObject]@{ SamAccountName = 'c'; DistinguishedName = 'CN=c,DC=domainb,DC=corp,DC=com' }
        )
        $result = Split-ADObjectByTargetDomain -InputObject $objs -TargetDomainDN 'DC=domainb,DC=corp,DC=com'
        @($result.InScope).Count | Should -Be 2
        @($result.Foreign).Count | Should -Be 1
        $result.Foreign[0].SamAccountName | Should -Be 'b'
    }
}
