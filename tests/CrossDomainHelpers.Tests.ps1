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
