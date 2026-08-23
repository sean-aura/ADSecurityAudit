#Requires -Modules Pester
<#
    Unit tests for the two new findings added to Test-ADDangerousPermissions
    in src/PermissionsAudits.ps1:
      - "Non-Standard Permissions on Schema Naming Context"
      - "Non-Standard Permissions on Configuration Naming Context"

    Snapshot-mode tests exercise Snapshot.ACLs.SchemaNamingContext/
    .ConfigurationNamingContext directly. Live-mode tests shadow every live
    AD cmdlet the function touches: Get-ADDomain, Get-ADObject, Get-ADGroup,
    and Get-ADRootDSEValue (via Get-ADRootDSE). No real Active Directory
    access is used.

    Run from the repo root:  Invoke-Pester ./tests/PermissionsAudits.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/PermissionsAudits.ps1')
}

function New-FlatAce {
    param(
        [string]$IdentityReference,
        [string]$ActiveDirectoryRights,
        [string]$AccessControlType = 'Allow',
        [bool]$IsInherited = $false,
        [string]$ObjectType = '00000000-0000-0000-0000-000000000000'
    )
    [PSCustomObject]@{
        IdentityReference     = $IdentityReference
        ActiveDirectoryRights = $ActiveDirectoryRights
        AccessControlType     = $AccessControlType
        IsInherited           = $IsInherited
        ObjectType            = $ObjectType
    }
}

Describe 'Test-ADDangerousPermissions (Schema/Configuration NC ACLs) - Snapshot mode' {
    function New-BaseSnapshot {
        @{
            ACLs = @{
                SchemaNamingContext        = @{ DistinguishedName = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'; Access = @() }
                ConfigurationNamingContext = @{ DistinguishedName = 'CN=Configuration,DC=contoso,DC=com'; Access = @() }
            }
        }
    }

    It 'produces no finding when the Schema NC ACL has only expected trustees' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.SchemaNamingContext.Access = @(
            New-FlatAce -IdentityReference 'NT AUTHORITY\SYSTEM' -ActiveDirectoryRights 'GenericAll'
            New-FlatAce -IdentityReference 'CONTOSO\Schema Admins' -ActiveDirectoryRights 'GenericAll'
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Schema Naming Context' }) | Should -BeNullOrEmpty
    }

    It 'fires Critical when a non-standard trustee holds a dangerous right on the Schema NC' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.SchemaNamingContext.Access = @(
            New-FlatAce -IdentityReference 'CONTOSO\svc-backup' -ActiveDirectoryRights 'GenericAll'
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Schema Naming Context' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Category | Should -Be 'Permissions'
        $finding.Severity | Should -Be 'Critical'
        $finding.SeverityLevel | Should -Be 4
        $finding.AffectedObject | Should -Match 'svc-backup'
        $finding.Details.Identity | Should -Be 'CONTOSO\svc-backup'
    }

    It 'ignores inherited ACEs on the Schema NC' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.SchemaNamingContext.Access = @(
            New-FlatAce -IdentityReference 'CONTOSO\svc-backup' -ActiveDirectoryRights 'GenericAll' -IsInherited $true
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Schema Naming Context' }) | Should -BeNullOrEmpty
    }

    It 'does not accept Schema Admins as a valid trustee on the Configuration NC (Schema-specific allowance)' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.ConfigurationNamingContext.Access = @(
            New-FlatAce -IdentityReference 'CONTOSO\Schema Admins' -ActiveDirectoryRights 'WriteDacl'
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' }
        $finding | Should -Not -BeNullOrEmpty
    }

    It 'fires Critical when a non-standard trustee holds a dangerous right on the Configuration NC' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.ConfigurationNamingContext.Access = @(
            New-FlatAce -IdentityReference 'CONTOSO\helpdesk-admins' -ActiveDirectoryRights 'WriteOwner'
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' }

        $finding | Should -Not -BeNullOrEmpty
        $finding.Severity | Should -Be 'Critical'
        $finding.Details.Identity | Should -Be 'CONTOSO\helpdesk-admins'
    }

    It 'does not flag a non-standard trustee holding only a benign (non-dangerous) right' {
        $snapshot = New-BaseSnapshot
        $snapshot.ACLs.ConfigurationNamingContext.Access = @(
            New-FlatAce -IdentityReference 'CONTOSO\helpdesk-admins' -ActiveDirectoryRights 'ReadProperty'
        )
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        ($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' }) | Should -BeNullOrEmpty
    }

    It 'skips both NC checks without throwing when the snapshot predates this ACL collection' {
        $snapshot = @{ ACLs = @{} }
        { Test-ADDangerousPermissions -Snapshot $snapshot } | Should -Not -Throw
        $findings = Test-ADDangerousPermissions -Snapshot $snapshot
        $findings | Should -BeNullOrEmpty
    }
}

Describe 'Test-ADDangerousPermissions (Schema/Configuration NC ACLs) - Live mode' {
    BeforeEach {
        function Get-ADDomain {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{ DistinguishedName = 'DC=contoso,DC=com'; DNSRoot = 'contoso.com' }
        }
        function Get-ADGroup {
            param($Filter, [switch]$ErrorAction, $Server)
            throw "Enterprise Key Admins group not found in the target domain"
        }
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            [PSCustomObject]@{
                schemaNamingContext        = 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
                configurationNamingContext = 'CN=Configuration,DC=contoso,DC=com'
            }
        }
        # Domain root and critical-OU reads all return an empty ACL by
        # default; the NC-specific test data is layered on top per-test.
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            switch ($Identity) {
                'CN=Schema,CN=Configuration,DC=contoso,DC=com' {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
                'CN=Configuration,DC=contoso,DC=com' {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
                default {
                    [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
                }
            }
        }
    }

    It 'produces no NC findings when both head objects have only expected trustees' {
        $findings = Test-ADDangerousPermissions
        ($findings | Where-Object { $_.Issue -match 'Naming Context' }) | Should -BeNullOrEmpty
    }

    It 'fires live for a non-standard ACE on the Schema NC head object' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=Schema,CN=Configuration,DC=contoso,DC=com') {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-FlatAce -IdentityReference 'CONTOSO\svc-backup' -ActiveDirectoryRights 'GenericAll') } }
            }
            else {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
            }
        }

        $findings = Test-ADDangerousPermissions
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Schema Naming Context' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.AffectedObject | Should -Match 'CN=Schema,CN=Configuration,DC=contoso,DC=com'
    }

    It 'fires live for a non-standard ACE on the Configuration NC head object' {
        function Get-ADObject {
            param($Identity, $Properties, $Server, [switch]$ErrorAction)
            if ($Identity -eq 'CN=Configuration,DC=contoso,DC=com') {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @(New-FlatAce -IdentityReference 'CONTOSO\helpdesk-admins' -ActiveDirectoryRights 'WriteDacl') } }
            }
            else {
                [PSCustomObject]@{ nTSecurityDescriptor = [PSCustomObject]@{ Access = @() } }
            }
        }

        $findings = Test-ADDangerousPermissions
        $finding = $findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on Configuration Naming Context' }
        $finding | Should -Not -BeNullOrEmpty
        $finding.AffectedObject | Should -Match 'CN=Configuration,DC=contoso,DC=com'
    }

    It 'does not throw and produces no NC findings when schema/configuration naming context cannot be resolved' {
        function Get-ADRootDSE {
            param([switch]$ErrorAction, $Server)
            throw "RootDSE unavailable"
        }

        { Test-ADDangerousPermissions } | Should -Not -Throw
        $findings = Test-ADDangerousPermissions
        ($findings | Where-Object { $_.Issue -match 'Naming Context' }) | Should -BeNullOrEmpty
    }
}
