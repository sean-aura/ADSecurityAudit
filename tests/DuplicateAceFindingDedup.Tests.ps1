#Requires -Modules Pester
<#
    Regression tests for v1.24.0: several ACE-iterating checks emitted one
    finding per raw ACE instead of one per (identity, rights) combination.
    Real AD ACLs commonly carry more than one ACE for the same trustee -
    one per property set/object type - even when ActiveDirectoryRights is
    identical, which produced fully-duplicate findings (same Category,
    Issue, AffectedObject, and Description) in the exported report. Found
    via a live lab run: 74 of 262 findings were exact duplicates, 60 of
    them from a single AdminSDHolder ACL with repeated ACEs per trustee.

    These tests use -Snapshot mode (no live AD access) and construct an
    ACL with two ACEs for the same trustee carrying identical rights, then
    assert exactly one finding is produced - not two.

    Run from the repo root:  Invoke-Pester ./tests/DuplicateAceFindingDedup.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
    . (Join-Path $root 'src/Scoring.ps1')
    . (Join-Path $root 'src/AdminSDAudits.ps1')
    . (Join-Path $root 'src/ExchangeEscalationAudits.ps1')
    . (Join-Path $root 'src/ReplicationAudits.ps1')

    function New-DuplicateAce {
        param(
            [string]$Identity,
            [string]$Rights,
            [string]$AccessControlType = 'Allow',
            [string]$ObjectType = '00000000-0000-0000-0000-000000000000'
        )
        # Two ACEs for the same trustee/rights but different ObjectType -
        # exactly the shape real AD ACLs produce (separate ACEs per
        # property set) that the dedup fix must collapse into one finding.
        @(
            [PSCustomObject]@{
                IdentityReference     = $Identity
                ActiveDirectoryRights = $Rights
                AccessControlType     = $AccessControlType
                IsInherited           = $false
                InheritanceType       = 'None'
                ObjectType            = $ObjectType
                InheritedObjectType   = '00000000-0000-0000-0000-000000000000'
            }
            [PSCustomObject]@{
                IdentityReference     = $Identity
                ActiveDirectoryRights = $Rights
                AccessControlType     = $AccessControlType
                IsInherited           = $false
                InheritanceType       = 'None'
                ObjectType            = 'bf967a86-0de6-11d0-a285-00aa003049e2'
                InheritedObjectType   = '00000000-0000-0000-0000-000000000000'
            }
        )
    }
}

Describe 'Test-AdminSDHolder (duplicate ACE dedup, snapshot mode)' {
    It 'emits exactly one Non-Standard Permissions finding for a trustee with two identical-rights ACEs' {
        $snapshot = @{
            Domain = [PSCustomObject]@{ NetBIOSName = 'CONTOSO' }
            ACLs   = @{
                AdminSDHolder = [PSCustomObject]@{
                    Access = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteProperty'
                }
            }
        }

        $findings = Test-AdminSDHolder -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on AdminSDHolder' })

        $hits.Count | Should -Be 1
        $hits[0].AffectedObject | Should -Match 'Exchange Trusted Subsystem'
    }

    It 'emits exactly one Deny ACE finding for a trustee with two identical Deny ACEs' {
        $snapshot = @{
            Domain = [PSCustomObject]@{ NetBIOSName = 'CONTOSO' }
            ACLs   = @{
                AdminSDHolder = [PSCustomObject]@{
                    Access = New-DuplicateAce -Identity 'CONTOSO\Exchange Servers' -Rights 'GenericAll' -AccessControlType 'Deny'
                }
            }
        }

        $findings = Test-AdminSDHolder -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Deny ACE on AdminSDHolder' })

        $hits.Count | Should -Be 1
    }

    It 'still reports two separate findings for two genuinely different trustees' {
        $aces = @(New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteProperty')[0], `
                @(New-DuplicateAce -Identity 'CONTOSO\Organization Management' -Rights 'GenericAll')[0]
        $snapshot = @{
            Domain = [PSCustomObject]@{ NetBIOSName = 'CONTOSO' }
            ACLs   = @{ AdminSDHolder = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-AdminSDHolder -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Non-Standard Permissions on AdminSDHolder' })

        $hits.Count | Should -Be 2
    }
}

Describe 'Test-ADExchangeEscalation (duplicate ACE dedup, snapshot mode)' {
    It 'emits exactly one finding per (identity, rights) pair on the domain root, not one per ACE' {
        $snapshot = @{
            ACLs = @{
                DomainRoot = [PSCustomObject]@{
                    DistinguishedName = 'DC=contoso,DC=com'
                    Access            = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'WriteDacl'
                }
            }
        }

        $findings = Test-ADExchangeEscalation -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Exchange Group Holds WriteDACL on Domain Object' })

        $hits.Count | Should -Be 1
    }

    It 'emits exactly one AdminSDHolder-related finding per (identity, rights) pair, not one per ACE' {
        $snapshot = @{
            ACLs = @{
                AdminSDHolder = [PSCustomObject]@{
                    DistinguishedName = 'CN=AdminSDHolder,CN=System,DC=contoso,DC=com'
                    Access            = New-DuplicateAce -Identity 'CONTOSO\Exchange Trusted Subsystem' -Rights 'GenericAll'
                }
            }
        }

        $findings = Test-ADExchangeEscalation -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Exchange-Related AdminSDHolder ACE' })

        $hits.Count | Should -Be 1
    }
}

Describe 'Test-ADReplicationSecurity (duplicate ACE dedup, snapshot mode)' {
    It 'emits exactly one Unauthorized DCSync Permissions finding for a trustee with two GenericAll ACEs (matches the observed lab duplicate)' {
        # Mirrors the real duplicate found in a lab run: the same trustee
        # held multiple GenericAll ACEs on the domain root (one per object
        # type), each independently matching all three DCSync rights and
        # producing three fully-duplicate findings before the fix.
        $aces = @(
            [PSCustomObject]@{
                IdentityReference     = 'CONTOSO\Exchange Trusted Subsystem'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '00000000-0000-0000-0000-000000000000'
            }
            [PSCustomObject]@{
                IdentityReference     = 'CONTOSO\Exchange Trusted Subsystem'
                ActiveDirectoryRights = 'GenericAll'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = 'bf967a86-0de6-11d0-a285-00aa003049e2'
            }
        )
        $snapshot = @{
            Domain = [PSCustomObject]@{ NetBIOSName = 'CONTOSO' }
            ACLs   = @{ DomainRoot = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-ADReplicationSecurity -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' })

        $hits.Count | Should -Be 1
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes'
        $hits[0].Details.Rights | Should -Match 'DS-Replication-Get-Changes-All'
    }

    It 'still reports two separate findings when the same trustee genuinely holds two different specific replication rights via different ObjectTypes' {
        $aces = @(
            [PSCustomObject]@{
                IdentityReference     = 'CONTOSO\Sync Service'
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # Get-Changes only
            }
            [PSCustomObject]@{
                IdentityReference     = 'CONTOSO\Sync Service'
                ActiveDirectoryRights = 'ExtendedRight'
                AccessControlType     = 'Allow'
                IsInherited           = $false
                ObjectType            = '89e95b76-444d-4c62-991a-0facbeda640c'  # Get-Changes-In-Filtered-Set only
            }
        )
        $snapshot = @{
            Domain = [PSCustomObject]@{ NetBIOSName = 'CONTOSO' }
            ACLs   = @{ DomainRoot = [PSCustomObject]@{ Access = $aces } }
        }

        $findings = Test-ADReplicationSecurity -Snapshot $snapshot
        $hits = @($findings | Where-Object { $_.Issue -eq 'Unauthorized DCSync Permissions' })

        # Different specific rights granted via different ObjectTypes are
        # genuinely distinct information, not duplicate ACEs, so dedup must
        # NOT collapse them.
        $hits.Count | Should -Be 2
    }
}
