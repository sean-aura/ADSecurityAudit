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

Describe 'Resolve-ADSecurityAuditTargetServer' {
    <#
        Regression/behavior coverage for PDC-Emulator resolution: whatever
        -Server resolves to (explicit value, or the $env:USERDNSDOMAIN
        default), this function takes one further step and resolves it to
        that domain's PDC Emulator specifically - a single, deterministic
        DC for the whole run/call, rather than a bare domain name (not a
        valid Get-ADDomainController -Identity value) or an arbitrary
        DC-locator pick.
    #>
    BeforeAll {
        function Get-ADDomain { }
    }

    It 'resolves an explicit -Server domain name to its PDC Emulator' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ PDCEmulator = 'dc01.domainb.corp.com' } } -ParameterFilter { $Server -eq 'domainb.corp.com' }

        $result = Resolve-ADSecurityAuditTargetServer -Server 'domainb.corp.com'
        $result | Should -Be 'dc01.domainb.corp.com'
    }

    It 'resolves an explicit -Server DC name to that domain''s PDC Emulator too (not necessarily the same DC)' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ PDCEmulator = 'dc01.domainb.corp.com' } } -ParameterFilter { $Server -eq 'dc02.domainb.corp.com' }

        $result = Resolve-ADSecurityAuditTargetServer -Server 'dc02.domainb.corp.com'
        $result | Should -Be 'dc01.domainb.corp.com'
    }

    It 'falls back to the plain requested value if PDC Emulator resolution fails' {
        Mock -CommandName Get-ADDomain -MockWith { throw 'simulated unreachable domain' }

        $result = Resolve-ADSecurityAuditTargetServer -Server 'unreachable.corp.com'
        $result | Should -Be 'unreachable.corp.com'
    }

    It 'returns $null when neither -Server nor $env:USERDNSDOMAIN is available' {
        $originalUserDnsDomain = $env:USERDNSDOMAIN
        try {
            $env:USERDNSDOMAIN = $null
            Resolve-ADSecurityAuditTargetServer | Should -BeNullOrEmpty
        }
        finally {
            $env:USERDNSDOMAIN = $originalUserDnsDomain
        }
    }
}

Describe 'Set-ADSecurityAuditTargetServer - GroupPolicy module coverage' {
    <#
        Regression coverage for a real, previously-undiscovered gap: the
        GroupPolicy module's cmdlets (Get-GPO, Get-GPInheritance,
        Get-GPPermission, Get-GPRegistryValue - used by
        Test-ADGroupPolicies, Test-ADLegacyAuthSurface,
        Test-ADDomainHardeningFlags, Test-ADKerberosHardening, and
        Get-ADSnapshot's GPO collection) start with "Get-GP", not "Get-AD"
        - the original 'Get-AD*:Server' wildcard never matched them, so
        every GPO-related check was completely unscoped by -Server this
        whole time, independent of whether an override was active for AD
        cmdlets.
    #>
    AfterEach {
        Clear-ADSecurityAuditTargetServer
    }

    It 'installs a Get-GP*:Server default alongside Get-AD*:Server' {
        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        $Global:PSDefaultParameterValues['Get-GP*:Server'] | Should -Be 'dc01.domainb.corp.com'
        $Global:PSDefaultParameterValues['Get-AD*:Server'] | Should -Be 'dc01.domainb.corp.com'
    }

    It 'installs defaults for Set-GP*/New-GP*/Remove-GP* too, matching the AD-cmdlet pattern' {
        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        $Global:PSDefaultParameterValues['Set-GP*:Server'] | Should -Be 'dc01.domainb.corp.com'
        $Global:PSDefaultParameterValues['New-GP*:Server'] | Should -Be 'dc01.domainb.corp.com'
        $Global:PSDefaultParameterValues['Remove-GP*:Server'] | Should -Be 'dc01.domainb.corp.com'
    }

    It 'removes all Get-GP*/Set-GP*/New-GP*/Remove-GP* defaults on Clear-ADSecurityAuditTargetServer' {
        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        Clear-ADSecurityAuditTargetServer
        $Global:PSDefaultParameterValues.ContainsKey('Get-GP*:Server') | Should -BeFalse
        $Global:PSDefaultParameterValues.ContainsKey('Set-GP*:Server') | Should -BeFalse
        $Global:PSDefaultParameterValues.ContainsKey('New-GP*:Server') | Should -BeFalse
        $Global:PSDefaultParameterValues.ContainsKey('Remove-GP*:Server') | Should -BeFalse
    }

    It 'demonstrates the wildcard actually auto-supplies -Server to a Get-GP* cmdlet call' {
        # A minimal fake cmdlet standing in for Get-GPO - proves the
        # wildcard match/auto-injection mechanism itself works for
        # "Get-GP*", not just that the string key was set correctly above.
        function Get-GPO { param([string]$Server) $Server }

        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        $result = Get-GPO
        $result | Should -Be 'dc01.domainb.corp.com'
    }
}

Describe 'AD-object ACL reads avoid the unscoped "AD:" PSDrive' {
    <#
        Regression coverage for a real, previously-undiscovered gap:
        Get-Acl -Path "AD:$dn" has NO -Server parameter at all and reads
        via the "AD:" PSDrive's own ambient default domain/DC - completely
        bypassing Set-ADSecurityAuditTargetServer's override, unlike every
        Get-AD* cmdlet call in this module. This affected certificate
        template (ESC4) and CA object (ESC7) ACL reads specifically
        (CertificateServicesAudits.ps1, CertificateServicesExtendedAudits.
        ps1, Get-ADSnapshot) - AdminSDAudits.ps1/PermissionsAudits.ps1/
        ControlPaths.ps1 were already doing this correctly via
        Get-ADObject -Properties nTSecurityDescriptor, which IS
        -Server-aware, and were used as the template for this fix.

        This is a static source-inspection test, in the same style as
        ADCSContainerScope.Tests.ps1: these functions have substantial
        unrelated setup that would need extensive mocking to execute
        safely here, so asserting the fix's actual shape (no more
        "AD:"-PSDrive ACL reads; nTSecurityDescriptor reads present
        instead) is a reliable, low-risk guard against this specific
        regression reappearing.
    #>
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        $script:AffectedFiles = @(
            (Join-Path $root 'src/CertificateServicesAudits.ps1')
            (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')
            (Join-Path $root 'src/Snapshot.ps1')
        )
    }

    It 'contains no remaining live Get-Acl -Path "AD:..." calls' {
        foreach ($file in $script:AffectedFiles) {
            $content = Get-Content -Path $file -Raw
            # Only real invocations - not the explanatory comments left
            # behind describing what NOT to do; those start with '#'.
            $liveCalls = [regex]::Matches($content, '(?m)^\s*[^#\r\n]*Get-Acl\s+-Path\s+"AD:')
            $liveCalls.Count | Should -Be 0 -Because "$file should read AD-object ACLs via Get-ADObject -Properties nTSecurityDescriptor, not the unscoped AD: PSDrive"
        }
    }

    It 'uses Get-ADObject -Properties nTSecurityDescriptor for every certificate template/CA ACL read' {
        foreach ($file in $script:AffectedFiles) {
            $content = Get-Content -Path $file -Raw
            $content | Should -Match 'Get-ADObject[^\r\n]*-Properties\s+nTSecurityDescriptor' -Because "$file should read certificate template/CA ACLs via the -Server-aware Get-ADObject path"
        }
    }
}

Describe 'SYSVOL UNC paths use the resolved -Server, not just the domain DNS name' {
    <#
        A bare domain name in a SYSVOL UNC path (\\domain.tld\SYSVOL\...)
        is resolved via DFS Namespace referral, which - like DC-locator
        for AD queries - picks a DC based on the CALLING MACHINE's own
        site/subnet proximity, not necessarily the domain being audited.
        Get-Acl has no -Server parameter for a UNC path, so the fix is to
        put the resolved DC directly in the path's server component.
    #>
    BeforeAll {
        $root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $root 'src/Common.ps1')
    }

    AfterEach {
        Clear-ADSecurityAuditTargetServer
    }

    It 'Get-ADGpoSecretsSysvolPolicyRoot uses the active -Server override for the UNC server component' {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/GpoSecretsAudits.ps1')
        function Get-ADDomain { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }

        Set-ADSecurityAuditTargetServer -Server 'dc01.domainb.corp.com'
        $result = Get-ADGpoSecretsSysvolPolicyRoot
        $result | Should -Be '\\dc01.domainb.corp.com\SYSVOL\domainb.corp.com\Policies'
    }

    It 'Get-ADGpoSecretsSysvolPolicyRoot falls back to the domain DNS name when no override is active' {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/GpoSecretsAudits.ps1')
        function Get-ADDomain { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }

        Clear-ADSecurityAuditTargetServer
        $result = Get-ADGpoSecretsSysvolPolicyRoot
        $result | Should -Be '\\domainb.corp.com\SYSVOL\domainb.corp.com\Policies'
    }
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

Describe 'Get-ADTargetDomainController' {
    <#
        Regression coverage: -Identity requires a real DC identity
        (GUID/Name/IPv4Address/DNSHostName of the DC itself), not a domain
        FQDN - but -Server (and therefore the active override) is commonly
        a domain FQDN per this module's own documented usage. The old
        implementation passed the override straight to -Identity and threw
        "Cannot find directory server with identity: <domain FQDN>" every
        time an operator used that documented form.
    #>
    BeforeAll {
        function Get-ADDomain { }
        function Get-ADDomainController { }
    }

    AfterEach {
        Clear-ADSecurityAuditTargetServer
    }

    It 'resolves a DC when the active override is a DOMAIN FQDN, not a specific DC name' {
        Mock -CommandName Get-ADDomain -MockWith { [PSCustomObject]@{ DNSRoot = 'domainb.corp.com' } }
        Mock -CommandName Get-ADDomainController -MockWith {
            @([PSCustomObject]@{ HostName = 'dc01.domainb.corp.com'; Domain = 'domainb.corp.com' })
        }

        Set-ADSecurityAuditTargetServer -Server 'domainb.corp.com'
        $result = Get-ADTargetDomainController -WarningAction SilentlyContinue
        $result | Should -Not -BeNullOrEmpty
        $result.HostName | Should -Be 'dc01.domainb.corp.com'
    }

    It 'falls back to -Discover when no override is active' {
        Mock -CommandName Get-ADDomainController -MockWith { [PSCustomObject]@{ HostName = 'discovered-dc.contoso.com' } } -ParameterFilter { $Discover }

        Clear-ADSecurityAuditTargetServer
        $result = Get-ADTargetDomainController
        $result.HostName | Should -Be 'discovered-dc.contoso.com'
    }

    It 'returns $null (not a throw) when the override domain has no reachable DCs' {
        Mock -CommandName Get-ADDomain -MockWith { throw 'simulated unreachable domain' }

        Set-ADSecurityAuditTargetServer -Server 'unreachable.corp.com'
        { Get-ADTargetDomainController -WarningAction SilentlyContinue } | Should -Not -Throw
        Get-ADTargetDomainController -WarningAction SilentlyContinue | Should -BeNullOrEmpty
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
