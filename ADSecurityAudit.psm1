<#
.SYNOPSIS
    Comprehensive Active Directory Audit and Reporting

.DESCRIPTION
    This module provides extensive capabilities to audit Active Directory environments
    for misconfigurations and security vulnerabilities. It evaluates user accounts,
    group policies, permissions, replication configurations, and AdminSDHolder objects.

.NOTES
    Author: AlchemicalChef
    Version: 1.11.0
    Requires: Active Directory PowerShell Module, Windows Server 2016+

.EXAMPLE
    Import-Module .\ADSecurityAudit.psm1
    Start-ADSecurityAudit -Verbose -ExportPath "C:\Reports"
#>
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

$script:ModuleRoot = $PSScriptRoot

# Single source of truth for the module version used at runtime (e.g. in the
# HTML report footer). Read from the manifest instead of being hardcoded a
# second time, so the two can never drift out of sync again.
try {
    $script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'ADSecurityAudit.psd1')).ModuleVersion
}
catch {
    Write-Verbose "Could not read ModuleVersion from manifest: $_"
    $script:ModuleVersion = 'Unknown'
}

$moduleScripts = @(
    'src/Common.ps1',
    'src/Scoring.ps1',
    'src/Snapshot.ps1',
    'src/UserAudits.ps1',
    'src/GroupAudits.ps1',
    'src/AdminSDAudits.ps1',
    'src/GpoAudits.ps1',
    'src/ReplicationAudits.ps1',
    'src/DomainSecurityAudits.ps1',
    'src/PermissionsAudits.ps1',
    'src/PrivilegedUsers.ps1',
    'src/CertificateServicesAudits.ps1',
    'src/CertificateServicesExtendedAudits.ps1',
    'src/KrbtgtAudits.ps1',
    'src/DomainTrustAudits.ps1',
    'src/LapsAudits.ps1',
    'src/AuditPolicyAudits.ps1',
    'src/DelegationAudits.ps1',
    'src/DomainAdminEquivalence.ps1',
    'src/MachineAccountQuotaAudits.ps1',
    'src/DomainHardeningAudits.ps1',
    'src/CoercionRelayAudits.ps1',
    'src/DnsSecurityAudits.ps1',
    'src/LegacyAuthAudits.ps1',
    'src/KerberosHardeningAudits.ps1',
    'src/StaleObjectDepthAudits.ps1',
    'src/Main.ps1',
    'src/Reporting.ps1'
)

foreach ($moduleScript in $moduleScripts) {
    $scriptPath = Join-Path -Path $script:ModuleRoot -ChildPath $moduleScript

    if (-not (Test-Path $scriptPath)) {
        throw "Required module file not found: $scriptPath"
    }

    . $scriptPath
}

Export-ModuleMember -Function @(
    'Start-ADSecurityAudit',
    'Test-ADUserSecurity',
    'Test-ADPrivilegedGroups',
    'Test-AdminSDHolder',
    'Test-ADGroupPolicies',
    'Test-ADReplicationSecurity',
    'Test-ADDomainSecurity',
    'Test-ADDangerousPermissions',
    'Get-ADPrivilegedUsers',
    'Test-ADCertificateServices',
    'Test-ADCSExtended',
    'Test-KRBTGTAccount',
    'Test-ADDomainTrusts',
    'Test-LAPSDeployment',
    'Test-AuditPolicyConfiguration',
    'Test-ConstrainedDelegation',
    'Test-ADDomainAdminEquivalence',
    'Test-ADMachineAccountQuota',
    'Test-ADDomainHardeningFlags',
    'Test-ADCoercionAndRelayExposure',
    'Test-ADDnsSecurity',
    'Test-ADLegacyAuthSurface',
    'Test-ADKerberosHardening',
    'Test-ADStaleObjectDepth',
    'Get-ADRiskScore',
    'Set-ADFindingMetadata',
    'Get-ADFindingMetadataMap',
    'Get-ADSnapshot',
    'Invoke-ADRuleSet',
    'Get-ADTier0Principal',
    'Invoke-ADQueryWithRetry',
    'ConvertTo-SafeCsvValue'
)
