@{
    RootModule = 'ADSecurityAudit.psm1'
    ModuleVersion = '1.4.0'
    GUID = '7eaedb96-5ee9-4cdf-9ebf-c5618a0d2f14'
    Author = 'AlchemicalChef'
    CompanyName = 'Community'
    Copyright = '(c) 2025 AlchemicalChef. All rights reserved.'
    Description = 'Comprehensive Active Directory security auditing and reporting.'
    PowerShellVersion = '5.1'
    RequiredModules = @('ActiveDirectory')
    FunctionsToExport = @(
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
        'Test-KRBTGTAccount',
        'Test-ADDomainTrusts',
        'Test-LAPSDeployment',
        'Test-AuditPolicyConfiguration',
        'Test-ConstrainedDelegation',
        'Test-ADDomainAdminEquivalence',
        'Test-ADMachineAccountQuota',
        'Get-ADRiskScore',
        'Set-ADFindingMetadata',
        'Get-ADFindingMetadataMap',
        'Get-ADSnapshot',
        'Invoke-ADRuleSet',
        'Get-ADTier0Principal',
        'Invoke-ADQueryWithRetry',
        'ConvertTo-SafeCsvValue'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Security', 'Audit', 'Compliance')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/AlchemicalChef/ADSecurityAudit'
            IconUri = ''
            ReleaseNotes = @"
v1.4.0 - Machine Account Quota
- Added Test-ADMachineAccountQuota: audits ms-DS-MachineAccountQuota on the domain root, flagging the unmodified default of 10 (High) and any other non-zero value (Medium) that lets authenticated users self-service-join computer accounts, which can be abused for RBCD relay and SamAccountName-spoofing privilege escalation.
- Snapshot-aware from day one: Get-ADSnapshot now also collects ms-DS-MachineAccountQuota; Test-ADMachineAccountQuota reads it from a supplied -Snapshot or falls back to a live Get-ADObject read.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (MITRE T1136.002).

v1.3.0 - Collect-Once Snapshot, Rule-Runner & Offline Mode
- Added Get-ADSnapshot: one paged, read-only collection pass over users, computers, groups, GPOs, ACLs on key objects, AD CS config, DNS zones, trusts, and DC inventory, with -ToJson for serialisation.
- Added Invoke-ADRuleSet -Snapshot: dispatches Test-* functions against a snapshot, defensively splatting -Snapshot only to functions that declare it so snapshot-unaware modules are called live and never error.
- Added Start-ADSecurityAudit -FromSnapshot <path> for offline re-analysis (no live AD access) producing the same JSON/HTML/CSV report and score.
- Added shared Get-ADTier0Principal helper (privileged/Tier-0 principal set) for reuse by later features.
- Began retrofitting existing audit functions (Test-ADUserSecurity, Test-KRBTGTAccount) with an optional -Snapshot parameter; remaining modules will be retrofitted gradually in later steps.

v1.2.0 - Scoring, ANSSI Maturity & MITRE ATT&CK
- Added 0-100 risk score (higher = worse) with per-category sub-scores and a 1-5 ANSSI-style maturity level (Get-ADRiskScore).
- Added MITRE ATT&CK technique and ANSSI control tagging on every finding via a central mapping table (src/Scoring.ps1, Set-ADFindingMetadata).
- Added additive MitreTechnique, AnssiControl, and Weight fields to ADSecurityFinding (output schema is now additive-only / contract-stable).
- Added score gauge, maturity panel, and MITRE technique summary to the HTML report; appended new CSV columns and a score/maturity sidecar JSON.

v1.1.0 - Reliability & Security Improvements
- SECURITY: Fixed CSV injection vulnerability in report exports
- Added Domain Controller failover support for improved reliability
- Added Invoke-ADQueryWithRetry helper for network resilience (exponential backoff)
- Added result pagination for large AD queries (prevents timeouts in large environments)
- Converted 40+ silent failures to proper try/catch with verbose logging
- Improved error handling across all audit modules
- Added ConvertTo-SafeCsvValue function for safe CSV exports

v1.0.1 - Bug Fixes
- Fixed nested group detection in Test-ADPrivilegedGroups
- Fixed LAPS schema path lookup
- Fixed SID lookup in DCSync detection
- Fixed variable ordering in Test-ADDomainAdminEquivalence
- Fixed GUID case sensitivity issues
- Added Test-ADDomainAdminEquivalence to exported functions
- Improved ESC1 detection to check enrollment permissions
- Improved audit policy checking to actually verify auditpol settings
- Improved Kerberoasting detection with encryption type and password age checks
- Fixed orphaned adminCount detection to use recursive group membership

v1.0.0 - Initial Release
- Core AD security auditing capabilities
- Certificate Services vulnerability scanning
- KRBTGT password age monitoring
- Domain trust auditing
- LAPS deployment verification
- Audit policy validation
- Constrained delegation analysis
"@
        }
    }
}
