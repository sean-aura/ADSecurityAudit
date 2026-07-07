@{
    RootModule = 'ADSecurityAudit.psm1'
    ModuleVersion = '1.8.0'
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
v1.8.0 - AD-Integrated DNS Security (DnsAdmins, Zone Transfer, Insecure Updates, ADIDNS)
- Added Test-ADDnsSecurity: audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's ServerLevelPluginDll mechanism), zone transfer exposure (transfers to any server or any NS-listed server, rather than an explicit secondary list), insecure (nonsecure) dynamic DNS updates, and overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface).
- Detection only: reads DnsAdmins group membership, AD-integrated zone object attributes (dNSProperty) and ACLs (nTSecurityDescriptor), and optionally the read-only Get-DnsServerZone/Get-DnsServerZoneTransfer cmdlets when the DnsServer RSAT module is available, falling back to a best-effort dNSProperty attribute parse otherwise. Never creates, deletes, or modifies a DNS record, zone, or plugin DLL configuration, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the DnsAdmins membership check (reads Snapshot.Groups); the zone transfer, dynamic update, and ADIDNS CreateChild checks are live-only (zone-level attributes/ACLs are not part of the current snapshot schema) and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle parity: P-DNSAdmin, P-DNSDelegation, A-DnsZoneTransfert, A-DnsZoneUpdate1, A-DnsZoneUpdate2, A-DnsZoneAUCreateChild).
- Fixed: the HTML report footer's module version string was hardcoded and had drifted out of sync with ModuleVersion since v1.7.0; it is now read from the module manifest at import time so it can no longer go stale.

v1.7.0 - AD CS Beyond ESC1/2/3/7 (ESC4, ESC8, ROCA, Weak PKI Crypto)
- Added Test-ADCSExtended: ESC4 (dangerous template ACLs granting Write/WriteDacl/WriteOwner/GenericAll/GenericWrite to low-privileged principals), a high-risk-without-approval check (enrollee-supplied subject/SAN or Any-Purpose EKU with no manager-approval gate, distinct from the existing ESC1/ESC2 checks), ESC8 (CA web enrollment reachable over HTTP without Extended Protection for Authentication), and a ROCA (CVE-2017-15361) / weak-signature-algorithm / weak-RSA-modulus sweep of the CA certificates and the NTAuth/AIA/Root store.
- Detection only: reads template/CA attributes, ACLs, and already-published certificate bytes; ESC8's only live-network step is a read-only remote check of the CA host's web-enrollment configuration. Never requests, forges, or relays a certificate, and sends no coercion/PoC traffic.
- Snapshot-aware where the data allows it: template/CA enumeration and the approval-gate and CA-certificate weak-crypto checks read from Snapshot.ADCS (unchanged snapshot schema). ESC4's per-template ACL read, the ESC8 CA-host probe, and the NTAuth/AIA/Root store sweep are live-only and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle parity: A-CertEnrollHttp, A-CertTempNoSecurity, A-CertTempAnyPurpose, A-CertTempAnyone, A-CertTempCustomSubject, A-CertROCA, A-CertWeakRsaComponent, A-MD5RootCert, A-SHA1RootCert).

v1.6.0 - Coercion & NTLM Relay Exposure
- Added Test-ADCoercionAndRelayExposure: audits each Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler running (PrinterBug), WebClient running (WebDAV coercion), NTDS LDAPServerIntegrity not requiring signing, and LdapEnforceChannelBinding not requiring Extended Protection for Authentication (EPA).
- Detection only: reads service and NTDS registry state per DC (remote registry / Invoke-Command); never sends a coercion trigger, never relays, and performs no exploitation or PoC traffic.
- Live per-DC probes are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with the anonymous-bind probe in Test-ADDomainHardeningFlags; the DC list itself is still read from the snapshot when supplied.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle parity: A-DC-Coerce, A-DC-Spooler, A-DC-WebClient, A-DCLdapSign, A-DCLdapsChannelBinding).

v1.5.0 - Domain Hardening Flags
- Added Test-ADDomainHardeningFlags: audits dSHeuristics for dangerous positional flags (anonymous access, List Object security mode, AdminSDHolder exclusion mask weakening), flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group, and performs a strictly read-only anonymous LDAP/RootDSE bind probe (success is the finding; refusal is secure).
- Snapshot-aware for dSHeuristics and Pre-Windows 2000 membership: Get-ADSnapshot now also collects DsHeuristics and PreWin2000Members. The anonymous-bind probe is a live network operation and is skipped when running from a snapshot (-FromSnapshot performs no live AD/network access).
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (MITRE T1556, T1078.002, T1087.002).

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
