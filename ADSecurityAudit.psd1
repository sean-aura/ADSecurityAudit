@{
    RootModule = 'ADSecurityAudit.psm1'
    ModuleVersion = '1.18.3'
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
        'Test-ADLegacyAuthSurface',
        'Test-ADKerberosHardening',
        'Test-ADStaleObjectDepth',
        'Test-ADGpoDeployedSecrets',
        'Test-ADKnownDCVulnerabilities',
        'Test-ADExchangeEscalation',
        'Test-ADRodcSecurity',
        'Get-ADControlPathGraph',
        'Test-ADControlPaths',
        'Export-ADControlPathGraphBloodHound',
        'Get-ADForestConsolidation',
        'Export-ADForestConsolidationHTML',
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
v1.18.3 - Fix Test-ADUserSecurity Regression Under -FromSnapshot
- Fixed Test-ADUserSecurity failing under -FromSnapshot with "Cannot process argument transformation on parameter 'User' ... the adapter cannot set the value of property 'Name'": a regression from 1.18.2. Test-PrivilegedUser's $User parameter was strongly typed as [Microsoft.ActiveDirectory.Management.ADUser], which broke once Snapshot.Users held flattened PSCustomObjects instead of raw ADUser objects. The parameter is now untyped since the function only reads .MemberOf.

v1.18.2 - Fix -FromSnapshot Duplicate-Key Error
- Fixed Start-ADSecurityAudit -FromSnapshot failing with a "duplicated keys 'ObjectGuid' and 'ObjectGUID'" error: Domain, DomainControllers, Users, and Computers are now flattened to plain PSCustomObjects with an explicit property list (same pattern as Groups/GPOs/ADCS/Trusts) instead of being stored as raw AD cmdlet output, which could carry the same attribute under two differently-cased property names.

v1.18.1 - Fix Get-ADSnapshot Hang, Add Progress Bar, Auto-Create Output Folders
- Fixed the AD CS collection step in Get-ADSnapshot requesting -Properties * on every certificate template/CA object (including full nTSecurityDescriptor ACLs and other unused binary attributes), which made ConvertTo-Json -Depth 12 during -ToJson serialization look like an indefinite hang on any domain with more than a handful of templates. Now requests only the specific properties Test-ADCSExtended reads, and flattens to plain PSCustomObjects (same pattern as Groups/GPOs). Applied the same fix to domain-trust collection.
- Added a stage-based Write-Progress bar to Get-ADSnapshot (12 collection stages) and to Invoke-ADRuleSet's offline test loop, matching the progress bar already present in Start-ADSecurityAudit's live-mode loop.
- Added missing Write-Verbose start/completion messages for the domain and domain-controller collection steps in Get-ADSnapshot.
- -ExportPath (Start-ADSecurityAudit) and the -ToJson parent directory (Get-ADSnapshot) are now created automatically if they don't exist, instead of erroring out.
- README.md: fixed unfenced Usage-section example commands (now proper powershell code blocks) and corrected -OutputPath to the actual -ExportPath parameter name.

v1.18.0 - CVE-2026-41089 (Netlogon RCE) Detection + BadSuccessor Patch-Level Classification
- Added a new Test-ADKnownDCVulnerabilities check for CVE-2026-41089: a critical (CVSS 9.8), unauthenticated Netlogon RPC (MS-NRPC) remote code execution against Domain Controllers, patched by Microsoft's May 12, 2026 Patch Tuesday update and reported under active in-the-wild exploitation since late May / early June 2026. Detection is patch/build-level evidence only (`Get-HotFix`/OS install date), identical in mechanism to the existing ZeroLogon/MS17-010/MS14-068/PrintNightmare checks - no Netlogon protocol traffic, authentication attempt, or exploit code of any kind. New ADFindingMetadataMap entry (MITRE T1210, ANSSI `vuln1_netlogon_cve2026_41089_unpatched`).
- Refined the BadSuccessor / dMSA Escalation Exposure finding to distinguish Domain Controllers patched for CVE-2025-53779 (build 26100.4946+, August 2025) from unpatched ones, instead of flagging every Windows Server 2025 DC identically regardless of patch level. Adds a new read-only per-DC UBR (Update Build Revision) remote registry read (`Get-ADKnownVulnUBR`, via .NET's `RegistryKey.OpenRemoteBaseKey` - no writes, no code execution) for DCs already gated by the existing Server 2025 base-build guard; a DC whose UBR cannot be read is reported as unknown patch status rather than silently assumed patched. Per independent post-patch research (Akamai), the finding continues to fire even for confirmed-patched DCs - with severity reduced from High to Medium only once every affected DC in the environment is confirmed patched - because a mutually-paired dMSA/target relationship can still be abused if an attacker controls both sides.
- Both additions are additive-only to the `Details` hashtable (`PatchedDomainControllers`, `UnpatchedDomainControllers`, `UnknownPatchStatusDomainControllers`, per-DC `UBR`/`BadSuccessorPatchStatus` fields); the `ADSecurityFinding` schema, existing ZeroLogon/MS17-010/MS14-068/PrintNightmare checks, and `-Snapshot` behavior (this audit remains live-only) are all unaffected.
- New Pester coverage in tests/KnownVulnAudits.Tests.ps1 for both features: the CVE-2026-41089 vulnerable/patched evidence paths, the UBR patch/unpatched/boundary/unreadable classification paths, and the severity-reduction-on-full-patch behavior.
- Sourcing note: the CVE-2026-41089 fix date (May 12, 2026, CVSS 9.8) and the CVE-2025-53779 UBR threshold (26100.4946) were independently re-verified on 2026-07-09 against multiple sources citing MSRC directly (SecurityWeek, Tenable, Zero Day Initiative, CERT-EU, and Microsoft's own KB5063878 support article) and both match this release's thresholds exactly. CERT-EU also lists verified per-OS fixed-build boundaries for CVE-2026-41089 (see the inline comment above the Netlogon2026 threshold); several lower-quality aggregator sites gave inconsistent KB numbers for the same CVE and were not relied on.

v1.17.1 - External Intelligence Refresh (Q3 2026)
- Quarterly refresh of external references in Test-ADKnownDCVulnerabilities and the MITRE ATT&CK mapping table. No detection logic, schema, or output contract changes.
- Re-verified all four legacy CVE fix-date thresholds (ZeroLogon, MS17-010, MS14-068, PrintNightmare) directly against MSRC; all four dates were already correct. Added inline source-URL + verification-date citation comments so the next refresh has a starting point.
- Added the missing MITRE ATT&CK display name for T1068 (Exploitation for Privilege Escalation) to the MitreTechniqueNames table - it was already referenced by two findings (DC Missing ZeroLogon Patch, PrintNightmare Exposure on DC) but had no display-name entry, a drift point flagged by this project's own maintenance checklist.
- Corrected the BadSuccessor / dMSA Escalation Exposure finding text, which claimed no version-detectable patched state existed for the issue. Microsoft shipped a partial KDC-side fix (CVE-2025-53779, August 2025, build 26100.4946+) since that text was written; Description/Impact/Remediation now reflect the patch while noting independent research shows the underlying dMSA-linking primitive still enables related abuse post-patch. The detection guard itself (Server 2025 base build >= 26100) is unchanged - distinguishing patched from unpatched builds would require reading the OS UBR, which is a new detection surface and is out of scope for this refresh (see the accompanying feature-request docs).
- Flagged two new feature-request candidates (not implemented in this release): a new Test-ADKnownDCVulnerabilities-family check for CVE-2026-41089 (unauthenticated Netlogon RCE, patched May 2026, actively exploited), and build-revision (UBR)-based patch-level detection for the existing BadSuccessor guard.

v1.17.0 - Multi-Domain / Forest Consolidation
- Added Get-ADForestConsolidation / Export-ADForestConsolidationHTML: an offline, file-based post-processing feature (not a live-AD detection module, not part of the Main.ps1 test dispatch table) that reads two or more of this module's own prior AD_Security_Audit_/AD_Security_Score_ JSON exports - one per domain - and rolls them up into a forest-wide view: a forest score/maturity using the same worst-category (MAX) semantics as Get-ADRiskScore, a per-category heatmap (worst domain per category), a worst-first domain comparison table, cross-domain trust-risk enrichment (annotates Test-ADDomainTrusts findings with the target domain's own score/maturity when that domain's report is also supplied), and "not scanned this run" flags for domains missing versus a prior consolidated run. No AD queries, credentials, or network access of any kind - pure offline aggregation of exports this module already produces. Comparable in spirit to PingCastle's paid "Conso" report, offered for free and implemented independently against this project's own JSON schema.

v1.16.2 - HTML Report: Consolidated Findings
- Findings that fire once per affected object (e.g. AdminSDHolder ACL Compromise across several principals) previously rendered as N separate top-level findings with identical Impact/Remediation text. The HTML report now groups by Category+Issue and renders one consolidated finding per group, with Impact/Remediation/MITRE/ANSSI shown once and every affected object (with its own specific description and detection time) listed underneath. Single-object findings render exactly as before. JSON/CSV exports are unchanged - this is a report-rendering change only, not an output-schema change.

v1.16.1 - Bug-Fix Release
- Fixed HTML report/console mojibake caused by a missing UTF-8 BOM (emoji literals replaced with HTML numeric character references).
- Fixed Test-ADDnsSecurity calling the nonexistent Get-DnsServerZoneTransfer cmdlet; transfer settings now read from Get-DnsServerZone's own properties.
- Fixed "PrivilegedGroupsString cannot be found" error in Get-ADTier0Principal (property now declared at construction).
- Fixed a Join-Path array-argument bug in Test-ADGpoDeployedSecrets that broke the script-credential scan.
- Added a legacy PublicKey.Key fallback in Test-ADCSWeakCertificate for hosts where GetRSAPublicKey() isn't resolvable.
- Fixed Test-ADCoercionAndRelayExposure losing Spooler status and wasting retries whenever WebClient wasn't installed; the two services are now queried independently.
- Fixed 6 findings in DomainAdminEquivalence.ps1 with a blank Impact field.
- Rebalanced Get-ADRiskScore to a diminishing-returns model so category scores no longer saturate to 100 after just 2-3 Critical findings (numeric scores will differ from v1.16.0 and earlier).
- Reduced default retry attempts/backoff in Invoke-ADQueryWithRetry for faster overall runs.
- HTML report: category risk bars now render (CSS display fix), findings are collapsible with per-section Expand/Collapse All, and the Executive Summary cards link to their section.
- Added progress bars to the main audit loop and export steps.
- Reworded PingCastle references throughout docs/code as feature comparisons, with an independence disclaimer added to the README.
- README installation steps now lead with running the module in place, with the previous copy-based install kept as a documented secondary option including update steps.

v1.16.0 - Attack-Path Graph & Indirect-Privilege (Control-Path) Findings
- Added Get-ADControlPathGraph: builds a directed control-edge graph from dangerous ACEs (GenericAll/WriteDacl/WriteOwner/GenericWrite/AllExtendedRights, the dangerous extended-rights and property-write tables in Common.ps1, including the DS-Replication set), group membership, and object ownership, reusing the existing rights tables and the step-02 snapshot/Get-ADTier0Principal.
- Added Test-ADControlPaths: breadth-first search from every non-Tier-0 principal that holds a dangerous ACE or ownership edge to the Tier-0 set (Get-ADTier0Principal + Domain Controllers + AdminSDHolder + the domain head object), emitting a finding per reachable path with the full principal->...->target hop chain in Details.HopChain. A broad principal (Everyone/Authenticated Users/Domain Users/ANONYMOUS LOGON) on any path is always Critical. Also flags Tier-0 objects owned by a non-Tier-0 principal (implicit WriteDacl-equivalent control via ownership).
- Chains the module's existing per-object primitives so the few paths that actually lead to Domain Admins/Domain Controllers surface as their own findings, rather than relying on a human to connect a pile of individually-scored flat ACE findings.
- Detection only: every edge is derived from a read of nTSecurityDescriptor, group membership, or object ownership - the same categories of read already performed elsewhere in the module. No exploitation, coercion, relay, ticket forging, or PoC traffic is ever sent to any host. ACL/ownership edges are scoped to the Tier-0 target set plus every group on a chain toward it, rather than sweeping nTSecurityDescriptor across the entire domain.
- Added Export-ADControlPathGraphBloodHound: optional BloodHound-compatible generic-edge JSON export of the same graph, written as a separate artifact so the existing JSON/HTML/CSV findings export is unchanged.
- Added a 'Control Paths to Tier-0' HTML report section rendering each path's hop chain.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-ControlPathIndirectEveryone, P-ControlPathIndirectMany, P-DCOwner, P-UnprotectedOU, P-DangerousExtendedRight).

v1.15.0 - Read-Only Domain Controller Security Posture
- Added Test-ADRodcSecurity: audits Read-Only Domain Controller configuration - Tier-0/privileged principals present in msDS-RevealedUsers (already cached) or the msDS-RevealOnDemandGroup allowed list (cross-referenced against Get-ADTier0Principal), password replication policy gaps (an allowed list that is too broad or a denied list missing expected privileged groups, via msDS-NeverRevealGroup), and orphaned RODC-specific krbtgt_* accounts left behind after an RODC was demoted/removed.
- Detection only: every determination is a read of RODC computer-object attributes (msDS-RevealedUsers, msDS-RevealOnDemandGroup, msDS-NeverRevealGroup) and a krbtgt_* account inventory cross-referenced against current RODC computer objects. No exploitation, coercion, relay, ticket forging, or PoC traffic is ever sent to any host.
- Clean exit when the domain has no RODCs.
- Snapshot-aware: accepts an optional -Snapshot parameter, falling back to live Get-ADDomainController/Get-ADObject reads when not supplied.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-RODCAdminRevealed, P-RODCAllowedGroup, P-RODCDeniedGroup, P-RODCNeverReveal, P-RODCRevealOnDemand, P-RODCKrbtgtOrphan, P-RODCSYSVOLWrite).

v1.14.0 - Exchange-in-AD Privilege Escalation (Exchange Windows Permissions / WriteDACL)
- Added Test-ADExchangeEscalation: flags Exchange security groups (Exchange Windows Permissions, Exchange Trusted Subsystem, Exchange Servers, Exchange Enterprise Servers, Organization Management) holding GenericAll/WriteDacl/WriteOwner on the domain head object (PrivExchange-style escalation to DCSync), and the same principals holding those rights on AdminSDHolder. Fires on RESIDUAL ACEs even when Exchange has been fully decommissioned from the forest, since the ACE is not cleaned up automatically.
- Detection only: every determination is a read of nTSecurityDescriptor.Access on the domain head and CN=AdminSDHolder,CN=System,<domain>. No PrivExchange push-subscription request, NTLM relay, or any other exploitation/coercion/PoC traffic is ever sent to any host.
- Snapshot-aware with no schema change: reads from Snapshot.ACLs.DomainRoot / Snapshot.ACLs.AdminSDHolder (both already collected by Get-ADSnapshot since v1.3.0), so -FromSnapshot is fully supported without any collection changes.
- Registered in Start-ADSecurityAudit's live test set and the offline rule registry; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-ExchangePrivEsc, P-ExchangeAdminSDHolder).

v1.13.0 - Known DC Vulnerabilities by Patch/Build (MS14-068, MS17-010, ZeroLogon, PrintNightmare, BadSuccessor)
- Added Test-ADKnownDCVulnerabilities: flags DC exposure to ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068, and PrintNightmare (CVE-2021-34527, only when the Spooler service is running) strictly from OS build/install date and installed hotfix level (Get-HotFix / Win32_QuickFixEngineering) against documented, inline-cited fix-date thresholds; also flags BadSuccessor/dMSA escalation exposure, guarded to Domain Controllers running Windows Server 2025 (build 26100+) since dMSA is a Server 2025-only feature.
- Detection only: every determination is a read of Win32_OperatingSystem, installed hotfixes, and the Print Spooler service state - the same category of read already used by Test-ADCoercionAndRelayExposure. No exploitation, authentication bypass, ticket forging, coercion, relay, or PoC traffic is ever sent to any host.
- Live-only: per-DC OS build, hotfix level, and Spooler state are real-time machine state with no snapshot equivalent, so this entire audit is skipped when invoked with -Snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure.
- Registered in Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-Vuln-MS14-068, S-Vuln-MS17_010, A-Krbtgt, A-DC-Spooler, A-BadSuccessor).

v1.12.0 - GPO-Deployed Secrets & Insecure Settings (GPP cpassword, Script Credentials)
- Added Test-ADGpoDeployedSecrets: scans each GPO's SYSVOL policy folder for Group Policy Preferences (GPP) 'cpassword' values left over from MS14-025 (Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml, DataSources.xml, Printers.xml), credential-flavoured patterns embedded in deployed logon/startup scripts, and insecure settings pushed via GPO (Windows Firewall disabled, hidden file extensions, RDP Network Level Authentication disabled or an insecure RDP security layer).
- Detection only: a 'cpassword' hit is reported by PRESENCE and FILE PATH ONLY - the value is never decrypted, decoded, or included in the finding; a script-credential hit is reported by file and line number only, never the matched line's content. Streams SYSVOL trees file-by-file/line-by-line rather than loading them wholesale, so large environments don't time out. Never modifies, deletes, or reuses any discovered secret, and performs no exploitation, coercion, relay, or PoC traffic.
- GPO enumeration can read from Snapshot.GPOs when -Snapshot is supplied, but every SYSVOL/registry.pol read is live file-share I/O (not part of the current snapshot schema), so this audit always performs live, read-only I/O regardless of -Snapshot, consistent with the other live-only sub-checks in the module.
- Registered in Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-DelegationGPOData, P-DelegationFileDeployed, P-DelegationLoginScript, S-FirewallScript, S-FolderOptions, S-TerminalServicesGPO, A-AnonymousAuthorizedGPO).

v1.11.0 - Stale-Object & Hygiene Depth (PASSWD_NOTREQD, primaryGroupID, Duplicate SPNs, DC Registration)
- Added Test-ADStaleObjectDepth: audits accounts with PASSWD_NOTREQD set (userAccountControl 0x0020), non-default primaryGroupID on user and computer objects (membership-hiding, distinguishing the legitimate Domain Controllers RID 516 for genuine DCs from a suspicious 516/other RID elsewhere), duplicate Service Principal Names across users and computers (reporting every holder), Domain Controllers not covered by any AD Sites & Services subnet object, and insufficient Domain Controller count (fewer than 2).
- Detection only: reads userAccountControl and primaryGroupID bitmasks/values, builds a case-insensitive in-memory SPN index from already-queried user/computer objects, and reads DC inventory (Get-ADDomainController) and subnet objects (Get-ADReplicationSubnet). Never sets, clears, or otherwise modifies any account attribute, SPN, or Sites & Services object, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the PASSWD_NOTREQD, primaryGroupID, and duplicate-SPN checks (Snapshot.Users / Snapshot.Computers, extended this release to also collect PrimaryGroupID for users and ServicePrincipalNames/SamAccountName for computers) and the DC-count check (Snapshot.DomainControllers); the DC subnet/site registration check always performs one live, read-only Get-ADReplicationSubnet call (subnet objects are not part of the current snapshot schema) even when -Snapshot supplies the DC list, consistent with the other live-only sub-checks elsewhere in the module.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-PwdNotRequired, S-PrimaryGroup, S-C-PrimaryGroup, S-Duplicate, S-DC-SubnetMissing, A-NotEnoughDC, S-DCRegistration).

v1.10.0 - Kerberos Hardening Depth (AES Enforcement, FAST/Armoring, Cross-Trust TGT Delegation)
- Added Test-ADKerberosHardening: audits RC4 Kerberos encryption still being permitted (Tier-0 privileged accounts and krbtgt via msDS-SupportedEncryptionTypes, trusts missing TRUST_USES_AES_KEYS, and the domain-wide 'Configure encryption types allowed for Kerberos' GPO/registry policy), Kerberos Armoring (FAST) not enabled (KDC and client EnableCbacAndArmor policy), and cross-trust TGT delegation (trustAttributes CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION).
- Detection only: reads msDS-SupportedEncryptionTypes bitmasks, GPO-linked registry policy (falling back to a direct per-DC registry read only when no linked GPO defines a setting), and trustAttributes via Get-ADTrust. Never sets, clears, or otherwise modifies any account attribute, policy, or registry value, never forges or requests a Kerberos ticket, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the account-level RC4 check (Snapshot.Users + the Tier-0 set) and both trust-level checks (Snapshot.Trusts); the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADLegacyAuthSurface and Test-ADCoercionAndRelayExposure.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-AesNotEnabled, T-AlgsAES, S-KerberosArmoring, S-KerberosArmoringDC, T-TGTDelegation).

v1.9.0 - Legacy Auth & Name-Poisoning Surface (SMBv1, Signing, LM/NTLMv1, LLMNR, WSUS-HTTP)
- Added Test-ADLegacyAuthSurface: audits legacy/weak authentication and name-resolution poisoning surface enforced (or left unenforced) via GPO/registry - SMBv1 enabled/not disabled by policy, SMB signing not required, LM/NTLMv1 authentication permitted (LmCompatibilityLevel < 3), LLMNR not disabled by policy, and WSUS delivered over HTTP (package-injection MITM surface).
- Detection only: reads GPO-linked registry policy values via Get-GPRegistryValue against each linked GPO's registry.pol (Domain Controllers OU first, then domain root), and falls back to a direct per-DC registry read only when no linked GPO defines a setting, so a locally configured (non-policy) value is still caught. Every finding's Details distinguishes a policy-enforced value (naming the source GPO) from one observed via live registry read with no enforcing policy found. Never sets, clears, or otherwise modifies any policy or registry value, and performs no exploitation, coercion, relay, or PoC traffic (e.g. no Responder-style poisoning or SMB relay is ever triggered).
- Live-only: GPO-linked registry policy state and per-DC registry reads are not part of the current snapshot schema, so this entire audit is skipped when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): S-SMB-v1, A-SMB2SignatureNotEnabled, A-SMB2SignatureNotRequired, A-LMHashAuthorized, S-OldNtlm, A-NoGPOLLMNR, S-WSUS-HTTP).

v1.8.0 - AD-Integrated DNS Security (DnsAdmins, Zone Transfer, Insecure Updates, ADIDNS)
- Added Test-ADDnsSecurity: audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's ServerLevelPluginDll mechanism), zone transfer exposure (transfers to any server or any NS-listed server, rather than an explicit secondary list), insecure (nonsecure) dynamic DNS updates, and overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface).
- Detection only: reads DnsAdmins group membership, AD-integrated zone object attributes (dNSProperty) and ACLs (nTSecurityDescriptor), and optionally the read-only Get-DnsServerZone/Get-DnsServerZoneTransfer cmdlets when the DnsServer RSAT module is available, falling back to a best-effort dNSProperty attribute parse otherwise. Never creates, deletes, or modifies a DNS record, zone, or plugin DLL configuration, and performs no exploitation, coercion, relay, or PoC traffic.
- Snapshot-aware for the DnsAdmins membership check (reads Snapshot.Groups); the zone transfer, dynamic update, and ADIDNS CreateChild checks are live-only (zone-level attributes/ACLs are not part of the current snapshot schema) and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): P-DNSAdmin, P-DNSDelegation, A-DnsZoneTransfert, A-DnsZoneUpdate1, A-DnsZoneUpdate2, A-DnsZoneAUCreateChild).
- Fixed: the HTML report footer's module version string was hardcoded and had drifted out of sync with ModuleVersion since v1.7.0; it is now read from the module manifest at import time so it can no longer go stale.

v1.7.0 - AD CS Beyond ESC1/2/3/7 (ESC4, ESC8, ROCA, Weak PKI Crypto)
- Added Test-ADCSExtended: ESC4 (dangerous template ACLs granting Write/WriteDacl/WriteOwner/GenericAll/GenericWrite to low-privileged principals), a high-risk-without-approval check (enrollee-supplied subject/SAN or Any-Purpose EKU with no manager-approval gate, distinct from the existing ESC1/ESC2 checks), ESC8 (CA web enrollment reachable over HTTP without Extended Protection for Authentication), and a ROCA (CVE-2017-15361) / weak-signature-algorithm / weak-RSA-modulus sweep of the CA certificates and the NTAuth/AIA/Root store.
- Detection only: reads template/CA attributes, ACLs, and already-published certificate bytes; ESC8's only live-network step is a read-only remote check of the CA host's web-enrollment configuration. Never requests, forges, or relays a certificate, and sends no coercion/PoC traffic.
- Snapshot-aware where the data allows it: template/CA enumeration and the approval-gate and CA-certificate weak-crypto checks read from Snapshot.ADCS (unchanged snapshot schema). ESC4's per-template ACL read, the ESC8 CA-host probe, and the NTAuth/AIA/Root store sweep are live-only and are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with Test-ADCoercionAndRelayExposure and the anonymous-bind probe in Test-ADDomainHardeningFlags.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): A-CertEnrollHttp, A-CertTempNoSecurity, A-CertTempAnyPurpose, A-CertTempAnyone, A-CertTempCustomSubject, A-CertROCA, A-CertWeakRsaComponent, A-MD5RootCert, A-SHA1RootCert).

v1.6.0 - Coercion & NTLM Relay Exposure
- Added Test-ADCoercionAndRelayExposure: audits each Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler running (PrinterBug), WebClient running (WebDAV coercion), NTDS LDAPServerIntegrity not requiring signing, and LdapEnforceChannelBinding not requiring Extended Protection for Authentication (EPA).
- Detection only: reads service and NTDS registry state per DC (remote registry / Invoke-Command); never sends a coercion trigger, never relays, and performs no exploitation or PoC traffic.
- Live per-DC probes are skipped entirely when run from a snapshot (-FromSnapshot performs no live AD/network access), consistent with the anonymous-bind probe in Test-ADDomainHardeningFlags; the DC list itself is still read from the snapshot when supplied.
- Registered in Invoke-ADRuleSet and Start-ADSecurityAudit's live test set; tagged in the central Scoring.ps1 mapping table (PingCastle-comparable check(s): A-DC-Coerce, A-DC-Spooler, A-DC-WebClient, A-DCLdapSign, A-DCLdapsChannelBinding).

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
