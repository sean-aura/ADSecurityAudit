# Active Directory Security Audit 

A comprehensive PowerShell module for identifying misconfigurations and security vulnerabilities within Active Directory environments.

The repository also includes a responsive web dashboard (in `ui/`) that visualizes the JSON output from the audit scripts. Upload an audit JSON or load the bundled sample to explore findings by category (e.g., computer account delegation, fine-grained password policies, DNS security configuration) and drill into remediation guidance with documentation links.

## Features

### Core Auditing Capabilities

- **User Account Auditing**: Detects AS-REP Roasting vulnerabilities, weak encryption, reversible passwords, unconstrained delegation, Kerberoasting risks, and inactive accounts
- **Privileged Group Analysis**: Identifies excessive membership, nested groups, and disabled users in critical groups
- **AdminSDHolder Security**: Scans for risky permissions and unauthorized modifications that could lead to persistent compromise
- **Group Policy Assessment**: Detects over-permissioned GPOs, insecure SYSVOL permissions, and mislinked policies
- **DCSync Detection**: Identifies unauthorized replication permissions that enable credential dumping attacks
- **Domain Security Settings**: Evaluates password policies, functional levels, legacy systems, and AzureADSSOACC rotation compliance
- **Dangerous Permissions**: Locates overly permissive rights on critical AD objects

### Advanced Security Features

- **Certificate Services (AD CS) Vulnerabilities**: Scans for exploitable certificate templates (ESC1/ESC2/ESC3) where attackers can request certificates for privilege escalation, and audits Certificate Authority permissions (ESC7)
- **KRBTGT Password Age Analysis**: Monitors KRBTGT account password age to prevent Golden Ticket attacks, alerting when passwords exceed the recommended 180-day rotation threshold
- **Domain Trust Security**: Comprehensive auditing of trust relationships including SID filtering status, selective authentication validation, trust direction analysis, and bidirectional trust detection
- **LAPS Deployment Verification**: Validates Local Administrator Password Solution (LAPS) schema installation, checks computer coverage percentage, and identifies systems with static local admin passwords
- **Audit Policy Configuration**: Verifies critical audit policies are enabled on domain controllers, validates SACL configurations on sensitive objects, and ensures proper security event logging
- **Constrained Delegation Analysis**: Identifies accounts with constrained delegation, dangerous protocol transition (T2A4D), and resource-based constrained delegation (RBCD) configurations
- **Risk Scoring, ANSSI Maturity & MITRE ATT&CK Tagging**: Rolls findings up into a 0-100 risk score with per-category sub-scores, a 1-5 ANSSI-style maturity level, and MITRE ATT&CK technique tagging, all driven by a single source-of-truth mapping table (`Get-ADRiskScore`, `Set-ADFindingMetadata`)
- **Collect-Once Snapshot & Offline Mode**: `Get-ADSnapshot` performs a single paged collection pass reused across checks, and `Start-ADSecurityAudit -FromSnapshot` re-runs the full audit offline with no live AD access
- **Machine Account Quota**: Audits `ms-DS-MachineAccountQuota` on the domain root and flags the unmodified default of 10 or any other non-zero value that lets authenticated users self-service-join computer accounts, a common foothold for RBCD relay and SamAccountName-spoofing privilege escalation
- **Domain Hardening Flags**: Positionally parses the `dSHeuristics` attribute for dangerous settings (anonymous access, List Object security mode, AdminSDHolder exclusion mask weakening), flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group, and performs a strictly read-only anonymous LDAP/RootDSE bind probe
- **Coercion & NTLM Relay Exposure**: Checks every Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler (PrinterBug) or WebClient (WebDAV) running, LDAP signing not enforced, and LDAP channel binding (EPA) not required
- **AD CS Extended (ESC4, ESC8, ROCA, Weak PKI Crypto)**: Extends AD CS coverage beyond ESC1/2/3/7 with dangerous template ACLs (ESC4), high-risk templates missing a manager-approval gate, CA web enrollment reachable over HTTP without Extended Protection for Authentication (ESC8), ROCA-vulnerable (CVE-2017-15361) RSA keys, and weak signature algorithms/RSA key sizes across the CA certificates and the NTAuth/AIA/Root store
- **AD-Integrated DNS Security**: Audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's `ServerLevelPluginDll` mechanism), DNS zone transfer exposure (transfers to any server or any NS-listed server rather than an explicit secondary list), insecure (nonsecure) dynamic DNS updates, and overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface)
- **Legacy Auth & Name-Poisoning Surface**: Audits GPO/registry-enforced legacy authentication and name-resolution poisoning surface - SMBv1 enabled/not disabled by policy, SMB signing not required, LM/NTLMv1 authentication permitted (`LmCompatibilityLevel` < 3), LLMNR not disabled by policy, and WSUS delivered over HTTP (package-injection MITM surface) - distinguishing policy-enforced values (naming the source GPO) from unset/local ones
- **Kerberos Hardening Depth**: Audits RC4 Kerberos encryption still being permitted (Tier-0 privileged accounts and krbtgt via `msDS-SupportedEncryptionTypes`, trusts missing the `TRUST_USES_AES_KEYS` attribute, and the domain-wide "Configure encryption types allowed for Kerberos" GPO/registry policy), Kerberos Armoring (FAST) not enabled (KDC and client `EnableCbacAndArmor` policy), and cross-trust TGT delegation (trusts with the `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` `trustAttributes` flag set)
- **Stale-Object & Hygiene Depth**: Audits accounts with the PASSWD_NOTREQD flag set (`userAccountControl` 0x0020), non-default `primaryGroupID` on user and computer objects (a known membership-hiding technique, distinguishing the legitimate Domain Controllers RID for genuine DCs from a suspicious value elsewhere), duplicate Service Principal Names across users and computers (reporting every holder), Domain Controllers not covered by any AD Sites & Services subnet object, and insufficient Domain Controller count

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Active Directory PowerShell Module (RSAT)
- Domain Administrator or equivalent permissions for full audit
- Windows Server 2016 or later (recommended)
- Network connectivity to Domain Controllers
- Appropriate read permissions for AD Certificate Services (if installed)

## Installation

1. Copy the module to your PowerShell modules directory:
```powershell
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\ADSecurityAudit"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item -Path ".\ADSecurityAudit.psd1" -Destination "$modulePath\ADSecurityAudit.psd1"
Copy-Item -Path ".\ADSecurityAudit.psm1" -Destination "$modulePath\ADSecurityAudit.psm1"
Copy-Item -Path ".\src" -Destination "$modulePath\src" -Recurse -Force
```


2. Import the module:
```powershell
Import-Module ADSecurityAudit
```


## Usage

### Basic Audit
Run a complete security audit with default settings:

Start-ADSecurityAudit -OutputPath "C:\ADReports"


### Advanced Options
Customize the audit with additional parameters:

Start-ADSecurityAudit -OutputPath "C:\ADReports" -Verbose

### Offline / Snapshot-Based Audit
Collect once, analyze later or elsewhere, with no live AD access at analysis time:

Get-ADSnapshot -ToJson "C:\Snapshots\contoso.json"
Start-ADSecurityAudit -FromSnapshot "C:\Snapshots\contoso.json" -ExportPath "C:\ADReports"


### Output Formats
The script generates these report formats:
- **HTML Report**: Color-coded interactive report with severity indicators, a risk-score gauge, an ANSSI maturity panel, per-category risk bars, and a MITRE ATT&CK technique summary
- **CSV Export**: Detailed findings in spreadsheet format for analysis (now includes appended `MitreTechnique`, `AnssiControl`, and `Weight` columns)
- **JSON Export**: Machine-readable findings (the new metadata fields serialize automatically)
- **Score sidecar (JSON)**: `AD_Security_Score_<timestamp>.json` containing the global risk score, per-category sub-scores, maturity level, and MITRE roll-up

## Scoring & Maturity

As of v1.2.0 every audit run produces an executive roll-up on top of the raw findings, computed by `Get-ADRiskScore`:

- **Risk score (0-100, higher = worse)** — each finding carries a `Weight`; a category's sub-score is the sum of its findings' weights (capped at 100), and the **global score is the worst category's sub-score** (PingCastle-style "you are as exposed as your weakest area").
- **Per-category sub-scores** — a 0-100 score per audit category (Kerberos Security, Certificate Services, Replication Security, etc.), rendered as bars in the HTML report.
- **ANSSI-style maturity level (1-5, higher = better)** — derived from the ANSSI control level mapped to each finding. A single Level 1 finding caps maturity at Level 1; maturity rises as the most critical hygiene gaps are closed.
- **MITRE ATT&CK tagging** — every finding is tagged with the technique it maps to (e.g. `T1558.001` Golden Ticket, `T1003.006` DCSync, `T1649` AD CS abuse), and the report shows a technique-frequency summary.

All tagging flows from a **single source-of-truth mapping table** in `src/Scoring.ps1` (`Issue → MITRE technique → ANSSI control → weight`). To extend coverage for a new check, add one entry there keyed by the finding's exact `Issue` string; `Set-ADFindingMetadata` and `Get-ADRiskScore` pick it up automatically. The output schema is **additive-only**: new finding fields and CSV columns are appended, never reordered or removed.

> Note: MITRE technique IDs are authoritative; the ANSSI control identifiers follow ANSSI/PingCastle maturity conventions and should be reviewed against the current official ANSSI Active Directory control catalogue before use in formal compliance reporting.

## Collect-Once Snapshot & Offline Analysis

As of v1.3.0, AD collection is decoupled from rule evaluation:

- **`Get-ADSnapshot [-ToJson <path>]`** performs one paged, read-only collection pass over users, computers, groups, GPOs (+ permissions), ACLs on key objects (AdminSDHolder, domain root, certificate templates container), AD CS configuration, DNS zones, domain trusts, DC inventory, and the domain's `ms-DS-MachineAccountQuota` attribute, returning a single structured snapshot. Pass `-ToJson` to also persist it to disk for later offline re-analysis.
- **`Invoke-ADRuleSet -Snapshot $snapshot`** dispatches the `Test-*` audit functions against that snapshot. Before passing `-Snapshot` to a function it checks whether that function actually declares the parameter (`(Get-Command $fn).Parameters.ContainsKey('Snapshot')`); functions that haven't been retrofitted yet are simply invoked live instead of erroring. Audit modules are being retrofitted with an optional `-Snapshot` parameter gradually (currently `Test-ADUserSecurity`, `Test-KRBTGTAccount`, `Test-ADMachineAccountQuota`, `Test-ADDomainHardeningFlags` (dSHeuristics and Pre-Windows 2000 membership only - its anonymous-bind check is a live network probe and is skipped in offline mode), `Test-ADCoercionAndRelayExposure` (its Spooler/WebClient/LDAP-registry checks are live per-DC network probes and are skipped entirely in offline mode; only the DC list is taken from the snapshot), and `Test-ADCSExtended` (template/CA enumeration and the approval-gate/CA-certificate weak-crypto checks read from `Snapshot.ADCS`; the per-template ACL read (ESC4), the CA-host web-enrollment probe (ESC8), and the NTAuth/AIA/Root store sweep are live-only and are skipped entirely in offline mode), and `Test-ADDnsSecurity` (the DnsAdmins membership check reads from `Snapshot.Groups`; the zone transfer, dynamic-update, and ADIDNS CreateChild checks read zone-level attributes/ACLs not present in the current snapshot schema and are skipped entirely in offline mode)); `Test-ADLegacyAuthSurface` declares an optional `-Snapshot` parameter for registry consistency but is entirely live-only (GPO-linked registry policy state and per-DC registry reads have no snapshot equivalent) and returns no findings when invoked with `-Snapshot`; `Test-ADKerberosHardening` (the account-level RC4 check reads from `Snapshot.Users` and the Tier-0 set, and both trust-level checks read from `Snapshot.Trusts`; the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely in offline mode); `Test-ADStaleObjectDepth` (the PASSWD_NOTREQD, primaryGroupID, and duplicate-SPN checks read from `Snapshot.Users`/`Snapshot.Computers`, and the DC-count check reads from `Snapshot.DomainControllers`; the DC subnet/site registration check always performs one live, read-only `Get-ADReplicationSubnet` call, since subnet objects are not part of the current snapshot schema, even when the DC list itself comes from the snapshot); this list will grow across future releases.
- **`Start-ADSecurityAudit -FromSnapshot <path>`** re-runs the full audit offline against a previously saved snapshot - no live AD access is performed - and produces the same JSON/HTML/CSV report and risk score as a live run.
- **`Get-ADTier0Principal [-Snapshot $snapshot]`** returns the shared privileged/Tier-0 principal set (recursive membership of the protected groups) used across detection modules; it can be derived from a snapshot or from live AD.

```powershell
# Collect once, on the DC or a management host with AD access:
Get-ADSnapshot -ToJson "C:\Snapshots\contoso_2026-07-07.json" -Verbose

# Later, anywhere, without AD access:
Start-ADSecurityAudit -FromSnapshot "C:\Snapshots\contoso_2026-07-07.json" -ExportPath "C:\ADReports"
```

New audit modules going forward should accept an optional `[hashtable]$Snapshot` parameter and read from it when supplied, falling back to live queries when it's not - keeping every module runnable both live and offline.

### Visual dashboard

Open `ui/index.html` in a browser and either upload your generated JSON report or click **Load sample report** to explore the UI. The dashboard highlights severity distributions, privileged account counts, and provides tap-to-expand detail views with remediation references for each finding.

## Security Findings Categories

The audit generates findings across multiple severity levels:

### Critical Findings
- Exploitable AD CS certificate templates
- CA web enrollment reachable over HTTP without EPA (ESC8)
- KRBTGT password not rotated (Golden Ticket risk)
- Unconstrained delegation on user accounts
- DCSync permissions granted to non-admin users
- Domain trusts without SID filtering

### High Findings
- Weak password policies
- Accounts with password never expires
- Service accounts with SPNs using weak encryption
- Missing LAPS deployment on computers
- Disabled critical audit policies
- Constrained delegation with protocol transition
- Machine Account Quota left at the unrestricted default of 10
- Dangerous dsHeuristics flags (anonymous access, List Object mode, AdminSDHolder exclusion mask weakening)
- Broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in Pre-Windows 2000 Compatible Access
- Certificate templates with weak ACLs granting write access to low-privileged principals (ESC4)
- Certificate templates allowing high-risk enrollment without manager approval
- ROCA-vulnerable (CVE-2017-15361) certificate keys
- Non-default membership in the DnsAdmins group (DNS server plugin-DLL code-execution path)
- AD-integrated DNS zones granting Authenticated Users/Everyone/ANONYMOUS LOGON broad CreateChild rights (ADIDNS spoofing)
- SMBv1 enabled or not disabled by policy
- SMB signing not required
- LM/NTLMv1 authentication permitted (`LmCompatibilityLevel` < 3)
- WSUS delivered over HTTP (package-injection MITM surface)

### Medium Findings
- Nested groups in privileged groups
- Stale privileged accounts
- Missing selective authentication on trusts
- Low LAPS coverage percentage
- Resource-based constrained delegation configurations
- Non-zero (but reduced) Machine Account Quota
- Anonymous LDAP/RootDSE binding permitted (null-session indicator)
- Weak signature algorithms (MD2/MD4/MD5/SHA0/SHA1) or undersized RSA keys in the PKI trust store
- AD-integrated DNS zones allowing transfer to any server or any NS-listed server
- AD-integrated DNS zones permitting insecure (nonsecure) dynamic updates
- LLMNR not disabled by policy

### Low Findings
- Informational findings about domain configuration
- Baseline security posture indicators

## Report Interpretation

### HTML Report Structure
- **Executive Summary**: Overview of total findings by severity
- **Risk Score & Maturity**: Global risk-score gauge, ANSSI 1-5 maturity ladder, per-category risk bars, and a MITRE ATT&CK technique summary
- **Critical Issues**: Immediate action required
- **Detailed Findings**: Complete list with remediation guidance (each finding shows its MITRE technique and ANSSI control)
- **Affected Objects**: Lists of users, groups, computers, and objects requiring attention

### Remediation Guidance
Each finding includes:
- **Description**: What the vulnerability is
- **Impact**: Why it matters for security
- **Affected Objects**: Specific accounts, groups, or systems
- **Remediation**: Step-by-step fix instructions

## Common Security Issues Detected

### Certificate Services Vulnerabilities
- Certificate templates allowing SAN specification (ESC1)
- Templates with overly permissive enrollment rights (ESC2)
- Enrollment agent templates (ESC3)
- CA permissions allowing unauthorized certificate issuance (ESC7)
- Certificate templates with weak ACLs (Write/WriteDacl/WriteOwner/GenericAll/GenericWrite for low-privileged principals) (ESC4)
- Templates allowing enrollee-supplied subject/SAN or an Any-Purpose EKU with no manager-approval gate
- CA web enrollment reachable over HTTP without Extended Protection for Authentication (ESC8)
- ROCA-vulnerable (CVE-2017-15361) RSA keys and weak signature algorithms/RSA key sizes across the CA certificates and the NTAuth/AIA/Root store

### Kerberos Security
- KRBTGT password older than 180 days
- Accounts with unconstrained delegation
- Accounts with constrained delegation and protocol transition
- Service accounts with weak Kerberos encryption (RC4)

### Trust Relationships
- Trusts without SID filtering (allows SID history attacks)
- Bidirectional trusts increasing attack surface
- Missing selective authentication on external trusts
- Stale or misconfigured trust relationships

### Local Administrator Security
- Computers without LAPS protection
- Static local admin passwords enabling lateral movement
- Missing LAPS schema extensions

### Machine Account Quota
- `ms-DS-MachineAccountQuota` left at the unmodified default of 10
- Any non-zero quota allowing unprivileged users to self-service-join computer accounts (RBCD / SamAccountName-spoofing foothold)

### Domain Hardening Flags
- Dangerous `dSHeuristics` positional flags: anonymous access, List Object security mode, or AdminSDHolder exclusion mask weakening
- Broad principals (Authenticated Users, Everyone, ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group
- Anonymous LDAP/RootDSE binding permitted (a null-session indicator)

### Coercion & NTLM Relay Exposure
- Print Spooler service running on a Domain Controller (PrinterBug coercion surface)
- WebClient (WebDAV) service running on a Domain Controller (WebDAV coercion surface)
- LDAP signing not enforced (`LDAPServerIntegrity` not set to require signing)
- LDAP channel binding / Extended Protection for Authentication not required (`LdapEnforceChannelBinding` not set to `2`)

### AD-Integrated DNS Security
- Non-default members in the built-in `DnsAdmins` group (a direct path to Domain-Controller code execution via `ServerLevelPluginDll`)
- AD-integrated zones configured to allow zone transfer to any server or any server listed as an NS record, instead of an explicit secondary-server list
- AD-integrated zones permitting nonsecure (unauthenticated) dynamic DNS updates
- AD-integrated zone objects granting Authenticated Users, Everyone, or ANONYMOUS LOGON the right to create child objects (ADIDNS spoofing/MITM surface)

### Legacy Auth & Name-Poisoning Surface
- SMBv1 permitted (enabled or not explicitly disabled by policy)
- SMB signing not required (`RequireSecuritySignature` not enforced)
- LM/NTLMv1 authentication permitted (`LmCompatibilityLevel` < 3)
- LLMNR not disabled by policy (no confirmed GPO sets `EnableMulticast` to 0)
- WSUS delivering updates over unencrypted HTTP (`WUServer` set to an `http://` URL - a known package-injection MITM vector)

### Kerberos Hardening Depth
- RC4-HMAC still permitted for Tier-0 privileged accounts or krbtgt (`msDS-SupportedEncryptionTypes` unset or with the RC4 bit set)
- Trusts missing the `TRUST_USES_AES_KEYS` attribute (RC4 remains usable across that trust)
- Domain-wide "Configure encryption types allowed for Kerberos" GPO/registry policy unset or still permitting RC4/DES
- Kerberos Armoring (FAST) not enabled on the KDC and/or client side (`EnableCbacAndArmor` not configured)
- Cross-trust TGT delegation enabled (`trustAttributes` `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` flag set), allowing a client's TGT to be forwarded across the trust boundary

### Stale-Object & Hygiene Depth
- Accounts with the PASSWD_NOTREQD flag set (`userAccountControl` 0x0020), which waives the domain password policy for that account
- Non-default `primaryGroupID` on a user or computer object, a technique for hiding effective privileged membership from memberOf-based reviews (RID 516 - Domain Controllers - is legitimate only for objects that are genuinely registered as DCs)
- Duplicate Service Principal Names registered on more than one account (reports every holder)
- Domain Controllers whose IPv4 address is not covered by any AD Sites & Services subnet object
- Fewer than two Domain Controllers in the domain (no redundancy)

### Monitoring & Logging
- Disabled audit policies for critical events
- Missing SACLs on AdminSDHolder container
- Insufficient logging for privilege escalation detection

## Troubleshooting

### Common Issues

**Module Import Failure**

# Ensure RSAT is installed
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online


**Permission Denied**
- Run PowerShell as Administrator
- Verify account has Domain Admin or equivalent permissions
- Check network connectivity to Domain Controllers

**Certificate Services Checks Failing**
- Requires AD CS to be installed in the environment
- Needs permissions to query Certificate Authority
- Gracefully skips if AD CS is not present

**Incomplete LAPS Results**
- Verify LAPS schema extensions are installed
- Check permissions to read ms-Mcs-AdmPwd attribute
- Confirms LAPS GPO deployment

## Security Best Practices

Based on audit findings, implement these security controls:

1. **Rotate KRBTGT Password**: Every 180 days (twice with 24-hour intervals)
2. **Deploy LAPS**: Achieve 100% coverage on all workstations and servers
3. **Review Certificate Templates**: Remove unnecessary templates, restrict enrollment rights
4. **Enable Audit Policies**: Configure advanced audit policies for AD object access
5. **Harden Trust Relationships**: Enable SID filtering, use selective authentication
6. **Remove Unconstrained Delegation**: Migrate to constrained or resource-based delegation
7. **Implement Tiered Access Model**: Separate Tier 0 administrative accounts
8. **Regular Audits**: Run this script monthly to track security posture improvements

## Automation & Integration

### Scheduled Audits
Create a scheduled task to run audits automatically:

powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Import-Module ADSecurityAudit; Start-ADSecurityAudit -OutputPath 'C:\ADReports'`""
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2am
Register-ScheduledTask -TaskName "AD Security Audit" -Action $action -Trigger $trigger -RunLevel Highest


### SIEM Integration
Import JSON reports into your SIEM for correlation and alerting:
powershell
# Example: Send findings to Splunk HEC
$findings = Get-Content "C:\ADReports\AD_Security_Findings_*.json" | ConvertFrom-Json
foreach ($finding in $findings) {
    Send-SplunkEvent -Finding $finding
}

## Visual dashboard for JSON outputs

An interactive, responsive frontend is available in `ui/` to explore audit JSON exports without additional tooling.

1. Start a simple static server (prevents browser CORS blocks):
   ```bash
   cd ui
   python3 -m http.server 8000
   ```
2. Open `http://localhost:8000` in your browser.
3. Choose an ingestion method:
   - **Upload audit JSON** directly from disk.
   - **Load from URL** by pasting a reachable HTTPS link to your exported JSON.
   - **Paste JSON** into the provided text area (no files leave your browser).
   - Or choose **Use bundled sample** to preview the experience.

The interface highlights Computer Account Delegation, Fine-Grained Password Policies, DNS Security Configuration, and other categories with severity-aware tiles, progress indicators, and remediation context.



## Contributing

Contributions are welcome! Seriously, I'm good at this stuff, but I know others are better. 

## License

MIT License - Use at your own risk. Always test in non-production environments first.

## Disclaimer

This tool performs read-only operations but requires elevated privileges. 

Always:
- Review the code before running in production
- Test in a lab environment first
- Ensure you have proper authorization
- Backup your environment before making remediation changes
- Understand the impact of recommended remediations

## Version History

### v1.11.0 (Current)
- Added `Test-ADStaleObjectDepth`: audits accounts with PASSWD_NOTREQD set (`userAccountControl` 0x0020), non-default `primaryGroupID` on user and computer objects (membership-hiding, distinguishing the legitimate Domain Controllers RID for genuine DCs from a suspicious value elsewhere), duplicate Service Principal Names across users and computers (reporting every holder), Domain Controllers not covered by any AD Sites & Services subnet object, and insufficient Domain Controller count (fewer than 2)
- Detection only: reads `userAccountControl`/`primaryGroupID` values, builds an in-memory case-insensitive SPN index, and reads DC inventory (`Get-ADDomainController`) and subnet objects (`Get-ADReplicationSubnet`); never modifies any account, SPN, or Sites & Services object
- Snapshot-aware for the PASSWD_NOTREQD, primaryGroupID, duplicate-SPN, and DC-count checks (the snapshot's `Users`/`Computers` collection now also includes `PrimaryGroupID`/`ServicePrincipalNames`/`SamAccountName` as needed); the DC subnet/site registration check always performs one live `Get-ADReplicationSubnet` call, since subnet objects aren't part of the snapshot schema

### v1.10.0
- Added `Test-ADKerberosHardening`: audits RC4 Kerberos encryption still being permitted (Tier-0 privileged accounts and krbtgt via `msDS-SupportedEncryptionTypes`, trusts missing `TRUST_USES_AES_KEYS`, and the domain-wide "Configure encryption types allowed for Kerberos" GPO/registry policy), Kerberos Armoring (FAST) not enabled (KDC and client `EnableCbacAndArmor` policy), and cross-trust TGT delegation (`trustAttributes` `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`)
- Snapshot-aware for the account-level RC4 check (`Snapshot.Users` + the Tier-0 set) and both trust-level checks (`Snapshot.Trusts`); the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely when run from a snapshot

### v1.9.0
- Added `Test-ADLegacyAuthSurface`: audits legacy/weak authentication and name-resolution poisoning surface enforced (or left unenforced) via GPO/registry - SMBv1 enabled/not disabled by policy, SMB signing not required, LM/NTLMv1 authentication permitted (`LmCompatibilityLevel` < 3), LLMNR not disabled by policy, and WSUS delivered over HTTP (package-injection MITM surface)
- Detection only: reads GPO-linked registry policy values via `Get-GPRegistryValue` against each linked GPO (Domain Controllers OU first, then domain root), falling back to a direct per-DC registry read only when no linked GPO defines a setting. Every finding distinguishes a policy-enforced value (naming the source GPO) from one observed via live registry read with no enforcing policy found. Never modifies any policy or registry value, and performs no exploitation, coercion, relay, or PoC traffic
- Live-only: declares an optional `-Snapshot` parameter for registration consistency, but GPO-linked registry policy state and per-DC registry reads have no snapshot equivalent, so the audit is skipped entirely (returns no findings) when run from a snapshot

### v1.8.0
- Added `Test-ADDnsSecurity`: audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's `ServerLevelPluginDll` mechanism), DNS zone transfer exposure (transfers to any server or any NS-listed server), insecure (nonsecure) dynamic DNS updates, and overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface)
- Detection only: reads DnsAdmins membership, zone attributes (`dNSProperty`) and ACLs (`nTSecurityDescriptor`), and optionally the read-only `Get-DnsServerZone`/`Get-DnsServerZoneTransfer` cmdlets when available, falling back to a best-effort attribute parse otherwise. Never modifies a DNS record, zone, or plugin-DLL configuration
- Snapshot-aware for the DnsAdmins membership check (`Snapshot.Groups`); the zone transfer, dynamic-update, and ADIDNS CreateChild checks are live-only and are skipped entirely when run from a snapshot
- Fixed: the HTML report footer's module version was hardcoded and had drifted out of sync with `ModuleVersion` since v1.7.0; it's now read from the module manifest at import time so it can't go stale again

### v1.7.0
- Added `Test-ADCSExtended`: extends AD CS coverage beyond ESC1/2/3/7 with ESC4 (certificate templates whose ACL grants Write/WriteDacl/WriteOwner/GenericAll/GenericWrite to low-privileged principals), a high-risk-without-approval check (enrollee-supplied subject/SAN or Any-Purpose EKU with no manager-approval gate), ESC8 (CA web enrollment reachable over HTTP without Extended Protection for Authentication), and a ROCA (CVE-2017-15361) / weak-signature-algorithm / weak-RSA-modulus sweep of the CA certificates and the NTAuth/AIA/Root store
- Detection only: reads template/CA attributes, ACLs, and already-published certificate bytes; ESC8's only live-network step is a read-only remote check of the CA host's web-enrollment configuration. Never requests, forges, or relays a certificate
- Snapshot-aware where the data allows it: template/CA enumeration and the approval-gate/CA-certificate weak-crypto checks read from `Snapshot.ADCS`; ESC4's per-template ACL read, the ESC8 CA-host probe, and the NTAuth/AIA/Root store sweep are live-only and are skipped entirely when run from a snapshot

### v1.6.0
- Added `Test-ADCoercionAndRelayExposure`: audits every Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler running (PrinterBug), WebClient running (WebDAV coercion), NTDS `LDAPServerIntegrity` not requiring signing, and `LdapEnforceChannelBinding` not requiring Extended Protection for Authentication (EPA)
- Detection only: reads service and NTDS registry state per DC; never sends a coercion trigger, never relays, and performs no exploitation or PoC traffic
- Live per-DC probes are skipped entirely when run from a snapshot (`-FromSnapshot` performs no live AD/network access); the DC list itself is still read from the snapshot when supplied

### v1.5.0
- Added `Test-ADDomainHardeningFlags`: positionally parses `dSHeuristics` for dangerous settings (anonymous access, List Object security mode, AdminSDHolder exclusion mask weakening), flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group, and performs a strictly read-only anonymous LDAP/RootDSE bind probe
- `Get-ADSnapshot` now also collects `DsHeuristics` and `PreWin2000Members`; the dsHeuristics and Pre-Windows 2000 checks are snapshot-aware, while the anonymous-bind probe (a live network operation) is skipped when running from a snapshot

### v1.4.0
- Added `Test-ADMachineAccountQuota`: flags `ms-DS-MachineAccountQuota` left at the unmodified default of 10 (High) or any other non-zero value (Medium), which lets any authenticated user self-service-join computer accounts - a common foothold for RBCD relay and SamAccountName-spoofing privilege escalation
- `Get-ADSnapshot` now also collects `ms-DS-MachineAccountQuota`; the new check is snapshot-aware

### v1.3.0
- Added `Get-ADSnapshot`: a single paged, read-only collection pass (users, computers, groups, GPOs, ACLs on key objects, AD CS config, DNS zones, trusts, DC inventory) with `-ToJson` for serialisation
- Added `Invoke-ADRuleSet -Snapshot`: dispatches `Test-*` functions against a snapshot, defensively passing `-Snapshot` only to functions that declare it so snapshot-unaware modules are called live and never error
- Added `Start-ADSecurityAudit -FromSnapshot <path>` for offline re-analysis (no live AD access), reproducing the same JSON/HTML/CSV report and risk score
- Added shared `Get-ADTier0Principal` privileged/Tier-0 principal helper for reuse across detection modules
- Began retrofitting existing audit functions (`Test-ADUserSecurity`, `Test-KRBTGTAccount`) with an optional `-Snapshot` parameter; remaining modules will be retrofitted gradually

### v1.2.0
- Added risk score (0-100), per-category sub-scores, and an ANSSI-style 1-5 maturity level via `Get-ADRiskScore`
- Added MITRE ATT&CK technique and ANSSI control tagging on every finding through a central mapping table (`src/Scoring.ps1`) and `Set-ADFindingMetadata`
- Added additive `MitreTechnique`, `AnssiControl`, and `Weight` fields to `ADSecurityFinding` (output schema is now additive-only / contract-stable)
- Added a risk-score gauge, maturity panel, per-category bars, and MITRE summary to the HTML report; appended new CSV columns and a score sidecar JSON

### v1.1.0
- **Security Fix**: Fixed CSV injection vulnerability in report exports
- Added Domain Controller failover support for improved reliability
- Added `Invoke-ADQueryWithRetry` helper for network resilience with exponential backoff
- Added result pagination for large AD queries (prevents timeouts in large environments)
- Converted 40+ silent failures to proper try/catch with verbose logging
- Improved error handling across all audit modules
- Added `ConvertTo-SafeCsvValue` function for safe CSV exports

### v1.0.1
- Fixed nested group detection in Test-ADPrivilegedGroups
- Fixed LAPS schema path lookup
- Fixed SID lookup in DCSync detection
- Improved ESC1 detection to check enrollment permissions
- Improved Kerberoasting detection with encryption type and password age checks

### v1.0.0
- Added Certificate Services vulnerability scanning (ESC1/ESC2/ESC3)
- Added KRBTGT password age monitoring
- Added comprehensive trust relationship auditing
- Added LAPS deployment verification
- Added audit policy configuration validation
- Added constrained delegation analysis
- Enhanced reporting with new critical findings

### v0.1.0
- Initial release with core AD security auditing
- Privileged group analysis
- DCSync detection
- AdminSDHolder security checks
- Basic delegation auditing

## Support

For issues, questions, or feature requests:
- Review the Troubleshooting section
- Check PowerShell event logs for detailed error messages
- Ensure all prerequisites are met
- Test with `-Verbose` flag for detailed output

## Acknowledgments

Built upon industry-standard Active Directory security assessment methodologies and inspired by:
- Microsoft Security Best Practices
- MITRE ATT&CK Framework (Active Directory techniques)
- Purple Knight Active Directory Security Assessment Tool
- BloodHound graph theory for AD privilege escalation paths
