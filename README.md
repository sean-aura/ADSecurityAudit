# Active Directory Security Audit 

A comprehensive PowerShell module for identifying misconfigurations and security vulnerabilities within Active Directory environments.

The repository also includes a responsive web dashboard (in `ui/`) that visualizes the JSON output from the audit scripts. Upload an audit JSON or load the bundled sample to explore findings by category (e.g., computer account delegation, fine-grained password policies, DNS security configuration) and drill into remediation guidance with documentation links.

> **Independence note:** ADSecurityAudit is an independent, MIT-licensed project. Throughout this README, the CHANGELOG, and the source code, you'll see notes like "PingCastle-comparable check" or "similar in spirit to PingCastle's approach" — these describe feature comparisons only (which known AD security concept a given check maps to), not affiliation, endorsement, or shared code. ADSecurityAudit is not produced by, affiliated with, or endorsed by Netwrix/PingCastle.

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
- **Domain Hardening Flags**: Positionally parses the `dSHeuristics` attribute for dangerous settings (anonymous access, List Object security mode, AdminSDHolder exclusion mask weakening), flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group, performs a strictly read-only anonymous LDAP/RootDSE bind probe, and audits `RestrictNullSessAccess`/`NullSessionPipes`/`NullSessionShares` (GPO-linked policy first, then live per-DC registry fallback) for null-session access to named pipes/shares (PingCastle `A-NullSession`-comparable)
- **Coercion & NTLM Relay Exposure**: Checks every Domain Controller for the configuration that enables coerce-then-relay attacks - Print Spooler (PrinterBug) or WebClient (WebDAV) running, LDAP signing not enforced, and LDAP channel binding (EPA) not required
- **AD CS Extended (ESC4, ESC8, ROCA, Weak PKI Crypto)**: Extends AD CS coverage beyond ESC1/2/3/7 with dangerous template ACLs (ESC4), high-risk templates missing a manager-approval gate, CA web enrollment reachable over HTTP without Extended Protection for Authentication (ESC8), ROCA-vulnerable (CVE-2017-15361) RSA keys, and weak signature algorithms/RSA key sizes across the CA certificates and the NTAuth/AIA/Root store
- **AD-Integrated DNS Security**: Audits DnsAdmins group membership (a well-known Domain-Controller code-execution path via the DNS server's `ServerLevelPluginDll` mechanism), DNS zone transfer exposure (transfers to any server or any NS-listed server rather than an explicit secondary list), insecure (nonsecure) dynamic DNS updates, overly broad CreateChild rights on AD-integrated zone objects granted to Authenticated Users/Everyone/ANONYMOUS LOGON (ADIDNS spoofing/MITM surface), and stale/dangling DNS zone delegations (a delegated child zone whose glue nameservers no longer answer, a well-documented subdomain-takeover risk)
- **Legacy Auth & Name-Poisoning Surface**: Audits GPO/registry-enforced legacy authentication and name-resolution poisoning surface - SMBv1 enabled/not disabled by policy, SMB signing not required, LM/NTLMv1 authentication permitted (`LmCompatibilityLevel` < 3), LLMNR not disabled by policy, and WSUS delivered over HTTP (package-injection MITM surface) - distinguishing policy-enforced values (naming the source GPO) from unset/local ones
- **Kerberos Hardening Depth**: Audits RC4 Kerberos encryption still being permitted (Tier-0 privileged accounts and krbtgt via `msDS-SupportedEncryptionTypes`, trusts missing the `TRUST_USES_AES_KEYS` attribute, and the domain-wide "Configure encryption types allowed for Kerberos" GPO/registry policy), Kerberos Armoring (FAST) not enabled (KDC and client `EnableCbacAndArmor` policy), and cross-trust TGT delegation (trusts with the `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` `trustAttributes` flag set)
- **Stale-Object & Hygiene Depth**: Audits accounts with the PASSWD_NOTREQD flag set (`userAccountControl` 0x0020), non-default `primaryGroupID` on user and computer objects (a known membership-hiding technique, distinguishing the legitimate Domain Controllers RID for genuine DCs from a suspicious value elsewhere), duplicate Service Principal Names across users and computers (reporting every holder), Domain Controllers not covered by any AD Sites & Services subnet object, and insufficient Domain Controller count
- **GPO-Deployed Secrets & Insecure Settings**: Scans each GPO's SYSVOL policy folder for leftover Group Policy Preferences (GPP) `cpassword` values (MS14-025, flagged by presence and file path only - never decrypted), credential-flavoured patterns embedded in deployed logon/startup scripts (reported by file and line number only), insecure settings pushed via GPO (Windows Firewall disabled, hidden file extensions, RDP Network Level Authentication disabled or an insecure RDP security layer), and a GPO-deployed User Rights Assignment granting a sensitive logon right (`SeNetworkLogonRight`, `SeRemoteInteractiveLogonRight`) to Everyone/ANONYMOUS LOGON/Authenticated Users (PingCastle `A-AnonymousAuthorizedGPO`-comparable, always Critical)
- **Known DC Vulnerabilities by Patch/Build**: Flags Domain Controller exposure to ZeroLogon (CVE-2020-1472), MS17-010/EternalBlue, MS14-068, PrintNightmare (CVE-2021-34527, only while the Spooler service is running), and CVE-2026-41089 (unauthenticated Netlogon RCE, CVSS 9.8) strictly from OS build/install date and installed hotfix level (`Get-HotFix`) against documented fix-date thresholds, plus BadSuccessor/dMSA escalation exposure on Windows Server 2025-level Domain Controllers - as of v1.18.0 each Server 2025-level DC is additionally classified Patched/Unpatched/Unknown for CVE-2025-53779 via a per-DC UBR (Update Build Revision) registry read, since independent research shows the underlying dMSA-linking primitive remains partially abusable even after that patch - every determination is a version/patch/config read, never exploitation
- **Exchange-in-AD Privilege Escalation**: Flags Exchange security principals (Exchange Windows Permissions, Exchange Trusted Subsystem, Exchange Servers, Exchange Enterprise Servers, Organization Management) holding GenericAll/WriteDacl/WriteOwner on the domain head object (the PrivExchange-style path to DCSync) or on AdminSDHolder, firing on residual ACEs even after Exchange has been fully decommissioned
- **Read-Only Domain Controller Security Posture**: Audits RODCs for Tier-0/privileged principals already cached (`msDS-RevealedUsers`) or allowed to replicate (`msDS-RevealOnDemandGroup`), password replication policy gaps (allowed list too broad or denied list missing expected privileged groups via `msDS-NeverRevealGroup`), and orphaned RODC-specific `krbtgt_*` accounts left behind after an RODC is demoted or removed
- **Attack-Path Graph & Indirect-Privilege (Control-Path) Findings**: Builds a directed control-edge graph from dangerous ACEs, group membership, and object ownership (`Get-ADControlPathGraph`), then computes reachability from non-Tier-0 principals to the Tier-0 set - Domain Admins/Enterprise Admins/etc. (per `Get-ADTier0Principal`), Domain Controllers, AdminSDHolder, and the domain head object - via `Test-ADControlPaths`, emitting a finding per reachable path with the full hop chain recorded in `Details`. Surfaces the indirect escalation paths that flat, per-object permission checks can't express on their own; a broad principal (Everyone/Authenticated Users/Domain Users/ANONYMOUS LOGON) on any path is always Critical. Includes an optional BloodHound-compatible generic-edge JSON export (`Export-ADControlPathGraphBloodHound`) for cross-checking against a BloodHound collection of the same environment
- **Multi-Domain / Forest Consolidation**: `Get-ADForestConsolidation` reads two or more of this module's own prior JSON exports (one per domain) entirely offline - no additional AD queries - and rolls them up into a forest score/maturity (same worst-category semantics as `Get-ADRiskScore`), a per-category heatmap, a worst-first domain comparison table, and cross-domain trust-risk enrichment (annotating `Test-ADDomainTrusts` findings with the target domain's own score when that domain was also scanned); `Export-ADForestConsolidationHTML` renders the result as a standalone report. A free equivalent to PingCastle's paid "Conso" consolidation feature

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Active Directory PowerShell Module (RSAT)
- Group Policy PowerShell Module (RSAT)
- Domain Administrator or equivalent permissions for full audit
- Windows Server 2016 or later (recommended)
- Network connectivity to Domain Controllers
- Appropriate read permissions for AD Certificate Services (if installed)

## Installation

Ensure RSAT PowerShell modules are installed:

```
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online | Add-WindowsCapability -Online
```

### Option A - Run in place (recommended)

No installation step is required. Clone or download the repository, then import the module directly from wherever it lives:

```powershell
git clone https://github.com/AlchemicalChef/ADSecurityAudit.git
cd ADSecurityAudit
Import-Module .\ADSecurityAudit.psd1
```

To update, pull the latest changes and re-import (`-Force` reloads an already-imported module in the current session):

```powershell
git pull
Import-Module .\ADSecurityAudit.psd1 -Force
```

If you didn't clone via git, updating is just re-downloading the repository over the same folder and re-running `Import-Module -Force`.

### Option B - Install into a PowerShell modules directory

If you'd rather have the module available by name (`Import-Module ADSecurityAudit`) from any working directory without pointing at a path, copy it into a location on `$env:PSModulePath` instead:

```powershell
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\ADSecurityAudit"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item -Path ".\ADSecurityAudit.psd1" -Destination "$modulePath\ADSecurityAudit.psd1"
Copy-Item -Path ".\ADSecurityAudit.psm1" -Destination "$modulePath\ADSecurityAudit.psm1"
Copy-Item -Path ".\src" -Destination "$modulePath\src" -Recurse -Force
Import-Module ADSecurityAudit
```

**Updating an Option B install:** copying over an existing install doesn't take effect in a session that already has the old version loaded. To update:

```powershell
# 1. Close any PowerShell session with the module loaded (or run: Remove-Module ADSecurityAudit -Force)
# 2. Re-copy the updated files over the existing install:
Copy-Item -Path ".\ADSecurityAudit.psd1" -Destination "$modulePath\ADSecurityAudit.psd1" -Force
Copy-Item -Path ".\ADSecurityAudit.psm1" -Destination "$modulePath\ADSecurityAudit.psm1" -Force
Copy-Item -Path ".\src" -Destination "$modulePath\src" -Recurse -Force
# 3. Start a new PowerShell session (or Import-Module ADSecurityAudit -Force) and confirm the version:
(Get-Module ADSecurityAudit).Version
```


## Usage

### Basic Audit
Run a complete security audit with default settings:

```powershell
Start-ADSecurityAudit -ExportPath "C:\ADReports"
```

### Advanced Options
Customize the audit with additional parameters:

```powershell
Start-ADSecurityAudit -ExportPath "C:\ADReports" -Verbose
```

### Multi-Domain Forest: Overriding the Target Domain/DC

In a multi-domain forest, every `Get-AD*`/`Set-AD*` call the AD PowerShell module makes without an explicit `-Server` performs a "serverless" bind - it resolves against the account running the audit's own logon domain (or whatever DC AD's client-side locator picks), not necessarily the domain you intend to audit. If you're running the audit as an account from Domain A against a machine that's actually in Domain B, this can silently produce results scoped to Domain A instead - most visibly in `Test-ADMachineAccountQuota`, since `ms-DS-MachineAccountQuota` lives on the domain object itself.

**Default behavior (no `-Server` needed for the common case):** when `-Server` is omitted, it now defaults automatically to the current user's own domain (`$env:USERDNSDOMAIN` - the DNS domain of the account actually running the session, not the machine's joined domain), rather than leaving that ambiguous. For most operators auditing their own domain, this "just works" with no parameter needed at all.

Pass `-Server` explicitly only when you need to target a domain **other** than your own account's - e.g. auditing Domain B while logged in as (or running under) a Domain A account:

```powershell
Start-ADSecurityAudit -Server domainb.corp.com -ExportPath "C:\ADReports"
# or target one specific DC directly:
Start-ADSecurityAudit -Server dc01.domainb.corp.com -ExportPath "C:\ADReports"
```

The same override (and the same user-domain default) is available standalone, independent of a full audit run:

```powershell
Test-ADMachineAccountQuota -Server domainb.corp.com
Get-ADSnapshot -Server domainb.corp.com -ToJson "C:\Snapshots\domainb.json"
```

`-Server` (and its user-domain default) is ignored (with a warning if passed explicitly) when combined with `-FromSnapshot`, since offline mode performs no live AD access at all - there's no domain to override.

**Known limitation:** if you use `runas /netonly` (or an equivalent alternate-credential technique) to run under a *different* domain's credentials than the one you're locally logged into, `$env:USERDNSDOMAIN` still reflects your original interactive logon's domain, not the alternate credential's domain - pass `-Server` explicitly in that case.

This override is applied consistently everywhere the module talks to AD: every `Get-AD*`/`Set-AD*` cmdlet call across every test module (via a shared `$PSDefaultParameterValues` mechanism, so no individual test had to be hand-edited), plus several classes of call that don't go through the normal AD-cmdlet path (or don't behave the way you'd expect even though they DO go through it) and would otherwise silently ignore `-Server` or silently query the wrong scope:
- A handful of files read `RootDSE` via a raw ADSI bind (`[ADSI]"LDAP://RootDSE"`) rather than `Get-ADRootDSE`; ADSI binds are COM object construction, not cmdlet calls, so they're invisible to the override mechanism above and would keep resolving to the calling machine's own domain regardless. These now go through `Get-ADRootDSE` instead.
- A few live-network-probe checks (the anonymous-bind test, DNS-cmdlet target resolution) called `Get-ADDomainController -Discover` directly, which is a different parameter set than `-Server` and would otherwise throw and silently skip the check under an active override. These now resolve directly against the override when one is set.
- Those same live-network-probe checks' shared DC-resolution helper (`Get-ADTargetDomainController`) previously passed the active `-Server` override straight to `Get-ADDomainController -Identity`, which requires an actual DC identity (GUID/Name/IPv4Address/DNS host name of the DC itself) - not a domain FQDN, which is this module's own documented, encouraged form of `-Server`. This threw `Cannot find directory server with identity: <domain FQDN>` and silently skipped the probe every time `-Server` was given as a domain name rather than a specific DC. Now resolves via the same domain-scoped DC enumeration described below.
- `Test-ADPrivilegedGroups`'s Enterprise Admins/Schema Admins checks: these two groups exist ONLY in the forest root domain, so a lookup scoped to a child domain via `-Server` always found nothing and silently skipped the group with no finding and no indication why. This now resolves the forest root (`Get-ADForest`) and re-queries there when the initial, target-domain-scoped lookup comes back empty.
- **Every per-DC probe in this module enumerated Domain Controllers via a bare `Get-ADDomainController -Filter *` - the actual root cause of "wrong domain" reports in a multi-domain forest.** `-Filter` is a fundamentally different code path than `-Identity`/`-Discover`: it queries the forest-wide `CN=Sites,CN=Configuration,...` container, which is replicated to every DC in the forest - so `-Server` only controlled *which DC answered the query*, never the query's *scope*. This is completely independent of whether the `-Server` override itself was working (it was) - the query it fed into was never domain-scoped to begin with, so a multi-domain-forest run could silently enumerate, and then probe/report on, DCs from a domain other than the one `-Server` was explicitly set to. This affected the anonymous-bind, null-session, Kerberos hardening, legacy auth, audit policy, known-DC-vulnerability, stale-object-depth, RODC security, control-path-graph, and coercion/relay checks, the main run's own DC connectivity check, and `Get-ADSnapshot`'s DC inventory collection (meaning it was also baked into offline snapshots, not just live runs). All of these now go through a new `Get-ADSecurityAuditDomainController` helper, which filters the same enumeration down to DCs whose own `.Domain` property actually matches the resolved target domain.

**If you've set `-Server` and are still seeing data that looks like it came from the wrong domain** (e.g. an account logged into/authenticated against one domain, on a machine joined to a different domain in the same forest, and the report reads like the machine's own domain rather than the one you targeted):

1. **Update first.** If you were on a version before this fix, the `Get-ADDomainController -Filter *` forest-wide-enumeration bug above is the most likely cause, particularly if the wrong-domain data shows up specifically in DC-level findings (anonymous bind, null session, Kerberos/legacy-auth/audit-policy checks, RODC security) - update and re-run before investigating further.
2. **Confirm the override is actually taking effect.** Run with `-Verbose` and look for the console line `Server override: forcing all AD queries to target '<value>' (...)` near the start of the run. If the value shown isn't what you expected, the problem is in what was passed in, not in how it's applied downstream.
3. **Pass a specific DC FQDN, not just the domain name**, e.g. `-Server dc01.domainb.corp.com` rather than `-Server domainb.corp.com`. A bare domain name still goes through DNS-based DC-locator SRV resolution, which depends on the *querying* machine's own DNS servers correctly resolving the target domain's zone - in a forest where that isn't fully configured (e.g. missing conditional forwarders between domains' DNS zones), locator resolution can silently fall back to a DC in the machine's own domain instead of erroring. Pinning to a specific DC FQDN removes that resolution step entirely.
4. **Confirm `-Server` is passed on the SAME invocation that produced the report you're looking at**, not a separate call. The override is installed and cleared entirely inside a single `Start-ADSecurityAudit` (or standalone `Get-ADSnapshot`/`Test-ADMachineAccountQuota`) call - it does not persist across separate commands in the same session. Calling an individual `Test-AD*` function directly, on its own, has no `-Server` parameter at all (only `Test-ADMachineAccountQuota` and `Get-ADSnapshot` do) and will silently use the ambient/serverless bind if `Start-ADSecurityAudit` isn't the thing that ran it.
5. **Check the "Cross-Domain Privileged Group Membership" finding** if the wrong-domain data specifically shows up as *group members* (privileged users/groups sections) rather than DCs. Nested/universal group membership in a forest can legitimately span domains - this finding surfaces exactly which domain(s) a privileged group's members actually belong to, which tells you whether what you're seeing is cross-domain membership being correctly reported (working as intended) versus something upstream querying the wrong domain (the `Server override:` line from step 2 not matching your target).
6. If you used `runas /netonly` or an equivalent alternate-credential technique, see the Known Limitation note above - pass `-Server` explicitly rather than relying on the `$env:USERDNSDOMAIN` default in that scenario.

### Offline / Snapshot-Based Audit
Collect once, analyze later or elsewhere, with no live AD access at analysis time:

```powershell
Get-ADSnapshot -ToJson "C:\Snapshots\contoso.json"
Start-ADSecurityAudit -FromSnapshot "C:\Snapshots\contoso.json" -ExportPath "C:\ADReports"
```

### Output Formats
The script generates these report formats:
- **HTML Report**: Color-coded interactive report with severity indicators, a risk-score gauge, an ANSSI maturity panel, per-category risk bars, and a MITRE ATT&CK technique summary
- **CSV Export**: Detailed findings in spreadsheet format for analysis (now includes appended `MitreTechnique`, `AnssiControl`, and `Weight` columns)
- **JSON Export**: Machine-readable findings (the new metadata fields serialize automatically)
- **Score sidecar (JSON)**: `AD_Security_Score_<timestamp>.json` containing the global risk score, per-category sub-scores, maturity level, and MITRE roll-up

### Recreating the main HTML report from an existing JSON export

If you have an `AD_Security_Audit_<timestamp>.json` findings export - from a prior run, restored from backup, whatever - but the matching `.html` is missing or was never generated, `Export-ADSecurityReportHTMLFromJson` rebuilds the HTML report directly from that JSON, with **no live Active Directory access and no re-run of the audit**:

```powershell
Export-ADSecurityReportHTMLFromJson -FindingsPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00.json" `
    -OutputPath "C:\Reports\AD_Security_Audit_2026-08-01_00-00-00-recreated.html" `
    -Domain "contoso.com"

# Folder form also works - picks the newest AD_Security_Audit_*.json in it,
# same resolution idiom as Get-ADRetestComparison's -BaselinePath/-RetestPath:
Export-ADSecurityReportHTMLFromJson -FindingsPath "C:\Reports" -OutputPath "C:\Reports\recreated.html"
```

**This is a different feature from the Retest Comparison JSON-recreate above** - that one (`Get-ADRetestComparison -ToJson` → `Export-ADRetestComparisonHTML`) rebuilds the two-run *comparison* report. This one rebuilds the ordinary single-run audit report you'd otherwise only get by re-running `Start-ADSecurityAudit` (or by hand-loading the JSON and calling the module's own report renderer, which this function does for you).

**Know the gaps before you rely on this:** `AD_Security_Audit_<timestamp>.json` only ever contains the flat findings array. Everything else the HTML report normally shows - `Domain`, `Duration`, `RunMode` (Live vs. Offline/Snapshot), `SnapshotCollectedDate`, `OfflineSkipNotes`, and the privileged-users section - is computed in-memory during a live run and was **never written to that JSON file**, so this function can't recover it:

- **Domain** - not present in the finding schema itself; pass `-Domain` if you know it, otherwise the header shows an explicit placeholder rather than guessing.
- **Duration** - defaults to 0 seconds unless you pass `-Duration`.
- **RunMode / SnapshotCollectedDate** - default to `Live` / none; pass both if you know the original run was `-FromSnapshot` and want that reflected.
- **Offline Mode Coverage Notes** - not recoverable at all; the recreated report will not show this section even if the original run had it.
- **Privileged Users section** - not recoverable; that data was only ever written to a separate `AD_Privileged_Users_<timestamp>.csv`, not JSON, so it isn't wired into this function.
- **Risk score / maturity / MITRE roll-up** - these ARE recovered, but always freshly **recomputed** from the findings via `Get-ADRiskScore` rather than read back from the `AD_Security_Score_<timestamp>.json` sidecar (same "never trust a stored sidecar score" rule `Get-ADRetestComparison` follows) - so a JSON export originally scored under an older module version is rescored under whichever version you run this with.

If you still have the original `.html`, it already has all of the above baked in and this function has nothing to add - it exists specifically for the "I only kept the JSON" case.

## Scoring & Maturity

As of v1.2.0 every audit run produces an executive roll-up on top of the raw findings, computed by `Get-ADRiskScore`:

- **Risk score (0-100, higher = worse)** — each finding carries a `Weight`; a category's score uses diminishing returns as findings accumulate (approaches, but doesn't abruptly hit, 100), and the **global score is the worst category's score** — similar in spirit to PingCastle's "you are as exposed as your weakest area" philosophy, though the underlying math is our own.
- **Per-category sub-scores** — a 0-100 score per audit category (Kerberos Security, Certificate Services, Replication Security, etc.), rendered as bars in the HTML report.
- **ANSSI-style maturity level (1-5, higher = better)** — derived from the ANSSI control level mapped to each finding. A single Level 1 finding caps maturity at Level 1; maturity rises as the most critical hygiene gaps are closed.
- **MITRE ATT&CK tagging** — every finding is tagged with the technique it maps to (e.g. `T1558.001` Golden Ticket, `T1003.006` DCSync, `T1649` AD CS abuse), and the report shows a technique-frequency summary.

All tagging flows from a **single source-of-truth mapping table** in `src/Scoring.ps1` (`Issue → MITRE technique → ANSSI control → weight`). To extend coverage for a new check, add one entry there keyed by the finding's exact `Issue` string; `Set-ADFindingMetadata` and `Get-ADRiskScore` pick it up automatically. The output schema is **additive-only**: new finding fields and CSV columns are appended, never reordered or removed.

> Note: MITRE technique IDs are authoritative; the ANSSI control identifiers follow ANSSI's Active Directory conventions with a maturity-level structure comparable to PingCastle's, and should be reviewed against the current official ANSSI Active Directory control catalogue before use in formal compliance reporting.

## Collect-Once Snapshot & Offline Analysis

As of v1.3.0, AD collection is decoupled from rule evaluation:

- **`Get-ADSnapshot [-ToJson <path>]`** performs one paged, read-only collection pass over users, computers, groups, GPOs (+ permissions), ACLs on key objects (AdminSDHolder, domain root, certificate templates container), AD CS configuration, DNS zones, domain trusts, DC inventory, and the domain's `ms-DS-MachineAccountQuota` attribute, returning a single structured snapshot. Pass `-ToJson` to also persist it to disk for later offline re-analysis.
- **`Invoke-ADRuleSet -Snapshot $snapshot`** dispatches the `Test-*` audit functions against that snapshot. Before passing `-Snapshot` to a function it checks whether that function actually declares the parameter (`(Get-Command $fn).Parameters.ContainsKey('Snapshot')`); functions that haven't been retrofitted yet are simply invoked live instead of erroring (this skip path stays in place for any future new test, though as of v1.19.0 it has nothing to skip - see below). Audit modules were retrofitted with an optional `-Snapshot` parameter gradually across releases; **as of v1.19.0, all 27 registered tests support `-Snapshot`, fully or partially**:
  - **Fully offline-capable** (no live AD access at all when `-Snapshot` is supplied): `Test-ADUserSecurity`, `Test-KRBTGTAccount`, `Test-ADMachineAccountQuota`, `Test-ADExchangeEscalation`, `Test-ADPrivilegedGroups`, `Test-AdminSDHolder`, `Test-ADReplicationSecurity`, `Test-ADDangerousPermissions`, `Test-LAPSDeployment`, `Test-ConstrainedDelegation`, `Test-ADDomainTrusts`, `Test-ADDomainSecurity`, `Test-ADCertificateServices`, and `Test-ADDomainAdminEquivalence` (added in v1.19.0, alongside the ten preceding names in this sentence starting from `Test-ADPrivilegedGroups`).
  - **Partially offline** (most checks run from the snapshot; a small number of sub-checks are genuinely real-time machine/network state with no AD-schema equivalent and are skipped entirely under `-Snapshot` - as of v1.19.1, this is unconditional: `-Snapshot` performs zero live AD/network access, full stop, with a structured note recorded for every skipped sub-check - see "Offline Mode Coverage Notes" below): `Test-ADDomainHardeningFlags` (dSHeuristics and Pre-Windows 2000 membership are offline; its anonymous-bind check is a live network probe and is skipped in offline mode), `Test-ADCoercionAndRelayExposure` (its Spooler/WebClient/LDAP-registry checks are live per-DC network probes and are skipped entirely in offline mode; only the DC list is taken from the snapshot), `Test-ADCSExtended` (template/CA enumeration, ESC4 (per-template ACL), the approval-gate/CA-certificate weak-crypto checks, and the NTAuth/AIA/Root store sweep all run from `Snapshot.ADCS` as of v1.19.1 - ESC4 and NTAuth/AIA/Root gained snapshot support that release; only ESC8, a live HTTP probe against the CA host itself, remains genuinely live-only and is skipped entirely in offline mode), `Test-ADDnsSecurity` (the DnsAdmins membership check reads from `Snapshot.Groups`; the zone transfer, dynamic-update, ADIDNS CreateChild, and delegation-staleness checks read zone-level attributes/ACLs/delegation records not present in the current snapshot schema and are skipped entirely in offline mode), `Test-ADKerberosHardening` (the account-level RC4 check reads from `Snapshot.Users` and the Tier-0 set, and both trust-level checks read from `Snapshot.Trusts`; the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely in offline mode), `Test-ADStaleObjectDepth` (the PASSWD_NOTREQD, primaryGroupID, and duplicate-SPN checks read from `Snapshot.Users`/`Snapshot.Computers`, and the DC-count check reads from `Snapshot.DomainControllers`; the DC subnet/site registration check has no AD-schema equivalent and is skipped entirely under `-Snapshot` as of v1.19.1 - see CHANGELOG), `Test-ADRodcSecurity` (reads RODC inventory from the snapshot when supplied, but every finding depends on per-RODC `msDS-RevealedUsers`/`RevealOnDemandGroup`/`NeverRevealGroup`/`KrbTgtLink` attributes with no snapshot equivalent, so this entire test is skipped under `-Snapshot` as of v1.19.1 - see CHANGELOG), `Test-ADGroupPolicies` (over-permissioned-GPO, DC-OU-linked-weak-permissions, and unlinked-GPO checks are offline via `Snapshot.GPOs`/`.LinkedTo`, added in v1.19.0; the SYSVOL file-share ACL check has no AD-schema equivalent and is skipped entirely under `-Snapshot` as of v1.19.1 - see CHANGELOG), `Test-AuditPolicyConfiguration` (the two AdminSDHolder/domain-root SACL-presence checks are offline via `Snapshot.ACLs.*.HasAuditRules`, added in v1.19.0; the per-DC `auditpol` check has no AD-schema equivalent and is skipped entirely under `-Snapshot` as of v1.19.1 - see CHANGELOG), and `Test-ADControlPaths` (group-membership/`MemberOf` edges, DC targets, and the AdminSDHolder/domain-root ACL/ownership edges all come from the snapshot with zero live access as of v1.19.1; ACL/ownership edges for any other control-relevant object in an escalation chain have no snapshot equivalent - the snapshot intentionally does not sweep ACLs domain-wide - so those objects contribute `MemberOf` edges only, a coverage gap recorded as a single note rather than a live read per object). `Test-ADGpoDeployedSecrets` is skipped entirely under `-Snapshot` as of v1.19.1 (its whole purpose is scanning SYSVOL *file content* - GPP cpassword, deployed scripts - which has no attribute/schema representation at all; prior to v1.19.1 it still performed live SYSVOL reads even under `-Snapshot`, which is now considered a bug, not a documented exception).
  - **Where to see this per-run, not just in this README**: every skipped sub-check above records a structured note during the run (`Add-ADOfflineSkipNote`/`Get-ADOfflineSkipNotes` in `src/Common.ps1`). A `-FromSnapshot` HTML report shows these in an **"Offline Mode Coverage Notes"** table - which sub-check, and why - so you don't have to cross-reference this README or the run log to know what a specific report does and doesn't cover. As of v1.19.1, no built-in test uses this mechanism's `StillLive` mode (a sub-check that runs anyway over a live connection) - every entry you'll see is `Skipped`, meaning `-Snapshot` performed zero live AD/network access for that run, full stop. If you're comparing a live run against a `-FromSnapshot` run for parity, check that table first: a finding-count difference that traces to a listed entry is expected coverage loss, not a bug.
  - **Declared but effectively live-only** (declare `-Snapshot` for registry/dispatch consistency, but every check they perform is real-time machine state with no snapshot equivalent, so this entire test returns no findings when invoked with `-Snapshot`, performing zero live AD/network access): `Test-ADLegacyAuthSurface` and `Test-ADKnownDCVulnerabilities`.
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

## Multi-Domain / Forest Consolidation

As of v1.17.0, `Get-ADForestConsolidation` rolls up two or more of this module's own prior exports - one `AD_Security_Audit_<timestamp>.json` + `AD_Security_Score_<timestamp>.json` pair per domain, produced by an existing `Start-ADSecurityAudit` run - into a single forest-wide view. This is an **offline, file-based post-processing feature**: it performs no additional LDAP/AD queries, requires no credentials, and needs no network access to any domain controller. It is not part of the live audit test set (`Main.ps1`'s `$allTests`) - it's a standalone command you run after one-or-more domains have already been scanned, the same way `Export-ADControlPathGraphBloodHound` is its own standalone command.

It produces:

- **Forest score rollup** - a forest-wide score and ANSSI maturity level using the exact same worst-category (MAX) semantics as the per-domain `Get-ADRiskScore`: the forest is only as strong as its weakest domain, not an average of all of them.
- **Per-category heatmap** - for each audit category, the worst per-domain score across the forest, so a category that's fine in one domain doesn't get diluted into an average with a domain where it's bad.
- **Domain comparison table** - finding counts by severity, per domain, sorted worst-first.
- **Cross-domain trust-risk enrichment** - for every `Test-ADDomainTrusts` finding naming a target domain, if a report for that target domain is also present in the input set, the finding's `Details` are annotated with the target domain's own score/maturity (e.g. "trusts Domain B, which itself scores 85/100, Maturity 1"); a finding whose target domain isn't part of the input set renders normally, unannotated.
- **Newly-missing domains** - pass a previous consolidated JSON via `-PriorConsolidationPath` and any domain present there but absent from the current input is flagged as "not scanned this run" instead of silently disappearing from the rollup.

Domain names are resolved from (in order): an explicit `-DomainName` array matching the discovered report pairs 1:1, the per-domain subfolder a report pair lives in (`<ReportPath>\<DomainName>\AD_Security_Audit_*.json`), or a synthetic `UnknownDomain-N` label with a warning - the underlying finding schema doesn't carry a `Domain` field, since a single audit run is already scoped to one domain.

```powershell
# Assumes AD_Security_Audit_*.json / AD_Security_Score_*.json exports already
# exist for each domain, e.g. one Start-ADSecurityAudit run per domain saved
# into its own subfolder:
#   C:\Reports\contoso.com\AD_Security_Audit_2026-07-01.json
#   C:\Reports\child.contoso.com\AD_Security_Audit_2026-07-01.json

Get-ADForestConsolidation -ReportPath "C:\Reports" -Verbose |
    Export-ADForestConsolidationHTML -OutputPath "C:\Reports\forest-report.html"

# Also persist the consolidated JSON, and compare against a prior run to
# catch domains that weren't re-scanned this time:
Get-ADForestConsolidation -ReportPath "C:\Reports" `
    -PriorConsolidationPath "C:\Reports\AD_Forest_Consolidation_2026-06-01.json" `
    -ToJson "C:\Reports\AD_Forest_Consolidation_2026-07-01.json"
```

Comparable in spirit to PingCastle's paid "Conso" (multi-domain consolidation) report - see the Independence note above: this is implemented independently against this project's own JSON schema, not against PingCastle's report format.

## Retest / Maturity-Delta Comparison

As of v1.21.0, `Get-ADRetestComparison` answers the question every retest engagement is actually for: **did remediation work, and by how much?** Like Forest Consolidation, this is an **offline, file-based post-processing feature** - it performs no additional LDAP/AD queries, requires no credentials, and needs no network access to any domain controller. It is not part of the live audit test set (`Main.ps1`'s `$allTests`) - it's a standalone command you run after two `Start-ADSecurityAudit` runs of the *same domain* already exist (typically a pre-remediation baseline and a post-remediation retest).

It produces:

- **Score & maturity delta** - both runs' findings are recomputed through the **current** `Get-ADRiskScore` mapping table (never the originally-stored score sidecar values), so a retest captured under a newer module version than the baseline stays apples-to-apples - the delta reflects posture change, not a scoring-table change. Each run's own recorded `ModuleVersion`/`GeneratedDate` is still shown for context.
- **Per-category delta** - baseline sub-score, retest sub-score, and the delta for every category present in either run.
- **New / Resolved / Still Open / Changed findings** - matched by `Category+Issue+AffectedObject` (a coarser Category+Issue key would hide partial remediation: 5 stale accounts down to 2 shows as 3 Resolved + 2 Still Open, not one "still present" bucket). A matched finding whose `Severity`/`Weight` differs between the two runs is classified as **Changed**, carrying both the before and after values, rather than folded into Still Open.
- **`Export-ADRetestComparisonHTML`** - a standalone HTML report with a togglable **Current State** (the retest's own findings, presented the same way the main report does) and **Delta View** (score/maturity delta headline, per-category delta bars, and the four New/Resolved/Still Open/Changed sections).

```powershell
# Assumes two prior Start-ADSecurityAudit runs of the same domain exist -
# a pre-remediation baseline and a post-remediation retest:
Get-ADRetestComparison -BaselinePath "C:\Reports\Pre" -RetestPath "C:\Reports\Post" -Verbose |
    Export-ADRetestComparisonHTML -OutputPath "C:\Reports\retest-report.html"

# Also persist the comparison as JSON:
Get-ADRetestComparison -BaselinePath "C:\Reports\Pre" -RetestPath "C:\Reports\Post" `
    -ToJson "C:\Reports\AD_Retest_Comparison_2026-08-01.json"
```

`-BaselinePath`/`-RetestPath` each accept either an explicit `AD_Security_Audit_<timestamp>.json` file or a folder (the newest matching export in it is used, same resolution idiom as Forest Consolidation's `-ReportPath`). A sibling `AD_Security_Score_<timestamp>.json` is read for each side, when present, purely for the informational `ModuleVersion`/`GeneratedDate` shown in the report header - it is never used as the authoritative score.

### Recreating the HTML report from a saved `-ToJson` file

*(This is for the retest-comparison report specifically. To recreate the ordinary single-run audit report from an `AD_Security_Audit_<timestamp>.json` findings export instead, see [Recreating the main HTML report from an existing JSON export](#recreating-the-main-html-report-from-an-existing-json-export) below - don't run a retest comparison just to regenerate that.)*

If you already ran `Get-ADRetestComparison -ToJson ...` (or just still have that file from a previous run) and want the HTML report without re-reading the two original findings exports, load the JSON back in and pipe it straight into `Export-ADRetestComparisonHTML` - no need to re-run the comparison itself:

```powershell
$comparison = Get-Content -Path "C:\Reports\AD_Retest_Comparison_2026-08-01.json" -Raw | ConvertFrom-Json
Export-ADRetestComparisonHTML -Comparison $comparison -OutputPath "C:\Reports\retest-report.html"

# or, equivalently, via the pipeline:
Get-Content -Path "C:\Reports\AD_Retest_Comparison_2026-08-01.json" -Raw |
    ConvertFrom-Json |
    Export-ADRetestComparisonHTML -OutputPath "C:\Reports\retest-report.html"
```

This works because `-ToJson` persists the exact object `Get-ADRetestComparison` returns, and `Export-ADRetestComparisonHTML` only ever reads properties off that object - it doesn't care whether it arrived fresh from `Get-ADRetestComparison` or round-tripped through `ConvertFrom-Json`. The same idiom works for `Get-ADForestConsolidation`/`Export-ADForestConsolidationHTML` and `Get-ADMaturityTrend`/`Export-ADMaturityTrendHTML` - every `-ToJson`-capable command in this module pairs with an `Export-...HTML` command that accepts the reloaded object the same way.

PingCastle does not publicly ship an equivalent retest-delta report - this is comparison tooling over this module's own prior exports, implemented independently.

## Multi-run Maturity Trend History

As of v1.22.0, `Get-ADMaturityTrend` answers a different question than the retest comparison above: not "what changed between these two specific runs", but **"what's the trajectory over N runs"** - a quarterly cadence over a year, say, without manually opening every historical score sidecar. Like the other post-processing features, this is **offline and file-based** - no additional LDAP/AD queries, no credentials, no network access to any domain controller. It is not part of the live audit test set.

It produces:

- **Score/maturity over time** - a chronological series of every `AD_Security_Score_<timestamp>.json` sidecar found under `-ReportPath`, ordered by each sidecar's *own* recorded generation date (not filename, in case files were renamed or moved).
- **Per-category trend** - the same chronological series broken out per audit category, each with a simple **Improving / Flat / Regressing** direction (first-vs-last score, with a small tolerance band for "Flat" - deliberately plain arithmetic, not a statistical regression).
- **`Export-ADMaturityTrendHTML`** - a hand-built inline-SVG line chart of score over time, small per-category sparklines, and a plain per-run table listing each run's date, score, maturity, and **module version** - so a score jump can be attributed to a tool change (the mapping table changed) vs. an actual posture change, at a glance.

**Important - this is the opposite design choice from Retest Comparison above:** `Get-ADMaturityTrend` does **not** recompute scores under the current scoring mapping table. It reads each sidecar's score exactly as it was originally computed, because the whole point is seeing how the tool's assessment evolved over the real historical record. `Get-ADRetestComparison` recomputes both sides under the current table for the opposite reason - a two-point apples-to-apples comparison. Don't assume the two features handle version-skew the same way.

```powershell
# Assumes 3+ Start-ADSecurityAudit runs of the same domain already exist,
# e.g. one AD_Security_Score_*.json sidecar per quarterly audit:
Get-ADMaturityTrend -ReportPath "C:\Reports\contoso.com" -Verbose |
    Export-ADMaturityTrendHTML -OutputPath "C:\Reports\maturity-trend.html"

# Also persist the trend as JSON:
Get-ADMaturityTrend -ReportPath "C:\Reports\contoso.com" -ToJson "C:\Reports\AD_Maturity_Trend_2026-08-01.json"
```

With only one score sidecar found, no trend can be computed - the command returns a result with `RunCount = 1` and a clear `Message` explaining this, rather than throwing. With two, the trend is simply the pairwise delta between them.

**Sidecars from before v1.21.0:** `GeneratedDate`/`ModuleVersion` were only added to `Get-ADRiskScore`'s output in v1.21.0, so an older score sidecar won't have them. Rather than silently dropping that run from the trend, its date is **estimated** from the sidecar file's own last-write time instead, and that run is flagged: `Series[].DateEstimated = $true`, a top-level `EstimatedDateCount`, a note in the returned `Message` naming the affected file(s), and a visible &#9888; **estimated** badge on that row in `Export-ADMaturityTrendHTML`'s per-run table (hover for why). This only affects the *displayed date* - the run's score/maturity data itself is read and trended normally.

## Exception / Remediation-State Tracking

As of v1.23.0, a small file-based store lets you record "we've accepted this risk, not fixing it" so a persisting finding stops looking indistinguishable from a genuinely neglected one on every retest. This extends `Get-ADRetestComparison` (v1.21.0) - it's an additive annotation step, not a change to the New/Resolved/Still Open/Changed classification itself, and omitting it behaves exactly as before.

- **`Set-ADRemediationState -Key <k> -Status <Open|AcceptedRisk|InProgress|Remediated> [-Owner] [-Note] -StatePath <path>`** - an explicit read-modify-write upsert. Re-running it for the same `-Key` updates the existing entry rather than duplicating it. This module never infers a remediation decision on its own - a human (or a script you write yourself) calls this explicitly.
- **`Get-ADRemediationState -StatePath <path>`** - reads the state file, returning an empty structure if it doesn't exist yet (no need to pre-create one).
- **`Get-ADRetestComparison -RemediationStatePath <path>`** (new optional parameter) - when supplied, `StillOpenFindings` and `ChangedFindings` are annotated with a `RemediationState` property (`Status`/`Owner`/`Note`/`SetDate`); untracked findings default to `Status = 'Open'` with nulls.
- **`Export-ADRetestComparisonHTML`** - the Still Open section badges each finding by its `RemediationState.Status`, using a distinct (not alarming) color for `AcceptedRisk` so a leadership reader can see at a glance which persisting findings are a deliberate decision.

The state-file key is built by the same `Get-ADFindingMatchKey` (Category+Issue+AffectedObject) that `Get-ADRetestComparison` already uses internally, so the two can never disagree on what a "key" is.

```powershell
# Mark a finding as an accepted risk:
$key = Get-ADFindingMatchKey -Category 'Certificate Services' `
    -Issue 'Enrollment Agent Template with Low-Privilege Enrollment (ESC3)' `
    -AffectedObject 'CN=LegacyEnroll,CN=Certificate Templates,...'

Set-ADRemediationState -Key $key -Status AcceptedRisk -Owner 'jane.doe@contoso.com' `
    -Note 'Legacy app dependency, tracked in JIRA-1234, revisit Q3 2027.' `
    -StatePath 'C:\Reports\AD_Remediation_State.json'

# Re-run the retest report - the tracked finding now shows an AcceptedRisk badge
# instead of looking like every other unaddressed Still Open finding:
Get-ADRetestComparison -BaselinePath 'C:\Reports\Pre' -RetestPath 'C:\Reports\Post' `
    -RemediationStatePath 'C:\Reports\AD_Remediation_State.json' |
    Export-ADRetestComparisonHTML -OutputPath 'C:\Reports\retest-report.html'
```

An `AcceptedRisk` finding still counts toward `Get-ADRiskScore` exactly as before - this is a reporting annotation only, not a scoring policy change, since silently excluding accepted-risk findings from the score would misrepresent actual security posture. There's no automatic expiry/review-date alerting on stale entries and no ticket-system (JIRA/ServiceNow) integration in this pass - the `Note` field is free text for you to paste a reference into.

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
- Null-session pipe/share access permitted (`RestrictNullSessAccess` disabled)
- Weak signature algorithms (MD2/MD4/MD5/SHA0/SHA1) or undersized RSA keys in the PKI trust store
- AD-integrated DNS zones allowing transfer to any server or any NS-listed server
- AD-integrated DNS zones permitting insecure (nonsecure) dynamic updates
- LLMNR not disabled by policy

### Low Findings
- Informational findings about domain configuration
- Baseline security posture indicators

## Report Interpretation

### HTML Report Structure
- **Executive Summary**: Overview of total findings by severity, with clickable cards linking straight to each severity section
- **Risk Score & Maturity**: Global risk-score gauge, ANSSI 1-5 maturity ladder, per-category risk bars, and a MITRE ATT&CK technique summary
- **Critical Issues**: Immediate action required
- **Detailed Findings**: Collapsed by default (click to expand; each severity section has Expand All/Collapse All). Findings that fire once per affected object are consolidated into a single entry per Category+Issue - the shared Impact/Remediation/MITRE/ANSSI tags are shown once, and every affected object is listed underneath with its own specific detail and detection time, rather than repeating the whole finding once per object
- **Affected Objects**: Every user, group, computer, or object flagged by a finding, listed under that finding with its own specific description

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
- Null-session (unauthenticated) access to named pipes/shares permitted (`RestrictNullSessAccess` disabled, checked via GPO-linked policy with live per-DC registry fallback)

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
- Stale/dangling DNS zone delegations - a delegated child zone whose NS/glue records point at nameservers that no longer answer authoritatively for it, so whoever can now claim that hostname or reclaim that IP address can serve authoritative-looking answers for the sub-zone (a well-documented DNS delegation/subdomain-takeover risk)

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

### GPO-Deployed Secrets & Insecure Settings
- Group Policy Preferences (GPP) `cpassword` values left over from MS14-025 in `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Drives.xml`, `DataSources.xml`, or `Printers.xml` - flagged by presence and file path only, never decrypted
- Credential-flavoured patterns (`net use /user:`, `runas /savecred`, `ConvertTo-SecureString`, etc.) embedded in logon/startup scripts deployed via GPO - reported by file and line number only, never the matched line's content
- Insecure settings deployed via GPO: Windows Firewall disabled for a profile, file extensions hidden by policy, RDP Network Level Authentication disabled, or an insecure (native) RDP security layer
- A GPO's User Rights Assignment (`GptTmpl.inf` `[Privilege Rights]`) granting `SeNetworkLogonRight` ("Access this computer from the network") or `SeRemoteInteractiveLogonRight` ("Allow log on through Remote Desktop Services") to Everyone, ANONYMOUS LOGON, or Authenticated Users - matched by SID, always Critical (PingCastle `A-AnonymousAuthorizedGPO`-comparable)

### Known DC Vulnerabilities by Patch/Build
- ZeroLogon (CVE-2020-1472) - no OS install date or installed hotfix on or after the August 11, 2020 fix
- MS17-010/EternalBlue - no patch evidence on or after the March 14, 2017 fix
- MS14-068 - no patch evidence on or after the November 18, 2014 out-of-band fix
- PrintNightmare (CVE-2021-34527) - Print Spooler running AND no patch evidence on or after the July 6, 2021 fix
- CVE-2026-41089 (Netlogon RCE, CVSS 9.8, unauthenticated) - no patch evidence on or after the May 12, 2026 fix; actively exploited in the wild as of June 2026
- BadSuccessor / dMSA Escalation Exposure - Domain Controllers running Windows Server 2025 (build 26100+), where the delegated Managed Service Account feature requires delegation/ACL review. As of v1.18.0, each affected DC is further classified Patched/Unpatched/Unknown for CVE-2025-53779 via a per-DC UBR (Update Build Revision, remote registry read) check against build 26100.4946 - the finding continues to fire even for confirmed-patched DCs (at a reduced severity when every affected DC is patched) since a mutually-paired dMSA/target relationship can still be abused if an attacker controls both sides
- Every determination comes from OS build/version, installed hotfix level (`Get-HotFix`), and service state - never from exploitation, authentication bypass, or PoC traffic

### Exchange-in-AD Privilege Escalation
- Exchange Group Holds WriteDACL on Domain Object - Exchange Windows Permissions / Exchange Trusted Subsystem / Organization Management (or similar Exchange principal) holding GenericAll, WriteDacl, or WriteOwner on the domain head object
- Exchange-Related AdminSDHolder ACE - the same Exchange principals holding those rights on `CN=AdminSDHolder,CN=System,<domain>`, propagated to every protected (Tier-0) account/group by SDProp
- Fires on residual ACEs even if Exchange has been fully decommissioned from the forest - the ACE, not the presence of Exchange servers, is what's evaluated
- Exact affected principal, right, and target object are recorded in `Details`

### Read-Only Domain Controller Security Posture
- Privileged Account Revealed to RODC - a Tier-0 principal (per `Get-ADTier0Principal`) appears in an RODC's `msDS-RevealedUsers` (secrets already cached) or its `msDS-RevealOnDemandGroup` allowed list
- RODC Password Replication Policy Misconfigured - the allowed replication group is too broad, or the `msDS-NeverRevealGroup` denied list is missing expected privileged groups
- Orphaned RODC krbtgt Account - a `krbtgt_*` account remains after the corresponding RODC computer object no longer exists
- Clean exit when the domain has no RODCs; every determination is a read of RODC attributes and the krbtgt account inventory, never exploitation, coercion, relay, or PoC traffic

### Attack-Path Graph & Indirect-Privilege (Control-Path) Findings
- Indirect Control Path to Tier-0 Object - a non-privileged principal can reach a Tier-0 object (Domain Admins/Enterprise Admins/etc., Domain Controllers, AdminSDHolder, or the domain head) through a chain of group-membership, dangerous-ACE, and/or ownership hops, with the full principal→…→target hop chain recorded in `Details.HopChain`
- Everyone/Authenticated Users on a Control Path to Tier-0 - same as above, but a broad principal (Everyone, Authenticated Users, Domain Users, or ANONYMOUS LOGON) sits somewhere on the path; always Critical regardless of hop count
- Owner of Tier-0 Object is Non-Privileged - a Tier-0 object is owned by a principal that is not itself Tier-0, which grants that owner implicit WriteDacl-equivalent control (an owner can always rewrite the DACL) regardless of the current ACL contents
- Reuses the existing dangerous-rights tables (`GenericAll`/`WriteDacl`/`WriteOwner`/`GenericWrite`/`AllExtendedRights`, the dangerous extended-rights and property-write GUID tables, including the DS-Replication set) and `Get-ADTier0Principal` rather than re-deriving its own definitions
- `Get-ADControlPathGraph` builds the underlying directed edge graph (exposed separately for scripting/inspection); `Test-ADControlPaths` runs the reachability analysis and emits findings; `Export-ADControlPathGraphBloodHound` optionally writes the same graph out as BloodHound-compatible generic-edge JSON for cross-checking against a BloodHound collection of the same environment
- Detection only - every edge comes from a read of `nTSecurityDescriptor`, group membership, or object ownership; ACL/ownership edges are scoped to the Tier-0 target set plus every group on a chain toward it, not a sweep of the entire domain. No exploitation, coercion, relay, ticket forging, or PoC traffic is ever sent to any host

### Monitoring & Logging
- Disabled audit policies for critical events
- Missing SACLs on AdminSDHolder container
- Insufficient logging for privilege escalation detection

## Troubleshooting

### Common Issues

**Module Import Failure**

# Ensure RSAT and Group Policy modules are installed

```
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online
Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online | Add-WindowsCapability -Online
```

**Permission Denied**
- Run PowerShell as Administrator
- Verify account has Domain Admin or equivalent permissions
- Check network connectivity to Domain Controllers

**Certificate Services Checks Failing**
- Requires AD CS to be installed in the environment
- Needs permissions to query Certificate Authority
- Gracefully skips if AD CS is not present
- If you see `CA '<name>' has no dNSHostName; skipping ESC8 probe` where `<name>` is literally **`Enrollment Services`** (not one of your actual CA names) - this was a bug, not a sign of a misconfigured CA. A pre-fix version of `Test-ADCertificateServices`/`Test-ADCSExtended`/`Get-ADSnapshot` enumerated CAs with a search that also matched the `CN=Enrollment Services` *container* object itself, which was then iterated alongside your real CA(s) and (having no `dNSHostName` of its own, since it's a container, not a CA) always tripped this message. Your real CA is a separate entry in the same list and is unaffected - update to a version with this fix and the bogus `Enrollment Services` entry disappears from the loop entirely. The same fix applies to a `Certificate Templates`-named entry appearing where a real template name is expected.

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

Full details for every release live in [CHANGELOG.md](./CHANGELOG.md). Recent highlights:

- **Unreleased** - Fixed a multi-domain-forest bug: no `Get-AD*`/`Set-AD*` call anywhere in the module passed `-Server`, so every query relied on the AD module's default serverless bind, which resolves against the invoking account's own logon domain rather than necessarily the target domain - reported as `Test-ADMachineAccountQuota` silently checking Domain A instead of Domain B when run by a Domain A account. Added a `-Server` parameter to `Start-ADSecurityAudit`, `Get-ADSnapshot`, and `Test-ADMachineAccountQuota`, backed by a shared `Set-/Clear-ADSecurityAuditTargetServer` helper (`Common.ps1`) that installs a `$PSDefaultParameterValues` override so the fix applies to every audit test's AD queries module-wide, not just the call sites touched directly.
- **v1.20.5** - Closed another real documentation/code drift, found via the same header-vs-code audit as v1.20.4: `DomainHardeningAudits.ps1`'s header comment had claimed `A-NullSession`-comparable coverage since the file was written, but no logic anywhere in the module read `RestrictNullSessAccess`/`NullSessionPipes`/`NullSessionShares`. Added a fourth check to `Test-ADDomainHardeningFlags` that audits null-session (unauthenticated) access to named pipes/shares, reusing `LegacyAuthAudits.ps1`'s existing GPO-linked-policy-then-live-per-DC-registry-fallback resolver instead of duplicating it (the shared per-DC registry fallback helper was promoted from a private, nested function to `Common.ps1` so both modules can call the same implementation). Registry-value read only; no live SMB/null-session connection is attempted; live-only and skipped under `-Snapshot` like this file's existing anonymous-bind check.
- **v1.20.4** - Closed a real documentation/code drift: `GpoSecretsAudits.ps1`'s header comment had claimed `A-AnonymousAuthorizedGPO`-comparable coverage since the file was written, but no logic anywhere in the module implemented it. Added a fourth check to `Test-ADGpoDeployedSecrets` that parses each GPO's `GptTmpl.inf` `[Privilege Rights]` section for `SeNetworkLogonRight`/`SeRemoteInteractiveLogonRight` grants to Everyone/ANONYMOUS LOGON/Authenticated Users (matched by SID), reported as its own always-Critical finding consistent with this module's broad-principal severity convention. Read-only; no schema changes.
- **v1.20.3** - Fixed a real, user-reported dashboard bug: the finding-detail modal rendered open and empty on every page load (and its close button appeared broken) because `.modal { display: grid; }` had the same CSS specificity as the browser's built-in `[hidden]` rule and was winning the cascade regardless of the `hidden` attribute - a pre-existing bug that predates v1.20.0 and went unnoticed since nothing in earlier testing loaded the page without deliberately opening the modal first. Added an explicit `.modal[hidden] { display: none; }` override. Every other `hidden`-toggled element in the dashboard was audited and does not share this problem.
- **v1.20.2** - Bug-fix release found via review of a real generated report. Fixed the "Risk by Category" chart rendering with oversized text - its SVG lacked a `max-width` rule and was stretching to the full container width, inflating its 700-unit viewBox by ~1.9x; capped it the same way the score gauge and control-path diagram already were. Also unified all code/monospace styling (hop-chain text, affected-object references) onto one `--font-mono` token and two shared classes (`.code-block`, `.meta-code`) across both the static report and the dashboard, replacing a mix of ad-hoc inline styles and inconsistent `em`-relative sizing.
- **v1.20.1** - Follow-up polish on the v1.20.0 visual overhaul: removed all remaining decorative emoji from both HTML surfaces in favor of solid-color "severity dots" (same palette as the severity badges, print-safe and platform-consistent); added a sticky mini table-of-contents and an in-page "Print / Save as PDF" button to the static report (plus an equivalent print button on the dashboard); added a "Technical Findings - Full Detail" divider separating the leadership-facing front section from the technical detail; and fixed long category/object names overflowing their fixed-width SVG boxes by truncating with a full-text hover tooltip.
- **v1.20.0** - Presentation-layer only: unified the static HTML report (`Reporting.ps1`) and the JSON-upload dashboard (`ui/`) onto one shared, professional visual design - a single light theme (no dark/light toggle), a system font stack (dropping the dashboard's Google Fonts CDN dependency), and no `linear-gradient` anywhere status/severity is shown. Added inline hand-built SVG visuals (risk-score ring gauge, per-category risk bars, a simplified source-to-Tier-0 control-path diagram) with no chart library or external asset. Added a "Prioritized Remediation Order" section ranking existing findings worst-first by severity then category risk score - no new scoring logic. Brought the dashboard up to parity with the static report (it now renders Risk Score, ANSSI maturity, and MITRE ATT&CK summary) and corrected its sample data/schema, which had drifted from the current `ADSecurityFinding`/`Get-ADRiskScore` contract and still carried a stale pre-AD-only-scope Entra field.
- **v1.19.1** - Bug-fix release for v1.19.0, found via a real audit transcript review and a full-codebase sweep. Fixed `Test-ADControlPaths` crashing on every run (a `Mandatory`/empty-`ArrayList` PowerShell parameter-binding quirk on `Add-ADControlPathEdge`). Hardened `-FromSnapshot` to mean literally **zero outbound connections**, no exceptions: several v1.19.0 checks (`Test-ADGroupPolicies`, `Test-AuditPolicyConfiguration`, `Test-ADGpoDeployedSecrets`, `Test-ADRodcSecurity`, `Test-ADStaleObjectDepth`) were still silently falling back to live DC connections under `-Snapshot` despite the "no live AD access" contract - all now hard skips instead, plus a narrower anti-pattern found via a full-codebase sweep (most notably in `Get-ADControlPathGraph`, which could make one live ACL read per group in an escalation chain). Also closed two real online/offline finding-count parity gaps (`Test-ADCSExtended`'s ESC4 and NTAuth/AIA/Root sweep now run fully offline) and added "Offline Mode Coverage Notes" throughout - every skipped sub-check now records a structured note, and the HTML report shows an explicit table of what wasn't scanned and why, instead of a blanket "no live access was made" claim. See CHANGELOG for the full list.
- **v1.19.0** - Offline/`-Snapshot` parity for the remaining 12 live-only modules (`Test-ADPrivilegedGroups`, `Test-AdminSDHolder`, `Test-ADReplicationSecurity`, `Test-ADDangerousPermissions`, `Test-ADGroupPolicies`, `Test-LAPSDeployment`, `Test-ConstrainedDelegation`, `Test-ADDomainTrusts`, `Test-AuditPolicyConfiguration`, `Test-ADDomainSecurity`, `Test-ADCertificateServices`, `Test-ADDomainAdminEquivalence`). All 27 registered tests now support `-Snapshot`, fully or partially. New shared `Resolve-ADSnapshotGroupMember` helper for in-memory recursive group-membership resolution; additive-only `Snapshot.*` schema extensions (new ACL targets, `HasAuditRules`, GPO `LinkedTo`, LAPS schema presence, password policy/forest mode/Recycle Bin, extended trust attributes, delegation/RBCD/shadow-credential presence flags, per-object ADCS ACLs). A few sub-checks (SYSVOL file-share ACLs, per-DC `auditpol`) were intended to remain live-only by design, but shipped with a bug that made them fall back to live DC connections instead of skipping - corrected in v1.19.1 above.

- **v1.18.0** - `Test-ADKnownDCVulnerabilities`: added a new check for CVE-2026-41089 (critical, unauthenticated Netlogon RCE against Domain Controllers, patched May 12, 2026, actively exploited since June 2026), and refined the BadSuccessor/dMSA finding to classify each Windows Server 2025-level DC as Patched/Unpatched/Unknown for CVE-2025-53779 via a per-DC UBR (Update Build Revision) registry read, instead of flagging every Server 2025 DC identically regardless of patch level. The finding still fires for confirmed-patched DCs (at reduced severity once every affected DC is patched) since the underlying dMSA-linking primitive remains partially abusable post-patch. Both additions are read-only version/patch-level checks - no exploitation or protocol traffic of any kind.
- **v1.17.0** - Added `Get-ADForestConsolidation` / `Export-ADForestConsolidationHTML`: an offline, file-based multi-domain/forest consolidation feature that reads this module's own prior per-domain JSON exports and rolls them up into a forest score, per-category heatmap, domain comparison table, and cross-domain trust-risk enrichment - a free equivalent to PingCastle's paid "Conso" report. Not a live-AD check; no additional AD access required.
- **v1.16.2** - HTML report: findings that fire once per affected object (e.g. `AdminSDHolder ACL Compromise` across several principals) are now consolidated into a single collapsible entry per Category+Issue, with Impact/Remediation/MITRE/ANSSI shown once and every affected object listed underneath with its own specific detail - instead of one repeated top-level finding per object. Report-rendering change only; JSON/CSV exports are unaffected.
- **v1.16.1** - Bug-fix release: corrected several PowerShell errors surfaced by real-world runs (see CHANGELOG for the full list), rebalanced the risk-score model to use diminishing returns instead of a hard 100-point cap, tightened default retry/backoff timing, added a progress bar to the audit run and export steps, and reworked the HTML report (collapsible findings, working category bars, clickable executive summary, fixed character encoding).
- **v1.16.0** - Added `Get-ADControlPathGraph` / `Test-ADControlPaths`: an attack-path graph that traces indirect privilege-escalation routes (dangerous ACEs, group membership, ownership) from any non-Tier-0 principal to a Tier-0 target, plus an optional BloodHound-compatible export.
- **v1.0.0 - v1.15.0** - Built up from core AD hygiene checks (privileged groups, AdminSDHolder, GPOs, trusts, certificate services) to a full parity backlog against known AD security assessment methodologies: risk scoring/ANSSI maturity/MITRE tagging, a collect-once snapshot mode for offline analysis, and dedicated modules for DNS security, Kerberos hardening, legacy-auth exposure, GPO-deployed secrets, known CVEs by patch level, Exchange escalation paths, and RODC posture.

See [CHANGELOG.md](./CHANGELOG.md) for the complete, version-by-version history.

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
- [PingCastle](https://github.com/netwrix/pingcastle) (Netwrix) - many of this project's checks are independently-implemented comparisons to detection concepts PingCastle popularized; see the Independence note at the top of this README

Thanks also to Claude (Anthropic) for AI-assisted source analysis, feature-gap research, and implementation/bug-fix work across this project's v1.2.0-v1.18.0 backlog.
