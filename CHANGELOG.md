# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- **JSON/CSV output alignment** - the main audit's CSV export
  (`AD_Security_Audit_<timestamp>.csv`) was silently missing two fields
  that the JSON export (and every finding object) always carried:
  `SeverityLevel` and `Details`. Appended both as new columns at the end of
  the existing column list (after `Weight`, per this file's own "append,
  never reorder" output contract) - `Details` is serialized as a compact,
  formula-injection-sanitized JSON string, since it's an open-ended
  per-check hashtable with no fixed column set to flatten it into.
- **Cross-domain privileged-group-membership visibility**
  (`Test-ADPrivilegedGroups`, GroupAudits.ps1) - `Get-ADGroupMember
  -Recursive` can return members from a domain OTHER than the group's own
  (a universal group, or - in a multi-domain forest where the operator's
  machine is joined to a different domain than the one being audited -
  membership resolved via a Global Catalog legitimately including full
  objects from other domains too), and this was previously invisible: a
  member's own domain was never checked against the group's. New
  `Split-ADObjectByTargetDomain` helper (Common.ps1) flags any such member
  with a `Write-Warning` and a new informational `Cross-Domain Privileged
  Group Membership` finding (Low severity, so it's visible in the HTML
  report - `Info` isn't a rendered severity bucket) listing the affected
  accounts and their actual domain(s), instead of silently folding them
  into the audited domain's membership count with no indication they came
  from somewhere else.
- **Enterprise Admins / Schema Admins now resolve correctly for non-root
  domains** (`Test-ADPrivilegedGroups`) - these two groups exist ONLY in
  the forest root domain. Auditing any child domain via `-Server`
  previously scoped the `Get-ADGroup -Filter` lookup to that child domain
  alone, always found nothing, and silently skipped the group entirely
  with no finding and no indication why. Now falls back to resolving the
  forest root (`Get-ADForest`) and re-querying there when the initial,
  target-domain-scoped lookup comes back empty.
- New `Get-ADSecurityAuditActiveServerOverride` helper (Common.ps1) -
  centralizes reading the currently-active `Set-ADSecurityAuditTargetServer`
  `-Server` value (previously duplicated inline inside
  `Get-ADTargetDomainController`) so other call sites that need the actual
  override value (not just the `$PSDefaultParameterValues` auto-injection)
  can reuse it consistently.
- **`Export-ADSecurityReportHTMLFromJson`** - recreates the main
  `Start-ADSecurityAudit` HTML report directly from a previously-exported
  `AD_Security_Audit_<timestamp>.json` findings file, with no live Active
  Directory access and no re-run of the audit. Accepts an explicit file or a
  folder (same newest-file resolution idiom as `Get-ADRetestComparison`'s
  `-BaselinePath`/`-RetestPath`). The risk score/maturity/MITRE roll-up is
  always freshly recomputed via `Get-ADRiskScore` (never read back from a
  stray score sidecar, matching `Get-ADRetestComparison`'s existing
  philosophy). `Domain`, `Duration`, `RunMode`, `SnapshotCollectedDate`,
  Offline Mode Coverage Notes, and the Privileged Users section are not
  present in the findings JSON and are not recoverable - `-Domain`/
  `-Duration`/`-RunMode`/`-SnapshotCollectedDate` parameters let you supply
  them if known, otherwise the recreated report shows explicit placeholders
  rather than guessing. See the README's "Recreating the main HTML report
  from an existing JSON export" section for the full list of gaps versus
  the original report.
### Fixed
- **Root cause of "-Server override doesn't work, wrong domain's data
  appears" in a multi-domain forest.** Every per-DC probe in this module
  (anonymous-bind, null-session, Kerberos hardening, legacy auth, audit
  policy, known-DC-vulnerability checks, stale-object depth, RODC
  security, control-path graph, coercion/relay exposure, the main run's
  own DC connectivity check, and `Get-ADSnapshot`'s DC inventory
  collection) enumerated Domain Controllers via a bare
  `Get-ADDomainController -Filter *`. **`-Filter` is a fundamentally
  different code path than `-Identity`/`-Discover`: it queries the
  forest-wide `CN=Sites,CN=Configuration,...` container, which is
  replicated to every DC in the forest - so `-Server` only controlled
  WHICH DC answered the query, never the query's SCOPE.** In a
  multi-domain forest this could silently return, and then iterate every
  per-DC check over, Domain Controllers from a domain OTHER than the one
  `-Server` was explicitly set to - a completely different (and far more
  fundamental) failure mode than the `$PSDefaultParameterValues` `-Server`
  auto-injection mechanism itself, which was working correctly the whole
  time. New `Get-ADSecurityAuditDomainController` helper (Common.ps1)
  performs the same enumeration, then filters the result to DCs whose own
  `.Domain` property matches the domain actually resolved via
  `Get-ADDomain` against the same `-Server` (which does NOT have this
  problem). Every affected call site now uses this helper instead;
  `Get-ADSnapshot` in particular means offline/`-FromSnapshot` re-analysis
  is also fixed at the source rather than only live runs.
- **`Get-ADRetestComparison` / `Export-ADRetestComparisonHTML`: the report
  header's `BASELINE GENERATED` (and, when a score sidecar predated this
  fix, `RETEST GENERATED`) rendered as raw PowerShell object text
  (`@{value=...; DisplayHint=2; DateTime=...}`) instead of a date.**
  Root cause: `Get-ADRiskScore` (Scoring.ps1) stored `GeneratedDate` as a
  live `[datetime]` object rather than a string. `ConvertTo-Json` expands a
  raw `[datetime]` using its own `DisplayHint`/`DateTime`/`value` note
  properties instead of writing a plain date string, so every downstream
  `ConvertFrom-Json` read of a score sidecar (or of any other object this
  module round-trips through `-ToJson`, including `Get-ADForestConsolidation`'s
  `LastSeen` and `Get-ADMaturityTrend`'s date fields, which had the same
  latent issue) got that dump back instead of a usable date. Fixed at the
  source (`GeneratedDate` is now stored via `.ToString('o')`) and defensively
  on read (`ConvertTo-ADFriendlyDateText`, Common.ps1, added to Get-ADRetestSidecarMeta
  and to `ForestConsolidation`'s/`MaturityTrend`'s date rendering) so
  already-generated, pre-fix sidecars/exports also render correctly without
  needing to be regenerated. Also added `BASELINE FINDINGS`/`RETEST FINDINGS`
  count fields to the retest report header for parity with the main report's
  `TOTAL FINDINGS`.
- **Anonymous LDAP / RootDSE Binding Permitted check (`Test-ADDomainHardeningFlags`,
  DomainHardeningAudits.ps1) only ever probed a single Domain Controller.**
  Root cause: unlike every other live per-DC probe in this module (e.g. the
  null-session check immediately below it, which enumerates every DC via
  `Get-ADDomainController -Filter *`), this check resolved its target via
  `Get-ADTargetDomainController`, which returns exactly one DC - the
  `-Discover` result, or the single overridden host if
  `Set-ADSecurityAuditTargetServer` was active. In a multi-DC domain this
  meant the finding (and whether the probe errored at all) depended on
  whichever one DC happened to be picked that run, rather than reflecting
  the domain's actual anonymous-bind posture across all DCs - a domain
  with a mix of hardened and non-hardened DCs could flag one host and
  silently miss the others (or error out entirely if the single resolved
  host was unreachable) with no indication only one DC had been tested.
  Fixed: now enumerates every DC via `Get-ADDomainController -Filter *`
  and probes each independently; the finding is raised if any DC's
  anonymous bind succeeds, and lists exactly which DCs are affected
  (`Details.VulnerableDomainControllers`) alongside the full per-DC
  breakdown (`Details.PerDomainControllerResults`), so a partially-hardened
  fleet is visible instead of hidden behind a single-DC sample.
- **`Set-ADFindingMetadata: Cannot process argument transformation on
  parameter 'Finding'`, thrown at the very end of a live run, after the
  transcript had already stopped, with no JSON/HTML/CSV report written.**
  Root cause: if any invoked test scriptblock emits more than one array to
  its own output pipeline, the per-test results-assembly loop's `else`
  branch (`$allFindings += $result`) appends that whole array as a single
  nested element instead of spreading it into individual findings -
  producing a jagged/nested `$allFindings` array. This module's own
  `ConvertTo-ADFlatFindingsArray` helper already existed to guard against
  exactly this shape of bug (previously documented as occurring "only
  after a JSON round-trip" via `Get-ADRetestComparison`/`Get-ADRiskScore`),
  but `Start-ADSecurityAudit`'s own findings-tagging loop never applied it
  before `Set-ADFindingMetadata` - whose strongly-typed
  `[ADSecurityFinding]$Finding` parameter cannot bind a nested array,
  throwing immediately, after the transcript had already been stopped in
  the `finally` block and before the export section ever ran. Fixed by
  flattening `$allFindings` immediately after test-result assembly, before
  the summary counts (which would otherwise silently undercount against
  the un-flattened array) and before the tagging loop - matching the
  defensive pattern already used by `Get-ADRiskScore`/
  `Get-ADRetestComparison`, just applied earlier so every consumer is
  protected, not only scoring.
- **`-ExportPath ".\foldername"` (or any relative path) threw "Export path
  is not writable" even for a valid, writable folder.** `Join-Path`/
  `Test-Path`/`New-Item` are PowerShell-provider-aware and correctly
  resolve a relative path against `$PWD` (the shell's own current
  location), but the writability probe a few lines later used a raw .NET
  call (`[System.IO.File]::WriteAllText`), and .NET resolves relative
  paths against `[Environment]::CurrentDirectory` instead - which many
  hosts (IDE integrated terminals, scheduled tasks, some launch shortcuts)
  leave pointing at the user's profile folder rather than keeping synced
  to `$PWD`. A relative `-ExportPath` would resolve correctly for the
  directory-creation check, then silently resolve against the profile
  folder for the write-test and fail. Fixed by resolving `-ExportPath` to
  a fully-qualified absolute path immediately on entry, via a new
  `Resolve-ADSecurityAuditPath` helper (`Common.ps1`) that uses
  PowerShell's own path resolution (always honors `$PWD`) rather than raw
  .NET path handling. Added Pester coverage that deliberately desyncs
  `[Environment]::CurrentDirectory` from `$PWD` to reproduce the exact
  failure condition.
### Added
- **`-Server` now defaults to the current user's own domain**
  (`$env:USERDNSDOMAIN`) when omitted, instead of leaving "no `-Server`"
  ambient/ambiguous. `$env:USERDNSDOMAIN` is the DNS domain of the account
  actually running the session (set by the LSA at logon) - not the
  machine's own joined domain - so the common case ("audit my own
  domain") is now deterministic without the operator needing to know
  about or type `-Server` at all. An explicit `-Server` still always wins.
  New shared `Resolve-ADSecurityAuditTargetServer` helper (`Common.ps1`)
  implements this for `Start-ADSecurityAudit`, `Get-ADSnapshot`, and
  `Test-ADMachineAccountQuota`. Known limitation: `runas /netonly` (or an
  equivalent alternate-credential technique) does not update
  `$env:USERDNSDOMAIN`, so pass `-Server` explicitly in that case.
### Fixed
- **Multi-domain-forest server confusion (part 2 - raw ADSI binds)**: even
  after adding `-Server` support, several files still read the
  Configuration/Schema naming context via a raw `[ADSI]"LDAP://RootDSE"`
  bind (`CertificateServicesAudits.ps1`, `CertificateServicesExtendedAudits.ps1`,
  `DomainHardeningAudits.ps1`, `Snapshot.ps1` - 7 call sites total). That
  syntax is a `System.DirectoryServices`/COM object construction, not a
  PowerShell AD cmdlet call, so it is completely invisible to
  `$PSDefaultParameterValues` and ignored the `-Server` override entirely -
  it always bound to a DC of the *calling machine's own joined domain*
  regardless of what `-Server` requested. This was the remaining root
  cause behind `-Server` still resolving to the wrong domain even when the
  operator's account and machine agreed with each other. Replaced every
  instance with the new `Get-ADRootDSEValue` helper (`Common.ps1`), which
  goes through `Get-ADRootDSE` - a real `Get-AD*` cmdlet - so it honors the
  override like everything else.
- **`Get-ADDomainController -Discover` / `-Server` parameter-set conflict**:
  `-Discover` and `-Server` are mutually exclusive parameter sets on that
  cmdlet. Two live-network-probe call sites (`DomainHardeningAudits.ps1`'s
  anonymous-bind check, `DnsSecurityAudits.ps1`'s DNS-cmdlet target-DC
  resolution) called `-Discover` directly, independent of `Main.ps1`'s own
  DC discovery - so an active `-Server` override would throw a
  parameter-binding error on these specific calls and silently skip the
  check instead of honoring the override. New shared
  `Get-ADTargetDomainController` helper (`Common.ps1`) centralizes the
  same "resolve directly against an active override; otherwise
  `-Discover`" logic `Main.ps1` already used for its own DC connectivity
  check, so every live-probe call site gets it for free.
- **Multi-domain-forest server confusion (part 1)**: no `Get-AD*`/`Set-AD*`
  call anywhere in the module passed `-Server`, so every one of them relied
  on the AD PowerShell module's default "serverless" bind - which resolves
  against the invoking account's own logon domain rather than necessarily
  the domain the operator intends to audit. In a multi-domain forest this
  produced the reported symptom: an account from Domain A running the
  audit against/on a Domain B machine would silently read Domain A's
  domain object, DCs, users, etc. `Test-ADMachineAccountQuota` (the check
  first noticed) was the most visible instance, but the same root cause
  applied module-wide.
### Added
- **`-Server` parameter on `Start-ADSecurityAudit`**: forces the entire live
  audit run - domain lookup, DC discovery, and every individual test - to
  explicitly target a specified domain FQDN or DC hostname, instead of the
  default serverless resolution. Ignored (with a warning) when combined
  with `-FromSnapshot`, since offline mode performs no live AD access.
- **`-Server` parameter on `Get-ADSnapshot`** for the same override when
  collecting a snapshot standalone, outside `Start-ADSecurityAudit`.
- **`-Server` parameter on `Test-ADMachineAccountQuota`** directly, for
  standalone/unit-test use independent of `Start-ADSecurityAudit`.
- **`Set-ADSecurityAuditTargetServer` / `Clear-ADSecurityAuditTargetServer`**
  (`Common.ps1`): the shared mechanism behind the above. Installs (and
  removes) a `$PSDefaultParameterValues` entry that auto-supplies `-Server`
  on every `Get-AD*`/`Set-AD*`/`New-AD*`/`Remove-AD*` call for the rest of
  the session, so the fix applies to every audit test's own AD queries -
  not just the handful of call sites touched directly - without having to
  edit each of the ~40 source files individually.
- **`Get-ADRootDSEValue` / `Get-ADTargetDomainController`** (`Common.ps1`):
  shared helpers backing the two "part 2" fixes above.

## [1.23.2]
### Fixed
- **`Get-ADRetestComparison` (and `Get-ADRiskScore`, called from it) could
  crash with a confusing `Cannot convert the System.Object[] value ... to
  type System.Int32` error** when a findings JSON export contained a jagged/
  nested element - a top-level array entry that was itself a sub-array of
  several findings rather than one. PowerShell's member-enumeration silently
  turns every property read on such an element into an array, which then
  fails deep inside the scoring arithmetic. Reported from real production
  data comparing a v1.20.6 baseline against a v1.23.1 retest. New shared
  `ConvertTo-ADFlatFindingsArray` helper (`Common.ps1`) recursively flattens
  a findings array (a `Details` hashtable is correctly left alone as
  finding-level content, not recursed into); `Get-ADRiskScore` now applies
  it defensively on every call, and `Get-ADRetestComparison` applies it to
  both exports immediately after parsing them. No-op for the normal,
  already-flat case.

## [1.23.1]
### Fixed
- **`Get-ADMaturityTrend` silently dropped any `AD_Security_Score_*.json`
  sidecar that predates v1.21.0's `GeneratedDate`/`ModuleVersion` fields**,
  since it relied on `GeneratedDate` to sort runs chronologically - a domain
  with run history spanning that version boundary would see its older runs
  vanish from the trend with only a console warning. Now falls back to the
  sidecar file's own last-write time when `GeneratedDate` is missing or
  unparsable, so older runs are included rather than dropped. Every such run
  is explicitly flagged (not silently blended in as if the date were
  authoritative): a new `DateEstimated` boolean per `Series` entry, a
  top-level `EstimatedDateCount`, a note in the returned `Message` naming the
  affected file(s), and a visible "estimated" badge in
  `Export-ADMaturityTrendHTML`'s per-run table. Only the displayed/sorted
  date is estimated - score/maturity data is read and trended unchanged.

## [1.23.0]
### Added
- `Set-ADRemediationState` / `Get-ADRemediationState` (a small,
  hand-editable JSON state file keyed by the same Category+Issue+
  AffectedObject key `Get-ADRetestComparison` already uses) and wires an
  optional `-RemediationStatePath` parameter into `Get-ADRetestComparison`
  to annotate StillOpen/Changed findings with tracked status (Open/
  AcceptedRisk/InProgress/Remediated), owner, note, and date.
  `Export-ADRetestComparisonHTML` badges tracked findings accordingly.
  Explicitly does not affect `Get-ADRiskScore` - an accepted-risk finding
  still counts toward the score, this is a reporting annotation only.
  No ticket-system integration, no expiry alerting (both left for a
  future pass). Zero behavior change when `-RemediationStatePath` is
  omitted.

## [1.22.0]
### Added
- `Get-ADMaturityTrend` / `Export-ADMaturityTrendHTML`: an offline,
  file-based command that reads all of a domain's historical
  `AD_Security_Score_*.json` sidecars (not just two) and produces a
  chronological score/maturity/per-category trend with a simple
  Improving/Flat/Regressing classification. Deliberately does NOT recompute
  scores under the current mapping table (opposite of
  `Get-ADRetestComparison`) - surfaces each run's own `ModuleVersion`
  instead so a reader can attribute a score jump to a tool change vs. an
  actual posture change. New inline-SVG trend-line helper
  (`Get-ADSvgTrendLine`), no chart library. Offline, no new AD queries.
  Complementary to, not a redesign of, `Get-ADRetestComparison` - see the
  README's "Multi-run Maturity Trend History" section for the distinction.

## [1.21.0]
### Added
- `Get-ADRetestComparison` / `Export-ADRetestComparisonHTML`: an offline,
  file-based comparison between two prior `Start-ADSecurityAudit` exports of
  the same domain (baseline vs. retest), for tracking configuration-maturity
  change across a remediation cycle. Matches findings by
  Category+Issue+AffectedObject to classify each as New / Resolved /
  Still Open / Changed, and recomputes both runs' scores under the current
  Scoring.ps1 mapping table so cross-version retests stay apples-to-apples.
  Renders as a standalone HTML report with a togglable Current State / Delta
  View, reusing the existing score gauge, category bars, and finding-list
  components. No additional AD queries, credentials, or schema changes.
- New shared `Get-ADFindingMatchKey` helper (`Common.ps1`): builds the
  `Category+Issue+AffectedObject` matching key used to identify the same
  finding across two runs. Single source of truth for this key so future
  features (e.g. remediation/exception tracking) can never disagree with
  `Get-ADRetestComparison` on what a "key" is.
### Changed
- `Get-ADRiskScore`'s output gained two additive fields, `GeneratedDate` and
  `ModuleVersion`, so a persisted score sidecar can be identified by when and
  by which module version it was produced. No existing field changed or
  removed.

## [1.20.6]
### Fixed
- **`DnsSecurityAudits.ps1`'s header comment had claimed `P-DNSDelegation`-comparable
  coverage since this file was written, but no delegation/NS-record logic existed anywhere
  in the codebase** - only zone-transfer, dynamic-update, and ADIDNS CreateChild-ACL checks
  were implemented (three of the six PingCastle-comparable ids the header claimed, not four).
  Found via the same header-vs-code audit that closed the GPO (`A-AnonymousAuthorizedGPO`,
  v1.20.4) and null-session (`A-NullSession`, v1.20.5) gaps. Added a fifth check to
  `Test-ADDnsSecurity`: for every AD-integrated zone this function already enumerates, it
  calls the read-only `Get-DnsServerZoneDelegation` cmdlet to list delegated child zones and
  their NS/glue records, then issues an ordinary SOA query against each glue IP to confirm the
  delegation is still live. A glue server that no longer answers authoritatively for the child
  zone is flagged as a stale/dangling delegation - the well-documented DNS delegation/
  subdomain-takeover risk where whoever can now claim that hostname or reclaim that IP can
  serve authoritative-looking answers for the sub-zone. Delegations that merely point outside
  this module's known AD Sites & Services subnets (`Get-ADReplicationSubnet`, reusing the same
  read-only cmdlet `StaleObjectDepthAudits.ps1` already uses) but still answer correctly are
  explicitly NOT flagged, to avoid false positives against legitimate delegations to non-AD
  infrastructure (e.g. a cloud DNS provider) - that check is recorded only as weak,
  informational context alongside a real finding, never as its own trigger. Severity is
  conditional (`Medium`/`High`) on whether any unresponsive glue IP is a public address
  (externally re-claimable by anyone) versus simply unreachable internal infrastructure,
  following the same conditional-severity pattern already used for "Excessive Privileged Group
  Membership" in `GroupAudits.ps1`. New "Stale/Dangling DNS Zone Delegation" finding, reported
  once per zone-security audit across all affected zones (consistent with how the neighboring
  zone-transfer/dynamic-update/ADIDNS findings in this file already aggregate). New
  `Scoring.ps1` mapping entry (MITRE `T1590.002` - reused from the existing "DNS Zone Transfer
  Allowed" entry in this same file rather than introducing a new technique independently, ANSSI
  `vuln2_dns_stale_delegation`).
- Delegation/NS records have no `dNSProperty`-based fallback representation (unlike the
  transfer/dynamic-update checks), so this new check is skipped entirely when the DnsServer
  RSAT module is unavailable, and - like this file's other three per-zone checks - is skipped
  entirely under `-Snapshot` with an `Add-ADOfflineSkipNote` entry, since delegation records
  are not part of the current `Snapshot.DnsZones` schema. No `ADSecurityFinding` schema
  changes. No exploitation code: this reads already-published glue records and issues ordinary
  DNS queries against them - it never registers a hostname, claims an IP address, or otherwise
  attempts an actual takeover to confirm exploitability.

## [1.20.5]
### Fixed
- **`DomainHardeningAudits.ps1`'s header comment had claimed `A-NullSession`-comparable
  coverage since this file was written, but no logic anywhere in the codebase read
  `RestrictNullSessAccess`/`NullSessionPipes`/`NullSessionShares`.** Found via the same
  header-vs-code audit that closed the `A-AnonymousAuthorizedGPO` gap in v1.20.4. Added a
  fourth, read-only check to `Test-ADDomainHardeningFlags`: it audits `RestrictNullSessAccess`
  (Security Options: "Network access: Restrict anonymous access to Named Pipes and Shares")
  for the disabled (`0`) state - checking GPOs linked to the Domain Controllers OU, then the
  domain root, and falling back to a direct per-DC registry read only when no linked GPO
  defines the value - the same GPO-then-live-fallback pattern `LegacyAuthAudits.ps1` already
  uses for SMBv1/SMB-signing/`LmCompatibilityLevel`. When the restriction is disabled, the
  finding is additionally enriched (not gated) with the configured `NullSessionPipes`/
  `NullSessionShares` allow-list sizes. Reported as its own new "Null-Session Pipe/Share
  Access Permitted" finding, Medium severity - the same severity as the neighboring
  "Anonymous LDAP / RootDSE Binding Permitted" finding it sits next to in this file, since
  both are the same class of unauthenticated-access exposure on a different protocol surface
  (SMB/named pipes vs. LDAP). New `Scoring.ps1` mapping entry (MITRE `T1135` - Network Share
  Discovery, ANSSI `vuln3_null_session_access`).
- **Reused, rather than duplicated, the existing GPO-link-resolution logic.** The new check
  calls `LegacyAuthAudits.ps1`'s existing `Get-ADLinkedGposOrdered` and
  `Get-ADPolicyRegistryValue` directly (both are already module-scope functions, reachable
  from any file dot-sourced into this module, regardless of load order, since none of them run
  until a `Test-*` function is actually invoked after every file has been sourced). The one
  piece of this pattern that was **not** already reusable - the live per-DC registry-read
  fallback - was a function nested inside `Test-ADLegacyAuthSurface` and therefore private to
  it. Promoted it to a new shared `Get-ADLiveRegistryValuePerDc` function in `Common.ps1` and
  removed the now-redundant nested copy from `LegacyAuthAudits.ps1`, so both modules call the
  same implementation instead of carrying two copies of identical remote-registry-read logic.
- No `ADSecurityFinding` schema changes. Registry-value read only - no live SMB/null-session
  connection is ever attempted (unlike the anonymous LDAP bind check two checks above it in
  the same file, which *is* a live probe). Live-only, skipped entirely under `-Snapshot` with
  an `Add-ADOfflineSkipNote` entry, consistent with this file's existing anonymous-bind check
  and with `Test-ADLegacyAuthSurface`'s entire live-only posture.

## [1.20.4]
### Fixed
- **`GpoSecretsAudits.ps1`'s header comment had claimed `A-AnonymousAuthorizedGPO`-comparable
  coverage since this file was written, but no logic anywhere in the codebase implemented it.**
  The module's only anonymous-related check (the pre-Windows 2000 Compatible Access group
  membership check in `DomainHardeningAudits.ps1`) is a different AD mechanism entirely - a
  group membership, not a GPO-deployed User Rights Assignment - so it did not close this gap.
  Added a fourth, read-only check to `Test-ADGpoDeployedSecrets`: it parses each GPO's already-read
  `GptTmpl.inf` `[Privilege Rights]` section for `SeNetworkLogonRight` ("Access this computer
  from the network") or `SeRemoteInteractiveLogonRight` ("Allow log on through Remote Desktop
  Services") grants that include the SID for Everyone (`S-1-1-0`), ANONYMOUS LOGON (`S-1-5-7`),
  or Authenticated Users (`S-1-5-11`) - matched on SID, since `GptTmpl.inf` lists granted
  principals as SIDs, not resolved names. Reported as its own new, always-Critical finding
  ("GPO Grants Sensitive Logon Right to Broad Principal"), consistent with this module's existing
  convention that a broad principal on any sensitive path is always Critical (see "Everyone/
  Authenticated Users on a Control Path to Tier-0"), rather than folded into the existing
  Medium-severity "Insecure Setting Deployed via GPO" bucket, which would have undersold this
  class of exposure relative to how it is scored everywhere else in the module. No schema
  changes; no exploitation code; reads a file `Test-ADGpoDeployedSecrets` already opens, inside
  the same `-Snapshot`-skipped code path as the other GptTmpl.inf-based checks.

## [1.20.3]
### Fixed
- **Dashboard: the finding-detail modal showed up empty on every page load, and its close
  button appeared to do nothing.** `.modal` sets `display: grid` unconditionally, which has
  the exact same CSS specificity as the browser's built-in `[hidden] { display: none }` rule -
  as an author-stylesheet rule, `.modal`'s `display: grid` won the cascade, so the modal
  rendered on every load regardless of its `hidden` attribute, with nothing in it (`openModal()`
  is only ever called from a click handler, never during boot). Clicking the close button
  correctly set `hidden` back to `true` in the DOM, but CSS was still forcing it visible, so
  nothing appeared to happen. Added an explicit `.modal[hidden] { display: none; }` override,
  which has higher specificity and restores `hidden` as the actual authority. This bug predates
  v1.20.0 - the dark-theme rewrite carried the same broken rule forward unnoticed since nothing
  in earlier testing opened the modal without deliberately clicking something first. Every other
  `hidden` element in the dashboard (`#priority-panel`, `#risk-score-panel`,
  `#control-paths-panel`, `#mitre-section`, `.tab-panel`) was checked and does not have this
  problem - none of them set `display` at a competing specificity.

## [1.20.2]
### Fixed
- **The "Risk by Category" chart rendered with oversized text.** Its SVG had no `max-width`
  CSS rule, so it stretched to fill the full container width (~1300px+) instead of its
  authored 700px design width - inflating every font-size and stroke in it by roughly 1.9x.
  Fixed in both the static report and the dashboard by capping the chart at `max-width: 700px`
  (matching its viewBox), the same pattern already used correctly for the score gauge and the
  control-path diagram. This was caught from a real generated report, not caught during v1.20.0/
  v1.20.1 development since no PowerShell runtime was available to render a live test report.
- **Unaligned code/monospace styling.** The control-path hop-chain text was a bare
  inline-styled paragraph (not using any shared class), while affected-object values were
  shown in monospace in some places (the multi-object finding list) and plain text in others
  (the single-object finding view, the dashboard's finding cards) for the same kind of content.
  Introduced a single `--font-mono` token and two shared classes - `.code-block` for
  path/command-style block content, `.meta-code` for inline object-name references - and
  applied them everywhere monospace content appears, in both the static report and the
  dashboard, so all "code-like" content now reads consistently at the same fixed 13px/12px
  scale rather than a mix of relative `em` sizes and ad-hoc inline styles.

## [1.20.1]
### Changed
- Removed all decorative emoji from both HTML surfaces (section headings, summary/admin
  cards, the upload label) - they render inconsistently across platforms/print and read too
  casually for a report shown alongside leadership material. Severity is now indicated with a
  small solid-color square ("severity dot") using the same palette as the severity badges,
  rather than an emoji glyph.
- Added a sticky mini table-of-contents to the static report, linking only to sections that
  actually rendered for that run (Executive Summary, Prioritized Remediation, Risk Score &
  Maturity, Control Paths, and whichever severity sections have findings), plus an in-page
  "Print / Save as PDF" button. The dashboard gained an equivalent print button for its active
  tab.
- Added a "Technical Findings - Full Detail" divider in the static report, separating the
  leadership-facing front section (Executive Summary through Control Paths) from the full
  finding-by-finding technical detail that follows.
### Fixed
- Category names and control-path source/target object names could overflow their fixed-width
  SVG boxes for long values with no truncation. Long labels are now truncated to fit (with a
  full-text hover tooltip via SVG `<title>`) in both the static report and the dashboard.

## [1.20.0]
### Changed
- Unified the static HTML report and the JSON-upload dashboard onto one shared, professional
  visual design - a single light theme (no dark/light toggle), consistent severity coloring,
  and a system font stack (removes the dashboard's Google Fonts CDN dependency).
- Reordered the static report so the executive risk picture and a new prioritized remediation
  list appear before technical detail: Executive Summary -> Prioritized Remediation Order ->
  Risk Score & Maturity -> Control Paths -> severity-grouped Findings.
- Removed every `linear-gradient` from status/summary cards and the score gauge in favor of
  flat color + accent border, for reliable grayscale/print legibility.
### Added
- Inline hand-built SVG visuals in the static report: a risk-score ring gauge, per-category
  risk bars, and a simplified source-to-Tier-0 control-path diagram. No 3rd-party chart
  library or CDN asset is used anywhere in the report.
- A "Prioritized Remediation Order" section: the top findings ranked worst-first by severity
  then by category risk score, each linking straight to its full evidence further down the
  report. Presentation-only - it sorts existing fields and adds no new scoring logic.
- The dashboard (`ui/`) now renders Risk Score, ANSSI maturity, and MITRE ATT&CK summary,
  none of which it previously displayed.
### Fixed
- The dashboard's sample data and rendering code were out of sync with the current
  `ADSecurityFinding`/`Get-ADRiskScore` contract (a stale pre-AD-only-scope Entra field,
  and missing severity-level/ANSSI/MITRE fields); both are now aligned with the current,
  AD-only schema.

## [1.19.1]
### Fixed
This release fixes bugs found immediately after v1.19.0 shipped, all
centered on one theme: `-FromSnapshot`'s "no live AD access" contract
wasn't actually being honored everywhere it claimed to be. Investigated
via a real audit transcript and a full-codebase sweep, and hardened until
`-Snapshot` performs **literally zero outbound connections**, for
environments where the Domain Controller genuinely is not reachable from
the analysis machine - the whole point of re-analysing a JSON snapshot.

- **`Test-ADControlPaths` crash on every run**: `Add-ADControlPathEdge`
  declared `-EdgeList` as `Mandatory` on an `ArrayList`. PowerShell's
  parameter binder rejects a `Mandatory` argument that is an *empty*
  collection, so the very first edge ever added to a freshly-built graph
  threw `Cannot bind argument to parameter 'EdgeList' because it is an
  empty collection.` Fixed by adding `[AllowEmptyCollection()]`, matching
  the `[AllowEmptyString()]` already applied to `-From`/`-To` on the same
  function. The downstream empty-graph handling in `Test-ADControlPaths`
  (`if (-not $graph.Edges -or $graph.Edges.Count -eq 0 ...)`) was already
  correct and needed no change.

- **Two v1.19.0 checks silently contacted live Domain Controllers under
  `-Snapshot`**: `Test-ADGroupPolicies`' SYSVOL file-share ACL check and
  `Test-AuditPolicyConfiguration`'s per-DC `auditpol` check fell back to
  live SMB (`Get-Acl` against `\\<dnsroot>\SYSVOL\...`) and
  `Invoke-Command -ComputerName <dc>` respectively - identified from a real
  `-FromSnapshot` run's transcript, where both fired a `WARNING` and went
  on to produce live findings even though the run was announced as
  `Offline mode: ... (no live AD access)`. The v1.19.0 doc comments for
  both claimed this matched "the same live-only-sub-check pattern already
  used by `Test-ADCoercionAndRelayExposure`/`Test-ADLegacyAuthSurface`" -
  but that precedent is actually to **skip** an unrepresentable live-only
  sub-check entirely, never fall back to live I/O. Both now skip with a
  `Write-Warning` instead.

- **Three more checks had the same problem, once we went looking harder**:
  - `Test-ADGpoDeployedSecrets` - previously still read SYSVOL file content
    live even when the GPO list itself came from the snapshot. Now skips
    entirely under `-Snapshot`. (Its underlying limitation is genuine and
    unavoidable - it scans SYSVOL file *content*, GPP `cpassword` and
    deployed scripts, which has no AD attribute or snapshot representation
    at all - but under `-Snapshot` it must skip, not silently go live.)
  - `Test-ADRodcSecurity` - previously still performed one live
    `Get-ADObject` call per RODC even under `-Snapshot`. Now skips
    entirely. A partial skip (keep the krbtgt_* orphan check, drop just
    the per-RODC read) was considered and rejected: with no
    `msDS-KrbTgtLink` data, every krbtgt_* account would be misreported as
    orphaned - a wrong answer, not just a coverage gap.
  - `Test-ADStaleObjectDepth` - its DC subnet/site registration check
    previously still queried `Get-ADReplicationSubnet` live even under
    `-Snapshot`. Now skipped entirely.

- **A narrower, more insidious variant of the same anti-pattern**, found
  via a full-codebase sweep: a live cmdlet call gated on whether a
  *specific snapshot key* was present, rather than on whether `-Snapshot`
  itself was supplied. This meant a live call could still fire under
  `-Snapshot` in edge cases (a key missing from an older or malformed
  snapshot, or - most importantly - any object outside a small fixed set
  of named ACL targets):
  - `Test-ADUserSecurity` - an unconditional live `Get-ADGroup 'Protected
    Users'` call ran regardless of `-Snapshot` (it was simply never inside
    the snapshot/live branch at all). Now resolved from `Snapshot.Groups`;
    the finding logic only ever used the group's existence as a boolean
    gate, so no behaviour changed beyond removing the live call.
  - `Get-ADTier0Principal` (shared helper in `src/Common.ps1`, used by
    `Test-ADRodcSecurity`, `Test-ADControlPaths`, and others) - fell back
    to a live group-membership walk if `-Snapshot` was supplied without a
    `'Groups'` key. Now returns an empty Tier-0 set instead.
  - `Test-ADMachineAccountQuota` - fell back to a live `Get-ADDomain`/
    `Get-ADObject` call if `-Snapshot` was supplied but
    `MachineAccountQuota` was missing/null. Now skips with no live call.
  - **`Get-ADControlPathGraph`** (used by `Test-ADControlPaths`) - by far
    the most significant fix here. Five separate resolution steps could
    each fall back to a live call under `-Snapshot`: domain resolution
    (`Get-ADDomain`), DC-list resolution (`Get-ADDomainController`),
    protected-group DN resolution (`Get-ADGroup`, per missing group),
    group-membership-edge collection (`Get-ADGroup -Filter '*'`), and -
    worst of all - **the per-object ACL/ownership-edge sweep**, which
    previously made one live `Get-ADObject` call for *every*
    control-relevant object in a privilege-escalation chain that wasn't
    AdminSDHolder or the domain root. On a real domain with any
    nested-group escalation paths, this meant `Test-ADControlPaths` could
    make dozens of live AD calls during a run that was supposed to be
    fully offline. All five are now hard-gated on `-Snapshot` itself: DNs
    outside the snapshot's small, fixed set of ACL targets simply
    contribute `MemberOf` edges (direct membership paths are unaffected),
    with ACE/Owner edges for those objects now a documented coverage gap -
    reported as a single offline-mode coverage note, not one per object.

### Fixed - online/offline finding-count parity gaps
- **`Test-ADCSExtended`'s ESC4 check** (dangerous certificate template
  ACLs) was documented as "live only - not captured in snapshot" and
  skipped entirely under `-Snapshot`. It didn't need to be:
  `Get-ADSnapshot` already collects a flattened per-template `Access` ACL
  (added for `Test-ADCertificateServices`' ESC7 check) - the exact data
  ESC4 needs, it just wasn't wired up in this function. Now reads
  `$template.Access` offline; detection logic is otherwise identical to
  the live path.
- **`Test-ADCSExtended`'s NTAuth/AIA/Root store weak-signature sweep** was
  also documented as live-only. `Get-ADSnapshot` now collects the same
  `cACertificate` blobs from the `NTAuthCertificates`/`AIA`/`Certification
  Authorities` containers that the live sweep reads - same data shape and
  risk profile (public certificate bytes) as the `CertificateAuthorities`
  `cACertificate` field already in the snapshot. New `Snapshot.ADCS`
  fields: `NTAuthCertificates`, `AIACertificates`, `RootCACertificates`. A
  snapshot collected with an older module version simply won't have these
  fields; `Test-ADCSExtended` detects that and records a coverage note
  rather than erroring.

### Added
- **Offline Mode Coverage Notes**: a new shared tracking mechanism
  (`Add-ADOfflineSkipNote` / `Get-ADOfflineSkipNotes` /
  `Reset-ADOfflineSkipNotes` in `src/Common.ps1`) records every sub-check
  that doesn't run under `-Snapshot`, as a structured note - not just a
  console `Write-Warning`/`Write-Verbose` line that only the transcript
  sees.
- The HTML report's offline-run banner no longer unconditionally states
  "no live Active Directory or Domain Controller connections were made"
  without evidence - that claim is true for every run as of this release.
  A new **"Offline Mode Coverage Notes"** table lists every skipped
  sub-check (Test / Sub-Check / Why), so a reader can see exactly what a
  given offline report does and doesn't cover without cross-referencing
  the run log.
- Wired into all known live-only sub-check sites across the codebase:
  `GroupPolicies` (SYSVOL ACL), `AuditPolicyConfiguration` (`auditpol`),
  `ADCSExtended` (ESC8 - genuinely live-only), `CoercionAndRelayExposure`
  (per-DC service/registry probes), `DnsSecurity` (zone
  transfer/dynamic-update/ADIDNS), `DomainHardeningFlags` (anonymous-bind
  probe), `KerberosHardening` (encryption-type policy; FAST/Armoring),
  `KnownDCVulnerabilities` (entire test), `LegacyAuthSurface` (entire
  test), `GpoDeployedSecrets` (entire test), `RodcSecurity` (entire test),
  `StaleObjectDepth` (subnet/site check), plus `Invoke-ADRuleSet`'s generic
  not-yet-retrofitted-test skip. Each site self-reports, so this list
  needs no further manual maintenance as new tests are added.
- `Start-ADSecurityAudit` prints a one-line console summary at the end of
  a `-FromSnapshot` run, pointing to the HTML report for the full
  breakdown.
- `Add-ADOfflineSkipNote`'s `Mode` parameter retains a `'StillLive'` value
  in the API for any future genuinely unavoidable case, but as of this
  release **no built-in check uses it** - every registered test is either
  fully offline-capable under `-Snapshot` or skips a sub-check/entire-test
  outright. If you ever see a `StillLive` entry in a report, that
  identifies a specific, narrow exception worth scrutinizing on its own
  merits, not a normal occurrence.

### Notes
- Every fix above was verified with a full-codebase sweep for the specific
  anti-pattern that caused it (a live cmdlet reachable when `-Snapshot` is
  truthy) - not just the sites originally reported. As of this release, no
  built-in test performs any live AD/network access when invoked with
  `-Snapshot`.
- If you rely on any of the now-hard-skipped coverage
  (`Test-ADGroupPolicies`' SYSVOL ACL, `Test-AuditPolicyConfiguration`'s
  `auditpol`, `Test-ADGpoDeployedSecrets`, `Test-ADRodcSecurity`,
  `Test-ADStaleObjectDepth`'s subnet check, or `Test-ADControlPaths`' full
  ACL/ownership edge set beyond AdminSDHolder/domain root), run those
  tests live (without `-Snapshot`) as a supplement to an otherwise fully
  offline `-FromSnapshot` audit.
- Re-collect your snapshot with this version if you want ESC4/NTAuth/AIA/
  Root coverage from a `-FromSnapshot` run - snapshots collected with
  v1.19.0 predate the schema fields those checks now read. Everything
  else in this release is a pure behavioral fix with no other new
  `Snapshot.*` schema fields.

## [1.19.0]
### Added
- **Offline/`-Snapshot` parity for the remaining 12 live-only modules**
  (originally planned as steps 18-29 of the offline-parity backlog;
  shipped together in this single 1.19.0 release): `Test-ADPrivilegedGroups`,
  `Test-AdminSDHolder`, `Test-ADReplicationSecurity`,
  `Test-ADDangerousPermissions`, `Test-ADGroupPolicies`,
  `Test-LAPSDeployment`, `Test-ConstrainedDelegation`, `Test-ADDomainTrusts`,
  `Test-AuditPolicyConfiguration`, `Test-ADDomainSecurity`,
  `Test-ADCertificateServices`, and `Test-ADDomainAdminEquivalence` all now
  accept an optional `-Snapshot` parameter. `Invoke-ADRuleSet`'s
  "will be skipped under `-FromSnapshot`" list is now empty - all 27
  registered tests support `-Snapshot`, fully or partially.
- New shared helper `Resolve-ADSnapshotGroupMember` (`src/Common.ps1`):
  resolves group membership recursively in-memory against a snapshot,
  mirroring `Get-ADGroupMember [-Recursive]` with no live AD access.
  Cycle-safe (a group nested inside itself, directly or transitively, is
  detected and does not hang or stack-overflow). Reused by
  `Test-ADPrivilegedGroups`, `Test-AdminSDHolder`, and
  `Test-ADDomainAdminEquivalence`.
- `Snapshot.ACLs` gains three new fixed targets: `DomainControllersOU`,
  `UsersContainer`, `ComputersContainer` (same flattened-ACE shape as the
  existing `AdminSDHolder`/`DomainRoot`/`CertificateTemplatesContainer`
  targets). A domain that has renamed/moved one of these containers simply
  omits that key - every consumer checks `ContainsKey` before reading it.
- Every `Snapshot.ACLs` target now also carries `HasAuditRules`
  (`$true`/`$false`/`$null` if undeterminable at collection time due to a
  `SeSecurityPrivilege`/SACL-read limitation - `$null` never produces a
  finding, only an explicit `$false` does).
- `Snapshot.GPOs[]` gains `LinkedTo` (array of linked DNs), built from a
  single pass over every OU/domain-root `gPLink` attribute instead of the
  live code's per-GPO reverse lookup.
- New `Snapshot.LapsSchema` (`LegacyLapsPresent`/`WindowsLapsPresent`
  booleans, from a one-time schema-object presence check).
- New `Snapshot.PasswordPolicy` (`MinPasswordLength`/`ComplexityEnabled`/
  `ReversibleEncryptionEnabled`), `Snapshot.Forest.ForestMode`,
  `Snapshot.RecycleBinEnabled`, and `Domain.DomainMode`.
- `Snapshot.Trusts[]` gains `SIDFilteringQuarantined`,
  `SelectiveAuthentication`, `Created`, `Modified` - four more plain
  scalars on the already-narrowed `Get-ADTrust` property list from the
  v1.18.1 hang fix; no binary/key-history attributes reintroduced.
- `Snapshot.Users[]`/`Snapshot.Computers[]` gain `TrustedToAuthForDelegation`.
  `Snapshot.Computers[]` also gains `HasRbcdConfigured` (a boolean presence
  flag for Resource-Based Constrained Delegation, derived from a targeted
  LDAP filter - never the raw `msDS-AllowedToActOnBehalfOfOtherIdentity`
  security descriptor, which was deliberately removed from the snapshot in
  v1.18.2 for the same reason `nTSecurityDescriptor` is never stored
  wholesale). RBCD offline coverage is scoped to computer objects, matching
  real-world usage - a deliberate, documented narrowing.
- `Snapshot.Users[]` gains `scriptPath` and `HasShadowCredentials`;
  `Snapshot.Computers[]` gains `HasShadowCredentials` and a per-computer
  `Access` ACL (named `-Properties` only, flattened immediately via
  `ConvertTo-ADFlatAce` - never `-Properties *`, the exact pattern that
  caused the v1.18.1 hang). `HasShadowCredentials` is a boolean presence
  flag derived from a targeted `(msDS-KeyCredentialLink=*)` LDAP filter,
  never the raw key-credential blob.
- New `Snapshot.PrivilegedUserAcls`: ACLs for `adminCount=1` users
  specifically (not every user, to avoid ballooning the snapshot for
  accounts that will never need this data).
- `Snapshot.ADCS.CertificateTemplates[]`/`.CertificateAuthorities[]` gain
  per-object `Access` ACLs (same flattened shape as `Snapshot.ACLs.*`,
  bounded to template/CA object counts - never a domain-wide sweep) and
  templates gain `msPKI-RA-Signature`.
- `ADSecurityAudit.psd1`, `README.md` updated for all of the above.

### Notes
- No `Snapshot.*` field was renamed or removed anywhere in this release -
  every schema change above is additive, and every new/extended function
  keeps its live-mode behaviour byte-for-byte identical to before.
- Three sub-checks remain live-only by design, matching the precedent
  already set by `Test-ADCoercionAndRelayExposure`/`Test-ADLegacyAuthSurface`:
  `Test-ADGroupPolicies`' SYSVOL file-share ACL check and
  `Test-AuditPolicyConfiguration`'s per-DC `auditpol` check are real-time
  machine/network state with no AD-schema equivalent. Both still run when
  `-Snapshot` is supplied (with a `Write-Warning` noting they did), so
  `-FromSnapshot` reports don't silently lose that coverage - they just
  aren't "no live AD access" for those two specific sub-checks.
- `Get-ADSnapshot`'s per-computer ACL sweep (needed for
  `Test-ADDomainAdminEquivalence`) is, by design, the one place in this
  entire backlog where a domain-wide per-object ACL read is unavoidable;
  every other step deliberately bounded ACL collection to a small, fixed
  set of targets. Benchmark collection time on a realistic computer count
  before relying on `-ToJson` in a large environment.

## [1.18.5]
### Fixed
- **HTML report footer showing "vUnknown" instead of the real module
  version**: `ADSecurityAudit.psd1`'s `ReleaseNotes` used an expandable
  (double-quoted) here-string (`@" ... "@`). `Import-PowerShellDataFile`
  runs in PowerShell's restricted "data language" mode, which rejects any
  embedded expression in a here-string outright - even an accidental one -
  because the type itself is considered dynamic. The 1.18.3 release notes
  entry mentioned a literal `$User` in prose, which was silently
  interpreted as a variable-expansion token, causing
  `Import-PowerShellDataFile` to throw on the *entire* manifest and fall
  back to the hardcoded `'Unknown'` default in `ADSecurityAudit.psm1`.
  Switched `ReleaseNotes` to a literal (single-quoted) here-string
  (`@' ... '@`), which closes off this whole bug class permanently rather
  than just fixing this one instance - verified with
  `Import-PowerShellDataFile` against the real manifest.
- **HTML report gave no indication a report was generated offline from a
  snapshot**: `Export-ADSecurityReportHTML` now accepts `-RunMode` ('Live'
  or 'Offline (Snapshot)') and `-SnapshotCollectedDate`. The report title
  now shows a colored mode badge, a dedicated warning banner appears for
  offline runs (noting no live AD access was made and pointing at which
  tests were skipped), and the header info grid shows the collection mode
  plus - for offline runs - when the underlying snapshot was originally
  collected. `Start-ADSecurityAudit` wires this through automatically for
  both the live and `-FromSnapshot` code paths.
- **Several already-"snapshot-aware" modules silently fell back to live
  queries when a snapshot collection was legitimately empty** (e.g. zero
  domain trusts - the common case for single-domain forests - or zero
  extra computers beyond DCs): the presence check used throughout the
  codebase was `$Snapshot.ContainsKey('X') -and $Snapshot.X`, which
  evaluates false for an empty-but-successfully-collected array or
  hashtable, indistinguishable from "not collected" under this check.
  Removed the truthiness half of the check everywhere (21 occurrences
  across 13 files - `Common.ps1`, `ControlPaths.ps1`,
  `KerberosHardeningAudits.ps1`, `StaleObjectDepthAudits.ps1`,
  `RodcSecurityAudits.ps1`, `CoercionRelayAudits.ps1`, `UserAudits.ps1`,
  `KrbtgtAudits.ps1`, `MachineAccountQuotaAudits.ps1`,
  `ExchangeEscalationAudits.ps1`, `DnsSecurityAudits.ps1`,
  `GpoSecretsAudits.ps1`, `CertificateServicesExtendedAudits.ps1`) so
  `ContainsKey` alone decides whether snapshot data is used. Found via
  actual execution against a synthetic snapshot with legitimately-empty
  collections, not static review - a live single-domain-forest `-FromSnapshot`
  run would previously have made unwanted live `Get-ADTrust` calls from
  `Test-ADKerberosHardening` despite claiming "no live AD access is
  performed".
- Verified this release end-to-end: full syntax-parse of all 41 module
  files with zero errors, a real module import/export smoke test, and a
  full `Start-ADSecurityAudit -FromSnapshot` run against a synthetic
  snapshot producing valid JSON/HTML/CSV output.

## [1.18.4]
### Fixed
- **`Start-ADSecurityAudit -FromSnapshot` was not actually offline for
  roughly half the audit**: `AuditPolicyConfiguration` and 11 other
  registered tests (`PrivilegedGroups`, `AdminSDHolder`, `GroupPolicies`,
  `ReplicationSecurity`, `DomainSecurity`, `DangerousPermissions`,
  `CertificateServices`, `DomainTrusts`, `LAPSDeployment`,
  `ConstrainedDelegation`, `DomainAdminEquivalence` - the full set of
  pre-v1.3.0 "core auditing" modules) have never been retrofitted with
  `-Snapshot` support. `Invoke-ADRuleSet`'s documented fallback for
  functions without `-Snapshot` was to run them live, which meant
  `-FromSnapshot` silently made live AD/DC connections for 12 of 27 tests
  - directly contradicting its own doc comment and the README's "no live
  AD access is performed" claim. `Invoke-ADRuleSet` now SKIPS a test that
  lacks `-Snapshot` support by default (with a warning naming it) instead
  of quietly falling back to live queries, so `-FromSnapshot` actually
  means no live AD access unless you ask otherwise. The old behaviour is
  still available via a new opt-in `-AllowLiveFallbackForUnsupportedTests`
  switch on both `Invoke-ADRuleSet` and `Start-ADSecurityAudit`, for anyone
  who specifically wants a partial-live/partial-offline run.
  `Start-ADSecurityAudit -FromSnapshot` also now prints up front which
  tests will be skipped, before the run starts.

## [1.18.3]
### Fixed
- **`Test-ADUserSecurity` failing under `-FromSnapshot` with "Cannot process
  argument transformation on parameter 'User' ... the adapter cannot set
  the value of property 'Name'"**: a regression from the 1.18.2 flattening
  fix. `Test-PrivilegedUser`'s `$User` parameter was strongly typed as
  `[Microsoft.ActiveDirectory.Management.ADUser]`, which was harmless while
  `Snapshot.Users` held raw `ADUser` objects (the type already matched),
  but once those were flattened to `PSCustomObject`s in 1.18.2, every
  `-FromSnapshot` call had to coerce a `PSCustomObject` into a real
  `ADUser` instance - which fails, since that type isn't constructible via
  property copying. `Test-PrivilegedUser` only ever reads `.MemberOf`, so
  the parameter is now untyped and works with either shape.

## [1.18.2]
### Fixed
- **`Start-ADSecurityAudit -FromSnapshot` failing with "dictionary ...
  contains the duplicated keys 'ObjectGuid' and 'ObjectGUID'"**: `Domain`,
  `DomainControllers`, `Users`, and `Computers` were still being stored in
  the snapshot as raw `Get-ADDomain`/`Get-ADDomainController`/
  `Get-ADUser`/`Get-ADComputer` objects. The ActiveDirectory module's
  property bag can expose the same attribute under two differently-cased
  names (the typed property alongside a case-variant extended property);
  both serialise to distinct, valid JSON keys, but `ConvertFrom-Json`'s
  case-insensitive key comparer throws when reading that JSON back in on
  the `-FromSnapshot` side. All four collections are now flattened to
  plain `PSCustomObject`s with an explicit, single-cased property list -
  the same pattern already used for Groups/GPOs/ADCS/Trusts - which
  removes the whole class of issue rather than just this one attribute
  pair. `Computers` no longer collects
  `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD): it's a binary
  security-descriptor attribute in the same risk class as
  `nTSecurityDescriptor`, and no `-Snapshot`-aware check currently reads it
  (the existing RBCD check in `DelegationAudits.ps1` is live-only).

## [1.18.1]
### Fixed
- **`Get-ADSnapshot` "hang" on `-ToJson`**: the AD CS collection step was
  requesting `-Properties *` on every certificate template and certificate
  authority object. That pulls back every attribute on the object,
  including `nTSecurityDescriptor` (a full ACL with per-ACE
  `IdentityReference` objects) and other large/binary attributes that
  `Test-ADCSExtended` never reads from the snapshot. `ConvertTo-Json -Depth
  12` then had to walk that entire object graph for every template and CA
  with zero progress output, which is what looked like an indefinite hang
  on any domain with more than a handful of templates - it wasn't stuck,
  it was serialising kilobytes of unused ACL/attribute data per object.
  `Get-ADSnapshot` now requests only the specific properties
  `Test-ADCSExtended` reads (`displayName`, `msPKI-Certificate-Name-Flag`,
  `msPKI-Enrollment-Flag`, `msPKI-Certificate-Application-Policy`,
  `pKIExtendedKeyUsage` for templates; `dNSHostName`, `cACertificate` for
  CAs) and flattens both to plain `PSCustomObject`s, the same pattern
  already used for Groups/GPOs. Applied the same fix to domain-trust
  collection (`Get-ADTrust -Properties *` -> `trustAttributes, Direction,
  TrustType`), since trusts can carry similarly large binary attributes
  (e.g. `trustAuthIncoming`/`trustAuthOutgoing`) that were never read.
- `Get-ADSnapshot` had no progress indication at all beyond `-Verbose`
  output, unlike `Start-ADSecurityAudit`'s live-mode loop. Added a
  12-stage `Write-Progress` bar covering every collection area (domain/DCs,
  machine account quota, dSHeuristics, pre-Windows 2000 compatible access,
  users, computers, groups, GPOs, ACLs, AD CS, DNS zones, trusts).
  `Invoke-ADRuleSet` (the dispatcher `Start-ADSecurityAudit -FromSnapshot`
  uses) also had no progress bar even though the live-mode test loop in
  `Main.ps1` does; it now reports "Test N of M" the same way.
- The domain and domain-controller collection steps in `Get-ADSnapshot`
  were the only two steps with no `Write-Verbose` output at all (start or
  completion), unlike every other collection area - `-Verbose` gave no
  indication anything was happening there. Added matching start/completion
  verbose messages.
- `-ExportPath` (`Start-ADSecurityAudit`) and `-ToJson`'s parent directory
  (`Get-ADSnapshot`) previously failed with a hard error if the folder
  didn't already exist. Both now create the folder automatically
  (`New-Item -ItemType Directory -Force`) and only error if creation
  itself fails (e.g. permissions).
- `README.md`: the Usage section's example commands were plain text
  instead of fenced ` ```powershell ` blocks, so they rendered as
  unbroken, unformatted paragraphs instead of separate monospaced command
  lines. Also corrected `-OutputPath` to the actual parameter name,
  `-ExportPath`.

## [1.18.0]
### Added
- `Test-ADKnownDCVulnerabilities`: new check for CVE-2026-41089 (unauthenticated
  Netlogon RCE against Domain Controllers, patched May 12, 2026, CVSS 9.8,
  actively exploited as of June 2026) - detection is patch/build-level only,
  consistent with this function's existing ZeroLogon/MS17-010/MS14-068/
  PrintNightmare checks. No exploitation or protocol traffic of any kind.
  New `$Script:ADFindingMetadataMap` entry in `src/Scoring.ps1` (MITRE T1210,
  ANSSI `vuln1_netlogon_cve2026_41089_unpatched`).
- `Test-ADKnownDCVulnerabilities` / BadSuccessor finding: now distinguishes
  Domain Controllers patched for CVE-2025-53779 (build 26100.4946+, August
  2025) from unpatched ones via a new per-DC UBR (Update Build Revision)
  remote registry read (`Get-ADKnownVulnUBR`, using .NET's
  `[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey` - read-only, no writes,
  no code execution), instead of flagging every Windows Server 2025 DC
  identically regardless of patch level. A DC whose UBR cannot be read
  (e.g. remote registry access denied) is reported with an unknown patch
  status rather than silently assumed patched. Per independent post-patch
  research (Akamai, "BadSuccessor Is Dead, Long Live BadSuccessor(?)"), the
  finding continues to fire for patched DCs - severity is reduced from High
  to Medium only once every affected DC in the environment is confirmed
  patched - since the underlying dMSA-linking primitive remains partially
  abusable even after the KDC-side fix.
- New `tests/KnownVulnAudits.Tests.ps1` Pester coverage for both features:
  the CVE-2026-41089 vulnerable/patched evidence paths, and the UBR
  patched/unpatched/boundary/unreadable classification paths plus the
  full-patch severity reduction.

### Changed
- `Test-ADKnownDCVulnerabilities`'s `.DESCRIPTION` comment block and the
  file-level header comment in `src/KnownVulnAudits.ps1` updated to
  document both additions above.

### Output / schema changes
- Additive only. New `Details` keys on the BadSuccessor finding:
  `PatchedDomainControllers`, `UnpatchedDomainControllers`,
  `UnknownPatchStatusDomainControllers`, `BadSuccessorPatchedUBRThreshold`.
  New per-DC fields on `PerDomainControllerState`: `UBR`,
  `BadSuccessorPatchStatus`. New `Issue` string and `Details` shape for the
  CVE-2026-41089 finding, following the same pattern as the existing four
  legacy-CVE findings. The `ADSecurityFinding` object's top-level fields
  are unchanged; existing ZeroLogon/MS17-010/MS14-068/PrintNightmare
  findings are byte-for-byte unaffected.

### Sourcing note
- The CVE-2026-41089 fix date (May 12, 2026, CVSS 9.8) and the CVE-2025-53779
  UBR threshold (26100.4946) were independently re-verified on 2026-07-09
  against multiple sources citing MSRC directly (SecurityWeek, Tenable, Zero
  Day Initiative, Help Net Security, CERT-EU for CVE-2026-41089; Microsoft's
  own KB5063878 support article for the UBR threshold) - both match this
  release's thresholds exactly. CERT-EU's advisory additionally lists
  verified per-OS fixed-build boundaries for CVE-2026-41089 (recorded in the
  `Netlogon2026.FixNote` comment in `src/KnownVulnAudits.ps1`); several
  lower-quality aggregator sites gave mutually inconsistent KB numbers for
  the same CVE and were deliberately not relied on. This function's
  detection logic remains FixDate-only (not per-OS build), consistent with
  the other three legacy-CVE checks in the same table.

## [1.17.1]
### Fixed
- **External intelligence refresh (Q3 2026)** - periodic maintenance pass over `src/KnownVulnAudits.ps1` and `src/Scoring.ps1`'s external references. No detection logic, schema, or output-contract changes.
  - Re-verified all four legacy CVE fix-date thresholds directly against MSRC: ZeroLogon (CVE-2020-1472, [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)), MS17-010 ([MS17-010 bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)), MS14-068 (CVE-2014-6324, [MSRC blog](https://msrc.microsoft.com/blog/2014/11/additional-information-about-cve-2014-6324/)), PrintNightmare (CVE-2021-34527, [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)). All four dates were already accurate; added inline source-URL + verification-date citation comments next to each threshold.
  - `$Script:MitreTechniqueNames` in `src/Scoring.ps1` was missing a display name for `T1068` (Exploitation for Privilege Escalation), which is already referenced by the "DC Missing ZeroLogon Patch" and "PrintNightmare Exposure on DC" findings in `$Script:ADFindingMetadataMap`. Added the missing entry. All other 29 MITRE technique IDs referenced by the mapping table were diffed against the current MITRE ATT&CK Enterprise matrix and confirmed unchanged (no renames or deprecations affecting this project's usage).
  - The BadSuccessor / dMSA Escalation Exposure finding (`Test-ADKnownDCVulnerabilities`) stated there was "no build/version-detectable patched state" for the issue. This is now stale: Microsoft shipped a partial KDC-side fix as CVE-2025-53779 in the August 12, 2025 cumulative update (KB5063878, OS build 26100.4946), requiring a mutual dMSA/target link before the KDC honors it. Corrected the finding's Description/Impact/Remediation text accordingly; independent post-patch research (Akamai) is cited noting the underlying dMSA-linking primitive still enables related credential abuse, so the finding continues to fire for any Server 2025 DC rather than being suppressed once patched. The detection guard itself (base OS build >= 26100) is unchanged - see "Flagged, not implemented" below for why.
- Re-read the ANSSI-convention disclaimer at the top of `src/Scoring.ps1` and the README's Independence note / Scoring & Maturity section; both still accurately describe the mapping as inspired by, not sourced from, ANSSI's official catalogue. No changes needed.

### Flagged, not implemented (candidate feature-request docs produced alongside this refresh, not built in this release)
- A new DC-known-CVEs-family check for **CVE-2026-41089** - a critical (CVSS 9.8), unauthenticated Netlogon RCE against domain controllers, patched by Microsoft on May 12, 2026 and under active exploitation as of June 2026. This is squarely in the ZeroLogon/PrintNightmare/NoPac severity class this module already tracks, but adding a new `Test-*`-family check is feature work (needs its own version bump, changelog entry, and test coverage per this project's build-prompt workflow), not a data refresh.
- **BadSuccessor build-revision (UBR) patch detection** - the existing guard only checks the base OS build (26100), not the UBR/patch revision, so it cannot currently distinguish a DC patched for CVE-2025-53779 (build 26100.4946+) from one that isn't. Reading the UBR is a new data source for this function (`Win32_OperatingSystem` alone doesn't expose it) and was judged to be new detection logic rather than a threshold correction, so it's deferred to a proper feature-request pass.

## [1.17.0]
### Added
- `Get-ADForestConsolidation` / `Export-ADForestConsolidationHTML`: offline, file-based multi-domain/forest consolidation over this module's own existing JSON exports - forest score rollup, per-category heatmap, cross-domain trust-risk correlation, and a domain comparison table (a check comparable to PingCastle's paid "Conso" report, implemented independently and offered for free).
- New `src/ForestConsolidation.ps1`. This is a post-processing feature, not a live-AD detection module: it performs no LDAP/AD queries, requires no credentials or network access, and is **not** added to `Main.ps1`'s `$allTests`. It is a standalone command run after one-or-more `Start-ADSecurityAudit` runs already exist, reading their `AD_Security_Audit_<timestamp>.json` + `AD_Security_Score_<timestamp>.json` exports pairwise (one pair per domain) entirely offline.
- Forest-wide score and per-category heatmap reuse the exact worst-category (MAX) aggregation semantics `Get-ADRiskScore` already uses at the per-domain level, rather than a new averaging formula - the forest is only as strong as its weakest domain.
- Cross-domain trust-risk enrichment: any `Test-ADDomainTrusts` finding whose target domain also has a report present in the consolidated input set gets its `Details` annotated with that domain's own `TotalScore`/`MaturityLevel`/`MaturityLabel`; a finding whose target domain isn't present is left unannotated rather than erroring.
- A domain seen in a prior consolidated run (via the new `-PriorConsolidationPath` parameter) but missing from the current input is flagged as "not scanned this run" in `MissingDomains` instead of being silently dropped from history.
- Registered in `ADSecurityAudit.psm1` (dot-source + `Export-ModuleMember`) and `ADSecurityAudit.psd1` (`FunctionsToExport`). No changes to the existing per-domain finding schema, JSON, CSV, or HTML export - this feature only reads those files.

## [1.16.2]
### Changed
- **HTML report - consolidated findings**: findings that fire once per affected object (e.g. `AdminSDHolder ACL Compromise` across several principals, or the two SID History Injection checks across several accounts) previously rendered as N separate top-level `<details>` blocks with identical Category/Impact/Remediation text repeated each time. The report now groups findings by `Category` + `Issue` and renders **one** consolidated block per group: Impact, Remediation, and any MITRE/ANSSI tags are shown once, and every affected object is listed underneath with its own specific description (which still carries the per-object detail, e.g. which principal/SID/rights) and its own detection timestamp. A small count badge ("N objects") appears in the finding title when a group has more than one member. Findings that only ever fire once render exactly as they did in v1.16.1 - no visual change for the common single-object case.
- This is a report-rendering change only. `Get-ADRiskScore`, the JSON export, and the CSV export are unaffected - they still emit one row/object per finding, so nothing downstream that consumes the raw data (dashboards, SIEM ingestion, diffing between runs) needs to change.

## [1.16.1]
### Fixed
- **Character encoding**: `src/Reporting.ps1` contained literal emoji saved without a UTF-8 BOM, which Windows PowerShell 5.1 mangled into mojibake (e.g. `ðŸ”´`) both on-screen and in the exported HTML report. Replaced every emoji literal with an HTML numeric character reference, making the source pure ASCII and immune to this regardless of file encoding or console codepage.
- **`Test-ADDnsSecurity` / DNS zone transfer check**: `Get-DnsServerZoneTransfer` is not a real cmdlet in the `DnsServer` module (verified against Microsoft's documentation) and always failed with "term not recognized." Zone-transfer settings are now read from the `SecureSecondaries`/`SecondaryServers` properties already present on the `Get-DnsServerZone` result. Also corrected the finding's remediation text, which cited a nonexistent `Set-DnsServerZoneTransfer` cmdlet (`Set-DnsServerPrimaryZone -SecureSecondaries` is correct).
- **`Get-ADTier0Principal` / `PrivilegedGroupsString`**: fixed "The property 'PrivilegedGroupsString' cannot be found on this object" - the property is now declared at object construction instead of being added after the fact, which PowerShell's `[PSCustomObject]` literal doesn't support.
- **`Test-ADGpoDeployedSecrets` / script-credential scan**: fixed "Cannot convert 'System.Object[]' to the type 'System.String'" - a missing pair of parentheses around two `Join-Path` calls caused PowerShell to chain them into a single malformed argument list instead of building a two-element array.
- **`Test-ADCSWeakCertificate` / ROCA check**: added a fallback to the legacy `PublicKey.Key` API when `GetRSAPublicKey()` isn't resolvable (older .NET Framework hosts), so weak-modulus/ROCA detection no longer silently skips certificates on those hosts.
- **`Test-ADCoercionAndRelayExposure` / Spooler+WebClient check**: querying both services in a single `Get-Service` call meant a missing `WebClient` service (common on modern/Core builds) failed the whole call and silently lost the `Spooler` result too, then retried 3x with exponential backoff for a result that could never succeed. The two services are now queried independently, and a missing `WebClient` service is treated as a normal "not installed" outcome rather than a retryable error.
- **`DomainAdminEquivalence.ps1`**: 6 findings (AdminSDHolder Ghost Account, Shadow Credentials Detected, both SID History Injection findings, Legacy Logon Script Defined, AdminSDHolder ACL Compromise) never populated the `Impact` field, leaving it blank in the report. All 6 now have an explicit impact statement; the HTML report also now shows a placeholder instead of a blank paragraph if any field is ever empty in the future.
- **HTML report - category risk bars**: the colored fill bars under "Risk by Category" never rendered (numbers showed, bars stayed grey) because `.cat-bar-track`/`.cat-bar-fill` were `<span>` elements with no `display: block`, and browsers ignore `width`/`height` on default inline elements. Both now render correctly.

### Changed
- **Risk scoring model** (`Get-ADRiskScore`): replaced the additive-sum-capped-at-100 category score with a diminishing-returns model (`Score = 100 * (1 - product of (1 - weight/100) across findings)`). Previously, 2-3 Critical findings in one category (weight 40 each) saturated it to 100/100 outright, which made the global score uninformative in any environment with a handful of Criticals. Scores now approach 100 smoothly as findings accumulate. **This changes the numeric score compared to prior versions** - a report re-run against the same environment will show a different (generally lower, more differentiated) score than under v1.16.0 and earlier. The `CategoryScores` output also gains a `RawPoints` field (the old additive sum) for transparency.
- **Default retry policy** (`Invoke-ADQueryWithRetry`, used throughout the tool for AD/network calls): `MaxAttempts` default reduced from 3 to 2, `DelaySeconds` from 2 to 1, cutting the maximum wasted time on a failed operation from ~6s to ~1s. Combined with the WebClient fix above, this meaningfully shortens total run time in environments with several DCs or partially-unreachable hosts.
- **HTML report**: individual findings now render as collapsible `<details>` elements (collapsed by default); each severity section has "Expand All"/"Collapse All" buttons; the Executive Summary cards are now clickable links to their corresponding severity section.
- **PingCastle references**: reworded throughout the codebase, README, and CHANGELOG from "parity"/"-style"/"-aligned" phrasing to "comparable"/"similar in spirit to" phrasing, and added an independence disclaimer to the README. These are feature comparisons only; ADSecurityAudit is not affiliated with, endorsed by, or a derivative of PingCastle/Netwrix.
- **README**: installation instructions now lead with running the module in place (`Import-Module .\ADSecurityAudit.psd1`, no copy step) with a matching update procedure; the previous "copy into a PSModulePath directory" method is retained as a secondary option with its own update steps. The ~100-line duplicated version history was condensed to a short pointer at this file.
- Added a progress bar (`Write-Progress`) to the main audit test loop and to the report-export steps, so long runs show visible progress instead of appearing to hang.

## [1.16.0]
### Added
- Attack-path graph (`Get-ADControlPathGraph`) and indirect-privilege findings (`Test-ADControlPaths`) reaching Tier-0 via ACL/membership/ownership chains.
- Optional BloodHound-compatible edge export (`Export-ADControlPathGraphBloodHound`).
- 'Control Paths to Tier-0' HTML report section.

## [1.15.0]
### Added
- `Test-ADRodcSecurity`: Read-Only Domain Controller security posture (a check comparable to a PingCastle rule).

## [1.14.0]
### Added
- `Test-ADExchangeEscalation`: Exchange-in-AD privilege escalation (Exchange Windows Permissions / WriteDACL) (a check comparable to a PingCastle rule).

## [1.13.0]
### Added
- `Test-ADKnownDCVulnerabilities`: Known DC vulnerabilities by patch/build (MS14-068, MS17-010, ZeroLogon, PrintNightmare, BadSuccessor) (a check comparable to a PingCastle rule).

## [1.12.0]
### Added
- `Test-ADGpoDeployedSecrets`: GPO-deployed secrets & insecure settings (GPP cpassword, script credentials) (a check comparable to a PingCastle rule).

## [1.11.0]
### Added
- `Test-ADStaleObjectDepth`: Stale-object & hygiene depth (PASSWD_NOTREQD, primaryGroupID, duplicate SPNs, DC registration) (a check comparable to a PingCastle rule).
- Accounts with PASSWD_NOTREQD Set check: `userAccountControl` bit 0x0020.
- Non-Default primaryGroupID (Membership Hiding) check: flags user/computer objects whose `primaryGroupID` does not match the expected default for their object type, distinguishing the legitimate Domain Controllers RID (516) for genuine DCs from a suspicious value elsewhere.
- Duplicate Service Principal Names check: case-insensitive SPN index across users and computers, reporting all holders.
- DC Subnet/Site Registration Gap check: cross-checks each Domain Controller's IPv4 address against AD Sites & Services subnet objects (`Get-ADReplicationSubnet`, live-only).
- Insufficient Domain Controller Count check: flags a domain with fewer than 2 Domain Controllers.
- Snapshot-aware for the PASSWD_NOTREQD, primaryGroupID, duplicate-SPN, and DC-count checks; `Get-ADSnapshot`'s `Users`/`Computers` collection now also includes `PrimaryGroupID` (users) and `ServicePrincipalNames`/`SamAccountName` (computers). The DC subnet/site registration check always performs one live `Get-ADReplicationSubnet` call, consistent with other live-only sub-checks.

## [1.10.0]
### Added
- `Test-ADKerberosHardening`: Kerberos hardening depth (AES enforcement, FAST/armoring, cross-trust TGT delegation) (a check comparable to a PingCastle rule).
- RC4 Kerberos encryption still permitted check: Tier-0 privileged accounts and krbtgt via `msDS-SupportedEncryptionTypes` bitmask, trusts missing the `TRUST_USES_AES_KEYS` attribute, and (live-only) the domain-wide "Configure encryption types allowed for Kerberos" GPO/registry policy.
- Kerberos Armoring (FAST) not enabled check: KDC-side and client-side `EnableCbacAndArmor` GPO/registry policy, with a direct per-DC registry fallback when no linked GPO defines a setting (live-only).
- Cross-Trust TGT Delegation Enabled check: flags trusts whose `trustAttributes` has the `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` bit set.
- Snapshot-aware for the account-level RC4 check (`Snapshot.Users` + the Tier-0 set) and both trust-level checks (`Snapshot.Trusts`); the domain-wide encryption-type policy and Kerberos Armoring (FAST) checks are live-only GPO/registry reads and are skipped entirely when run from a snapshot, consistent with `Test-ADLegacyAuthSurface` and `Test-ADCoercionAndRelayExposure`.

## [1.9.0]
### Added
- `Test-ADLegacyAuthSurface`: Legacy auth & name-poisoning surface (SMBv1, signing, LM/NTLMv1, LLMNR, WSUS-HTTP) (a check comparable to a PingCastle rule).
- SMBv1 enabled/not-disabled-by-policy check, SMB signing not required check, LM/NTLMv1 permitted check (`LmCompatibilityLevel` < 3), LLMNR not disabled by policy check, and WSUS delivered over HTTP check.
- GPO-linked registry policy values are read via `Get-GPRegistryValue` (Domain Controllers OU first, then domain root); falls back to a direct per-DC registry read only when no linked GPO defines a setting, so the finding always distinguishes a policy-enforced value (naming the source GPO) from an unset/local one.
- Live-only: registered in `Invoke-ADRuleSet`'s test registry with an optional `-Snapshot` parameter for consistency, but returns no findings when run from a snapshot since GPO-linked registry policy state has no snapshot equivalent.

## [1.8.0]
### Added
- `Test-ADDnsSecurity`: AD-integrated DNS security (DnsAdmins, zone transfer, insecure updates, ADIDNS) (a check comparable to a PingCastle rule).
- DnsAdmins non-default membership check (DC code-execution path via `ServerLevelPluginDll`), zone-transfer exposure check, insecure dynamic-update check, and ADIDNS broad CreateChild ACL check on AD-integrated zone objects.
- `Get-DnsServerZone`/`Get-DnsServerZoneTransfer` used when the DnsServer RSAT module is available, with a best-effort `dNSProperty` attribute fallback otherwise.
- Snapshot-aware for the DnsAdmins membership check (`Snapshot.Groups`); registered in `Invoke-ADRuleSet`'s test registry. The zone-level checks are live-only and are skipped entirely when run from a snapshot.

### Fixed
- HTML report footer's module version string was hardcoded and had drifted from `ModuleVersion` since v1.7.0; it is now read from the module manifest at import time instead of being duplicated.

## [1.7.0]
### Added
- `Test-ADCSExtended`: AD CS beyond ESC1/2/3/7 (ESC4, ESC8, ROCA, weak CA crypto) (a check comparable to a PingCastle rule).

## [1.6.0]
### Added
- `Test-ADCoercionAndRelayExposure`: Coercion & NTLM relay exposure (PrinterBug / WebClient / LDAP signing / channel binding) (a check comparable to a PingCastle rule).

## [1.5.0]
### Added
- `Test-ADDomainHardeningFlags`: Domain hardening flags (dsHeuristics, pre-Win2000, anonymous binding) (a check comparable to a PingCastle rule).
- Positionally parses `dSHeuristics` for dangerous settings: anonymous access (char 7 = '2'), List Object security mode (char 1 = '1'), and AdminSDHolder exclusion mask weakening (char 16 non-zero).
- Flags broad membership (Authenticated Users/Everyone/ANONYMOUS LOGON) in the built-in Pre-Windows 2000 Compatible Access group.
- Performs a strictly read-only anonymous LDAP/RootDSE bind probe; success is the finding, refusal is the secure state.
- `Get-ADSnapshot` now also collects `DsHeuristics` and `PreWin2000Members` (additive snapshot keys); the dsHeuristics and Pre-Win2000 checks are snapshot-aware. The anonymous-bind probe is a live network operation and is skipped when running from a snapshot.

## [1.4.0]
### Added
- `Test-ADMachineAccountQuota`: flags `ms-DS-MachineAccountQuota` left at the unmodified default of 10 (High) or any other non-zero value (Medium), which lets any authenticated user self-service-join computer accounts - a common foothold for RBCD relay and SamAccountName-spoofing privilege escalation.
- `Get-ADSnapshot` now also collects `ms-DS-MachineAccountQuota` (additive snapshot key); the new check is snapshot-aware and registered in `Invoke-ADRuleSet`.

## [1.3.0]
### Added
- `Get-ADSnapshot` collect-once pass with `-ToJson` and `Invoke-ADRuleSet` rule-runner.
- `Start-ADSecurityAudit -FromSnapshot <path>` offline re-analysis.
- Shared `Get-ADTier0Principal` privileged-principal helper.
### Changed
- Rule-runner invokes audit functions defensively (passes `-Snapshot` only to functions that declare it), so snapshot-unaware modules are unaffected.

## [1.2.0]
### Added
- Risk score (0–100), per-category sub-scores, and ANSSI-style 1–5 maturity level.
- MITRE ATT&CK technique and ANSSI control tagging on every finding via a central mapping table (`src/Scoring.ps1`).
- `MitreTechnique`, `AnssiControl`, `Weight` fields on `ADSecurityFinding` (additive).
- Score/maturity/MITRE sections in the HTML report; new CSV columns.

### Changed
- Output schema is now contract-stable: finding fields are additive only.

## [1.1.0]
### Added
- Domain Controller failover support for improved reliability.
- `Invoke-ADQueryWithRetry` helper for network resilience (exponential backoff).
- Result pagination for large AD queries (prevents timeouts in large environments).
- `ConvertTo-SafeCsvValue` function for safe CSV exports.

### Fixed
- CSV injection vulnerability in report exports.
- Converted 40+ silent failures to proper try/catch with verbose logging.

## [1.0.1]
### Fixed
- Nested group detection in `Test-ADPrivilegedGroups`.
- LAPS schema path lookup.
- SID lookup in DCSync detection.
- Orphaned `adminCount` detection now uses recursive group membership.
- ESC1 detection now checks enrollment permissions.
- Kerberoasting detection now factors in encryption type and password age.

## [1.0.0]
### Added
- Initial release: core AD security auditing, AD CS scanning, KRBTGT monitoring,
  domain trust auditing, LAPS verification, audit policy validation, and
  constrained delegation analysis.
