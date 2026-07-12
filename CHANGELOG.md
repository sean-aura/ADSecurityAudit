# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
