# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.24.0] - 2026-08-29
### Added
- **Test Coverage tracking**: every check now reports whether it ran clean, ran and found something, failed, or was deliberately excluded (`-IncludeTests`/`-ExcludeTests`) - not just console output, but a durable, report-visible record. Previously a check that errored out only produced a console `Write-Warning`, and a check that ran and found nothing was completely indistinguishable from a check that never ran at all once you were only looking at the findings list.
  - `Main.ps1` tracks every entry in `$allTests` (not just the ones that ran) and writes `AD_Security_TestCoverage_<timestamp>.json`/`.csv` sidecars alongside the existing exports.
  - `Export-ADSecurityReportHTML` gained a `-TestCoverage` parameter and a new "Test Coverage" report section, with per-check badges (COMPLETED / CLEAN / FAILED / EXCLUDED) and a summary line breaking out passed-clean vs. found-issues vs. untested (failed+excluded) as distinct counts.
  - A fully clean run (zero findings) now still exports a full report - this was previously gated on `$allFindings.Count -gt 0` and silently produced no output files at all for the best possible outcome (everything checked, nothing found).
- **New `Export-ADSecurityReportCSVFromJson`**: the CSV equivalent of `Export-ADSecurityReportHTMLFromJson` - rebuilds the findings CSV (and, if available, a coverage CSV) from an old JSON export offline. Both CSV export paths (this and `Main.ps1`'s live export) now share one column-construction function, `ConvertTo-ADFindingsCsvRows` (`Common.ps1`), so they can no longer independently drift out of sync with each other.
- An export that predates test coverage tracking (before this version) or is otherwise missing its coverage sidecar gets an explicit, version-citing note instead of silently omitting the section: the HTML rebuild path adds a "Test Coverage Not Available" run-scope note, and the CSV rebuild path still writes a `-coverage.csv` file, but with a single explanatory `NotAvailable` row - so the limitation is visible in the output artifact itself, not just a verbose log line, and it's unambiguous that coverage data doesn't exist for that run rather than everything having been silently excluded or failed.
- **Test coverage awareness extended to every downstream consumer of historical/comparative data, closing the same blind spot one level up in each**:
  - **`Get-ADRetestComparison` could falsely report a finding as "Resolved".** A finding present in the baseline but absent from the retest was always classified as Resolved, with no consideration of whether the check that would have produced it actually ran in the retest. A check excluded via `-ExcludeTests`/`-IncludeTests`, or one that failed with an exception, makes every finding it would have reported disappear too - identically to genuine remediation as far as a key-based diff can tell. Fixed: findings are now tagged with the `TestName` of the check that produced them (new additive `ADSecurityFinding.TestName` field, set by `Main.ps1`'s test loop). `Get-ADRetestComparison` cross-references a disappeared finding's `TestName` against the retest's coverage sidecar; if that check shows `Failed` or `Excluded`, the finding is moved out of `ResolvedFindings` into a new `UnconfirmedFindings` bucket with a clear reason, instead of being counted as resolved. New additive `CoverageCaveats` field surfaces when cross-checking wasn't even possible (coverage data missing on either side). `Export-ADRetestComparisonHTML` gained a matching "Unconfirmed" section and a coverage-caveats box. Also extended `Get-ADRemediationState` annotation to cover the new `UnconfirmedFindings` bucket (functionally still-open-but-uncertain, same as `StillOpenFindings`).
  - **`Get-ADMaturityTrend` and `Get-ADForestConsolidation` had the same blind spot, one level up**: a historical run/domain with excluded or failed checks scores better than a fully-tested one purely from checking less, with nothing distinguishing "genuine improvement" from "checked less this time." Both now look up each run's/domain's coverage sidecar (via a generalized `Get-ADTestCoverageSidecar`, which now accepts either a findings or a score sidecar file) and flag incomplete/unavailable coverage: `Get-ADMaturityTrend` gained `CoverageAvailable`/`UntestedCount` per run and `IncompleteCoverageCount`/`NoCoverageDataCount` overall (surfaced in `Message`, same pattern as the existing `DateEstimated` handling, and a new Coverage column in `Export-ADMaturityTrendHTML`'s per-run table); `Get-ADForestConsolidation` gained `IncompleteCoverageDomains`/`NoCoverageDataDomains` (named, not just counted, since a forest is typically much smaller than a trend's run history) and a matching Coverage column in `Export-ADForestConsolidationHTML`'s domain comparison table.
  - Verified end-to-end for all three: the false-"Resolved" scenario (an excluded RODC check), the misleading-trend scenario (a score improvement caused purely by an excluded check), and the misleading-domain-comparison scenario, each alongside a control case (genuine remediation/full coverage) confirming nothing is over-flagged.
### Fixed
- **Full-codebase audit of the findings pipeline (JSON/HTML/CSV) found one real latent gap: an unexpected `Severity` value would silently vanish from the HTML report entirely.** `Export-ADSecurityReportHTML`'s severity-bucketing only ever created sections for exactly `Critical`/`High`/`Medium`/`Low`; `Scoring.ps1` already has its own silent "Info" catch-all bucket for any other value (`default { $sevCounts.Info++ }` - present for defensive reasons, never previously triggered). Confirmed by tracing every literal and every conditional/variable-based `Severity` assignment in the entire codebase that no check currently produces anything other than the four canonical values - this was not an active bug affecting real findings today - but a finding with any other severity (a future check, a typo, or an externally-supplied finding) would still be scored and still appear in JSON/CSV (neither filters by severity at all) while never rendering ANYWHERE in the HTML report, with no warning that anything was missing. Fixed with a catch-all "Other / Unclassified Severity Findings" section (own nav link, same collapsible per-finding rendering as the four standard sections) plus a `Write-Warning` naming the affected Issue(s), so this can never happen silently again. The rest of the audit (every finding-generation block sets all 5 required core fields; every `$findings +=` uses the same variable, no bypassed findings; all 28 top-level checks are registered in `$allTests`; every "helper" `Test-*` function is genuinely called; CSV/JSON export apply zero severity filtering; the HTML "Detailed Findings" sections iterate every group and every member with no truncation) turned up no other gaps.
- **"User Account with SPN (Kerberoasting Risk)" / "Privileged Account with SPN (Kerberoasting Risk)" (`UserAudits.ps1`) had no supporting-information backfill at all.** These two findings set `Issue` AND `EstimatedEffort`/`KnownRisks`/`BackupRollback` all via `if ($isPrivileged) { 'A' } else { 'B' }` - a pattern `tools/Build-ADFindingNarrativeLibrary.ps1`'s plain-literal extractor didn't recognize at all, so this Issue silently had no `FindingNarrativeLibrary.ps1` entry whatsoever. Recreating a report from an export that predates these fields (or was generated before an older remediation-numbering bug in this same finding was fixed, leaving stale gapped `1. / 2. text / 3. text / 4. / 5.` `Remediation` text baked into the JSON) left `EstimatedEffort`/`KnownRisks`/`BackupRollback` permanently blank, with no guidance to backfill from. Fixed with a new `Get-ADConditionalFieldBranches` extractor (the build script) that recognizes this `if/else`-two-literal-branches shape and pairs each field's branches positionally with `Issue`'s own branches, producing two correctly-paired library entries. Audited the rest of the codebase for the same pattern (a full source scan for every `EstimatedEffort`/`KnownRisks`/`BackupRollback`/`OperationalNotes` assignment that isn't a plain string literal) - this was the only occurrence. Verified end-to-end: recreating a report from an old export with either variant of this finding now backfills the correct, distinct text for that variant. (The remediation-numbering bug itself - conditional steps rendering as blank numbered lines - was already fixed in the current live-generation code; only the *offline backfill* for pre-existing stale exports was the remaining gap.)
- A coverage sidecar, once round-tripped through `Get-ADTestCoverageSidecar`, could come back as ONE entry whose `TestName`/`Status`/`FindingCount`/`ErrorMessage` were each arrays instead of N separate entries ("columnar" shape) - reported as the HTML report showing "1 check(s) tracked" while the per-check table crammed every test name, finding count, and status badge into a single row/cell, and the CSV rebuild's `-coverage.csv` writing the literal string `"System.Object[]"` into every column. Confirmed the exact rendering mechanism directly: string interpolation of an array value space-joins its elements (explaining the crammed-together test names/finding counts), and PowerShell's `switch` statement, given a collection rather than a scalar as its test value, evaluates every element independently and accumulates every match's output (explaining why N separately-styled status badges all appeared in one cell). The columnar shape itself was not reproducible from a normal Main.ps1 write + `ConvertFrom-Json` read round-trip in this module's tested PowerShell version, so it may be specific to Windows PowerShell 5.1's JSON handling or another environment difference. Fixed defensively regardless of root cause: new `ConvertTo-ADNormalizedTestCoverage` (`Common.ps1`) detects the columnar shape (checking all four properties, not just `TestName`, in case a different malformation only affects some of them) and un-transposes it back into one entry per check, wired into `Get-ADTestCoverageSidecar` (covering both the HTML and CSV rebuild paths) and defensively into `Export-ADSecurityReportHTML` itself; a no-op for the normal, already-correctly-shaped case. Also added a second safety net directly in the HTML render: if `Sort-Object` ever produces zero usable rows despite non-empty coverage data (a different, narrower failure mode than the columnar one - e.g. genuine `$null` array elements, which `Sort-Object` silently drops), the report now shows an explicit "could not be rendered" diagnostic naming the real entry count, instead of a table with just a header row and no data (which would look identical to "nothing to report" and hide that something went wrong). Verified directly against reproductions of both the columnar-shape symptom and the empty-after-sort case.
- `Set-ADFindingMetadata`'s `-Finding` parameter was typed `[ADSecurityFinding]`; passing it a JSON-deserialized `PSCustomObject` (as both JSON-recreate paths do) silently tagged a throwaway converted copy and discarded it, so a finding missing MITRE/ANSSI/Weight metadata scored 0 instead of its real weight when a report/score was recreated from an older export - with no error of any kind. Fixed via an untyped parameter plus a new `Set-ADFindingProperty` helper (`Common.ps1`) that mutates in place regardless of object shape, including the case where the property doesn't exist on the object at all.
- `DetectedDate.ToString(...)` threw when `DetectedDate` was missing from an older export (visible console error, while the field itself silently rendered blank regardless). New `Format-ADFindingDetectedDate` helper.
- New `src/FindingNarrativeLibrary.ps1` + `Merge-ADFindingNarrativeGaps` backfill `EstimatedEffort`/`KnownRisks`/`BackupRollback`/`OperationalNotes` on findings loaded from an export that predates those fields, using current guidance mechanically extracted from source (`tools/Build-ADFindingNarrativeLibrary.ps1`) - never overwrites real data, only fills genuinely blank fields. Guarded against drifting from its own source of truth by `tests/FindingNarrativeLibrary.Tests.ps1`, which regenerates the library and asserts it's byte-identical to the checked-in copy.
- **General PowerShell bug found while testing the coverage-awareness features above, affecting 6 call sites**: `ConvertTo-ADFlatFindingsArray`'s result can silently collapse to a real `$null` (not an empty array) across a function-call boundary whenever it's empty - a fundamental PowerShell behavior (a function that outputs zero objects produces "nothing" on the pipeline, which a plain variable assignment sees as `$null`), not fixable inside the function itself. This then failed `Get-ADRiskScore`'s `Mandatory`+`[AllowEmptyCollection()]` `-Findings` parameter with "Cannot bind argument... because it is null" for any genuinely-empty (all findings resolved) run. Fixed by wrapping every call site in `@(...)` (`Main.ps1`, `Reporting.ps1` x2, `RetestComparison.ps1` x2, and the self-call inside `Get-ADRiskScore` itself in `Scoring.ps1`); documented as a hard requirement in `ConvertTo-ADFlatFindingsArray`'s own docs so a future new call site doesn't reintroduce it.
- **`Export-ADSecurityReportCSVFromJson` was defined but never exported** - present in `Reporting.ps1` but missing from both `ADSecurityAudit.psd1`'s `FunctionsToExport` and `ADSecurityAudit.psm1`'s `Export-ModuleMember` list, so it was invisible after `Import-Module` (no tab-completion, no `Get-Help`, "not recognized" if called directly). Added to both.
- **`-OutputPath` on both `Export-ADSecurityReportHTMLFromJson` and `Export-ADSecurityReportCSVFromJson` now accepts a folder, not just an exact file path** - matching `-FindingsPath`/`-BaselinePath`/`-RetestPath` already accepting either. New shared `Resolve-ADRebuiltReportOutputPath` (`Common.ps1`) treats `-OutputPath` as a folder when it already exists as a directory, or has no file extension at all (creating it if needed), and auto-names the file `AD_Security_Audit_<timestamp>-recreated.<ext>` inside it - timestamp matched to the findings export being rebuilt from. Deliberately NOT the same filename a live run would use for that timestamp, so pointing this at the same folder the original report already lives in can't silently overwrite it (verified directly: an original same-timestamp `.html`/`.csv` survives untouched). An explicit path with a file extension is still honored exactly as given, unchanged from prior behavior.
- **`Export-ADSecurityReportHTML` itself was also missing from both export lists** - found during a full audit of every function defined in `src/*.ps1` against both export lists (prompted by the `Export-ADSecurityReportCSVFromJson` gap above). Every sibling `Export-AD*HTML` function (`Export-ADRetestComparisonHTML`, `Export-ADMaturityTrendHTML`, `Export-ADForestConsolidationHTML`) was already exported; this one, the core report renderer, was not. Added to both lists. (Everything else found unexported in that audit was confirmed to be a genuine internal helper, consistent with the existing pattern for `ConvertTo-ADFlatFindingsArray`/`Get-ADFindingMatchKey`/etc.)
- **`-FromSnapshot` mode never tracked test coverage at all, and rendered a nonsensical "0 check(s) tracked" box on every offline report.** `-FromSnapshot` dispatches tests through `Invoke-ADRuleSet`, a completely separate code path from `Main.ps1`'s live test loop (the one Test Coverage tracking was originally built for) - `$testCoverage` was only ever assigned in the live-mode branch, so it was an undefined variable (silently `$null`) by the time the shared HTML-export call at the end of `Start-ADSecurityAudit` referenced it. That `$null` then hit the documented `@($null)`-has-Count-1 quirk (see `ConvertTo-ADFlatFindingsArray`'s docs): the Test Coverage section's gate came out true while its actual per-row data (built via `Sort-Object`, which silently drops a `$null` element) came out empty, rendering "0 check(s) tracked: 0 passed clean, 0 found issue(s), and 0 untested" on every single `-FromSnapshot` report regardless of what actually ran. Fixed with a new tracker (`Add-ADTestCoverageEntry`/`Get-ADTestCoverageTracker`/`Reset-ADTestCoverageTracker` in `Common.ps1`, mirroring the existing Offline-Skip-Notes pattern) that `Invoke-ADRuleSet` now populates per-test (`Completed`/`Failed`/`Excluded`, including both `-IncludeTests`/`-ExcludeTests` filtering and the "no `-Snapshot` support yet" skip path), read back by `Main.ps1`'s `-FromSnapshot` branch into `$testCoverage`. Verified end-to-end with a 5-test fixture covering all four outcomes - the HTML report now correctly reads "5 check(s) tracked: 0 passed clean, 1 found issue(s), and 3 untested (1 failed, 2 excluded)" instead of the broken zero-state.
- New Pester coverage: `tests/RetestComparison.Tests.ps1` (Excluded/Failed/Completed/no-coverage-data cases for `UnconfirmedFindings` reclassification, plus HTML rendering), `tests/MaturityTrend.Tests.ps1` (incomplete coverage, no-coverage-data, all-fully-covered, and HTML rendering), `tests/ForestConsolidation.Tests.ps1` (per-domain coverage flagging and HTML rendering), `tests/InvokeADRuleSet.Tests.ps1` (new - all four `-FromSnapshot` coverage-tracking outcomes plus the HTML rendering regression), plus new cases in `tests/ReportingFromJson.Tests.ps1`/`tests/ReportingCSVFromJson.Tests.ps1` for the folder-`-OutputPath` behavior (existing folder, not-yet-created folder, no-overwrite, and exact-path-still-honored).
- **The Test Coverage section's full per-check list is now collapsed by default (expandable on click)**, rendered as a `<details>`/`<summary>` element instead of a plain always-expanded box - it's a large chunk of content near the top of the report, and the summary line (N tracked, passed-clean/found-issues/untested counts) already gives the at-a-glance answer without needing the full table visible. The counts summary stays visible either way; only the per-check table itself is hidden until expanded.
- **Added explicit `-FindingsPath`/`-OutputPath` usage examples for `Export-ADSecurityReportHTMLFromJson` and `Export-ADSecurityReportCSVFromJson` to the README** (both the exact-file-path and folder-form calling styles), alongside the existing function-level `.EXAMPLE` help text.
- **Duplicate findings from repeated ACEs on the same trustee.** A lab run against a real (if messy) 4-DC domain surfaced that 74 of 262 exported findings (28%) were exact duplicates - same Category, Issue, AffectedObject, and Description - almost all from a single AdminSDHolder ACL where one trustee held 18 separate but rights-identical ACEs. Real AD ACLs commonly carry more than one ACE per trustee (one per property set/object type) even when the summarized `ActiveDirectoryRights` flag is identical; five ACE-iterating checks across four modules created one finding per raw ACE instead of deduplicating: `Test-AdminSDHolder` (`AdminSDAudits.ps1`, both the "Non-Standard Permissions" and "Deny ACE" checks, both snapshot and live branches), `Test-ADDomainAdminEquivalence`'s "AdminSDHolder ACL Compromise" check (`DomainAdminEquivalence.ps1`, both branches), `Test-ADExchangeEscalation`'s domain-root and AdminSDHolder checks (`ExchangeEscalationAudits.ps1`), and `Test-ADReplicationSecurity`'s DCSync check (`ReplicationAudits.ps1`, both branches). Fixed by deduplicating on `(identity, rights[, access type])` before creating a finding, so a trustee with N functionally-identical ACEs is reported once, not N times; a trustee genuinely holding two *different* specific rights (e.g. two different DCSync extended rights via different ObjectType GUIDs) still produces separate findings, since that's real, distinct information rather than a duplicate ACE. This also directly affects the risk score and maturity rating - the same lab run's AdminSDHolder category scored 100/100 (worst possible) and contributed 58 of the run's 94 Critical findings almost entirely from this inflation, not from 58 genuinely distinct issues. New `tests/DuplicateAceFindingDedup.Tests.ps1` covers all four modules, including a case confirming genuinely-different rights are NOT collapsed.
- **`Test-ADKerberosHardening`'s RC4 account check silently found nothing for every Tier-0 principal in the same lab run.** The live-mode check preferred each principal's SID over its DistinguishedName when calling `Get-ADObject`; all 8 of 8 SID-based lookups failed with "Cannot find an object with identity: '\<SID\>'" while the exact same objects resolved fine by DistinguishedName elsewhere in the same run (only two retries per principal, each silently caught and logged as `Write-Verbose`/`Write-Warning`, so the check appeared to complete cleanly with zero RC4 findings rather than visibly failing). Fixed by preferring DistinguishedName (always unambiguous for a specific object) and falling back to SID only when no DistinguishedName is available. New `tests/KerberosHardeningIdentityResolution.Tests.ps1` reproduces the exact SID-rejection failure mode and confirms the check still detects an RC4-permitted account via the DN fallback.
- **`Test-ADDnsSecurity`'s delegation-staleness check produced a malformed, doubled zone name** (`_msdcs.ad.local..ad.local` observed live) whenever `Get-DnsServerZoneDelegation` returned a child zone name with a trailing root dot (a normal DNS FQDN convention). The "is this already fully-qualified" regex match required the name to end in exactly `.$zoneName`, which a trailing dot broke, so the code fell through to appending `$zoneName` again onto an already-qualified name. Fixed by trimming the trailing dot before the match/concatenation. New regression case added to `tests/DnsSecurityAudits.Tests.ps1`.
- **Follow-up duplicate-finding sweep, prompted by a second lab run**: re-running against a fixed build dropped duplicates from 74 to 1 - but that one remaining case (two ACEs granting the same trustee two genuinely *different* specific DCSync rights) revealed the fix needed to go further than per-ACE dedup. A proactive audit of every ACE-consuming check in the codebase (not just the ones that happened to fire in either lab run) found the same "one finding/one bullet per raw ACE" pattern in several more places:
  - **`DomainAdminEquivalence.ps1`'s shared `Add-Evidence`/`Add-SnapshotEvidence` helpers had no dedup at all.** These back six separate ACE-iterating sub-checks (Shadow Credentials on computers, Shadow Credentials on privileged users, WriteSPN, and Domain Root/AdminSDHolder/DC-OU direct control), all feeding into one aggregated "Domain Admin Equivalent Access Detected" finding per principal. This is very likely the single largest contributor to the original 74-duplicate count: a principal with two ACEs on the same target produced the identical evidence bullet (e.g. "Domain Root control via GenericAll") twice inside one finding's Description, not two separate findings, so the original whole-finding-text duplicate scan undercounted this class of duplication. Fixed by deduplicating on `(Principal, Reason)` inside the shared helper - single fix point, covers all six call sites in both snapshot and live modes.
  - **`PermissionsAudits.ps1`**: the Enterprise Key Admins over-privilege checks (both "Over-Privileged" and "Not Scoped" sub-findings), the critical-OU sweep ("Dangerous Rights on Critical OU"), and the Schema/Configuration NC ACL check all had the same per-ACE duplication risk, in both snapshot and live branches (6 locations total).
  - **`CertificateServicesAudits.ps1`**: "Overly Permissive CA Permissions (ESC7)" and "Low-Privilege CA Management Rights" could each fire more than once for the same CA/principal/right if the CA's ACL had more than one qualifying ACE (both snapshot and live branches); also deduplicated the low-privilege enrollment-principal list built per certificate template (`Test-ADCertificateServices`'s ESC1/ESC3 findings), which could otherwise name the same principal twice in one finding's text.
  - **`CertificateServicesExtendedAudits.ps1`**: the same principal-list duplication in the ESC4 weak-ACL finding's aggregated "principal (rights)" bullet list.
  - **`GpoAudits.ps1`**: "Insecure SYSVOL Permissions" had the equivalent risk on the filesystem ACL side (NTFS ACEs, not AD ACEs) - the same principal can appear in more than one ACE with different inheritance-flag scopes but the same effective `FileSystemRights`.
  - Reviewed and confirmed **not** affected, by design: `ControlPaths.ps1`'s attack-path graph (`Get-ADControlPathGraph`/`Test-ADControlPaths`) builds one finding per unique source principal via a visited-node-tracked BFS, and derives "Owner" edges from a single-valued Owner field per object - both structurally immune to the duplicate-ACE class of bug even though `Add-ADControlPathEdge` itself doesn't dedupe.
  - **`Test-ADReplicationSecurity`'s DCSync check went further than per-ACE dedup**: rather than only deduplicating identical ACEs, it now aggregates ALL rights a given identity holds across every one of its ACEs into one finding (matching how a single `GenericAll` ACE already aggregated all three DCSync rights at once) - so two ACEs each granting a different specific right (e.g. `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` via separate ACEs) now correctly produce ONE finding naming both rights, rather than two findings with an identical generic Description that looked like an exact duplicate. The specific rights are now also named in the top-level Description text, not just `Details.Rights`, for the same reason (see the next item).
  - **Confirmed a real "sub-finding gets lost in the flat report view" gap, and fixed the one instance found**: `Test-ADDnsSecurity`'s "Stale/Dangling DNS Zone Delegation" finding's per-delegation detail (which specific NameServer/glue IP is actually stale) previously lived ONLY in `Details.StaleDelegations` - `Get-FindingHTML` (`Reporting.ps1`) never renders the raw `Details` object except for a few named Attack-Paths-specific keys, so a reader of the HTML report saw a zone-name list and a count with no way to find the actual record to fix without opening the JSON. Now enumerated as bullets in the Description, matching the existing convention used by the Domain Admin Equivalence evidence list and the ESC4 weak-ACL finding (both of which already put their per-item detail in Description, not Details-only). Audited every other multi-item `Details` array in the codebase (`PerDomainControllerState`/`PerDomainControllerResults`, `Evidence`) and confirmed each already has its per-item detail surfaced in Description via the same bullet convention, or (for `PerDomainControllerState`) is genuinely supplementary per-DC diagnostic detail rather than a distinct finding a reader would need to act on separately.
  - Separately confirmed the CSV export is not affected by any of the above: `ConvertTo-ADFindingsCsvRows` (`Common.ps1`) serializes the entire `Details` object to compact JSON (`-Depth 5`) regardless of shape, so nested arrays like `Evidence`/`StaleDelegations`/`PerDomainControllerState` are fully preserved in the CSV's `Details` column even though the HTML report doesn't render them directly.
  - New/updated Pester coverage: `tests/DuplicateAceFindingDedup.Tests.ps1` gained a `Test-ADDomainAdminEquivalence` case for the `Add-Evidence` dedup fix, and its DCSync-aggregation test was rewritten to assert the new one-finding-with-both-rights behavior instead of the old two-findings expectation.
- **New: three tiered `tests/fixtures/ForcedFail-*pct-Snapshot.json` fixtures** (100%/60%/25% of the 23 -Snapshot-capable checks deliberately misconfigured; 5 of the 28 registered checks always return zero findings under `-FromSnapshot` by design regardless of fixture data - see `tests/fixtures/README.md`) - hand-authored, entirely synthetic `-FromSnapshot` fixtures (fake domain `contoso.local`, no real environment/identities) that exercise the full pipeline (every check, scoring, JSON/CSV/HTML/TestCoverage export) end-to-end with no live AD access at all. Generated from one parameterized script, `tools/build-forcedfail-fixtures.py` (a Python maintainer utility, not part of the PowerShell module itself), so all three stay consistent as checks change. The 100%-tier fixture deliberately includes several repeated ACEs/evidence entries shaped to reproduce the exact duplicate-finding bugs fixed in v1.24.0/v1.24.1, so a future regression of that bug class shows up immediately. Run via `tools/Test-ForcedFailFixture.ps1 -Tier <100|60|25>` (drops real report output for manual review) or `tests/ForcedFailFixture.Tests.ps1` (Pester smoke test asserting tier ordering, the specific dedup cases, and overall pipeline health across all three). See `tests/fixtures/README.md` for what each tier covers, what's structurally impossible to cover under any snapshot fixture (and why), and - importantly - a maintenance checklist: these fixtures should be revisited whenever a check's detection logic changes meaningfully, the same way they were built directly from this session's lab-run findings.

## [1.23.9] - 2026-08-23
### Added
- **New "Run Scope Information" report section (and console notice) whenever `-Server` names an explicit, specific Domain Controller that is NOT the domain's actual PDC Emulator.** This module's "PDC-only" checks (`Test-ADMachineAccountQuota`, `Test-ADDomainSecurity`) correctly still ran and returned real answers in this scenario - a domain/forest-wide attribute is readable from any DC - but gave no indication that they queried the named DC directly instead of the PDC, which a reader could reasonably assume never happens for a check documented as "PDC-only". Requested directly: a check that effectively runs against a different target than its documented assumption should be communicated, not left implicit.
- New mechanism in `Common.ps1`, parallel to but distinct from the existing offline-skip-notes tracker: `Add-ADRunScopeNote` / `Get-ADRunScopeNotes` / `Reset-ADRunScopeNotes`. Populated directly inside `Resolve-ADSecurityAuditTargetServer`, at the exact point it already distinguishes an explicit DC from a domain name resolved to the PDC - the one place in the codebase that already has both the named DC and, cheaply, the domain's real PDC in hand.
- `Get-ADSnapshot` persists any notes recorded during collection into `Snapshot.RunScopeNotes`, so a later `-FromSnapshot` analysis (which performs no live resolution of its own) still surfaces a scoping condition that was true at collection time. `Start-ADSecurityAudit` merges live-run notes with any carried snapshot notes (de-duplicated by message).
- `Export-ADSecurityReportHTML` gained a `-RunScopeNotes` parameter and renders the new section for both live and offline runs, unlike the existing "Offline Mode Coverage Notes" box which only ever applies to `-FromSnapshot` runs.
- New Pester coverage: `tests/RunScopeNotes.Tests.ps1`.

## [1.23.8] - 2026-08-23
### Fixed
- **`Test-ADStaleObjectDepth`'s `Insufficient Domain Controller Count` finding undercounted the domain's true DC total whenever `-Server` named one specific DC.** The check reused the same `-Server`-scoped `$domainControllers` list that the DC subnet/site-registration probe correctly narrows to just the named DC. A redundancy assessment of the whole domain has no business being narrowed this way, so a domain with 5 DCs would report "only 1 Domain Controller" the moment an operator pointed `-Server` at one of them.
- **Same root cause also caused false-positive `Non-Default primaryGroupID (Membership Hiding)` findings against real Domain Controllers.** The primaryGroupID=516 legitimacy check used the same narrowed list to decide which computer objects are legitimately DCs; any real DC excluded from that narrowed list was misclassified as a suspicious non-DC object holding primaryGroupID 516.
- Fix: `Get-ADSecurityAuditDomainController` (`Common.ps1`) gained a new `-IgnoreExplicitDCScope` switch — it still uses the resolved `-Server` value as the query target, but always returns every DC in the resolved domain rather than narrowing to one named DC. `Test-ADStaleObjectDepth` now collects a second, always-unscoped DC inventory via this switch for both the count check and the primaryGroupID legitimacy check, while the existing scoped list continues to correctly narrow the subnet/site-registration probe itself. `Get-ADSnapshot` gained matching `TotalDomainControllerCount`/`AllDomainControllerComputerObjectDNs` fields so a snapshot collected with `-Server` narrowed to one DC still preserves accurate data for `-FromSnapshot` re-analysis; older snapshots fall back to the previous (possibly-narrowed) behavior with a Verbose accuracy note.
- Also fixed: `Get-ADTargetDomainController` (used by `Test-ADDnsSecurity` and other single-DC-only live probes) picked the first DC in enumeration order rather than deterministically preferring the domain's PDC Emulator when the target was a domain name — harmless in practice (AD-integrated DNS/LDAP state is identical DC to DC) but inconsistent with the module's "PDC-only checks use the domain's actual PDC" convention. Now explicitly resolves and prefers the PDC; an explicit specific DC named via `-Server` is still honored exactly as given.
- Documentation only, no logic change: `Test-ADMachineAccountQuota` and `Test-ADDomainSecurity` now explicitly document why they make a single domain/forest-wide query rather than enumerating DCs — both already correctly implement the module's `-Server` contract via `Resolve-ADSecurityAuditTargetServer`.
- Verified by code trace, unchanged: `Test-ADRodcSecurity`, `Test-AuditPolicyConfiguration`, `Test-ADDomainHardeningFlags`, `Get-ADControlPathGraph`/`Test-ADControlPaths`, `Test-ADKerberosHardening`, and `Test-ADLegacyAuthSurface` already correctly implement the three-mode `-Server`/DC-enumeration contract via the existing `Get-ADSecurityAuditDomainController` + `Get-ADSecurityAuditServerIsExplicitDC` mechanism. Re-verified with a second, deeper pass through each function's actual per-DC threshold/consensus logic (not just the enumeration call site) specifically hunting for the same "domain total vs. scoped set" confusion that caused the two bugs above - every ratio/threshold found (e.g. `Test-ADKerberosHardening`'s FAST-armoring consensus check) compares "of what was actually tested" against itself, never against an independently-assumed domain total, so none is susceptible to the same bug class. Added `tests/RodcSecurityAudits.Tests.ps1` to lock in the one genuinely novel, previously-untested interaction found during this pass: a non-default `-Filter` (RODC-only) combined with an explicit-DC `-Server` override, including the "explicit DC is a writable DC, not an RODC" edge case (clean zero-findings exit, not a false "domain has no RODCs" claim).

## [1.23.7] - 2026-08-23
### Added
- **Closed the four forest/forest-root coverage gaps identified in the forest-level finding coverage review.** `Test-ADDomainSecurity` gained two new findings: `Outdated Forest Functional Level` (previously the forest mode was only ever surfaced as a `Details` sidecar under the domain-level `Outdated Domain Functional Level` finding, so a stale forest FL behind a current-looking domain FL never fired on its own — now checked against the same deprecated-levels list, with Impact text citing the AD Recycle Bin's Windows Server 2008 R2 forest-mode requirement and PAM's Windows Server 2016 requirement, both re-verified against current Microsoft documentation) and `Short Tombstone Lifetime` (flags forest `tombstoneLifetime` below 180 days; an unset attribute is correctly treated as its [MS-ADTS]-specified 60-day default rather than "no value to report", and the 180-day default is documented as applying to forests created with Windows Server 2003 SP1 or later installation media, not simply any forest running a newer OS). `Test-ADDangerousPermissions` gained two new Critical findings: `Non-Standard Permissions on Schema Naming Context` and `Non-Standard Permissions on Configuration Naming Context`, both using the same allowlist-based ACE review already established for AdminSDHolder and the critical-OU sweep (SYSTEM/Domain Admins/Enterprise Admins/BUILTIN\Administrators accepted, Schema Admins additionally accepted for the Schema NC). The Configuration NC check is deliberately scoped to the head object only — narrower than, and independent of, the existing Public Key Services container check — with Impact text that names the NC's forest-wide replication scope and contents but stops short of asserting a specific downstream attack chain, since that depends on inheritance behavior that varies by environment. All four findings are fully offline-capable: `Get-ADSnapshot` gained a new `TombstoneLifetimeDays` scalar and two new ACL-collection targets (`SchemaNamingContext`, `ConfigurationNamingContext`). New `Scoring.ps1` entries: `Outdated Forest Functional Level` (`T1078.002`, `vuln4_outdated_ffl`, Weight 4, matching the domain-level entry), `Short Tombstone Lifetime` (no MITRE technique — a recoverability/hygiene parameter, not an attack technique; `vuln5_short_tombstone_lifetime`, Weight 1, matching `AD Recycle Bin Not Enabled`), and both new ACL findings (`T1098`, `vuln1_schema_nc_acl` / `vuln1_config_nc_acl`, Weight 40, matching the existing AdminSDHolder ACL-abuse entry).

## [1.23.6] - 2026-08-23
### Added
- **New check: `Test-ADCSChaseFallback` detects CA chase-fallback exposure (CVE-2026-54121 / "Certighost").** Reads each discovered Enterprise CA's `policy\EditFlags` registry value for the `EDITF_ENABLECHASECLIENTDC` bit (`0x00100000`), which enables the CA's client-DC ("chase") fallback during certificate-request identity resolution. On an unpatched CA, this lets an authenticated, low-privileged attacker with network access supply a client-DC hint pointing at an attacker-controlled host, causing the CA to issue a certificate asserting that host as a Domain Controller - enabling DC impersonation and DCSync-class domain compromise (CVE-2026-54121, CVSS 8.8, patched by Microsoft on July 14, 2026). The finding fires at Critical severity whenever the flag is set, independent of whether the July patch is installed: the patch adds chase-target validation but does not clear the flag, so a patched CA with the flag still set remains configured in the historically risky state and can become exploitable again if the flag is re-enabled later (policy, imaging, or admin action). Remediation cites both the Microsoft patch and the `certutil -setreg policy\EditFlags -EDITF_ENABLECHASECLIENTDC` stopgap mitigation. Detection-only: reads one registry value per discovered CA via the same remote-`Invoke-Command` pattern already used for the ESC8 web-enrollment probe; no certificate requests, PoC/exploitation traffic, or coercion of any kind. Live-only (registry state on the CA host has no snapshot/AD-attribute representation, same as ESC8) - skipped under `-Snapshot` with an offline-coverage note, same as `Test-ADCSExtended`'s ESC8 check. Registered as a new top-level `ADCSChaseFallback` test (`src/CertificateServicesExtendedAudits.ps1`, sibling function to `Test-ADCSExtended` rather than folded into it, since that function was already ~700 lines). New `Scoring.ps1` mapping entry: `T1649` (Steal or Forge Authentication Certificates, consistent with every other AD CS finding in this module), `vuln1_adcs_certighost_chase`, Weight 40 (matching other Critical/direct-domain-compromise findings).

## [1.23.5] - 2026-08-21
### Fixed
- **Every per-DC probe (`Test-AuditPolicyConfiguration` reported, but the same shared helper is used by 12 call sites) still enumerated and interrogated EVERY Domain Controller in the domain even when `-Server` named one specific, explicit DC.** `Get-ADSecurityAuditDomainController` (`Common.ps1`) always resolved the target domain from `-Server` and then did a domain-wide `Get-ADDomainController -Filter *` enumeration, with no distinction between "a domain name was given, enumerate every DC" and "one specific DC was already named, scope to only that DC." An operator who names a specific DC very often does so because it's the only one reachable/in-scope for the engagement (a segmented network, explicit rules of engagement) - every per-DC check (`Test-AuditPolicyConfiguration`, `Test-ADCoercionAndRelayExposure`, `Test-ADControlPaths`/`Get-ADControlPathGraph`, the anonymous-bind and null-session checks in `Test-ADDomainHardeningFlags`, both DC-enumeration points in `Test-ADKerberosHardening`, `Test-ADKnownDCVulnerabilities`, `Test-ADLegacyAuthSurface`, `Start-ADSecurityAudit`'s own DC connectivity check, `Test-ADRodcSecurity`, `Get-ADSnapshot`, `Test-ADStaleObjectDepth`) would still attempt every OTHER DC in the domain too, generating failures/noise against DCs that were never meant to be touched and defeating the entire point of naming one specific DC. Because the resolved `-Server` string alone can't distinguish "operator named this DC" from "a domain name got resolved down to one DC (the PDC Emulator) as a deterministic pick" (see the v1.23.4 fix to `Resolve-ADSecurityAuditTargetServer`), a new `Get-ADSecurityAuditServerIsExplicitDC` flag (set by `Resolve-ADSecurityAuditTargetServer`, cleared by `Clear-ADSecurityAuditTargetServer`) now carries that distinction forward explicitly. `Get-ADSecurityAuditDomainController` checks it and, when true, resolves and returns ONLY the named DC - still honoring a non-default `-Filter` (e.g. the RODC-only filter) by checking that one DC's own membership in the filtered result set, since `-Filter` and `-Identity` are mutually exclusive parameter sets on `Get-ADDomainController`. A domain name (explicit or defaulted) is unaffected and still enumerates every DC in the domain exactly as before - this was an intentional, separate fix (v1.23.3) for catching a partially-hardened DC fleet and must not be narrowed. Added Pester coverage for both the single-DC-scoping behavior and the filter-match/non-match cases, and confirmed via `grep` that no other file duplicates this enumeration logic outside the one shared helper.

## [1.23.4] - 2026-08-21
### Fixed
- **`-Server` given as a SPECIFIC Domain Controller was silently redirected to that domain's PDC Emulator instead - a different DC than the one requested.** `Resolve-ADSecurityAuditTargetServer` (`Common.ps1`) always resolved whatever value it received (explicit `-Server`, or the `$env:USERDNSDOMAIN` default) one further step to the target domain's PDC Emulator, with no distinction between "a domain name was given, please pick one well-defined DC" and "a specific DC was already named, use that one." This broke a legitimate case introduced by the same v1.23.3 default-domain/PDC-resolution feature: an operator whose engagement only has access to one particular DC (a segmented network, explicit rules of engagement, a specific DC being tested) who passes e.g. `-Server dc02.corp.com` had every query in the run silently redirected to `dc01` (the PDC Emulator) instead - which may not even be reachable, defeating the purpose of naming a specific DC. Since this helper is the single, shared resolution point behind every `-Server` parameter in the module (`Start-ADSecurityAudit`, `Get-ADSnapshot`, `Test-ADMachineAccountQuota`, and every other function's own `-Server`), the bug applied module-wide, not just to the function it was first reported against. Fixed by checking the requested value against `Get-ADDomainController -Identity` first - which only succeeds for a real DC's own GUID/Name/IPv4Address/DNS host name, not a bare domain FQDN (the same distinction `Get-ADTargetDomainController` already relies on) - and returning it unchanged when it is already a specific DC, instead of substituting the PDC Emulator for it. A domain name (explicit or defaulted) is unaffected and still resolves to the PDC Emulator exactly as before. Added Pester coverage asserting a specific-DC `-Server` value is returned as-is and never triggers a `Get-ADDomain` call at all.

## [1.23.3] - 2026-08-21
### Fixed
- **Every remaining `Get-AD*`/`Get-GP*` call in the codebase now explicitly
  passes `-Server`, rather than relying solely on the
  `$PSDefaultParameterValues` global default.** This was completed by
  reconciling a patch from [denandz](https://github.com/denandz) (which
  independently discovered and fixed
  the same class of issue via a `Get-ADSecurityAuditTargetServerValue`
  helper - now a permanent alias for this module's existing
  `Get-ADSecurityAuditActiveServerOverride`, so code written against either
  name works) against the fixes already in this file, merging rather than
  reapplying so the SYSVOL DFS-referral fix, the `nTSecurityDescriptor`
  ACL-read conversion, the `-SearchScope OneLevel` container-exclusion fix,
  and the Enterprise Admins/Schema Admins forest-root handling were
  preserved rather than regressed. Several more genuine gaps were found
  during three successive verification sweeps of the merged result:
  `RodcSecurityAudits.ps1`'s RODC filter, `Snapshot.ps1`'s `Get-GPO`/
  `Get-GPPermission`/Pre-Windows-2000-members calls, `LegacyAuthAudits.ps1`'s
  own domain/DC-enumeration calls (only its two shared GPO-reading helpers
  had been fixed previously), `KerberosHardeningAudits.ps1`'s krbtgt and
  per-Tier-0-principal lookups, and three `Get-ADRootDSEValue` callers that
  weren't passing `-Server` through to that helper. `Get-ADTier0Principal`
  (`Common.ps1`) was also found to share the Enterprise Admins/Schema
  Admins forest-root-only-group gap already fixed in `Test-ADPrivilegedGroups`
  and was fixed the same way, since it feeds the Kerberos RC4/FAST checks.
- **Documented the underlying lesson directly in the code, not just here**:
  `Get-ADSecurityAuditActiveServerOverride`'s doc-comment in `Common.ps1`
  now carries a `MANDATORY PATTERN` note explaining that the global
  `$PSDefaultParameterValues` default *should* auto-supply `-Server` to
  every matching cmdlet call (the wildcard matching logic is correct
  PowerShell) but was observed not to be reliably picked up in practice;
  every new `Get-AD*`/`Set-AD*`/`Get-GP*`/`Set-GP*` call added to this
  module going forward must explicitly pass `-Server`, not depend on the
  global default alone.
- **Null-safety of the `-Server` value itself was verified, not assumed**:
  `Set-ADSecurityAuditTargetServer`'s `-Server` parameter carries
  `[ValidateNotNullOrEmpty()]`, so every value flowing through
  `Get-ADSecurityAuditActiveServerOverride`/`Get-ADSecurityAuditTargetServerValue`
  is guaranteed to be either a genuine, non-empty server name or a clean
  `$null` - never an empty string that could cause ambiguous cmdlet
  behavior. This module's own helper functions
  (`Get-ADRootDSEValue`, `Get-ADSecurityAuditDomainController`,
  `Get-ADTargetDomainController`) already used conditional splatting
  internally and are safe regardless of what's passed in. Passing an
  explicit `-Server $null` to the underlying `Get-AD*`/`Get-GP*` cmdlets
  themselves is the standard PowerShell idiom for optional
  connection-targeting parameters and is expected to behave identically to
  omitting `-Server` entirely, though this specific point rests on
  well-established convention rather than direct execution in this
  environment - worth keeping in mind if anything unexpected surfaces in
  testing.
- **Certificate template (ESC4) and CA object (ESC7) ACL reads used
  `Get-Acl -Path "AD:$dn"`, which has NO `-Server` parameter at all** and
  reads via the built-in `AD:` PSDrive's own ambient default domain/DC -
  completely bypassing `Set-ADSecurityAuditTargetServer`'s override,
  regardless of every other fix in this file. Affected
  `Test-ADCertificateServices`, `Test-ADCSExtended`, and
  `Get-ADSnapshot`'s ADCS collection (baking the wrong domain's ACL data
  permanently into snapshots too). `Test-AdminSDHolder`,
  `Test-ADDangerousPermissions`, and `Get-ADControlPathGraph` were
  already reading ACLs correctly, via `Get-ADObject -Properties
  nTSecurityDescriptor` (a real `Get-AD*` cmdlet, which IS `-Server`-
  aware and returns the identical `ActiveDirectorySecurity`/`.Access`
  object shape `Get-Acl` does) - used as the template for this fix at all
  five affected call sites.
- **SYSVOL UNC paths (`Test-ADGroupPolicies`'s permission check,
  `Test-ADGpoDeployedSecrets`'s policy root) were built from the bare
  domain DNS name** (`\\domain.tld\SYSVOL\...`), which is resolved via
  DFS Namespace referral - the same "closest DC to the calling machine,
  not necessarily the domain being audited" ambiguity DC-locator has for
  AD queries. `Get-Acl` on a UNC path has no `-Server` parameter to fix
  this with; the only fix is putting the resolved DC directly in the
  path. Both now use the active `-Server` override for the UNC path's
  server component (falling back to the domain DNS name, exactly as
  before, when no override is set).
- **GPO-related checks were completely unscoped by `-Server` this entire
  time - a separate, previously-undiscovered gap from everything else in
  this section.** `Set-ADSecurityAuditTargetServer` only ever installed a
  `$PSDefaultParameterValues` wildcard for `Get-AD*`/`Set-AD*`/`New-AD*`/
  `Remove-AD*` (the ActiveDirectory module). The GroupPolicy module's
  cmdlets - `Get-GPO`, `Get-GPInheritance`, `Get-GPPermission`,
  `Get-GPRegistryValue` - start with `Get-GP`, not `Get-AD`, so that
  wildcard **never matched them, at all, regardless of whether an
  override was active for AD cmdlets.** Every GPO-consuming check
  (`Test-ADGroupPolicies`, `Test-ADLegacyAuthSurface`'s and
  `Test-ADDomainHardeningFlags`'s and `Test-ADKerberosHardening`'s shared
  `Get-ADLinkedGposOrdered`/`Get-ADPolicyRegistryValue` helpers, and
  `Get-ADSnapshot`'s GPO collection) has been silently reading GPOs from
  whatever domain the GroupPolicy module's own default resolution picked
  - the machine's own joined domain, in the classic multi-domain-forest
  scenario - even when `-Server` was correctly set and honored for every
  AD cmdlet in the same run. Fixed by installing the equivalent
  `Get-GP*`/`Set-GP*`/`New-GP*`/`Remove-GP*` wildcards alongside the
  existing AD ones (both cleared together too); no call-site changes were
  needed since these cmdlets already accept `-Server` and derive the
  target domain from it, identically to the AD cmdlets.
### Changed
- **`-Server` now resolves to the target domain's PDC Emulator
  specifically, not a bare domain name or an arbitrary DC-locator pick.**
  `Resolve-ADSecurityAuditTargetServer` (used by `Start-ADSecurityAudit`,
  `Get-ADSnapshot`, `Test-ADMachineAccountQuota`, and every other
  function's own `-Server` parameter below) now takes whatever value it
  would previously have returned (an explicit `-Server`, or the
  `$env:USERDNSDOMAIN` default) and resolves it one further step to that
  domain's PDC Emulator FSMO role holder via `Get-ADDomain`'s own
  `.PDCEmulator` property, falling back to the plain value if that
  resolution fails. This removes an entire category of ambiguity in one
  place rather than depending on every downstream call being individually
  correct: a bare domain FQDN was never a valid
  `Get-ADDomainController -Identity` value to begin with, and letting the
  AD client's own DC-locator pick "a" DC for a domain name is exactly the
  non-deterministic, potentially-wrong-domain-in-a-forest resolution this
  module's `-Server` override exists to bypass. Every AD query for the
  rest of a run now targets one single, consistent, well-defined DC.
- **Every individual audit function now accepts its own `-Server`
  parameter** (`Test-ADUserSecurity`, `Get-ADPrivilegedUsers`,
  `Test-ADPrivilegedGroups`, `Test-ADDomainAdminEquivalence`,
  `Test-ADRodcSecurity`, joining `Test-ADMachineAccountQuota` and
  `Get-ADSnapshot`, which already had one) - defense-in-depth for the
  case where a function is called standalone rather than through
  `Start-ADSecurityAudit -Server ...`. Previously, calling any of these
  directly meant every `Get-AD*` call inside fell back to the ambient/
  serverless bind with no way to target a specific domain at all.
  Installs the same `Set-ADSecurityAuditTargetServer` override
  `Start-ADSecurityAudit` uses, for the duration of that call only, and
  only if one isn't already active - so nesting inside a
  `Start-ADSecurityAudit -Server` run is completely unaffected (never
  double-installs or clears the parent run's override). The remaining
  ~20 audit functions do not yet have this - they still rely solely on
  an active override being installed by whatever called them.
### Fixed
- **`Get-ADTargetDomainController` failed with "Cannot find directory
  server with identity: `<domain FQDN>`" whenever the active `-Server`
  override was a domain name rather than a specific DC name** - which is
  this module's own documented, encouraged form of `-Server` ("target a
  domain other than your own", e.g. `-Server domainb.corp.com`).
  `Get-ADDomainController -Identity` requires an actual DC identity
  (GUID/Name/IPv4Address/DNS host name of the DC itself), not a domain
  FQDN, so every live-network-probe check that depends on this function
  (anonymous-bind DirectoryEntry probe, DNS zone-transfer target
  resolution) silently failed to resolve a DC and skipped its probe
  whenever `-Server` was given as a domain name. Now resolves via
  `Get-ADSecurityAuditDomainController` instead, which correctly handles
  either form.
- **AD CS Certificate Templates/Enrollment Services enumeration returned
  the CONTAINER OBJECT ITSELF alongside real templates/CAs**
  (`Test-ADCertificateServices`, `Test-ADCSExtended`, `Get-ADSnapshot`).
  `Get-ADObject -SearchBase "CN=Certificate Templates,..."` (and
  `"CN=Enrollment Services,..."`) with the default `-SearchScope`
  (Subtree) also matches the base container object, which is never
  filtered out downstream - its own `Name` is literally "Certificate
  Templates"/"Enrollment Services", and it has no template attributes or
  `dNSHostName`/`cACertificate`. This produced exactly the confusing
  symptom "CA 'Enrollment Services' has no dNSHostName; skipping ESC8
  probe" even when a real, correctly-configured Enterprise CA exists -
  the message is about the container, not the real CA (which is a
  separate entry in the same result set and is unaffected). Fixed at all
  six call sites (two per file) with `-SearchScope OneLevel`, since
  neither object type is ever nested further than one level under these
  containers.

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
