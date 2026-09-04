# ForcedFail-*pct-Snapshot.json

Three hand-authored, entirely synthetic `-FromSnapshot` fixtures - the same
fake domain (`contoso.local`), each with a different proportion of its
checks deliberately misconfigured:

| File | Target failure rate | What it's for |
|---|---|---|
| `ForcedFail-100pct-Snapshot.json` | 100% (worst case) | Every controllable "dirty area" present - the fullest possible report, and the one the duplicate-finding regression tests run against |
| `ForcedFail-60pct-Snapshot.json` | ~60% | A "moderately unhealthy" domain - roughly six in ten checkable areas are bad |
| `ForcedFail-25pct-Snapshot.json` | ~25% | A "mostly clean" domain with a handful of real issues |

No real environment, hostnames, SIDs, or identities are used anywhere in
these fixtures. Every name, SID, and DN is made up for this purpose.

## Quick start

```powershell
.\tools\Test-ForcedFailFixture.ps1              # 100%-tier (default)
.\tools\Test-ForcedFailFixture.ps1 -Tier 60
.\tools\Test-ForcedFailFixture.ps1 -Tier 25
```

Each run drops real `AD_Security_Audit_*.json/csv/html` and
`AD_Security_TestCoverage_*.json/csv` files under
`tests/fixtures/output/<tier>pct/` (gitignored) - open the `.html` file to
eyeball the full report, or diff the `.json`/`.csv` against a previous run
to spot an unintended change.

You can also run one directly:

```powershell
Import-Module .\ADSecurityAudit.psd1 -Force
Start-ADSecurityAudit -FromSnapshot .\tests\fixtures\ForcedFail-60pct-Snapshot.json -ExportPath .\out
```

## Important: what "100% failing" actually means here

**5 of the 28 registered checks always return zero findings under
`-FromSnapshot`, by design, regardless of any fixture data:**
`KnownDCVulnerabilities`, `GpoDeployedSecrets`, `LegacyAuthSurface`,
`CoercionAndRelayExposure`, and `RodcSecurity`. Each of these audits
real-time machine/network state (OS patch level, SYSVOL file content,
live per-DC registry/service probes, per-RODC live attribute reads) that
has no AD-schema/snapshot equivalent - they explicitly skip themselves
entirely under `-Snapshot` rather than give a potentially wrong answer.
This is a documented, intentional property of offline mode itself (see
each function's own `Add-ADOfflineSkipNote` call), not something these
fixtures work around or a gap in them.

So "100%" here means: **100% of the 23 checks that CAN produce a finding
offline do so** - not literally all 28 registered checks. The remaining 5
show up in the HTML report's "Offline Mode Coverage Notes" /
Test-Coverage section as skipped, not as passing clean - don't mistake
that for "23/28 = 82% is as bad as it gets," the tool is working
correctly; those 5 categories genuinely need a live run to evaluate.

The 60%/25% figures are the same kind of approximation, and are further
approximate because a single toggle sometimes feeds more than one check
(and a few checks read more than one toggle) - they're close, not exact.
If you need an exact percentage for a specific purpose, run
`tools/Test-ForcedFailFixture.ps1` and count the actual Test Coverage
section's "passed clean" vs "found issue(s)" totals in the generated
report.

## What these are for

- **Smoke-testing a code change end-to-end** at more than one severity
  level. Snapshot-mode unit tests (`tests/*.Tests.ps1`) assert specific
  behavior of one function in isolation; these fixtures instead run the
  *whole* pipeline - every `Test-AD*` check, `Invoke-ADRuleSet`, scoring,
  and all four export formats - the same way a real `-FromSnapshot`
  re-analysis would.
- **Regression coverage for the duplicate-finding dedup fixes**, in the
  100%-tier fixture specifically (see the table below).
- **Eyeballing what the report/scoring looks like at different severity
  levels** - e.g. confirming the maturity rating, HTML styling, and
  summary language all still read sensibly for a "mostly clean" domain and
  not just a maximally-bad one.

## What these are NOT for

- Asserting exact per-check pass/fail behavior - that's what the
  `-Snapshot`-mode unit tests under `tests/` are for.
- Testing the 5 always-skipped-under-snapshot checks listed above, or any
  other live-only sub-check within a check that's otherwise
  snapshot-capable (e.g. Kerberos Armoring/FAST within
  `Test-ADKerberosHardening`, or the anonymous-LDAP-bind live probe within
  `Test-ADDomainHardeningFlags`) - this is a known, documented limitation
  of offline mode itself, not something these fixtures work around.

## Deliberately duplicated entries (100%-tier fixture only - dedup regression coverage)

| Location | What's duplicated | Should produce |
|---|---|---|
| `ACLs.AdminSDHolder.Access` | `CONTOSO\svc-helpdesk` granted `GenericAll` via two ACEs (different `ObjectType`) | ONE "Non-Standard Permissions on AdminSDHolder" finding |
| `ACLs.DomainRoot.Access` | `CONTOSO\svc-sync` granted two *different* specific DCSync rights via two ACEs | ONE "Unauthorized DCSync Permissions" finding naming both rights |
| `ACLs.ConfigurationNamingContext.Access` | `CONTOSO\svc-helpdesk` granted `GenericAll` via two ACEs | ONE "Non-Standard Permissions on Configuration Naming Context" finding |
| `ADCS.CertificateTemplates[0].Access` | `CONTOSO\Domain Users` granted enrollment `ExtendedRight` via two ACEs | ONE ESC1 finding, principal listed once (not twice) |
| `ADCS.CertificateAuthorities[0].Access` | `CONTOSO\svc-helpdesk` `GenericAll` (ESC7) and `CONTOSO\Domain Users` `ExtendedRight` (Low-Priv CA rights), each via two ACEs | ONE finding each |
| `PrivilegedUserAcls[0].Access` | Identical `GenericWrite` ACE from `CONTOSO\svc-helpdesk` appears twice | Exactly TWO evidence bullets in the "Domain Admin Equivalent Access Detected" finding for Administrator (one Shadow Credentials, one WriteSPN) - not four |

If any of these ever produce more findings/bullets than the table says in
the 100%-tier fixture, something regressed. `tests/ForcedFailFixture.Tests.ps1`
asserts every row of this table automatically.

## The 31 "dirty area" toggles

All three fixtures are generated from one script,
`tools/build-forcedfail-fixtures.py`, which builds the domain from 31
independent boolean toggles (each feeding at least one of the 23
snapshot-capable checks) and simply turns a different subset of them on
per tier:

- **100%-tier**: all 31 ON.
- **60%-tier** (19/31 ON): `rc4_kerberos`, `kerberoastable`, `sid_history`,
  `adminsdholder_ghost`, `suspicious_group_membership`,
  `dangerous_aces_adminsdholder`, `dcsync_aces`, `eka_overprivilege`,
  `schema_config_nc_aces`, `critical_ou_ace`, `gpo_permissions`,
  `adcs_esc1_esc2`, `adcs_esc7_lowpriv`, `dnsadmins_member`,
  `trust_quarantine_disabled`, `weak_password_policy`,
  `laps_not_deployed`, `unconstrained_delegation`,
  `domain_admin_equivalence_evidence`.
- **25%-tier** (8/31 ON): `rc4_kerberos`, `sid_history`,
  `dangerous_aces_adminsdholder`, `adcs_esc1_esc2`, `laps_not_deployed`,
  `weak_password_policy`, `dnsadmins_member`, `pre_win2000_members`.

Everything not listed for a tier is left in its clean/compliant state for
that fixture (e.g. `msDS-SupportedEncryptionTypes` defaults to AES-only,
`PasswordNeverExpires` to `false`, the password policy to 14 characters
with complexity enabled, etc.) - see the script for the exact clean-state
value of each toggle.

## What's covered (100%-tier; subsets thereof at 60%/25%)

RC4-permitted Kerberos encryption (including on `krbtgt`), Kerberoasting/
AS-REP-roasting exposure, unconstrained delegation, RBCD configured,
Shadow Credentials, SID History injection (same-domain, high-privilege
RID), an AdminSDHolder "ghost" account, suspicious Backup Operators
membership, dangerous ACEs on AdminSDHolder/DomainRoot/Schema NC/
Configuration NC/a critical OU, an over-privileged Enterprise Key Admins
grant, a PrivExchange-style Exchange-principal ACE, ESC1 + ESC2 + ESC4 +
ESC7 + low-privilege CA management rights, a non-default DnsAdmins member,
a quarantine-disabled external trust, a weak password policy, LAPS not
deployed, AD Recycle Bin disabled, an old forest functional level, a
Pre-Windows 2000 Compatible Access member, a GPO editable by Authenticated
Users, and an unlinked/stale GPO.

## What's NOT covered (known gaps in these fixtures, not in the tool)

- The 5 always-skipped-under-snapshot checks (see above).
- AD CS ROCA/weak-signature checks (`NTAuthCertificates`/`AIACertificates`/
  `RootCACertificates` are left empty - synthesizing a realistic weak
  certificate blob by hand wasn't worth the complexity for this fixture).
- `ADCSChaseFallback` (EDITF_ENABLECHASECLIENTDC/"Certighost") - this
  reads a per-CA policy flag that isn't part of the current
  `ADCS.CertificateAuthorities` snapshot shape, so it isn't independently
  toggleable here; may or may not fire depending on the check's own
  fallback behavior.
- Multi-domain/multi-forest scenarios - these are single-domain fixtures.
- Attack path / control path chains spanning more than one hop - the ACEs
  here are mostly direct-object grants, not a nested privilege-escalation
  chain. `ControlPaths.ps1`'s BFS-based checks may still fire on some of
  the direct ACEs onto Tier-0 objects (e.g. AdminSDHolder), but multi-hop
  chains aren't specifically exercised; that's covered by its own
  dedicated unit tests instead.

## Maintenance: keep these fixtures current

**When you add or meaningfully change a check, ask whether these fixtures
should change too:**

- New finding type / new `Test-AD*` sub-check → add a new toggle in
  `tools/build-forcedfail-fixtures.py` (`ALL_TOGGLES` + the `build_snapshot`
  function) for a small, clearly-bad entry that would trigger it, add it to
  the 100%-tier's `ALL_TOGGLES` (automatic - it's always all-on) and decide
  whether it belongs in the 60%/25% `SIXTY_ON`/`TWENTYFIVE_ON` lists too,
  then re-run `python3 tools/build-forcedfail-fixtures.py` and commit the
  regenerated JSON files.
- Changed `Issue` name or `Category` → no fixture change needed (the
  fixtures don't hardcode expected Issue names anywhere except in
  `tests/ForcedFailFixture.Tests.ps1`'s dedup-regression assertions and this
  README's tables - update those two places if the specific Issue names
  involved change), but re-run `tools/Test-ForcedFailFixture.ps1` for each
  tier and skim the HTML output once to confirm the renamed finding still
  reads sensibly.
- New `Snapshot` field a check now reads → add a realistic value for it in
  `build-forcedfail-fixtures.py`'s `build_snapshot` function (see
  `src/Snapshot.ps1`'s `Get-ADSnapshot` for the authoritative schema -
  every field these fixtures use was copied from there).
- Fixed a bug found via a real lab run (as happened for the v1.24.0/1.24.1
  duplicate-finding fixes) → add a toggle reproducing that exact shape,
  the same way the "Deliberately duplicated entries" table above does, so
  the fix has permanent regression coverage in the full pipeline, not just
  in an isolated unit test.

A fixture set that never changes gradually stops testing anything new -
please don't treat these as one-time artifacts.

## Schema reference

Every field in these fixtures matches the shape `Get-ADSnapshot` produces
(see `src/Snapshot.ps1`), which is also exactly what
`Start-ADSecurityAudit -ToJson` + `-FromSnapshot` round-trips. If you're
unsure what shape a field should be, find the real collection code in
`Get-ADSnapshot` rather than guessing - `ConvertTo-ADHashtable` (also in
`src/Snapshot.ps1`) is what turns this JSON back into the nested
hashtables/arrays every `Test-AD*` function expects.
