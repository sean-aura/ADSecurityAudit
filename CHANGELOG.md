# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
