# WinDSH changelog

## v2.0.2 — 2026-10-07

### Changed

- Remove unused internal declarations, use singular private helper names, and
  normalize null comparisons without changing the supported command-line options.
- Consolidate menu output and document narrowly scoped analyzer exceptions for
  host-stream diagnostics, data factories, and test-double signatures.
- Enforce a zero-error/zero-warning analyzer baseline through a shared local/CI check.
- Document hash-verified contributor dependencies using the same package pins as CI.
- Add a clearly labeled synthetic HTML report and README preview, plus a repeatable
  generator that does not query or modify the host.
- Add a Windows validation matrix and manual test protocol. Outstanding physical
  Windows checks remain explicitly pending; a sample report is not test evidence.
- Record the maintainer's approval of process-scoped Bypass for the launcher and
  self-elevation. Runtime behavior is unchanged; persistent policy changes, Mark of
  the Web removal, and organization policy overrides remain prohibited.

### Validation

All five CI jobs passed. Windows PowerShell 5.1 and PowerShell 7 each
passed 141 tests with no failures or skips. PSScriptAnalyzer reported zero errors
and warnings. Live Windows audit/report, RMM, and no-write preview checks passed.

Physical Windows validation remains pending and is planned for **2026-10-10**.
The maintainer approved publication before those checks. Record actual results in
the [validation matrix](docs/VALIDATION.md); a hosted VM does not establish physical
hardware compatibility.

## v2.0.1 — 2026-10-07

### Fixed

- Keep unavailable runtime and registry evidence unknown; avoid false active
  results, scores, and Secured-core qualification. Distinguish shadow-stack audit
  mode from enforcement.
- Preserve existing VBS/Memory Integrity locks and locked Credential Guard.
  Accept only documented platform-security values instead of a numeric minimum.
- Block affected changes on registry or policy read errors and unexpected values.
- Normalize comma-separated control IDs before elevation. Disable changes whenever
  the generated script's integrity cannot be verified, including malformed metadata.
- Record rollback writes in reports and RMM change counts. Preserve earlier reports
  when multiple saves occur within one second; use locale-independent SVG numbers.
- Check the administrator token instead of the Server service in the launcher;
  wait for elevated completion and return the application's exit code.
- Refresh boot and hardware facts on an explicit interactive re-check.
- Keep failed firmware, virtualization, TPM, edition, build, and boot queries
  unknown instead of excluding them from the score or allowing remediation.
- Preserve unknown BitLocker protection status in firmware warnings. Recommend
  firmware changes only for confirmed findings, and offer firmware reboot only
  for UEFI systems with a firmware setting to change.
- Avoid inferring a completed reboot from absent pending markers. Keep unknown
  CIS runtime evidence visible in reports and use a warning color for incomplete scores.
- Refuse release reruns that could replace published assets or mix files into an
  existing draft. Fail closed when the authenticated release check is unavailable.

### Changed

- Share each OS, computer-system, and processor CIM query across collectors,
  reducing those queries from six to three per full assessment.
- Document JSON/RMM schema 2.1, unknown evidence, and separate apply/rollback counts.
- Add regressions for the audited failures and Windows launcher process handling.
- Resolve child-process test hosts from `PSHOME`, so restricted process views do
  not break portable tests.
- Ignore the default debug log and clarify draft-release naming, ZIP verification,
  and the requirement to keep published tags unchanged.

### Validation

All five Windows CI jobs passed. Windows PowerShell 5.1 and PowerShell 7 each
passed 134 tests with no failures or skips. Live Windows audit/report, RMM, and
no-write preview smoke checks passed.

Physical Windows remediation and rollback, UAC, driver compatibility, organization
execution policies, and firmware restart checks have not been completed for this
release. Validate these paths on representative systems before deployment. CI on a
hosted Windows VM does not establish physical hardware compatibility.

## v2.0.0 — 2026-10-03

Full rebuild. Same distribution model (one `WinDSH.ps1` plus the launcher), new internals.

### Added

- Add `WinDSH.zip` to release assets, containing only `Run-WinDSH-AsAdmin.bat` and
  `WinDSH.ps1`, with SHA-256 checksums and build provenance. Document extraction
  and launch steps in the public download section.
- Allow maintainers to build a verified draft release and version tag from the
  GitHub website without manually uploading release assets.

- **Security score out of 100** with a grade, weighted across the controls this machine
  can actually run. Controls the hardware cannot support are excluded from the total
  rather than counted as failures.
- **HTML report** with the score, a per-control table, what to do next, the CIS
  comparison and a Secured-core PC verdict. Self-contained: no external CSS, fonts,
  scripts or images, so it renders offline and survives being emailed.
- **Plain-text report** (`-TextReport`) and an interactive format chooser.
- **CIS Benchmark mapping** for section 18.9.5, all seven controls, including two that
  earlier versions never configured: Require UEFI Memory Attributes Table (18.9.5.4) and
  Kernel-mode Hardware-enforced Stack Protection (18.9.5.7).
- **Rollback.** Every change is journalled to `%ProgramData%\WinDSH\changes.jsonl` before
  the registry is written, so `-Revert` works even after an interrupted run. A value that
  did not previously exist is removed rather than set to zero.
- **`-Explain <control>`** and a generic explainer that walks the dependency chain and
  returns the single most actionable cause instead of a checklist.
- **Driver identification.** Code Integrity Event ID 3087 warnings are resolved to a
  publisher, version and owning service rather than a bare `.sys` filename.
- **Detection-only controls**: Hypervisor-enforced Paging Translation, SMM Firmware
  Measurement, and DEP. Reported but never configured, and carrying no scoring weight.
- `-ListControls`, `-Advanced`, `-NoColor` (also honours `NO_COLOR`), and status markers
  alongside colour so output is readable without it.

### Changed

- **Single source of truth.** All settings live in one declarative control catalog. Audit,
  `-WhatIf`, apply, revert, scoring, CIS comparison and every report format are
  projections over it. Previous versions restated the same registry facts in three places
  and had a hand-written diagnostic per feature.
- **Two-tier interactive menu**: five common actions, everything else behind "More
  options". The previous menu had grown to fourteen entries.
- **State collection split into static and volatile.** Hardware, firmware, TPM and OS
  identity are collected once; only DeviceGuard state, registry values and restart status
  are re-read after a change.
- **The launcher no longer strips Mark of the Web.** It uses process-scope
  `-ExecutionPolicy Bypass` instead. Stripping the mark permanently edited the file and
  removed the "came from the internet" signal for every other program on the machine;
  process-scope Bypass affects one child process and ends with it. No persistent execution
  policy is changed either way.
- **The launcher forwards no arguments** into the elevated process and now waits and
  propagates the real exit code. It previously forwarded `%*` unfiltered and always
  exited 0.
- The script self-elevates, so it works when started from a non-elevated prompt.
- Source is now modular under `src/`, built into the single distributable file by
  `build/Build-WinDSH.ps1`, which also stamps the integrity hash so it cannot go stale.

### Fixed

- Separate safe-set intent from explicit control selection. HVCI preflight fails closed
  on inaccessible logs; known incompatibilities require real interactive typed consent.
  Preview includes preflight and dependency blockers.
- Make rollback conflict-aware, type-aware, and non-repeatable. Track completed writes
  and restored entries, serialize operations, validate catalog targets, protect journal
  permissions, and preserve ambiguous interrupted writes for manual review.
- Ignore inherited journal path overrides in production.
- Declare platform requirements per control so DEP does not inherit VBS requirements.
- Refresh status, score, CIS, Secured-core, and explanations as one assessment after changes.
- Preserve command-line intent through elevation; test native Windows argv round-trips.
- Support explicitly selected RMM report formats and consistent process/JSON exit codes;
  do not mask partial failures with restart success.
- Clarify applicable-score semantics and synchronize README/CONTRIBUTING with the CLI,
  including current process-scoped launcher policy without changing that behavior.
- Pin GitHub Actions to commit SHAs and PSGallery packages to verified SHA-256 hashes;
  remove the unused release dry-run input and add dependency update configuration.
- Expand rollback, preflight, interactive, automation, native-argv, and disposable-key
  Windows provider regression coverage. Hardware-affecting remediation remains a manual
  test on representative systems before release.

- `RequirePlatformSecurityFeatures` was written as `1` unconditionally, silently weakening
  a machine an administrator had set to `3` (Secure Boot + DMA protection). It is now
  treated as a floor, so a stronger existing value is preserved.
- Firmware mode was decided by substring-matching a display string that can read
  `Legacy BIOS or unsupported UEFI` — which contains `UEFI`. Secure Launch prerequisites
  were reported as met on non-UEFI machines. Decisions now use a normalised mode field.
- `hypervisorlaunchtype=Off` blocks every VBS feature regardless of the registry and is
  invisible there. It is now detected and reported as a blocker.
- Pending restart was reported on nearly every machine, because the mere existence of
  `PendingFileRenameOperations` was treated as evidence. Only Component Based Servicing
  and Windows Update now set it.
- Quitting after a read-only session ran a second full audit and prompted twice. It is now
  immediate and silent when nothing changed.
- Action results are no longer buried: each action waits for a keypress, and remediation
  no longer reprints the whole audit over its own output.

### Maintenance

- Separate the public quick start from the detailed usage guide and document the
  release process. Correct stale validation and signing statements.
- Add issue and pull request templates, editor/line-ending settings, and syntax
  coverage for build and test scripts. Remove the unused duplicate QR image.
- Include the MIT notice in the distributable script while keeping the public ZIP
  limited to the launcher and application. Align the control catalog output.

### Unchanged by design

- No BitLocker or encryption management. BitLocker status is read only, to warn before
  firmware changes.
- No TPM clearing, no Secure Boot key changes, no antivirus modification, no organization
  policy bypass.
- The Group Policy hive is never written. Policy-managed values are detected and left alone.
- No network access, no encoded commands, no remote downloads.
- The self-integrity check detects accidental corruption and is not a security boundary.
- WinDSH is not code signed. See `CODE_SIGNING_POLICY.md`.

## v1.5.0 — 2026-09-09

First public release. Includes Windows platform security auditing, interactive
remediation, preview mode, text/JSON reports, RMM output, and PowerShell 5.1 support.

See the [v1.5.0 release notes](https://github.com/OJXW65A/WinDSH/releases/tag/v1.5.0).
