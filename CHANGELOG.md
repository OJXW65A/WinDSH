# WinDSH changelog

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
  rele…1813 tokens truncated…atIf` makes no registry changes
- safety-gating preflight, conflict-aware rollback, and interactive assessment refresh
- actual native Windows child-process argument binding on both runtimes
- real Windows registry apply/revert on a disposable test key

All CI jobs should pass before a pull request is considered ready.

## PSScriptAnalyzer

You can run PSScriptAnalyzer locally with:

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path .\src -Recurse
Invoke-ScriptAnalyzer -Path .\build
```

Warnings should be reviewed. New analyzer errors should not be introduced.

## Preview changes before remediation

When modifying remediation logic, test preview behavior first:

```powershell
.\WinDSH.ps1 -EnableAllSafe -WhatIf
```

`-WhatIf` must not change Windows security settings.

Changes affecting remediation should be tested on representative Windows systems
before broad use.

## Pull requests

Keep pull requests focused on one logical change where practical.

A pull request should explain:

- what problem it solves;
- what behavior changes;
- whether registry or security settings are affected;
- how it was tested;
- whether a restart may be required;
- any Windows-version, edition, firmware, or hardware assumptions.

If the contribution changes user-visible behavior, update the relevant
documentation.

If it fixes a bug, add or update a regression test when practical.

## Commit messages

Use concise, descriptive commit messages.

Examples:

```text
Fix empty firmware action handling
Add Secure Launch capability test
Improve HVCI diagnostic reporting
Update PowerShell 5.1 regression tests
```

## Coding style

Prefer:

- built-in Windows and PowerShell interfaces;
- clear function names;
- approved PowerShell verbs where practical;
- explicit error handling;
- debug logging for optional provider failures;
- human-readable output for non-technical users;
- structured output for automation.

Avoid unnecessary external dependencies.

## Generated files

Do not commit generated content such as:

- WinDSH debug logs
- local reports
- release ZIP archives
- temporary files
- test-result output

The repository `.gitignore` excludes common generated files.

## Releases

Releases are produced only by `.github/workflows/release.yml`, triggered by pushing a
tag matching the script version, such as `v2.0.0`, or by explicitly requesting a draft
from `main` with **Run workflow**. The workflow verifies the integrity hash, checks the tag matches
`$script:ToolVersion`, runs the tests, builds the artifact set, generates `SHA256SUMS`,
and opens a draft GitHub Release.

The [release process](docs/RELEASING.md) covers validation, packaging, and publication.

Do not hand-upload release assets. An artifact that was not built by the workflow cannot
be attested and breaks the chain between the published file and this source.

## Code signing

Do not add private keys, signing credentials, API tokens, certificate passwords,
or signing-service secrets to the repository.

WinDSH is currently unsigned. Signing status and policy are described in
[CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## License

By contributing to WinDSH, you agree that your contribution may be distributed
under the repository's [MIT License](LICENSE).

## Repository protection

The repository administrator should protect `main` with required pull requests and
required checks: `Workflow files are valid`, `Built file is current`, `Windows PowerShell 5.1`,
`PowerShell 7`, and `Live audit smoke test`. Require the branch to be up to date and
prevent force pushes/deletion. This is a GitHub settings change; committing this document
alone does not enable enforcement. Do not require approvals from other people unless
there are reviewers available, or a single-maintainer project will be unable to merge.

CI actions are pinned to full commit SHAs and PSGallery packages are pinned by version
and SHA-256 in `.github/psgallery-lock.json`. Review the upstream revision/package when
updating a pin. Dependabot proposes action updates; package hashes require explicit review.
