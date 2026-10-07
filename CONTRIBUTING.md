# Contributing to WinDSH

Thank you for considering a contribution to WinDSH.

WinDSH is a Windows security auditing and remediation utility, so changes should
favor safety, clarity, compatibility, and predictable behavior over convenience.

## Ways to contribute

Contributions are welcome in areas such as:

- bug reports
- PowerShell 5.1 compatibility fixes
- Windows-version compatibility fixes
- documentation improvements
- test coverage
- usability improvements
- hardware or firmware detection improvements
- reporting and RMM improvements
- HVCI / Device Guard diagnostics
- carefully scoped feature proposals

For security vulnerabilities, please follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## Before opening an issue

Please check whether the issue already exists.

For a bug report, include as much of the following as possible:

- WinDSH version
- Windows edition, version, and build
- Windows PowerShell / PowerShell version
- device manufacturer and model when relevant
- whether the machine is physical or virtual
- the exact command or menu action used
- expected behavior
- observed behavior
- relevant error text
- a WinDSH debug log when available

To create a debug log:

```powershell
.\WinDSH.ps1 -AuditOnly -DebugLogPath "C:\Temp\WinDSH-Debug.log"
```

Review debug logs before posting them publicly and remove any information you do
not want to disclose.

Do not include passwords, private keys, authentication tokens, BitLocker recovery
keys, TPM secrets, or other credentials.

## Development principles

Changes to WinDSH should preserve the project's conservative security model.

Contributions must not intentionally add behavior that:

- disables Microsoft Defender or other antivirus products;
- creates antivirus exclusions;
- bypasses organization Group Policy;
- clears or resets TPM keys;
- modifies Secure Boot keys;
- manages BitLocker or disk encryption;
- downloads or executes remote code;
- uses encoded or obfuscated PowerShell commands;
- permanently weakens PowerShell execution policy;
- silently changes security settings without clear user intent.

Firmware-dependent settings should be detected and explained rather than modified
through undocumented or vendor-specific mechanisms.

## PowerShell compatibility

Windows PowerShell 5.1 is a primary supported runtime.

Contributors should avoid changes that work only in PowerShell 7 unless there is
a compatible Windows PowerShell 5.1 path.

Be especially careful with:

- `$null` values
- empty strings
- zero-item collections
- single-item collections
- multi-item collections
- StrictMode behavior
- CIM/WMI property types
- registry values that may not exist
- provider behavior that varies between Windows versions

## Source layout and building (IMPORTANT)

`WinDSH.ps1` in the repository root is **generated**. Do not edit it by hand.

Source lives in `src/` as ordered modules:

```
src/10-core.ps1          parameters, output, registry provider, elevation, integrity
src/20-catalog.ps1       the control catalog - single source of truth
src/30-state.ps1         system state collection
src/40-evaluate.ps1      status, scoring, CIS comparison, explainer
src/45-firmware.ps1      BIOS/UEFI guidance and Code Integrity diagnostics
src/50-apply.ps1         plan, pre-flight, confirmation, apply, journal, revert
src/55-report-text.ps1   plain-text report
src/60-report-html.ps1   HTML report
src/65-selftest.ps1      synthetic self-test
src/70-main.ps1          console rendering, menu, entry point
```

After any edit under `src/`, run:

```powershell
.\build\Build-WinDSH.ps1
```

This concatenates the modules into `WinDSH.ps1` and stamps the self-integrity hash. If the
hash is stale, the shipped script warns every user and **disables all remediation** for
that run (exit code 3). CI fails the build if `WinDSH.ps1` has drifted from `src/`.

Verify without writing:

```powershell
.\build\Build-WinDSH.ps1 -Check
```

## Adding a control

Declare `PlatformRequirements` explicitly for every control; prerequisites are not inferred
from category or control ID.

Settings are declarative. A new control is **one entry in `src/20-catalog.ps1`**, not
edits across several functions. Audit, preview, apply, revert, scoring, CIS comparison,
the explainer and all report formats read that entry.

If you find yourself writing per-feature logic in more than one place, the catalog is
missing a field.

## PowerShell compatibility traps

Code must run on Windows PowerShell 5.1 and PowerShell 7. These have each caused a real
defect in this project:

- Variable names are case-insensitive: a local `$state` shadows a `$State` parameter.
- `$True`, `$False`, `$args`, `$host`, `$input` and `$matches` are automatic variables and
  cannot be used as parameter or variable names.
- `(if ...)` as a sub-expression parses on 7 and fails on 5.1. Use `$(if ...)`.
- StrictMode 2.0 throws on a missing property. Use `Get-PropertySafe`, or give every object
  in a collection the same shape.
- A single-item result is a scalar. Wrap with `@(...)` before using `.Count`.
- Assigning a function's output to a variable captures its whole output stream.

Add a regression test for every bug you fix.

## Verified development dependencies

Use a normal PowerShell session at the repository root. The package versions and
SHA-256 hashes in the [dependency lock](https://github.com/OJXW65A/WinDSH/blob/main/.github/psgallery-lock.json) are the
same pins CI uses; do not install an unversioned latest module instead.

```powershell
.\build\Install-CIDependencies.ps1 -Name Pester
.\build\Install-CIDependencies.ps1 -Name PSScriptAnalyzer
```

The installer downloads each package from PowerShell Gallery, verifies its hash
before extraction/import, and imports it into the current session from a fresh
temporary directory. It requires internet access, but does not require administrator
rights, mark a repository trusted, or modify persistent execution policy. Repeat this
setup in each new session and in both Windows PowerShell 5.1 and PowerShell 7.
If organization policy blocks script execution, use an approved development environment;
do not weaken that policy to run these commands.

## Running the tests

WinDSH uses Pester regression tests.

After importing the verified dependencies above:

```powershell
$result = Invoke-Pester -Path .\tests -PassThru
if ($result.Result -ne 'Passed' -or $result.PassedCount -eq 0) {
    throw 'The test run failed or did not execute any passing tests.'
}
```

The GitHub Actions CI workflow also checks:

- `CHANGELOG.md` has an entry for the declared version
- `WinDSH.ps1` is current with `src/`
- Windows PowerShell 5.1 parsing
- PowerShell 7 parsing
- PSScriptAnalyzer (build fails on Error or Warning severity)
- Pester regression tests on both runtimes
- a live `-AuditOnly` run produces a structurally valid JSON report
- `-RMM` emits exactly one JSON object on stdout
- `-EnableAllSafe -WhatIf` makes no registry changes
- safety-gating preflight, conflict-aware rollback, and interactive assessment refresh
- actual native Windows child-process argument binding on both runtimes
- real Windows registry apply/revert on a disposable test key

All CI jobs should pass before a pull request is considered ready.

## PSScriptAnalyzer

After importing verified PSScriptAnalyzer, run the same check as CI:

```powershell
.\build\Test-CodeQuality.ps1
```

The baseline is zero errors and zero warnings. Fix findings rather than disabling
rules repository-wide. Existing `SuppressMessageAttribute` exceptions are scoped to
specific functions or build scripts and explain why a rule does not apply:

- console/build diagnostics intentionally use the host stream, separate from RMM JSON;
- provider and report factories return data without performing machine changes;
- synthetic test doubles retain the real provider's parameter signature.

Any new exception requires a similarly narrow scope and a written justification.

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

The generated `WinDSH.ps1` is the required exception and must be committed after
source changes. The labeled synthetic report sample and its preview are documentation
fixtures, not reports from a user's computer; see [the sample guide](docs/SAMPLE_REPORT.md).

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
