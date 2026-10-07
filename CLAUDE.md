# CLAUDE.md — working rules for this repository

Read this before changing anything. It is the project's own design constraints, not
general advice.

---

## What WinDSH is

WinDSH (Windows Device Security Helper) audits Windows hardware-backed security features,
explains their state in plain language, and can configure a conservative subset locally.

Target users are **helpdesk technicians, Windows administrators, and semi-technical end
users**. Many are not security professionals. Output must be readable by someone who does
not know what HVCI stands for.

Focus: TPM, Secure Boot, VBS, Memory Integrity (HVCI), Credential Guard, System Guard
Secure Launch, kernel shadow stacks, Kernel DMA protection, Device Guard capabilities.

## Hard scope boundaries — do not cross these

WinDSH does **not**, ever:

- manage BitLocker or enable encryption (read-only status checks are allowed, and are used
  only to warn before firmware changes)
- clear or provision the TPM
- modify Secure Boot keys
- modify antivirus configuration or add exclusions
- bypass organization Group Policy or other enforced security controls
- write the Group Policy hive (`HKLM\SOFTWARE\Policies\...`) — it is read-only, used to
  detect managed settings and to evaluate CIS compliance
- download or execute external code
- use encoded commands or hidden actions

If a change would require any of the above, stop and raise it rather than implementing it.

## Design philosophy

- **Safety first.** Explain before changing. Detect hardware limits and policy
  restrictions. No unsafe automatic actions.
- **Conservative remediation.** "Fix what can be fixed safely" means only supported,
  low-risk, Microsoft-supported features. It must never enable something with known
  compatibility risk without an explicit warning and confirmation.
- **Human-readable output.** Plain language first, technical detail behind `-Advanced`.
- **Quality before feature expansion.** Do not add controls to pad the list.

## Architecture (v2)

Source lives in `src/` as ordered modules and is concatenated into a single
distributable `WinDSH.ps1` by `build/Build-WinDSH.ps1`.

```
src/10-core.ps1          parameters, output, registry provider, elevation, integrity
src/20-catalog.ps1       THE CONTROL CATALOG - single source of truth
src/30-state.ps1         system state collection (static / volatile split)
src/40-evaluate.ps1      control status, scoring, CIS comparison, explainer
src/45-firmware.ps1      BIOS/UEFI guidance, BitLocker warning, CI event diagnostics
src/50-apply.ps1         plan, pre-flight, confirmation, apply, change journal, revert
src/55-report-text.ps1   plain-text report
src/60-report-html.ps1   HTML report with score
src/65-selftest.ps1      synthetic self-test
src/70-main.ps1          console rendering, interactive menu, entry point
```

**Everything is a projection over the catalog.** Audit, `-WhatIf` preview, apply, revert,
scoring, CIS comparison, the explainer, and all three report formats read the same table.
Adding a control means adding one catalog entry, not editing five functions. If you find
yourself hand-writing per-feature logic in more than one place, that is the bug.

### Mandatory after ANY edit to `src/`

```powershell
.\build\Build-WinDSH.ps1      # regenerates WinDSH.ps1 and stamps the integrity hash
.\WinDSH.ps1 -SelfTest        # must print "0 failed"
```

Never hand-edit `WinDSH.ps1`. It is generated. CI fails if it has drifted from `src/`.

The integrity hash is computed by the build script. If it is stale, the shipped script
warns every user and **disables all remediation** (exit code 3).

## PowerShell compatibility — must work on 5.1 and 7

These have already caused real defects here. Do not reintroduce them:

- **Variable names are case-insensitive.** A local `$state` shadows a `$State` parameter.
- **`$True`, `$False`, `$args`, `$host`, `$input`, `$matches` are automatic variables.**
  Never use them as parameter or local variable names.
- **`(if ...)` as a sub-expression** parses on 7 and fails on 5.1. Use `$(if ...)`.
- **StrictMode 2.0 throws on a missing property.** Use `Get-PropertySafe`, or give every
  object in a collection the same shape.
- **A single-item result is a scalar, not an array.** Wrap with `@(...)` before `.Count`.
- **Assigning a function's output to a variable captures its whole output stream.** This
  silently broke `-Version` and RMM JSON once already.

## Testing

- `-SelfTest` is synthetic and must run on any host with no side effects. It uses the
  in-memory registry provider, so apply/revert is verified without touching a real HKLM.
- It must never block on a prompt. `Confirm-Action` returns true when
  `$script:Unattended` is set.
- Pester tests in `tests/` are the CI-facing wrapper.
- Add a regression test for every bug you fix.

## Commit conventions

One reviewable idea per commit. Subject in imperative mood, under ~72 characters, no
trailing period. Blank line. Body explains **why**, not what — the diff shows what.

Project history matters here beyond tidiness: SignPath Foundation declined the code
signing application on public-visibility grounds, and sustained, legible activity is part
of what they asked for. Avoid squashing unrelated work into one opaque commit.

## Approved launcher execution policy

On **2026-10-07**, the maintainer approved keeping the existing **process-scoped
`-ExecutionPolicy Bypass`** behavior for one-click launch. This resolves the earlier
open design question; it does not change runtime behavior.

- Use this setting only for PowerShell child processes started by
  `Run-WinDSH-AsAdmin.bat` or the script's self-elevation path.
- Never change persistent `CurrentUser` or `LocalMachine` execution policy.
- Preserve Mark of the Web; do not restore automatic `Unblock-File` or equivalent
  file modification.
- Respect `MachinePolicy` and `UserPolicy`, which take precedence. Do not work around
  organization policy that blocks the unsigned script.
- Keep unsigned-release and download-verification disclosures accurate. Process-scoped
  Bypass does not authenticate the publisher.

See [the usage guide](docs/USAGE.md#execution-policy-and-code-signing) for the public
explanation. Future changes to this launch policy require an explicit maintainer decision.

## Validation status

CI runs on Windows and checks Windows PowerShell 5.1 and PowerShell 7 parsing,
PSScriptAnalyzer, synthetic self-tests, native child-process argument binding,
apply/revert on a disposable Windows registry key, and live audit/RMM/WhatIf smoke
runs. `build/Build-WinDSH.ps1 -Check` verifies the generated script and integrity hash.

These checks do not prove firmware-dependent behavior on physical hardware.
Before a public release, manually validate interactive remediation and rollback on
representative supported Windows systems, real TPM/Secure Boot states, a blocking
Code Integrity event 3087, organization execution policies, and restart into firmware.
Record what was tested; do not describe all Windows paths as either untested or proven.

Use [the validation matrix](docs/VALIDATION.md) to track actual results. A pending or
blocked physical test is not a pass. Synthetic report fixtures are documentation only.

See [the release process](docs/RELEASING.md) for the release and maintenance steps.
