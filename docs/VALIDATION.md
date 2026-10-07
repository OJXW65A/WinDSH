# Windows validation

[Back to the README](../README.md) · [Release process](RELEASING.md)

Automated checks and physical-hardware checks cover different risks. A passing hosted
Windows CI run, an in-memory test, or a synthetic sample report does not establish
physical hardware compatibility. Record actual results; never convert a pending test
to a pass because an automated test with a similar name passed.

## v2.0.2 automated evidence

Evidence snapshot: **2026-10-07**, source commit
`ab001ab6d8d155a96283c4bada8492714484fe93`.
These results cover v2.0.2 code before the release metadata was finalized. Release
preparation changes documentation only. For final packaging evidence, see the
[v2.0.2 release](https://github.com/OJXW65A/WinDSH/releases/tag/v2.0.2).

| Automated check | Environment | Result | Evidence |
|---|---|---|---|
| Build freshness and version/changelog | Hosted Windows | Passed | [CI run](https://github.com/OJXW65A/WinDSH/actions/runs/37667168300) |
| Parsing and Pester | Windows PowerShell 5.1 | 141 passed, 0 failed, 0 skipped | Same CI run |
| Parsing and Pester | PowerShell 7 | 141 passed, 0 failed, 0 skipped | Same CI run |
| PSScriptAnalyzer | Both Windows runtimes | 0 errors, 0 warnings | Same CI run |
| Live audit/report, RMM, no-write preview | Hosted Windows VM | Passed | Same CI run |
| Workflow validation | Hosted Linux | Passed | Same CI run |

## Published v2.0.1 evidence

Evidence snapshot: **2026-10-07**, source commit
`3f9f921f2c7506890146d24b342551299765dcc3`.
These results belong to the published v2.0.1 release, not every later development commit.
For development changes, use the corresponding PR's checks and
[Actions runs](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml).

| Automated check | Environment | Result | Evidence |
|---|---|---|---|
| Build freshness and version/changelog | Hosted Windows | Passed | [CI run](https://github.com/OJXW65A/WinDSH/actions/runs/37657708538) |
| Parsing and Pester | Windows PowerShell 5.1 | 134 passed, 0 failed, 0 skipped | Same CI run |
| Parsing and Pester | PowerShell 7 | 134 passed, 0 failed, 0 skipped | Same CI run |
| Live audit/report, RMM, no-write preview | Hosted Windows VM | Passed | Same CI run |
| Workflow validation | Hosted Linux | Passed | Same CI run |
| ZIPs, checksums, provenance | Hosted Windows release build | Passed | [Release build](https://github.com/OJXW65A/WinDSH/actions/runs/37658027673) |

## Manual validation matrix

**All rows below are pending. Physical Windows checks have not been completed.**
Do not describe v2.0.1 or v2.0.2 as fully hardware-validated. Repeat relevant checks
on both PowerShell runtimes.

The maintainer approved publishing v2.0.2 before these checks on **2026-10-07** and
plans physical validation for **Saturday, 2026-10-10**. This is a planned test date,
not validation evidence. Update statuses only after actual test records are available.

| Scenario | Required environment | Expected evidence | Status |
|---|---|---|---|
| Interactive audit and report accuracy | Representative physical Windows 10/11 systems; record edition/build | Compare reported states with Windows tools and firmware facts | Pending |
| UAC, cancellation, launcher completion | Standard user and elevated administrator sessions | Cancellation causes no changes; successful elevation waits and returns the application's exit code | Pending |
| Preview, selected remediation, rollback | Disposable physical Windows lab with supported controls | Preview is read-only; only approved values change; rollback restores prior values and preserves conflicts | Pending |
| Restart and re-audit | Physical system requiring a protection restart | A fresh audit verifies runtime state; absent pending markers alone do not prove completion | Pending |
| TPM and Secure Boot variations | Lab devices with known firmware states | Correct supported/unsupported/unknown evidence without TPM provisioning or Secure Boot key changes | Pending |
| Driver compatibility event 3087 | Lab with genuine existing compatibility evidence | Safe-set HVCI planning is blocked; no unsafe automatic override | Pending |
| Organization settings and execution policy | Authorized managed lab | Policy-managed settings are not changed; enforced execution policy is respected | Pending |
| Firmware restart offer | UEFI lab with an actual firmware setting to change | Cancel is harmless; approved restart reaches firmware; no automatic firmware-setting changes | Pending |

## Safe test protocol

1. Use an authorized disposable lab, not an end user's production device. Keep a tested
   recovery route and backups. If encryption is present, have its recovery material
   securely available to the operator; never paste recovery keys into reports or issues.
2. Record script version, exact commit, downloaded file hash, Windows edition/build,
   PowerShell version, physical/VM status, device model, firmware mode, and policy context.
   Record the operator and test date locally. Redact identifiers before publishing results.
3. Capture a baseline with `-AuditOnly -HtmlReport -JsonReport -TextReport`. Compare
   relevant states against Windows Security, Windows providers, and known firmware facts.
   Also test the launcher from a non-elevated session, including UAC cancellation.
4. Choose a specifically approved control. Run `-Enable <control-id> -WhatIf -NoReport`
   first, compare relevant registry values before/after, and confirm there were no writes.
   Test ordinary apply only when prerequisites, compatibility, and policy allow it.
   Never bypass a blocker simply to finish this checklist.
5. Inspect the resulting report and journal. Restart only when approved, then re-audit
   to verify runtime activation. Validate rollback with `-Revert`; compare original
   values and types. For conflict handling, use only lab-owned values and confirm a later
   administrator change is preserved. Do not enable new UEFI locks for this test.
6. Test blocked/unknown cases with genuine lab conditions. Do not manufacture a passing
   result, tamper with security event logs, clear a TPM, change Secure Boot keys, or weaken
   organization policy. A scenario without a suitable device remains pending/blocked.
7. Save work before an approved firmware restart. Check the encryption warning and
   cancellation path first. Confirm the offer appears only on eligible UEFI systems
   with something to change; an unsupported machine must not be offered that action.

## Record a result

For each scenario, add a record with:

- tested version/commit and SHA-256; date and operator;
- Windows edition/build, PowerShell version, device/firmware and policy context;
- exact command/menu actions and the approved controls;
- expected versus observed behavior, exit code, restart, and rollback outcome;
- reviewed, redacted evidence location;
- **Pass**, **Fail**, **Blocked**, or **Pending**, with the reason and follow-up.

A blank or blocked scenario is not a pass. Link completed records from the release
notes and update this matrix only when that evidence exists.
