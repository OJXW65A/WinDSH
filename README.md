# WinDSH

[![WinDSH CI](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml/badge.svg)](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml)

**Windows Device Security Helper** audits Windows platform security, explains why a
protection is not running, and optionally configures supported local settings.
Reports include an applicable protection score, a Secured-core assessment, and a
comparison with CIS Device Guard policy settings.

**Contact:** windsh@rootauthority.com

## Download

**[Download WinDSH.zip](https://github.com/OJXW65A/WinDSH/releases/latest/download/WinDSH.zip)**

The ZIP contains only the two files needed to run WinDSH:

- `Run-WinDSH-AsAdmin.bat` — launcher that requests Administrator rights.
- `WinDSH.ps1` — the complete WinDSH application.

Right-click the downloaded ZIP and choose **Extract All**, then open the extracted
folder, double-click **Run-WinDSH-AsAdmin.bat**, and approve the administrator prompt.
Keep both extracted files together in the same folder.

The single-file download will be available when the next release is published.
Until then, download [Run-WinDSH-AsAdmin.bat](https://github.com/OJXW65A/WinDSH/raw/refs/heads/main/Run-WinDSH-AsAdmin.bat)
and [WinDSH.ps1](https://github.com/OJXW65A/WinDSH/raw/refs/heads/main/WinDSH.ps1) separately
into the same folder. If a link opens as text, right-click it and choose **Save link as...**.

## Requirements

- Windows 10 or Windows 11; Windows PowerShell 5.1 or PowerShell 7.
- Administrator rights for platform auditing and registry changes.
- Features depend on Windows build/edition, firmware, CPU, drivers, and organization policy.

## Quick start

Keep `Run-WinDSH-AsAdmin.bat` beside `WinDSH.ps1`. Double-click the launcher for the
interactive menu and standard UAC elevation, or run from PowerShell:

```powershell
.\WinDSH.ps1                                  # interactive
.\WinDSH.ps1 -AuditOnly                        # audit and default HTML report
.\WinDSH.ps1 -EnableAllSafe -WhatIf -NoReport   # preview including safety blockers
.\WinDSH.ps1 -Explain hvci
.\WinDSH.ps1 -ListControls
.\WinDSH.ps1 -EnableAllSafe                    # apply the conservative set
.\WinDSH.ps1 -Revert                          # undo the newest open change run
```

## Controls

| ID | Protection | Configurable | CIS 18.9.5 |
|---|---|---|---|
| `vbs` | Virtualization-based Security | Yes | 18.9.5.1 |
| `platform-security` | Secure Boot requirement for VBS | Yes | 18.9.5.2 |
| `hvci` | Memory Integrity | Yes | 18.9.5.3 |
| `hvci-mat` | Require UEFI Memory Attributes Table | Yes | 18.9.5.4 |
| `credential-guard` | Credential Guard | Yes | 18.9.5.5 |
| `secure-launch` | System Guard Secure Launch | Yes | 18.9.5.6 |
| `kernel-shadow-stacks` | Kernel-mode hardware stack protection | Yes | 18.9.5.7 |
| `driver-blocklist` | Microsoft vulnerable driver blocklist | Yes | — |
| `hvpt` | Hypervisor-enforced Paging Translation | Report only | — |
| `smm-firmware-measurement` | SMM Firmware Measurement | Report only | — |
| `dep` | Data Execution Prevention | Report only | — |

WinDSH also reports TPM, UEFI/Secure Boot, CPU virtualization, hypervisor launch
configuration, DMA/SMM capabilities, pending restarts, and virtual-machine context.
DEP is evaluated independently of VBS prerequisites.

## Remediation and safety

`-EnableAllSafe` selects `vbs`, `platform-security`, `hvci-mat`, `hvci`, and
`driver-blocklist`. Unsupported and policy-managed settings are skipped.
Credential Guard, Secure Launch, and kernel shadow stacks remain opt-in:

```powershell
.\WinDSH.ps1 -Enable credential-guard
.\WinDSH.ps1 -Enable hvci,driver-blocklist
```

Memory Integrity is skipped if recent Code Integrity event 3087 evidence exists
or the compatibility log cannot be queried. This applies to both the safe set and
explicit unattended `-Enable hvci`. An override requires selecting the protection
in the **interactive specific-protection menu**, reading the warning, and typing
`hvci`. Unattended invocation never substitutes for that typed confirmation.
No matching events means the log check passed; it does not prove every driver is compatible.
Preview and execution use the same support, policy, dependency, and preflight decisions.

The interactive menu provides re-check, safe remediation, per-control explanations,
report saving, specific-control remediation, rollback, CIS comparison, Windows Security,
firmware guidance, and driver diagnostics. Technical details are available with `-Advanced`.

WinDSH never writes `HKLM\SOFTWARE\Policies`, clears/provisions the TPM, changes Secure
Boot keys, manages BitLocker, changes antivirus configuration, or downloads/executes
remote code. Firmware actions are guidance; the firmware restart option requires consent.
Registry configuration does not guarantee the protection is running; check again after restarting.

## Command-line options

| Option | Behavior |
|---|---|
| `-AuditOnly` | Audit without changing security settings. |
| `-EnableAllSafe` | Apply the conservative set without ordinary prompts. |
| `-Enable <ids>` | Apply specific controls and their dependencies; comma-separated IDs are accepted. |
| `-Revert [-RunId <id>]` | Restore completed journal writes that still match current state. |
| `-ListControls` / `-Explain <id>` | List controls or explain one control and exit. |
| `-HtmlReport`, `-TextReport`, `-JsonReport` | Select report formats; switches can be combined. |
| `-NoReport` | Suppress report files. |
| `-ReportDirectory <path>` | Override the report directory. |
| `-Rmm` | Unattended operation with one compact JSON object on stdout. |
| `-Advanced` / `-NoColor` | Full console details / disable color; `NO_COLOR` is honored. |
| `-AutoReboot` | Restart after a successful unattended change run when required. |
| `-DebugLogPath <path>` | Enable diagnostics at the specified existing parent directory. |
| `-SelfTest` / `-Version` | Run synthetic tests / print the version, without elevation. |
| `-WhatIf` | Preview security changes without modifying the registry or journal. |

Use one change mode at a time. `-AuditOnly` cannot accompany changes; `-RunId` requires
`-Revert`. Report-only controls cannot be passed to `-Enable`.
There are no `-DebugLog` or `-ReportFormat` parameters.

## Reports and automation

Normal unattended runs write **HTML by default**. Reports go to
`Desktop\WinDSH-Reports`, with a temporary-directory fallback if Desktop is unavailable.
Select additional or alternative formats explicitly:

```powershell
.\WinDSH.ps1 -AuditOnly -HtmlReport -TextReport -JsonReport
.\WinDSH.ps1 -AuditOnly -JsonReport -ReportDirectory 'C:\Reports'
.\WinDSH.ps1 -AuditOnly -DebugLogPath 'C:\Temp\WinDSH-Debug.log'
```

RMM mode requires an already-elevated agent; it does not request UAC. It produces
no report files by default. Explicit report switches also work in RMM mode:

```powershell
.\WinDSH.ps1 -AuditOnly -Rmm
.\WinDSH.ps1 -EnableAllSafe -Rmm -TextReport -ReportDirectory 'C:\Reports'
```

The JSON stdout `exitCode` matches the process exit code. A partial failure takes
precedence over restart-required success. Custom report/debug paths are written
with administrator privileges after elevation; select trusted locations.
Reports and debug logs are local and are never uploaded automatically.

## Score and CIS interpretation

The **applicable protection score** is weighted across scored controls whose platform
requirements are met. Unsupported controls are excluded; reports show how many scored
controls are applicable. A score of 100 on limited hardware is not equivalent to
Secured-core qualification, and is not an overall measure of endpoint security.
Detection-only controls have zero scoring weight.

The comparison targets **CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0,
section 18.9.5**. CIS checks the Group Policy hive; WinDSH writes local values under
`HKLM\SYSTEM\CurrentControlSet\Control` and never writes Group Policy. Protections
can run while the policy-based CIS checks still fail. WinDSH also enables Memory
Integrity and Credential Guard **without UEFI locks** so those changes can be undone
from Windows; the mapped CIS settings require the locked form.

## Rollback

The journal is `%ProgramData%\WinDSH\changes.jsonl`. The directory is restricted to
Administrators and SYSTEM, and an exclusive lock serializes WinDSH change operations.
Each write has an intent record and a completion marker. Revert validates targets
against the control catalog and checks current registry values **and types** before restoring.
A value absent before the run is removed rather than set to zero.

```powershell
.\WinDSH.ps1 -Revert
.\WinDSH.ps1 -Revert -RunId 'your-run-id'
.\WinDSH.ps1 -Revert -RunId 'your-run-id' -WhatIf -NoReport
```

Later administrator changes are preserved and reported as conflicts. Successfully
restored entries are recorded and not repeated; completed runs are excluded from
selection. Conflicted entries remain available for retry. A write interrupted before
its completion marker is **ambiguous** and requires manual review; WinDSH never assumes
that an intent proves it changed the registry. Legacy journals are accepted with
catalog/current-state checks, but lack original write-completion evidence.
Malformed terminated or middle records block change operations; only a torn final
append is recoverable. Keep the journal when troubleshooting an interrupted run.
The inherited `WINDSH_JOURNAL_PATH` environment variable is ignored.

## Exit codes and restart

| Code | Meaning |
|---:|---|
| `0` | Completed successfully; no WinDSH restart required. |
| `1` | Invalid usage, startup/runtime failure, or remediation stopped by an error. |
| `2` | Completed with warnings, including skipped requested protections. |
| `3` | Integrity failure; security changes are disabled. |
| `4` | Administrator rights were unavailable. |
| `5` | Revert failed or encountered unresolved conflicts. |
| `3010` | Completed successfully; restart required. |

An existing Windows restart request does not mean WinDSH changed anything.
`-AutoReboot` is opt-in, for unattended change runs only; it does not restart after
failed operations or during `-WhatIf`. Re-audit after restarting to confirm actual running state.

## Execution policy and code signing

The current batch launcher and self-elevation path use **process-scoped
`-ExecutionPolicy Bypass`**. They do not change persistent execution policy or remove
Mark of the Web. `MachinePolicy` and `UserPolicy` still take precedence. The maintainer's
choice of launcher policy remains open; this audit fix preserves the current behavior.

Releases are currently **unsigned**. Compare downloads with the release's SHA-256
checksums. The internal integrity check detects accidental corruption, not malicious
publisher impersonation. Signing remains a goal; the SignPath Foundation application
was declined on public-visibility grounds and no signing sponsorship is in place.
See [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## Development and testing

`WinDSH.ps1` is generated from `src/`; never edit it directly.

```powershell
.\build\Build-WinDSH.ps1
.\WinDSH.ps1 -SelfTest
Invoke-Pester -Path .\tests
.\build\Build-WinDSH.ps1 -Check
```

CI checks PowerShell 5.1 and 7, syntax, build freshness, analyzer errors, synthetic
regressions, native child-process argument round-trips, and real Windows apply/revert
on a disposable test registry key. Live audit smoke tests exercise Windows collectors.
Hardware-affecting remediation still requires testing on representative Windows VMs
or physical machines before broad deployment.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Support WinDSH

WinDSH is developed and maintained as a free and open-source personal project.
If WinDSH is useful to you or your organization and you would like to support
continued development, testing, documentation, and future code-signing costs,
voluntary donations are appreciated.

Donations are completely optional and do not affect access to WinDSH,
its features, source code, or support for the MIT-licensed project.

### Bitcoin

`bc1qxevtatsn3gn9vzw57qtk4ys9j2gnn4c8ameagy`

<p align="center">
  <img src="assets/bitcoin-qr.png" alt="Bitcoin donation QR code" width="200">
</p>

---

## License

WinDSH is licensed under the [MIT License](LICENSE).

---

## Deployment caution

Test changes on representative systems before organizational deployment. Drivers,
firmware, Windows editions, and policy can prevent configured protections from running.
