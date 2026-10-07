# WinDSH v2 usage

This guide describes the v2.0.2 source. For packaged versions, use the documentation
from the matching release tag.

[Back to the README](../README.md)

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

Existing VBS/Memory Integrity locks and locked Credential Guard are preserved.
New settings use reversible defaults; WinDSH does not remove firmware locks.
Unreadable local or policy values, unexpected registry types, and unrecognized
platform-security values block the affected changes and require review.

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
Each report save has a unique filename and refuses to overwrite an existing report.
See [JSON and RMM schema 2.1](REPORT_SCHEMA.md) before updating automation consumers.

## Score and CIS interpretation

The **applicable protection score** is weighted across controls with known support
or unverified prerequisites. Only confirmed unsupported controls are excluded;
reports show how many controls remain in scoring. A score of 100 on limited hardware is not equivalent to
Secured-core qualification, and is not an overall measure of endpoint security.
Detection-only controls have zero scoring weight.

`Unknown` means required platform, runtime, or configuration evidence could not be
verified. Scored unknown controls stay in the denominator, earn no points, and produce an **Incomplete assessment**
grade. Shadow-stack `AuditMode` earns no enforcement points. Configuration-only
controls describe registry requirements; they do not independently prove runtime
enforcement. Missing policy evidence produces unknown CIS results rather than a
claim that policy is absent.

The comparison targets **CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0,
section 18.9.5**. CIS checks the Group Policy hive; WinDSH writes local values under
`HKLM\SYSTEM\CurrentControlSet\Control` and never writes Group Policy. Protections
can run while the policy-based CIS checks still fail. WinDSH also enables Memory
Integrity and Credential Guard **without UEFI locks when newly configured**, so
those changes can be undone from Windows. Existing locks remain in place; the
mapped CIS settings require the locked form.

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
Reports record actual rollback writes in `RevertedChanges`. RMM `changes` includes
both applied and reverted registry writes, with separate counts for each. Preview
and recovery of an already-restored value do not count as new registry writes.

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

The batch launcher and self-elevation path use **process-scoped
`-ExecutionPolicy Bypass`**. They do not change persistent execution policy or remove
Mark of the Web. `MachinePolicy` and `UserPolicy` still take precedence; an organization
policy that blocks the unsigned script must be respected. See Microsoft's
[execution policy scope and precedence](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1#execution-policy-scope-and-precedence).

Releases are currently **unsigned**. Compare downloads with the release's SHA-256
checksums. The internal integrity check detects accidental corruption, not malicious
publisher impersonation. Signing remains a goal; the SignPath Foundation application
was declined on public-visibility grounds and no signing sponsorship is in place.
See [the code signing policy](../CODE_SIGNING_POLICY.md).
