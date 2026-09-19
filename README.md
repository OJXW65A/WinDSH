# WinDSH

[![WinDSH CI](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml/badge.svg)](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml)

**Windows Device Security Helper**

WinDSH is an open-source PowerShell utility for auditing Windows hardware-backed
security capabilities and safely enabling supported Microsoft Windows security
protections.

It is intended for helpdesk technicians, administrators, and non-technical users
who need a clear view of which Windows Device Security features are available,
enabled, disabled, unsupported, or require firmware configuration.

WinDSH gives you a **security score out of 100**, an **HTML report** you can send to
someone, a **plain-English explanation** of why any given protection is not running, and
a **CIS Benchmark comparison** for Device Guard.

**Contact:** windsh@rootauthority.com

---

## Quick start

Double-click **Run-WinDSH-AsAdmin.bat**. It requests Administrator rights and runs the
audit. Keep it in the same folder as `WinDSH.ps1`.

From PowerShell:

```powershell
.\WinDSH.ps1                       # interactive
.\WinDSH.ps1 -AuditOnly            # report only, no changes
.\WinDSH.ps1 -AuditOnly -HtmlReport
.\WinDSH.ps1 -Explain hvci         # why is this not running?
.\WinDSH.ps1 -ListControls         # what can this tool see and change?
.\WinDSH.ps1 -EnableAllSafe -WhatIf   # preview, changes nothing
.\WinDSH.ps1 -Revert               # undo the last change run
```

---

## What it checks

| Control | Configurable | CIS |
|---|---|---|
| Virtualization-based Security | yes | 18.9.5.1 |
| Platform Security Level (Secure Boot requirement) | yes | 18.9.5.2 |
| Memory Integrity (HVCI) | yes | 18.9.5.3 |
| Require UEFI Memory Attributes Table | yes | 18.9.5.4 |
| Credential Guard | yes | 18.9.5.5 |
| System Guard Secure Launch | yes | 18.9.5.6 |
| Kernel-mode Hardware-enforced Stack Protection | yes | 18.9.5.7 |
| Microsoft vulnerable driver blocklist | yes | - |
| Hypervisor-enforced Paging Translation | report only | - |
| SMM Firmware Measurement | report only | - |
| Data Execution Prevention | report only | - |

It also reports TPM, Secure Boot, UEFI mode, CPU virtualization, hypervisor launch type,
Kernel DMA protection capability, pending restart state and virtual-machine context.

WinDSH distinguishes between **supported, unsupported, configured, actually running,
firmware action required, policy managed** and **reboot required** — because a feature
that is configured but not running is the most common and most confusing case.

---

## Explaining failures

The most useful thing WinDSH does is answer "why is this off, and what do I do?"

- **Memory Integrity blocked?** It reads the Code Integrity event log for driver
  compatibility warnings (Event ID 3087) and names the driver, with its publisher,
  version and owning service.
- **Secure Launch configured but not running?** It walks the dependency chain and tells
  you whether it is a pending restart, a firmware setting, or DRTM hardware your machine
  simply does not have.
- **Something needs a BIOS change?** It gives the menu path for your manufacturer,
  the other names the setting goes by, and warns you about BitLocker recovery keys
  *before* you go near the TPM.

---

## Safety principles

WinDSH is deliberately conservative.

It does **not**:

- disable Microsoft Defender or other antivirus products
- create antivirus exclusions
- bypass organization Group Policy
- clear or reset the TPM
- modify Secure Boot keys
- enable Secure Boot directly in firmware
- manage BitLocker or disk encryption
- download or execute remote code
- use encoded or obfuscated PowerShell commands
- modify persistent PowerShell execution policy
- use `ExecutionPolicy Bypass`

Firmware-dependent settings are detected and explained to the user rather than
being modified using undocumented or vendor-specific methods.

---

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 or later
- Administrator permission for complete auditing and remediation

Actual security capabilities depend on the Windows version, edition, processor,
firmware, TPM, virtualization support, installed drivers, and organization policy.

---

## Quick start

Download or extract the complete WinDSH release.

For normal interactive use, double-click:

```text
Run-WinDSH-AsAdmin.bat
```

The launcher requests standard Windows UAC elevation and starts WinDSH in an
elevated PowerShell session.

You can also run WinDSH directly from PowerShell:

```powershell
.\WinDSH.ps1
```

---

## Interactive mode

WinDSH starts with a human-readable security assessment followed by detailed
technical information.

The menu allows supported actions such as:

- refresh the audit
- enable Memory Integrity / HVCI
- enable System Guard Secure Launch where supported
- configure advanced supported protections
- preview recommended changes
- run HVCI driver diagnostics
- save reports

Unsupported actions remain visible so the user knows the capability exists,
but they are marked unavailable with an explanation.

---

## Enable all safe protections

```powershell
.\WinDSH.ps1 -EnableAllSafe
```

WinDSH enables only the protections classified as safe and applicable to the
current machine.

Unsupported capabilities are skipped and reported rather than blindly modified.

A plain-text report is automatically created.

---

## Preview changes

To see what WinDSH would change without modifying Windows:

```powershell
.\WinDSH.ps1 -EnableAllSafe -WhatIf
```

Interactive mode also provides a preview option.

---

## Audit only

```powershell
.\WinDSH.ps1 -AuditOnly
```

JSON report:

```powershell
.\WinDSH.ps1 -AuditOnly -JsonReport
```

---

## Debug logging

```powershell
.\WinDSH.ps1 -DebugLog
```

By default, the diagnostic log is created on the current user's Desktop.

A custom location can be supplied:

```powershell
.\WinDSH.ps1 -DebugLog -DebugLogPath "C:\Temp\WinDSH-Debug.log"
```

Debug logging contains Windows security-provider and diagnostic information
needed for troubleshooting, but is not intended to collect credentials,
encryption keys, TPM secrets, or unrelated personal files.

---

## RMM / automation mode

WinDSH supports non-interactive machine-readable output:

```powershell
.\WinDSH.ps1 -AuditOnly -RMM
```

`-RMM` suppresses the interactive interface and emits compact JSON to standard
output.

Example remediation:

```powershell
.\WinDSH.ps1 -EnableAllSafe -RMM
```

To additionally create a report file:

```powershell
.\WinDSH.ps1 -EnableAllSafe -RMM -ReportFormat Text
```

---

## Reports

Supported report formats:

- Plain text
- JSON

Default report directory:

```text
Desktop\WinDSH-Reports\
```

JSON reports include a schema version and structured security-state information
for automation and fleet analysis.

---

## Exit codes

| Exit code | Meaning |
|---:|---|
| `0` | Success; no WinDSH-requested restart required |
| `1` | Fatal/internal error |
| `2` | Requested remediation blocked by organization policy |
| `3` | WinDSH self-integrity check failed |
| `4` | Explicitly requested remediation unavailable due to prerequisites |
| `5` | Remediation attempted but one or more actions failed |
| `3010` | Success; restart required or recommended |

Unsupported optional hardware discovered during a normal audit is reported to
the user and does not by itself make the audit fail.

---

## Restart behavior

Some Windows security protections only become active after a restart.

WinDSH distinguishes between a setting being configured and actually running.

When a restart is required, interactive mode informs the user and offers to
restart Windows. Unattended operation can use:

```powershell
.\WinDSH.ps1 -EnableAllSafe -AutoReboot
```

---

## PowerShell execution policy

WinDSH does not permanently modify PowerShell execution policy.

The launcher may use a temporary process-scoped `RemoteSigned` policy when
organization policy permits it.

That temporary setting exists only for the PowerShell process running WinDSH and
disappears when that process terminates.

WinDSH does not attempt to override `MachinePolicy` or `UserPolicy` configured
by an organization.

If organization policy prevents WinDSH from running, the launcher displays an
explanation to the user.

---

## Current code-signing status

Current development releases are not yet Authenticode signed.

WinDSH currently includes an internal SHA-256 based check intended to detect
accidental corruption or unintended modification. It is **not** a substitute
for cryptographic publisher authentication.

Authenticode signing is planned for stable releases.

---

## Code signing policy

See [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

WinDSH is **not currently code signed**. Releases are distributed unsigned and should
be verified using the SHA-256 checksums published with each GitHub Release.

An application to the SignPath Foundation OSS program was declined because the project
does not yet meet their public-visibility threshold. Signing remains a goal and the
release pipeline is already built to support it, but no signing sponsorship is in place
and none should be inferred.

---

## Undoing changes

Every value WinDSH writes is recorded in a change journal at
`%ProgramData%\WinDSH\changes.jsonl` **before** the registry is touched, so a run can be
undone even if it was interrupted.

```powershell
.\WinDSH.ps1 -Revert                 # undo the most recent change run
.\WinDSH.ps1 -Revert -RunId <id>     # undo a specific run
```

A value that did not exist before a run is removed on revert, not set to zero.

---

## CIS Benchmark comparison

WinDSH maps its controls to **CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0,
section 18.9.5 (Device Guard)** and reports pass or fail for each.

**Read this before using those results.** CIS audits the Group Policy hive
(`HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard`). WinDSH configures local
machine values under `HKLM\SYSTEM\CurrentControlSet\Control` and **never writes Group
Policy**. A machine configured by WinDSH will have the protections running but will still
report non-compliant against a CIS scan of 18.9.5. WinDSH states this plainly rather than
implying compliance it does not deliver.

Two deliberate differences from CIS are documented in the reports: WinDSH configures
Memory Integrity and Credential Guard **without a UEFI lock**, so they can be reverted
from Windows. CIS requires the locked form, which cannot be removed remotely.

---

## Privacy

WinDSH performs its Windows security assessment locally.

**This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it.**

WinDSH does not automatically upload reports, debug logs, hardware information,
or other collected information.

---

## Contributing

Bug reports, documentation improvements, tests, and carefully scoped code
contributions are welcome.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md).

---

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

## Disclaimer

WinDSH changes security configuration only when explicitly requested.

Hardware, firmware, drivers, Windows editions, organization policies, and
third-party software can affect whether a protection can successfully run.

Test remediation on representative systems before broad organizational
deployment.
