# WinDSH

[![WinDSH CI](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OJXW65A/WinDSH/actions/workflows/ci.yml)

**Windows Device Security Helper** audits Windows platform security, explains why a
protection is not running, and optionally configures supported local settings.
Reports include an applicable protection score, a Secured-core assessment, and a
comparison with CIS Device Guard policy settings.

**Contact:** windsh@rootauthority.com

**Version status:** `main` contains v2.0.0 development code. The latest published
release is currently v1.5.0. The examples below describe v2; see the
[v1.5.0 README](https://github.com/OJXW65A/WinDSH/blob/v1.5.0/README.md)
for the released version.

## Download

**[Download the latest public release](https://github.com/OJXW65A/WinDSH/releases/latest)**

Download the ZIP from the release page, right-click it, choose **Extract All**,
then open the folder containing **WinDSH.ps1** and double-click
**Run-WinDSH-AsAdmin.bat**.
Approve the administrator prompt and keep the launcher beside **WinDSH.ps1**.

The next release will include **WinDSH.zip**, containing only these two files.
The ZIP is not yet a published release asset.

To test the v2 development version now, download both files into the same folder:

- [Run-WinDSH-AsAdmin.bat](https://github.com/OJXW65A/WinDSH/raw/refs/heads/main/Run-WinDSH-AsAdmin.bat)
- [WinDSH.ps1](https://github.com/OJXW65A/WinDSH/raw/refs/heads/main/WinDSH.ps1)

If a file opens as text, right-click its link and choose **Save link as...**.

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

## What it checks

WinDSH reports TPM, UEFI/Secure Boot, Virtualization-based Security, Memory Integrity,
Credential Guard, System Guard Secure Launch, kernel shadow stacks, the vulnerable
driver blocklist, DEP, DMA/SMM capabilities, and pending restarts.

The report includes an applicable protection score, Secured-core assessment, CIS
comparison, and explanations of unsupported or inactive protections.
See the [control catalog and command reference](docs/USAGE.md).

## Safety and signing

WinDSH detects organization policy and hardware limits before proposing changes.
`-WhatIf` previews changes; remediation records a journal for conflict-aware rollback.
The Group Policy hive is read only. WinDSH does not manage encryption, clear the TPM,
change Secure Boot keys or antivirus configuration, or download and execute code.

The current launcher uses process-scoped `-ExecutionPolicy Bypass`; organization
Group Policy still takes precedence. Releases are unsigned. Verify published files
against the release's SHA-256 checksums. The internal integrity check detects
accidental corruption and does not authenticate the publisher.

Test remediation on representative Windows systems before organizational deployment.
Re-audit after restarting to confirm that configured protections are running.

## Documentation

| Guide | Contents |
|---|---|
| [Usage](docs/USAGE.md) | Controls, command-line options, reports, scoring, rollback, exit codes |
| [Contributing](CONTRIBUTING.md) | Source layout, builds, tests, contribution rules |
| [Release process](docs/RELEASING.md) | Release validation, packaging, publication, repository maintenance |
| [Security policy](SECURITY.md) | Supported versions and private vulnerability reporting |
| [Code signing policy](CODE_SIGNING_POLICY.md) | Current signing status and future signing requirements |
| [Changelog](CHANGELOG.md) | Released and upcoming changes |

For bugs and feature requests, [open an issue](https://github.com/OJXW65A/WinDSH/issues/new/choose).
Report security vulnerabilities privately to **windsh@rootauthority.com**.

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

## License

WinDSH is distributed under the [MIT License](LICENSE).
