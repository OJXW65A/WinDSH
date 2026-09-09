# WinDSH

**Windows Device Security Helper**

WinDSH is an open-source PowerShell utility for auditing Windows hardware-backed
security capabilities and safely enabling supported Microsoft Windows security
protections.

It is intended for helpdesk technicians, administrators, and non-technical users
who need a clear view of which Windows Device Security features are available,
enabled, disabled, unsupported, or require firmware configuration.

**Contact:** windsh@rootauthority.com

---

## Features

WinDSH audits and reports security capabilities including:

- TPM / Security Processor
- Secure Boot
- UEFI firmware status
- CPU virtualization
- Virtualization-Based Security (VBS)
- Memory Integrity / HVCI
- System Guard Secure Launch / Firmware Protection
- Credential Guard
- Kernel-mode Hardware-enforced Stack Protection
- Kernel DMA Protection capability
- DEP / NX
- SMM security capabilities
- Microsoft Vulnerable Driver Blocklist
- Relevant Device Guard capabilities
- Pending restart state
- Virtual machine awareness
- HVCI / Code Integrity driver-event diagnostics

WinDSH distinguishes between:

- supported
- unsupported
- enabled
- configured
- actually running
- firmware action required
- policy managed
- reboot required

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
