# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io/),
certificate by [SignPath Foundation](https://signpath.org/).

## Project

**WinDSH — Windows Device Security Helper**

The official WinDSH source code is maintained in this GitHub repository:

https://github.com/OJXW65A/WinDSH

Only artifacts produced from the official WinDSH source repository are eligible
for official project signing.

## Team roles

### Committers and reviewers

- [OJXW65A](https://github.com/OJXW65A)

### Approvers

- [OJXW65A](https://github.com/OJXW65A)

Every production release signing request requires manual approval.

## Release policy

Official signed WinDSH releases will be produced through the project's trusted
GitHub Actions build and release workflow.

The project will not use its signing capability to sign unrelated third-party
software.

Release artifacts must originate from the official source repository and the
approved release workflow.

Production signing requests must correspond to an identifiable WinDSH release,
tag, or approved release artifact produced from the official repository.

## Privacy

This program will not transfer any information to other networked systems unless
specifically requested by the user or the person installing or operating it.

WinDSH does not automatically upload:

- audit results
- hardware information
- debug logs
- reports
- credentials
- security configuration
- TPM secrets or keys
- encryption keys or recovery information

## System changes

WinDSH clearly reports security configuration changes made or proposed by the
tool.

WinDSH does not intentionally:

- disable antivirus protection
- create antivirus exclusions
- bypass organization Group Policy
- modify persistent PowerShell execution policy
- clear or reset TPM keys
- manage BitLocker or disk encryption
- modify Secure Boot keys
- enable Secure Boot through undocumented firmware methods
- download or execute remote code
- use encoded or obfuscated PowerShell commands

## Signing security

Signing credentials, API tokens, private keys, and signing-service credentials
must never be stored in the source repository.

Official release signatures must be produced through the project's approved
SignPath signing workflow.

The signing process must use artifacts originating from the official WinDSH
repository and approved trusted build system.

Signed release artifacts must not be modified after signing.

## Verification

Users and administrators should verify official signed releases using Windows
Authenticode signature validation.

For PowerShell releases, the signature can be inspected with:

```powershell
Get-AuthenticodeSignature .\WinDSH.ps1
