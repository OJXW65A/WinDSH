# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io/),
certificate by [SignPath Foundation](https://signpath.org/).

## Project

**WinDSH — Windows Device Security Helper**

The official WinDSH source code is maintained in this GitHub repository.

Only artifacts produced from the official WinDSH source repository are eligible
for official project signing.

## Team roles

### Committers and reviewers

The WinDSH repository owner and authorized repository maintainers.

### Approvers

The WinDSH repository owner.

Every production release signing request requires manual approval.

## Release policy

Official signed WinDSH releases will be produced through the project's trusted
GitHub Actions build and release workflow.

The project will not use its signing capability to sign unrelated third-party
software.

Release artifacts must originate from the official source repository and
approved release workflow.

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

## System changes

WinDSH clearly reports security configuration changes made or proposed by the
tool.

WinDSH does not intentionally:

- disable antivirus protection
- create antivirus exclusions
- bypass organization Group Policy
- clear TPM keys
- manage disk encryption
- modify Secure Boot keys
- download executable code

## Signing security

Signing credentials and signing-service API credentials must never be stored in
the source repository.

Official release signatures must be produced through the project's approved
SignPath signing workflow.
