# Security Policy

## Supported versions

WinDSH is an actively developed project.

Security fixes are normally applied to the latest public release. Older releases
may not receive separate security updates.

| Version | Supported |
|---|---|
| Latest public release | Yes |
| Older releases | Best effort |

Users are encouraged to test and use the latest published release from the
official WinDSH repository:

https://github.com/OJXW65A/WinDSH/releases

## Reporting a security issue

Please do not open a public GitHub issue for a vulnerability that could put
WinDSH users at risk before the issue has been reviewed.

Report security issues privately by email:

**windsh@rootauthority.com**

Please include, when available:

- WinDSH version
- Windows version and build
- PowerShell version
- a clear description of the issue
- steps required to reproduce it
- expected and observed behavior
- relevant WinDSH debug output with sensitive information removed
- whether the issue requires administrator privileges
- whether the issue affects audit-only or remediation behavior

Do not send passwords, private keys, BitLocker recovery keys, TPM secrets,
authentication tokens, or other credentials.

## Security issues of particular interest

Examples include:

- security settings being changed without explicit authorization
- remediation occurring when WinDSH is in preview or audit-only mode
- incorrect handling of organization Group Policy
- a way to bypass WinDSH integrity or safety checks that could lead to unsafe
  remediation
- unsafe execution-policy behavior
- command or argument injection through the launcher or WinDSH parameters
- unintended execution of downloaded or remote code
- sensitive information being exposed through reports, logs, JSON, or RMM output
- incorrect privilege or UAC handling
- a security feature being reported as running when Windows does not report it
  as running

## Not security vulnerabilities

The following are normally better reported as regular GitHub issues:

- unsupported hardware or firmware
- a Windows security feature unavailable on a specific device
- feature requests
- cosmetic or formatting problems
- documentation errors
- driver incompatibility already reported by Windows
- expected behavior caused by organization policy
- antivirus false positives without evidence of a WinDSH security defect

## Disclosure process

After receiving a report, the maintainer will review and reproduce the issue
where possible.

If the report is confirmed as a security problem, the goal is to:

1. understand the affected versions and impact;
2. prepare and test a fix;
3. publish an updated release;
4. document the security-relevant change without unnecessarily exposing users
   before a fix is available.

Reasonable coordinated disclosure is appreciated.

## Security design principles

WinDSH is intentionally designed to avoid behaviors that unnecessarily weaken
Windows security.

WinDSH does not intentionally:

- disable Microsoft Defender or other antivirus products;
- create antivirus exclusions;
- bypass organization Group Policy;
- clear or reset TPM keys;
- modify Secure Boot keys;
- manage BitLocker or disk encryption;
- download or execute remote code;
- use encoded or obfuscated PowerShell commands;
- permanently weaken PowerShell execution policy.

Administrator permission is required for remediation actions.

## Authenticity

Current development releases may not yet have a publicly trusted Authenticode
signature.

Official releases should only be obtained from:

https://github.com/OJXW65A/WinDSH/releases

Release hashes are published where available.

Publicly trusted Authenticode signing is planned for a future mature release.
