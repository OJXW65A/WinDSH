WinDSH v1.5.0
Windows Device Security Helper
windsh@rootauthority.com
================================================================================

PURPOSE
-------
WinDSH audits Windows hardware-backed/device-security capabilities and can safely
configure a deliberately small set of documented Windows protections. It is designed
for helpdesk technicians and non-technical end users: a plain-English summary is
shown first, followed by detailed technical status and guidance.

WinDSH intentionally does NOT configure BitLocker/device encryption, clear the TPM,
change Secure Boot keys/firmware state, bypass Group Policy, disable antivirus, download
code, use encoded PowerShell, or make persistent PowerShell execution-policy changes.

RECOMMENDED START
-----------------
For normal interactive helpdesk use, keep these two files together and double-click:

    Run-WinDSH-AsAdmin.bat
    WinDSH.ps1

The launcher:
  * clearly stops if organization MachinePolicy/UserPolicy requires Restricted or
    AllSigned execution and explains what the end user should do;
  * automatically removes Windows Mark of the Web from THIS WinDSH.ps1 only when
    present;
  * starts a new elevated PowerShell process with temporary Process-scope RemoteSigned;
  * does not set CurrentUser or LocalMachine execution policy;
  * does not override organization Group Policy.

The temporary Process-scope execution policy disappears automatically when that
PowerShell process closes, even if the user closes the window or the process crashes.

WHAT v1.5.0 ADDS
----------------
  * Native -WhatIf preview for unattended remediation and [P] Preview in the menu.
  * Unsupported actions remain visible but are grayed and include a plain-English reason.
  * Stable unattended/RMM exit-code contract.
  * -RMM mode: exactly one compact JSON object on stdout, no normal menu/banner.
  * JSON SchemaVersion 1.0 and richer structured state.
  * InitialState + FinalState reporting for remediation runs.
  * HVCI/Memory Integrity driver diagnostics using Windows Code Integrity and Device
    Guard event logs. Actual .sys names are shown only when Windows event data contains them.
  * Enable All Safe conservatively skips Memory Integrity when recent Code Integrity
    Event ID 3087 compatibility evidence is found and reports the reason for technician review.
  * Virtual-machine detection with informational hypervisor guidance.
  * Refactored system-state collectors for firmware, TPM, virtualization, OS and
    Device Guard data.
  * Line-ending-normalized accidental-corruption self-integrity check.
  * -Version and -SelfTest switches.
  * More provider exceptions routed to -DebugLog rather than silently discarded.
  * PowerShell 5.1 hardening for empty/null/single/multi-item result handling.

INTERACTIVE MENU
----------------
The main action menu is single-key: 1, 2, A, P, R, Q, etc. act immediately without
pressing Enter. Confirmation prompts still require explicit confirmation.

Grayed [UNAVAILABLE] items cannot be selected. The reason is shown on the same menu
line and is also included in the audit/report so a non-technical user knows why the
feature cannot be enabled locally.

ENABLE ALL SAFE
---------------
Enable All Safe is intentionally conservative. It considers only:
  1. VBS + Memory Integrity / HVCI, without UEFI lock.
  2. System Guard Secure Launch / Firmware protection when prerequisites are confirmed.

It does NOT automatically enable Credential Guard, Kernel Shadow Stacks, Secure Boot,
TPM provisioning, the explicit vulnerable-driver blocklist preference, or encryption.

Unsupported/non-applicable safe features are skipped and clearly reported. They do not
make a generic Enable All Safe run fail. Organization policy blocks are reported as a
policy outcome.

When recent HVCI compatibility Event ID 3087 evidence is found, Enable All Safe skips
Memory Integrity pending technician review. The interactive Memory Integrity action can
still be used after reviewing the event evidence and explicitly confirming the risk.

REPORTING
---------
Interactive Save Report asks for Text or JSON; Text is the default.

-EnableAllSafe automatically creates a Text report without asking unless overridden:

    .\WinDSH.ps1 -EnableAllSafe

Default location:

    Desktop\WinDSH-Reports\WinDSH-<computer>-<timestamp>.txt

Overrides:

    .\WinDSH.ps1 -EnableAllSafe -JsonReport
    .\WinDSH.ps1 -EnableAllSafe -ReportFormat Json
    .\WinDSH.ps1 -EnableAllSafe -NoReport

JSON reports include:
  * SchemaVersion
  * tool/version/integrity metadata
  * exit outcome
  * InitialState
  * FinalState
  * human summary rows
  * firmware actions
  * unsupported capabilities
  * HVCI diagnostics when collected
  * planned changes in WhatIf mode
  * restart state
  * change log

RMM MODE
--------
RMM mode suppresses the human-oriented console UI and emits exactly one compact JSON
object to stdout. Run RMM mode from an already elevated process/context.

Audit only, stdout JSON only:

    .\WinDSH.ps1 -AuditOnly -RMM

Enable all safe, stdout JSON only:

    .\WinDSH.ps1 -EnableAllSafe -RMM

RMM plus an explicit Text file:

    .\WinDSH.ps1 -EnableAllSafe -RMM -ReportFormat Text

RMM plus an explicit JSON file:

    .\WinDSH.ps1 -EnableAllSafe -RMM -JsonReport

RMM creates no report file by default. An explicit report option is required.

WHATIF / PREVIEW
----------------
Preview recommended safe changes without modifying Windows:

    .\WinDSH.ps1 -EnableAllSafe -WhatIf

Preview Credential Guard changes:

    .\WinDSH.ps1 -EnableCredentialGuard -WhatIf

Interactive users can press:

    P

The plan shows the exact registry path/name, current value, proposed value, skipped
features and expected restart requirement. Preview follows the same conservative HVCI
compatibility rule as Enable All Safe.

HVCI / MEMORY INTEGRITY DIAGNOSTICS
-----------------------------------
Interactive menu option [7] checks recent events from:

    Microsoft-Windows-CodeIntegrity/Operational
    Microsoft-Windows-DeviceGuard/Operational

WinDSH highlights recent Code Integrity Event ID 3087 compatibility events and extracts
.sys names/paths only when Windows actually places them in event data. This diagnostic
is evidence, not proof that every unlisted driver is compatible or that a listed driver
is the only blocker.

Menu option [8] opens the Code Integrity Operational Event Viewer log. Option [6] opens
Windows Security Core isolation.

EXIT CODE CONTRACT
------------------
These are WinDSH.ps1 unattended/RMM exit codes:

    0     Success; no WinDSH-requested restart required.
    1     Fatal/internal error or required Administrator context unavailable.
    2     Requested remediation blocked by organization-managed policy.
    3     WinDSH self-integrity check failed; remediation is blocked.
    4     An explicitly requested remediation is unavailable because a required
          prerequisite is missing.
    5     One or more requested remediation actions failed/could not complete safely.
    3010  Success; restart required/recommended to complete verification.

Important:
  * A normal audit can report unsupported capabilities and still return 0.
  * -EnableAllSafe skips unsupported/non-applicable optional capabilities and reports
    them; those skips alone do not return 4.
  * Exit 4 is reserved for an explicitly requested remediation whose prerequisite is
    unavailable, such as an unsupported explicit Credential Guard request.
  * Use WinDSH.ps1 directly from the RMM/deployment system when you need the final
    WinDSH exit code. The BAT is an interactive bootstrap launcher and exits after it
    starts the elevated PowerShell process.

OTHER COMMAND EXAMPLES
----------------------
Interactive:
    .\WinDSH.ps1

Audit only with Text report:
    .\WinDSH.ps1 -AuditOnly

Audit only with JSON report:
    .\WinDSH.ps1 -AuditOnly -JsonReport

Enable Safe protections and automatically reboot if WinDSH requires it:
    .\WinDSH.ps1 -EnableAllSafe -AutoReboot

Advanced Credential Guard action:
    .\WinDSH.ps1 -EnableCredentialGuard -ReportFormat Text

Debug log on current user's Desktop:
    .\WinDSH.ps1 -DebugLog

Custom debug log path:
    .\WinDSH.ps1 -DebugLogPath "C:\Temp\WinDSH-Debug.log"

Version without elevation:
    .\WinDSH.ps1 -Version

Synthetic decision-logic regression test without Windows changes:
    .\WinDSH.ps1 -SelfTest

SELF-INTEGRITY
--------------
WinDSH contains an embedded normalized SHA-256 check intended to detect accidental
corruption/incomplete copies/unintended edits. CRLF/LF line-ending differences are
normalized before hashing in v1.5.0.

This is NOT tamper-proof. A deliberate editor can change both the script and the
embedded expected value. Authenticode signing remains the planned authenticity control
for a mature release.

If the self-check fails, WinDSH allows audit/debug activity but disables remediation.
Unattended/RMM runs return exit code 3.

SECURITY / SAFETY BOUNDARIES
----------------------------
WinDSH does not:
  * use -ExecutionPolicy Bypass;
  * make persistent execution-policy changes;
  * override MachinePolicy/UserPolicy;
  * disable or exclude antivirus/Defender;
  * download or execute remote code;
  * use encoded/obfuscated PowerShell;
  * clear/reset the TPM;
  * change Secure Boot keys or firmware settings;
  * enable UEFI-lock or VBS Mandatory mode;
  * delete incompatible drivers;
  * configure BitLocker/device encryption;
  * add scheduled tasks/persistence.

TESTING NOTE
------------
This release is intended to remain conservative across Windows 10/11 hardware, but
hardware/firmware/CIM providers vary. Test WinDSH on representative systems before a
broad rollout. -DebugLog and -SelfTest are included to make Windows PowerShell 5.1 and
vendor-specific problems easier to diagnose.

Authenticode signing is intentionally deferred until the code/interface mature.
