#requires -Version 5.1
<#
.SYNOPSIS
    Audits and safely enables selected Windows Device Security protections.

.DESCRIPTION
    WinDSH is designed for helpdesk technicians and non-technical
    end users. It shows a plain-English summary first, then detailed technical
    information. It uses only Windows built-in PowerShell, CIM/WMI and documented
    registry interfaces.

    Safe/scriptable remediation:
      - Virtualization-based Security (VBS) + Memory Integrity / HVCI
      - System Guard Secure Launch / Firmware protection

    Advanced opt-in remediation:
      - Credential Guard without UEFI lock (supported Windows editions only)
      - Microsoft Vulnerable Driver Blocklist explicit local preference

    Audit / guidance:
      - UEFI vs Legacy firmware
      - Secure Boot
      - TPM / Security Processor
      - CPU virtualization and SLAT
      - Kernel DMA / Memory Access Protection capability
      - DEP / NX
      - SMM mitigations and measurement
      - MBEC / GMET
      - Kernel-mode Hardware-enforced Stack Protection
      - Hypervisor-Enforced Paging Translation (HSPT)
      - Device Guard policy ownership
      - Pending restart indicators

    This tool intentionally does NOT configure drive/device encryption.

    v1.5.0 adds preview/WhatIf support, stable automation exit codes, compact RMM JSON,
    JSON schema versioning, before/after reporting, VM awareness, HVCI driver/event
    diagnostics, unsupported-action visibility, and internal collector refactoring.
    Automatic Mark of the Web handling and temporary Process-scope RemoteSigned remain
    launcher-only bootstrap behavior; organization Group Policy is never bypassed.

.PARAMETER AuditOnly
    Run an audit, make no security changes, save the selected report format, and exit.

.PARAMETER EnableAllSafe
    Non-interactively enable the protections this tool considers suitable for generic
    helpdesk remediation: Memory Integrity/HVCI and System Guard Secure Launch.
    Firmware-controlled settings are never changed.

.PARAMETER EnableCredentialGuard
    Explicitly enable Credential Guard without UEFI lock when the detected Windows
    edition supports it. This is NOT included in EnableAllSafe because legacy
    authentication/delegation compatibility should be tested first.

.PARAMETER AutoReboot
    After requested changes and report generation, automatically restart Windows if
    this run made a change that requires reboot verification.

.PARAMETER ReportFormat
    Text, Json, or None. In unattended mode the default is Text.

.PARAMETER JsonReport
    Convenience switch equivalent to -ReportFormat Json.

.PARAMETER NoReport
    Convenience switch equivalent to -ReportFormat None.

.PARAMETER ReportDirectory
    Directory used for reports. Default: Desktop\WinDSH-Reports.

.PARAMETER DebugLog
    Enable detailed troubleshooting logging. The default log location is the current
    user's Desktop when -DebugLogPath is not specified.

.PARAMETER DebugLogPath
    Optional full path for the debug log. Supplying this parameter also enables debug
    logging. Default when debug logging is enabled: Desktop\WinDSH-Debug-<timestamp>.log.

.PARAMETER Unattended
    Do not show the interactive menu. With no enable switch, this performs an audit
    and writes the selected report (Text by default).

.PARAMETER RMM
    Suppress normal console UI and emit exactly one compact JSON object to standard
    output. No report file is created by default in RMM mode unless -JsonReport or
    -ReportFormat is explicitly supplied. Run RMM mode from an already elevated context.

.PARAMETER Version
    Display the WinDSH version and exit without elevation or system changes.

.PARAMETER SelfTest
    Run synthetic decision-logic regression checks and exit without changing Windows.

.PARAMETER WhatIf
    Native PowerShell preview mode. Use with -EnableAllSafe or -EnableCredentialGuard
    to display/report the exact registry changes that would be requested without writing them.

.EXAMPLE
    .\WinDSH.ps1
    Interactive audit/remediation.

.EXAMPLE
    .\WinDSH.ps1 -AuditOnly
    Unattended audit with a plain-text report.

.EXAMPLE
    .\WinDSH.ps1 -EnableAllSafe -AutoReboot
    Enable safe scriptable protections, write a text report, then reboot if required.

.EXAMPLE
    .\WinDSH.ps1 -EnableAllSafe -JsonReport
    Enable safe scriptable protections, write JSON, and return 3010 if reboot is required.

.EXAMPLE
    .\WinDSH.ps1 -EnableCredentialGuard -ReportFormat Text
    Explicitly enable Credential Guard without UEFI lock where supported.

.EXAMPLE
    .\WinDSH.ps1 -DebugLog
    Run interactively and write detailed troubleshooting information to the current user's Desktop.

.EXAMPLE
    .\WinDSH.ps1 -AuditOnly -DebugLogPath C:\Temp\WinDSH-Debug.log
    Run an unattended audit and write the diagnostic log to a specific path.

.EXAMPLE
    .\WinDSH.ps1 -EnableAllSafe -WhatIf
    Preview the exact safe registry changes without modifying Windows.

.EXAMPLE
    .\WinDSH.ps1 -AuditOnly -RMM
    Emit one compact JSON object to stdout and create no report file by default.

.EXAMPLE
    .\WinDSH.ps1 -Version
    Print the tool version and exit.

.NOTES
    No ExecutionPolicy Bypass or persistent execution-policy change, encoded command, AV exclusion, Defender disabling,
    remote download, TPM clear, Secure Boot key modification, UEFI lock, VBS Mandatory
    mode, driver deletion, persistence, or scheduled task is used.

    Microsoft documentation references:
      https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
      https://learn.microsoft.com/windows-hardware/design/device-experiences/oem-hvci-enablement
      https://learn.microsoft.com/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection
      https://learn.microsoft.com/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
      https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
      https://learn.microsoft.com/windows/security/identity-protection/credential-guard/configure
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$AuditOnly,
    [switch]$EnableAllSafe,
    [switch]$EnableCredentialGuard,
    [switch]$AutoReboot,
    [ValidateSet('Text','Json','None')]
    [string]$ReportFormat,
    [switch]$JsonReport,
    [switch]$NoReport,
    [string]$ReportDirectory,
    [switch]$DebugLog,
    [string]$DebugLogPath,
    [switch]$Unattended,
    [switch]$RMM,
    [switch]$Version,
    [switch]$SelfTest,
    [Parameter(DontShow=$true)]
    [switch]$PauseOnExit,
    [Parameter(DontShow=$true)]
    [switch]$ElevatedChild
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Get-ComputerInfo and some Windows providers can emit transient progress overlays
# that visually cover the startup banner. WinDSH does not use progress output, so
# suppress it for this script process only.
$ProgressPreference = 'SilentlyContinue'

$script:ToolName = 'WinDSH'
$script:ToolVersion = '1.5.0'
$script:ContactEmail = 'windsh@rootauthority.com'
$script:SchemaVersion = '1.0'
# This value protects against accidental corruption only. It is NOT a tamper-proof
# security boundary because a deliberate editor can change both code and this value.
$script:ExpectedIntegrityHash = '74c89f6ef21058ff0847d8f961147cc0daacce11fdfbfa8d11a4dc11807ddcff'
$script:IntegrityState = $null
$script:RemediationAllowed = $true
$script:Changes = @()
$script:RestartRecommended = $false
$script:RestartReasons = @()
$script:EffectiveReportFormat = $null
$script:WasElevatedByTool = $false
$script:DebugEnabled = $false
$script:ResolvedDebugLogPath = $null
$script:RmmMode = [bool]$RMM
$script:PreviewRequested = [bool]$WhatIfPreference
$script:InitialState = $null
$script:FinalState = $null
$script:LastHvciDiagnostics = $null
$script:PlannedChanges = @()
$script:LastReportPath = $null
$script:LastExitCode = 0
$script:Outcome = [ordered]@{
    PolicyBlocked = $false
    IntegrityFailed = $false
    PrerequisiteUnavailable = $false
    RemediationFailed = $false
    UnsupportedSkipped = @()
    PolicyReasons = @()
    FailureReasons = @()
    PrerequisiteReasons = @()
}
$script:InvocationBoundParameters = @{}
foreach ($key in $PSBoundParameters.Keys) { $script:InvocationBoundParameters[$key] = $PSBoundParameters[$key] }

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-QuotedProcessArgument {
    param([Parameter(Mandatory=$true)][string]$Value)
    return ('"{0}"' -f ($Value -replace '"','\"'))
}

function Get-RelaunchArgumentString {
    # Use a native PowerShell array for Windows PowerShell 5.1 compatibility.
    $parts = @('-NoProfile','-File',(ConvertTo-QuotedProcessArgument $PSCommandPath))

    if ($AuditOnly) { $parts += '-AuditOnly' }
    if ($EnableAllSafe) { $parts += '-EnableAllSafe' }
    if ($EnableCredentialGuard) { $parts += '-EnableCredentialGuard' }
    if ($AutoReboot) { $parts += '-AutoReboot' }
    if ($JsonReport) { $parts += '-JsonReport' }
    if ($NoReport) { $parts += '-NoReport' }
    if ($DebugLog) { $parts += '-DebugLog' }
    if ($Unattended) { $parts += '-Unattended' }
    if ($RMM) { $parts += '-RMM' }
    if ($PauseOnExit) { $parts += '-PauseOnExit' }
    if ($script:PreviewRequested) { $parts += '-WhatIf' }
    $parts += '-ElevatedChild'
    if ($script:InvocationBoundParameters.ContainsKey('ReportFormat')) {
        $parts += '-ReportFormat'
        $parts += (ConvertTo-QuotedProcessArgument $ReportFormat)
    }
    if ($script:InvocationBoundParameters.ContainsKey('ReportDirectory')) {
        $parts += '-ReportDirectory'
        $parts += (ConvertTo-QuotedProcessArgument $ReportDirectory)
    }
    if ($script:InvocationBoundParameters.ContainsKey('DebugLogPath')) {
        $parts += '-DebugLogPath'
        $parts += (ConvertTo-QuotedProcessArgument $DebugLogPath)
    }
    return ($parts -join ' ')
}

function Test-PauseOnExitApplicable {
    if (-not $PauseOnExit) { return $false }

    # Deployment/unattended switches must never wait for keyboard input.
    $nonInteractiveRequested = ($AuditOnly -or $EnableAllSafe -or $EnableCredentialGuard -or $AutoReboot -or $JsonReport -or $NoReport -or $Unattended -or $RMM -or $Version -or $SelfTest -or $script:InvocationBoundParameters.ContainsKey('ReportFormat') -or $script:PreviewRequested)
    return (-not $nonInteractiveRequested)
}

function Wait-BeforeWinDSHClose {
    param([string]$Reason)

    if (-not (Test-PauseOnExitApplicable)) { return }

    Write-Host ''
    Write-Host ('-' * 82) -ForegroundColor DarkGray
    if (-not [string]::IsNullOrWhiteSpace($Reason)) {
        Write-Host $Reason -ForegroundColor Cyan
    }
    Write-Host 'Review the information above before closing this window.' -ForegroundColor Gray
    try {
        [void](Read-Host 'Press Enter to close WinDSH')
    }
    catch {
        # Read-Host can fail in unusual hosts. Keep the result visible briefly rather
        # than turning a successful/error exit into another exception.
        Start-Sleep -Seconds 10
    }
}

function Exit-WinDSH {
    param(
        [int]$Code = 0,
        [string]$Reason,
        [switch]$SkipPause
    )

    if (-not $SkipPause) { Wait-BeforeWinDSHClose -Reason $Reason }
    exit $Code
}

function Request-Elevation {
    if (Test-IsAdministrator) { return }

    if ($RMM) {
        $obj = [ordered]@{
            schemaVersion = $script:SchemaVersion
            tool = $script:ToolName
            version = $script:ToolVersion
            exitCode = 1
            status = 'AdministratorRequired'
            message = 'RMM mode must be started from an already elevated PowerShell/process context; WinDSH did not request interactive UAC.'
        }
        [Console]::Out.WriteLine(($obj | ConvertTo-Json -Compress -Depth 4))
        exit 1
    }

    if ($ElevatedChild) {
        Write-Host ''
        Write-Host 'Administrator permission was requested, but the elevated process still does not have an Administrator token.' -ForegroundColor Red
        Write-Host 'Ask your administrator/helpdesk to run this tool with an account that can approve the Windows UAC prompt.' -ForegroundColor Yellow
        Exit-WinDSH -Code 1 -Reason 'WinDSH could not obtain Administrator access.'
    }

    if (-not $PSCommandPath) {
        Write-Host 'This tool must be started from its .ps1 file.' -ForegroundColor Yellow
        Exit-WinDSH -Code 1 -Reason 'WinDSH could not start from a valid script file.'
    }

    Write-Host ''
    Write-Host 'Windows Administrator permission is required.' -ForegroundColor Yellow
    Write-Host 'A User Account Control (UAC) prompt will appear now. Choose Yes to continue.' -ForegroundColor Cyan

    try {
        $arguments = Get-RelaunchArgumentString
        # -WhatIf previews WinDSH remediation, not the UAC bootstrap itself.
        $savedWhatIfPreference = $WhatIfPreference
        $WhatIfPreference = $false
        try {
            $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -PassThru -Wait
        }
        finally { $WhatIfPreference = $savedWhatIfPreference }
        Exit-WinDSH -Code $child.ExitCode -SkipPause
    }
    catch {
        Write-Host ''
        Write-Host ('Administrator elevation was cancelled or failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
        Write-Host 'No Device Security settings were changed.' -ForegroundColor Gray
        Exit-WinDSH -Code 1 -Reason 'Administrator elevation was not completed.'
    }
}

function Get-DefaultDebugLogPath {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktopPath)) { $desktopPath = Join-Path $env:USERPROFILE 'Desktop' }
    if ([string]::IsNullOrWhiteSpace($desktopPath)) { $desktopPath = $env:TEMP }
    return (Join-Path $desktopPath ('WinDSH-Debug-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
}

function Initialize-DebugLogging {
    $script:DebugEnabled = [bool]($DebugLog -or $script:InvocationBoundParameters.ContainsKey('DebugLogPath'))
    if (-not $script:DebugEnabled) { return }

    if ($script:InvocationBoundParameters.ContainsKey('DebugLogPath') -and -not [string]::IsNullOrWhiteSpace($DebugLogPath)) {
        $script:ResolvedDebugLogPath = [Environment]::ExpandEnvironmentVariables($DebugLogPath)
    }
    else {
        $script:ResolvedDebugLogPath = Get-DefaultDebugLogPath
    }

    try {
        $parent = Split-Path -Parent $script:ResolvedDebugLogPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -ItemType Directory -Force -WhatIf:$false | Out-Null
        }
        $header = @(
            ('=' * 82),
            ('{0} v{1} diagnostic log' -f $script:ToolName,$script:ToolVersion),
            $script:ContactEmail,
            ('Started: {0}' -f (Get-Date).ToString('s')),
            ('Computer: {0}' -f $env:COMPUTERNAME),
            ('User: {0}\\{1}' -f $env:USERDOMAIN,$env:USERNAME),
            ('PowerShell: {0} ({1})' -f $PSVersionTable.PSVersion,$PSVersionTable.PSEdition),
            ('64-bit process: {0}' -f [Environment]::Is64BitProcess),
            ('Elevated: {0}' -f (Test-IsAdministrator)),
            ('Script path: {0}' -f $PSCommandPath),
            ('=' * 82),
            ''
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($script:ResolvedDebugLogPath,$header,(New-Object Text.UTF8Encoding($false)))
        if (-not $script:RmmMode) { Write-Host ('Debug logging: {0}' -f $script:ResolvedDebugLogPath) -ForegroundColor DarkGray }
    }
    catch {
        $script:DebugEnabled = $false
        if (-not $script:RmmMode) { Write-Host ('WARNING: Debug log could not be created: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
    }
}

function Write-DebugLog {
    param([Parameter(Mandatory=$true)][string]$Message)
    if (-not $script:DebugEnabled -or [string]::IsNullOrWhiteSpace($script:ResolvedDebugLogPath)) { return }
    try {
        $line = '[{0}] {1}{2}' -f (Get-Date -Format 'HH:mm:ss.fff'),$Message,[Environment]::NewLine
        [IO.File]::AppendAllText($script:ResolvedDebugLogPath,$line,(New-Object Text.UTF8Encoding($false)))
    }
    catch { }
}

function Write-DebugException {
    param(
        [Parameter(Mandatory=$true)][string]$Stage,
        [Parameter(Mandatory=$true)]$ErrorRecord
    )
    if (-not $script:DebugEnabled) { return }
    Write-DebugLog ('FAILED STAGE: {0}' -f $Stage)
    Write-DebugLog ('Exception type: {0}' -f $ErrorRecord.Exception.GetType().FullName)
    Write-DebugLog ('Message: {0}' -f $ErrorRecord.Exception.Message)
    Write-DebugLog ('FullyQualifiedErrorId: {0}' -f $ErrorRecord.FullyQualifiedErrorId)
    Write-DebugLog ('CategoryInfo: {0}' -f $ErrorRecord.CategoryInfo)
    if ($ErrorRecord.InvocationInfo) {
        Write-DebugLog ('Position: {0}' -f (($ErrorRecord.InvocationInfo.PositionMessage -replace '[\r\n]+',' | ').Trim()))
    }
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.ScriptStackTrace)) {
        Write-DebugLog ('ScriptStackTrace: {0}' -f ($ErrorRecord.ScriptStackTrace -replace '[\r\n]+',' | '))
    }
}

function Invoke-DebugStage {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    Write-DebugLog ('BEGIN: {0}' -f $Name)
    try {
        $result = & $ScriptBlock
        Write-DebugLog ('END: {0} - SUCCESS' -f $Name)
        return $result
    }
    catch {
        Write-DebugException -Stage $Name -ErrorRecord $_
        throw
    }
}

function Write-SystemStateDebugSnapshot {
    param([Parameter(Mandatory=$true)]$State)
    if (-not $script:DebugEnabled) { return }
    try {
        Write-DebugLog 'SYSTEM STATE SNAPSHOT:'
        Write-DebugLog ('  Computer={0}; Windows={1}; Build={2}; Firmware={3}' -f $State.Computer.Name,$State.Computer.ProductName,$State.Computer.Build,$State.Firmware.Type)
        Write-DebugLog ('  SecureBootSupported={0}; SecureBootEnabled={1}' -f $State.Firmware.SecureBootSupported,$State.Firmware.SecureBootEnabled)
        Write-DebugLog ('  TPM Present={0}; Ready={1}; SpecVersion={2}' -f $State.TPM.Present,$State.TPM.Ready,$State.TPM.SpecVersion)
        Write-DebugLog ('  Virtualization FirmwareEnabled={0}; HypervisorPresent={1}; SLAT={2}' -f $State.Virtualization.VirtualizationFirmwareEnabled,$State.Virtualization.HypervisorPresent,$State.Virtualization.SLAT)
        Write-DebugLog ('  VBS StatusCode={0}; Status={1}' -f $State.VBS.StatusCode,$State.VBS.Status)
        if ($State.DeviceGuardRaw) {
            $a = $State.DeviceGuardRaw.AvailableSecurityProperties
            $c = $State.DeviceGuardRaw.SecurityServicesConfigured
            $r = $State.DeviceGuardRaw.SecurityServicesRunning
            Write-DebugLog ('  DeviceGuard Available type={0}; values=[{1}]' -f $(if ($null -eq $a) {'<null>'} else {$a.GetType().FullName}),$(if ($null -eq $a) {''} else {($a -join ',')}))
            Write-DebugLog ('  DeviceGuard Configured type={0}; values=[{1}]' -f $(if ($null -eq $c) {'<null>'} else {$c.GetType().FullName}),$(if ($null -eq $c) {''} else {($c -join ',')}))
            Write-DebugLog ('  DeviceGuard Running type={0}; values=[{1}]' -f $(if ($null -eq $r) {'<null>'} else {$r.GetType().FullName}),$(if ($null -eq $r) {''} else {($r -join ',')}))
        }
        else {
            Write-DebugLog '  DeviceGuard provider returned no object.'
        }
    }
    catch {
        Write-DebugException -Stage 'Write system-state debug snapshot' -ErrorRecord $_
    }
}

function Get-SelfIntegrityResult {
    $result = [ordered]@{
        Status = 'Unknown'
        ExpectedHash = $script:ExpectedIntegrityHash
        ActualHash = $null
        ScriptPath = $PSCommandPath
        Note = 'Accidental-corruption check only; not a tamper-proof security boundary.'
    }

    try {
        if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
            $result.Status = 'Unavailable'
            return [pscustomobject]$result
        }
        $source = [IO.File]::ReadAllText($PSCommandPath)
        $placeholder = '0' * 64
        $pattern = '(?m)^\$script:ExpectedIntegrityHash\s*=\s*''[0-9A-Fa-f]{64}''\s*$'
        $normalizedLine = "`$script:ExpectedIntegrityHash = '$placeholder'"
        $normalized = [regex]::Replace($source,$pattern,$normalizedLine,1)
        if ($normalized -eq $source -and $script:ExpectedIntegrityHash -ne $placeholder) {
            $result.Status = 'Unavailable'
            $result.Note = 'Integrity marker was not found in the expected format.'
            return [pscustomobject]$result
        }

        # This is an accidental-corruption check. Normalize line endings so an editor
        # changing CRLF to LF (or vice versa) does not invalidate an otherwise identical file.
        $normalized = $normalized -replace "`r`n", "`n"
        $normalized = $normalized -replace "`r", "`n"

        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
            $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
        }
        finally { $sha.Dispose() }
        $result.ActualHash = $actual
        if ($actual -eq $script:ExpectedIntegrityHash.ToLowerInvariant()) { $result.Status = 'OK' }
        else { $result.Status = 'FAILED' }
    }
    catch {
        $result.Status = 'ERROR'
        $result.Note = ('Integrity calculation failed: {0}' -f $_.Exception.Message)
        Write-DebugException -Stage 'Self integrity check' -ErrorRecord $_
    }
    return [pscustomobject]$result
}

function Invoke-SelfIntegrityCheck {
    $script:IntegrityState = Get-SelfIntegrityResult
    Write-DebugLog ('Integrity status: {0}; expected={1}; actual={2}' -f $script:IntegrityState.Status,$script:IntegrityState.ExpectedHash,$script:IntegrityState.ActualHash)

    if ($script:IntegrityState.Status -eq 'OK') { return $true }

    $script:RemediationAllowed = $false
    $script:Outcome.IntegrityFailed = $true
    if (-not $script:RmmMode) {
        Write-Host ''
        Write-Host ('=' * 82) -ForegroundColor DarkGray
        Write-Host ' Script integrity warning' -ForegroundColor Yellow
        Write-Host ('=' * 82) -ForegroundColor DarkGray
        Write-Host ('Integrity status: {0}' -f $script:IntegrityState.Status) -ForegroundColor Yellow
        Write-Host ('The script does not match the expected {0} v{1} self-check value.' -f $script:ToolName,$script:ToolVersion) -ForegroundColor Yellow
        Write-Host 'This check is intended to detect accidental corruption, incomplete copies, or unintended edits.' -ForegroundColor Gray
        Write-Host 'Security-changing actions are disabled for this run; audit and debug logging remain available.' -ForegroundColor Gray
        if ($script:IntegrityState.ActualHash) {
            Write-Host ('Calculated normalized SHA-256: {0}' -f $script:IntegrityState.ActualHash) -ForegroundColor DarkGray
        }
    }
    return $false
}

function Test-RemediationAllowed {
    if ($script:RemediationAllowed) { return $true }
    Write-Host 'Security changes are disabled because the self-integrity check did not pass.' -ForegroundColor Red
    return $false
}

function Add-UniqueString {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Array,
        [Parameter(Mandatory=$true)][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return @($Array) }
    $result = @($Array)
    if (-not ($result -contains $Value)) { $result += $Value }
    return $result
}

function Set-OutcomeIssue {
    param(
        [ValidateSet('Policy','Prerequisite','Failure','Unsupported')][string]$Type,
        [Parameter(Mandatory=$true)][string]$Reason
    )
    switch ($Type) {
        'Policy' {
            $script:Outcome.PolicyBlocked = $true
            $script:Outcome.PolicyReasons = @(Add-UniqueString -Array @($script:Outcome.PolicyReasons) -Value $Reason)
        }
        'Prerequisite' {
            $script:Outcome.PrerequisiteUnavailable = $true
            $script:Outcome.PrerequisiteReasons = @(Add-UniqueString -Array @($script:Outcome.PrerequisiteReasons) -Value $Reason)
        }
        'Failure' {
            $script:Outcome.RemediationFailed = $true
            $script:Outcome.FailureReasons = @(Add-UniqueString -Array @($script:Outcome.FailureReasons) -Value $Reason)
        }
        'Unsupported' {
            $script:Outcome.UnsupportedSkipped = @(Add-UniqueString -Array @($script:Outcome.UnsupportedSkipped) -Value $Reason)
        }
    }
}

function Get-ExitCodeMeaning {
    param([int]$Code)
    switch ($Code) {
        0 { 'Success; no WinDSH-requested restart is required.' }
        1 { 'Fatal/internal error or required Administrator context was unavailable.' }
        2 { 'Requested remediation was blocked by organization-managed policy.' }
        3 { 'WinDSH self-integrity check failed; remediation is blocked and the file should be replaced with an intact copy.' }
        4 { 'An explicitly requested remediation is unavailable because a required prerequisite is missing.' }
        5 { 'One or more requested remediation actions failed or could not complete safely.' }
        3010 { 'Success; a Windows restart is required/recommended to complete verification.' }
        default { 'Unknown WinDSH exit code.' }
    }
}

function Resolve-InvocationMode {
    if ($AuditOnly -and ($EnableAllSafe -or $EnableCredentialGuard)) {
        throw '-AuditOnly cannot be combined with an enable/remediation switch.'
    }
    if ($JsonReport -and $NoReport) {
        throw '-JsonReport and -NoReport cannot be used together.'
    }
    if ($JsonReport -and $script:InvocationBoundParameters.ContainsKey('ReportFormat') -and $ReportFormat -ne 'Json') {
        throw '-JsonReport conflicts with the specified -ReportFormat.'
    }
    if ($NoReport -and $script:InvocationBoundParameters.ContainsKey('ReportFormat') -and $ReportFormat -ne 'None') {
        throw '-NoReport conflicts with the specified -ReportFormat.'
    }
    if ($script:PreviewRequested -and -not ($EnableAllSafe -or $EnableCredentialGuard)) {
        throw '-WhatIf must be combined with -EnableAllSafe or -EnableCredentialGuard. Interactive users can press P to preview recommended changes.'
    }

    $explicitReportRequest = ($JsonReport -or $NoReport -or $script:InvocationBoundParameters.ContainsKey('ReportFormat'))
    if ($NoReport) {
        $script:EffectiveReportFormat = 'None'
    }
    elseif ($JsonReport) {
        $script:EffectiveReportFormat = 'Json'
    }
    elseif ($script:InvocationBoundParameters.ContainsKey('ReportFormat')) {
        $script:EffectiveReportFormat = $ReportFormat
    }
    elseif ($RMM) {
        # RMM stdout is the report by default. A file is created only when explicitly requested.
        $script:EffectiveReportFormat = 'None'
    }

    $nonInteractiveRequested = ($AuditOnly -or $EnableAllSafe -or $EnableCredentialGuard -or $AutoReboot -or $JsonReport -or $NoReport -or $Unattended -or $RMM -or $script:InvocationBoundParameters.ContainsKey('ReportFormat') -or $script:PreviewRequested)

    # -EnableAllSafe automatically creates a plain-text report unless the caller explicitly
    # chose another report mode. Other unattended modes retain Text as the normal default.
    if ($nonInteractiveRequested -and -not $script:EffectiveReportFormat) {
        $script:EffectiveReportFormat = 'Text'
    }
    if ($RMM -and -not $explicitReportRequest) {
        $script:EffectiveReportFormat = 'None'
    }

    return [bool]$nonInteractiveRequested
}

function Get-DefaultReportDirectory {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktopPath)) {
        $desktopPath = Join-Path $env:USERPROFILE 'Desktop'
    }
    if ([string]::IsNullOrWhiteSpace($desktopPath)) {
        $desktopPath = $env:TEMP
    }
    return (Join-Path $desktopPath 'WinDSH-Reports')
}

function Get-ReportRoot {
    if (-not [string]::IsNullOrWhiteSpace($ReportDirectory)) {
        return [Environment]::ExpandEnvironmentVariables($ReportDirectory)
    }
    return Get-DefaultReportDirectory
}

function Initialize-ReportFolder {
    $root = Get-ReportRoot
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -Path $root -ItemType Directory -Force -WhatIf:$false | Out-Null
    }
    return $root
}

function Write-Section {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Host ''
    Write-Host ('=' * 82) -ForegroundColor DarkGray
    Write-Host (' {0}' -f $Title) -ForegroundColor Cyan
    Write-Host ('=' * 82) -ForegroundColor DarkGray
}

function Write-SubSection {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Host ''
    Write-Host $Title -ForegroundColor White
    Write-Host ('-' * 82) -ForegroundColor DarkGray
}

function Write-StatusLine {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][AllowNull()][AllowEmptyString()]$Value,
        [ValidateSet('Good','Warn','Bad','Info')][string]$Kind = 'Info'
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        $Value = 'Not reported'
    }
    else {
        $Value = [string]$Value
    }
    $color = switch ($Kind) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad'  { 'Red' }
        default { 'Gray' }
    }
    Write-Host ('{0,-45} {1}' -f $Name, $Value) -ForegroundColor $color
}

function Write-SummaryItem {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Status,
        [ValidateSet('Good','Warn','Bad','Info','Unavailable')][string]$Kind = 'Info',
        [string]$NextStep
    )
    $tag = switch ($Kind) {
        'Good' { '[OK]' }
        'Warn' { '[ACTION]' }
        'Bad'  { '[PROBLEM]' }
        'Unavailable' { '[N/A]' }
        default { '[INFO]' }
    }
    $color = switch ($Kind) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad'  { 'Red' }
        'Unavailable' { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host ('{0,-10} {1,-34} {2}' -f $tag,$Name,$Status) -ForegroundColor $color
    if (-not [string]::IsNullOrWhiteSpace($NextStep)) {
        Write-Host ('           Next: {0}' -f $NextStep) -ForegroundColor DarkGray
    }
}

function Get-ObjectPropertySafe {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        Write-DebugException -Stage ('Read registry value {0}\\{1}' -f $Path,$Name) -ErrorRecord $_
        return $null
    }
}

function Set-DwordValue {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][int]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Test-ArrayContains {
    param($Array, [int]$Value)
    if ($null -eq $Array) { return $false }
    return (@($Array) -contains $Value)
}

function ConvertTo-DGStatusText {
    param([Nullable[int]]$Value)
    if ($null -eq $Value) { return 'Unknown / provider unavailable' }
    switch ([int]$Value) {
        0 { 'Disabled' }
        1 { 'Configured, not running' }
        2 { 'Running' }
        default { 'Unknown ({0})' -f $Value }
    }
}

function Add-Change {
    param(
        [string]$Feature,
        [string]$Action,
        [string]$Before,
        [string]$After,
        [string]$Result
    )
    $script:Changes += [pscustomobject]@{
        Time = (Get-Date).ToString('s')
        Feature = $Feature
        Action = $Action
        Before = $Before
        After = $After
        Result = $Result
    }
}

function Set-RestartRecommended {
    param([Parameter(Mandatory=$true)][string]$Reason)
    $script:RestartRecommended = $true
    if (-not ($script:RestartReasons -contains $Reason)) {
        $script:RestartReasons += $Reason
    }
}

function Get-PendingRestartState {
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $pendingRename = $false
    try {
        $value = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        $pendingRename = ($null -ne $value)
    }
    catch { Write-DebugException -Stage 'Pending restart: PendingFileRenameOperations' -ErrorRecord $_ }
    return [pscustomobject]@{
        Pending = [bool]($cbs -or $wu -or $pendingRename)
        ComponentBasedServicing = [bool]$cbs
        WindowsUpdate = [bool]$wu
        PendingFileRenameOperations = [bool]$pendingRename
    }
}

function Get-DeviceGuardState {
    try {
        return Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    }
    catch {
        Write-DebugException -Stage 'Query Win32_DeviceGuard' -ErrorRecord $_
        return $null
    }
}

function Test-CredentialGuardEditionSupport {
    param([string]$EditionID)
    if ([string]::IsNullOrWhiteSpace($EditionID)) { return $false }
    return [bool]($EditionID -match 'Enterprise|Education')
}

function Get-VirtualMachineAssessment {
    param(
        [string]$Manufacturer,
        [string]$Model
    )
    $text = ('{0} {1}' -f $Manufacturer,$Model).Trim()
    $detected = $false
    $platform = $null

    if ($text -match '(?i)VMware') { $detected = $true; $platform = 'VMware' }
    elseif ($text -match '(?i)VirtualBox|innotek') { $detected = $true; $platform = 'VirtualBox' }
    elseif ($text -match '(?i)Microsoft Corporation.*Virtual Machine|Virtual Machine.*Microsoft Corporation') { $detected = $true; $platform = 'Hyper-V / Microsoft virtual machine' }
    elseif ($text -match '(?i)KVM|QEMU') { $detected = $true; $platform = 'KVM/QEMU' }
    elseif ($text -match '(?i)Xen|HVM domU') { $detected = $true; $platform = 'Xen' }
    elseif ($text -match '(?i)Parallels') { $detected = $true; $platform = 'Parallels' }
    elseif ($text -match '(?i)Nutanix') { $detected = $true; $platform = 'Nutanix AHV or related virtual platform' }

    return [pscustomobject]@{
        Detected = $detected
        PlatformHint = $platform
        Evidence = if ($detected) { $text } else { $null }
        Note = if ($detected) { 'Virtual hardware capabilities depend on the hypervisor configuration; TPM and Secure Boot may be virtualized.' } else { $null }
    }
}

function Get-ComputerAndOsState {
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    catch { Write-DebugException -Stage 'Query Win32_OperatingSystem' -ErrorRecord $_; throw }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    catch { Write-DebugException -Stage 'Query Win32_ComputerSystem' -ErrorRecord $_; throw }
    try { $processors = @(Get-CimInstance Win32_Processor -ErrorAction Stop) }
    catch { Write-DebugException -Stage 'Query Win32_Processor' -ErrorRecord $_; $processors = @() }

    $cvPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $productName = Get-RegistryValueSafe -Path $cvPath -Name 'ProductName'
    $displayVersion = Get-RegistryValueSafe -Path $cvPath -Name 'DisplayVersion'
    $build = Get-RegistryValueSafe -Path $cvPath -Name 'CurrentBuildNumber'
    $ubr = Get-RegistryValueSafe -Path $cvPath -Name 'UBR'
    $editionId = Get-RegistryValueSafe -Path $cvPath -Name 'EditionID'

    if (-not $productName) { $productName = $os.Caption }
    if (-not $build) { $build = $os.BuildNumber }
    $buildInt = 0
    [void][int]::TryParse([string]$build, [ref]$buildInt)

    $rawProductName = [string]$productName
    $displayProductName = $rawProductName
    if ($buildInt -ge 22000 -and $displayProductName -match '^Windows 10\b') {
        $displayProductName = $displayProductName -replace '^Windows 10', 'Windows 11'
    }

    $domainRole = [int](Get-ObjectPropertySafe -Object $cs -Name 'DomainRole' -Default 0)
    $computer = [pscustomobject]@{
        Name = $env:COMPUTERNAME
        Manufacturer = [string]$cs.Manufacturer
        Model = [string]$cs.Model
        ProductName = [string]$displayProductName
        RegistryProductName = [string]$rawProductName
        EditionID = [string]$editionId
        DisplayVersion = [string]$displayVersion
        Build = if ($null -ne $ubr) { '{0}.{1}' -f $build,$ubr } else { [string]$build }
        BuildNumber = $buildInt
        OSArchitecture = [string]$os.OSArchitecture
        Domain = [string]$cs.Domain
        DomainRole = $domainRole
        IsDomainController = [bool]($domainRole -eq 4 -or $domainRole -eq 5)
    }

    $dep = [pscustomobject]@{
        Available = Get-ObjectPropertySafe -Object $os -Name 'DataExecutionPrevention_Available' -Default $null
        Drivers = Get-ObjectPropertySafe -Object $os -Name 'DataExecutionPrevention_Drivers' -Default $null
        Applications32Bit = Get-ObjectPropertySafe -Object $os -Name 'DataExecutionPrevention_32BitApplications' -Default $null
    }

    return [pscustomobject]@{
        OS = $os
        ComputerSystem = $cs
        Processors = $processors
        Computer = $computer
        DEP = $dep
        VirtualMachine = Get-VirtualMachineAssessment -Manufacturer $computer.Manufacturer -Model $computer.Model
    }
}

function Get-FirmwareState {
    $firmwareType = 'Unknown'
    try {
        $ci = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
        if ($null -ne $ci.BiosFirmwareType) { $firmwareType = [string]$ci.BiosFirmwareType }
    }
    catch { Write-DebugException -Stage 'Determine BIOS firmware type' -ErrorRecord $_ }

    $secureBootSupported = $false
    $secureBootEnabled = $null
    try {
        $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $secureBootSupported = $true
        if ($firmwareType -eq 'Unknown') { $firmwareType = 'UEFI' }
    }
    catch {
        Write-DebugException -Stage 'Query Secure Boot state' -ErrorRecord $_
        if ($firmwareType -eq 'Unknown') { $firmwareType = 'Legacy BIOS or unsupported UEFI' }
    }

    return [pscustomobject]@{
        Type = $firmwareType
        SecureBootSupported = $secureBootSupported
        SecureBootEnabled = $secureBootEnabled
    }
}

function Get-TpmState {
    $present = $false
    $ready = $false
    $enabled = $null
    $activated = $null
    $specVersion = $null
    $manufacturer = $null
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $present = [bool]$tpm.TpmPresent
        $ready = [bool]$tpm.TpmReady
        $enabled = $tpm.TpmEnabled
        $activated = $tpm.TpmActivated
    }
    catch { Write-DebugException -Stage 'Query Get-Tpm' -ErrorRecord $_ }

    if ($present) {
        try {
            $tpmWmi = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
            $specVersion = [string]$tpmWmi.SpecVersion
            $manufacturer = [string]$tpmWmi.ManufacturerVersionInfo
        }
        catch { Write-DebugException -Stage 'Query Win32_Tpm details' -ErrorRecord $_ }
    }

    $isTpm2 = [bool]($present -and (-not [string]::IsNullOrWhiteSpace($specVersion)) -and ($specVersion -match '(^|\D)2\.0(\D|$)'))
    return [pscustomobject]@{
        Present = $present
        Ready = $ready
        Enabled = $enabled
        Activated = $activated
        SpecVersion = $specVersion
        IsTPM2 = $isTpm2
        ManufacturerVersionInfo = $manufacturer
    }
}

function Get-VirtualizationState {
    param(
        [Parameter(Mandatory=$true)]$ComputerSystem,
        [AllowEmptyCollection()][object[]]$Processors
    )
    $processorsArray = @($Processors)
    $hypervisorPresent = [bool](Get-ObjectPropertySafe -Object $ComputerSystem -Name 'HypervisorPresent' -Default $false)
    $vmMonitor = @($processorsArray | Where-Object { (Get-ObjectPropertySafe -Object $_ -Name 'VMMonitorModeExtensions' -Default $false) -eq $true }).Count -gt 0
    $virtFirmwareRaw = @($processorsArray | Where-Object { (Get-ObjectPropertySafe -Object $_ -Name 'VirtualizationFirmwareEnabled' -Default $false) -eq $true }).Count -gt 0
    $slat = @($processorsArray | Where-Object { (Get-ObjectPropertySafe -Object $_ -Name 'SecondLevelAddressTranslationExtensions' -Default $false) -eq $true }).Count -gt 0
    $virtualizationEnabled = [bool]($virtFirmwareRaw -or $hypervisorPresent)
    $slatAssessment = if ($slat) {
        'Supported / reported by CPU'
    }
    elseif ($hypervisorPresent) {
        'Not reported by Win32_Processor while hypervisor is active'
    }
    else {
        'Not reported / unsupported'
    }
    return [pscustomobject]@{
        HypervisorPresent = $hypervisorPresent
        VMMonitorModeExtensions = $vmMonitor
        VirtualizationFirmwareEnabled = $virtualizationEnabled
        VirtualizationFirmwareRaw = $virtFirmwareRaw
        SLAT = $slat
        SLATAssessment = $slatAssessment
    }
}

function Get-DeviceGuardFeatureState {
    param(
        $DeviceGuard,
        [Parameter(Mandatory=$true)]$Computer,
        [Parameter(Mandatory=$true)]$Firmware,
        [Parameter(Mandatory=$true)]$TPM
    )

    $available = @()
    $configured = @()
    $running = @()
    $vbsStatus = $null
    if ($DeviceGuard) {
        $available = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'AvailableSecurityProperties' -Default @()))
        $configured = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'SecurityServicesConfigured' -Default @()))
        $running = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'SecurityServicesRunning' -Default @()))
        $rawVbsStatus = Get-ObjectPropertySafe -Object $DeviceGuard -Name 'VirtualizationBasedSecurityStatus'
        if ($null -ne $rawVbsStatus) { $vbsStatus = [int]$rawVbsStatus }
    }

    $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $hvciRegPath = Join-Path $dgPath 'Scenarios\HypervisorEnforcedCodeIntegrity'
    $systemGuardRegPath = Join-Path $dgPath 'Scenarios\SystemGuard'
    $kernelStackRegPath = Join-Path $dgPath 'Scenarios\KernelShadowStacks'
    $ciConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $policyDGPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

    $vbsReg = Get-RegistryValueSafe -Path $dgPath -Name 'EnableVirtualizationBasedSecurity'
    $platformSecurityReg = Get-RegistryValueSafe -Path $dgPath -Name 'RequirePlatformSecurityFeatures'
    $hvciReg = Get-RegistryValueSafe -Path $hvciRegPath -Name 'Enabled'
    $systemGuardReg = Get-RegistryValueSafe -Path $systemGuardRegPath -Name 'Enabled'
    $kernelStackReg = Get-RegistryValueSafe -Path $kernelStackRegPath -Name 'Enabled'
    $blocklistReg = Get-RegistryValueSafe -Path $ciConfigPath -Name 'VulnerableDriverBlocklistEnable'
    $lsaCfgFlags = Get-RegistryValueSafe -Path $lsaPath -Name 'LsaCfgFlags'

    $policyVbs = Get-RegistryValueSafe -Path $policyDGPath -Name 'EnableVirtualizationBasedSecurity'
    $policyHvci = Get-RegistryValueSafe -Path $policyDGPath -Name 'HypervisorEnforcedCodeIntegrity'
    $policySecureLaunch = Get-RegistryValueSafe -Path $policyDGPath -Name 'ConfigureSystemGuardLaunch'
    $policyCredentialGuard = Get-RegistryValueSafe -Path $policyDGPath -Name 'LsaCfgFlags'

    $credentialGuardConfigured = (Test-ArrayContains $configured 1) -or ($lsaCfgFlags -eq 1) -or ($lsaCfgFlags -eq 2) -or ($policyCredentialGuard -eq 1) -or ($policyCredentialGuard -eq 2)
    $credentialGuardRunning = Test-ArrayContains $running 1
    $hvciConfigured = (Test-ArrayContains $configured 2) -or ($hvciReg -eq 1)
    $hvciRunning = Test-ArrayContains $running 2
    $secureLaunchConfigured = (Test-ArrayContains $configured 3) -or ($systemGuardReg -eq 1) -or ($policySecureLaunch -eq 1)
    $secureLaunchRunning = Test-ArrayContains $running 3
    $smmMeasurementConfigured = Test-ArrayContains $configured 4
    $smmMeasurementRunning = Test-ArrayContains $running 4
    $kernelStackConfigured = (Test-ArrayContains $configured 5) -or (Test-ArrayContains $configured 6) -or ($kernelStackReg -eq 1)
    $kernelStackRunning = Test-ArrayContains $running 5
    $kernelStackAudit = Test-ArrayContains $running 6
    $hsptConfigured = Test-ArrayContains $configured 7
    $hsptRunning = Test-ArrayContains $running 7

    $isWin11 = ($Computer.BuildNumber -ge 22000)
    $blocklistEffective = 'Unknown'
    if ($hvciRunning) { $blocklistEffective = 'Enforced by Memory Integrity (HVCI)' }
    elseif ($blocklistReg -eq 1) { $blocklistEffective = 'Enabled by explicit local preference' }
    elseif ($blocklistReg -eq 0) { $blocklistEffective = 'Disabled by explicit local preference' }
    elseif ($isWin11 -and $Computer.BuildNumber -ge 22621) { $blocklistEffective = 'Windows default is enabled; no explicit local override found' }
    else { $blocklistEffective = 'No explicit local preference found' }

    $hardware = [pscustomobject]@{
        HypervisorSupport = (Test-ArrayContains $available 1)
        SecureBootCapability = (Test-ArrayContains $available 2)
        DMACapability = (Test-ArrayContains $available 3)
        SecureMemoryOverwrite = (Test-ArrayContains $available 4)
        NXAvailable = (Test-ArrayContains $available 5)
        SMMMitigations = (Test-ArrayContains $available 6)
        MBECorGMET = (Test-ArrayContains $available 7)
        APICVirtualization = (Test-ArrayContains $available 8)
        RawAvailableSecurityProperties = $available
    }

    $features = [pscustomobject]@{
        CredentialGuard = [pscustomobject]@{
            Configured = $credentialGuardConfigured
            Running = $credentialGuardRunning
            LsaCfgFlags = $lsaCfgFlags
            ManagedByPolicy = ($null -ne $policyCredentialGuard)
            PolicyValue = $policyCredentialGuard
            EditionSupported = (Test-CredentialGuardEditionSupport -EditionID ([string]$Computer.EditionID))
        }
        MemoryIntegrity = [pscustomobject]@{
            Configured = $hvciConfigured
            Running = $hvciRunning
            RegistryEnabled = $hvciReg
            ManagedByPolicy = (($null -ne $policyVbs) -or ($null -ne $policyHvci))
        }
        SecureLaunch = [pscustomobject]@{
            Configured = $secureLaunchConfigured
            Running = $secureLaunchRunning
            RegistryEnabled = $systemGuardReg
            ManagedByPolicy = ($null -ne $policySecureLaunch)
            BasicPrerequisitesConfirmed = [bool](($Firmware.Type -match 'UEFI') -and $TPM.IsTPM2)
        }
        SMMFirmwareMeasurement = [pscustomobject]@{
            Configured = $smmMeasurementConfigured
            Running = $smmMeasurementRunning
        }
        KernelStackProtection = [pscustomobject]@{
            Configured = $kernelStackConfigured
            Running = $kernelStackRunning
            AuditMode = $kernelStackAudit
            RegistryEnabled = $kernelStackReg
            WindowsVersionEligible = ($isWin11 -and $Computer.BuildNumber -ge 22621)
        }
        HypervisorEnforcedPagingTranslation = [pscustomobject]@{
            Configured = $hsptConfigured
            Running = $hsptRunning
        }
        VulnerableDriverBlocklist = [pscustomobject]@{
            RegistryValue = $blocklistReg
            EffectiveAssessment = $blocklistEffective
        }
    }

    $policy = [pscustomobject]@{
        EnableVirtualizationBasedSecurity = $policyVbs
        HypervisorEnforcedCodeIntegrity = $policyHvci
        ConfigureSystemGuardLaunch = $policySecureLaunch
        CredentialGuardLsaCfgFlags = $policyCredentialGuard
    }

    $raw = if ($DeviceGuard) {
        [pscustomobject]@{
            RequiredSecurityProperties = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'RequiredSecurityProperties' -Default @()))
            AvailableSecurityProperties = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'AvailableSecurityProperties' -Default @()))
            SecurityServicesConfigured = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'SecurityServicesConfigured' -Default @()))
            SecurityServicesRunning = @((Get-ObjectPropertySafe -Object $DeviceGuard -Name 'SecurityServicesRunning' -Default @()))
            VirtualizationBasedSecurityStatus = (Get-ObjectPropertySafe -Object $DeviceGuard -Name 'VirtualizationBasedSecurityStatus')
            SmmIsolationLevel = (Get-ObjectPropertySafe -Object $DeviceGuard -Name 'SmmIsolationLevel')
            CodeIntegrityPolicyEnforcementStatus = (Get-ObjectPropertySafe -Object $DeviceGuard -Name 'CodeIntegrityPolicyEnforcementStatus')
            UsermodeCodeIntegrityPolicyEnforcementStatus = (Get-ObjectPropertySafe -Object $DeviceGuard -Name 'UsermodeCodeIntegrityPolicyEnforcementStatus')
        }
    } else { $null }

    return [pscustomobject]@{
        HardwareCapabilities = $hardware
        VBS = [pscustomobject]@{
            StatusCode = $vbsStatus
            Status = (ConvertTo-DGStatusText -Value $vbsStatus)
            RegistryEnabled = $vbsReg
            RequirePlatformSecurityFeatures = $platformSecurityReg
        }
        Features = $features
        Policy = $policy
        DeviceGuardRaw = $raw
    }
}

function Get-SystemState {
    # v1.5 keeps this orchestration function intentionally small. Each domain collector
    # can fail/log independently and can be regression-tested without a 300-line monolith.
    $base = Get-ComputerAndOsState
    $firmware = Get-FirmwareState
    $tpm = Get-TpmState
    $virtualization = Get-VirtualizationState -ComputerSystem $base.ComputerSystem -Processors @($base.Processors)
    $dg = Get-DeviceGuardState
    $security = Get-DeviceGuardFeatureState -DeviceGuard $dg -Computer $base.Computer -Firmware $firmware -TPM $tpm

    return [pscustomobject]@{
        Timestamp = (Get-Date).ToString('s')
        Computer = $base.Computer
        VirtualMachine = $base.VirtualMachine
        Firmware = $firmware
        TPM = $tpm
        Virtualization = $virtualization
        HardwareCapabilities = $security.HardwareCapabilities
        DEP = $base.DEP
        VBS = $security.VBS
        Features = $security.Features
        Policy = $security.Policy
        Restart = Get-PendingRestartState
        DeviceGuardRaw = $security.DeviceGuardRaw
    }
}

function Get-UnsupportedCapabilities {
    param([Parameter(Mandatory=$true)]$State)
    $items = @()

    if (-not $State.Firmware.SecureBootSupported) {
        $items += [pscustomobject]@{ Feature='Secure Boot'; Status='Unavailable or not exposed to Windows'; Reason='Native UEFI Secure Boot support is not confirmed.' }
    }
    if (-not $State.TPM.Present) {
        $items += [pscustomobject]@{ Feature='TPM / Security Processor'; Status='Not available'; Reason='Windows cannot see a TPM. Check Intel PTT / AMD fTPM / discrete TPM availability.' }
    }
    elseif (-not $State.TPM.IsTPM2) {
        $items += [pscustomobject]@{ Feature='TPM 2.0'; Status='Not confirmed'; Reason=('Reported TPM specification: {0}' -f $(if ($State.TPM.SpecVersion) {$State.TPM.SpecVersion} else {'unknown'})) }
    }
    if (-not $State.HardwareCapabilities.DMACapability) {
        $items += [pscustomobject]@{ Feature='Kernel DMA / Memory Access Protection'; Status='Capability not reported'; Reason='The platform may require VT-d/IOMMU firmware support or may not implement Kernel DMA Protection.' }
    }
    if (-not $State.Features.CredentialGuard.EditionSupported) {
        $items += [pscustomobject]@{ Feature='Credential Guard local enable action'; Status='Unavailable for this edition'; Reason=('Detected edition: {0}; WinDSH keeps this action to supported Enterprise/Education editions.' -f $State.Computer.EditionID) }
    }
    if (-not $State.Features.KernelStackProtection.WindowsVersionEligible) {
        $items += [pscustomobject]@{ Feature='Kernel hardware stack protection'; Status='Not available on this Windows build'; Reason='Windows 11 22H2 or later is required for the client feature surface used by WinDSH.' }
    }
    if (-not $State.Features.SecureLaunch.BasicPrerequisitesConfirmed) {
        $reason = if ($State.Firmware.Type -match 'Legacy') { 'UEFI firmware mode is not confirmed.' } elseif (-not $State.TPM.IsTPM2) { 'TPM 2.0 is not confirmed.' } else { 'Basic platform prerequisites are not confirmed.' }
        $items += [pscustomobject]@{ Feature='Secure Launch local enable action'; Status='Unavailable until prerequisite is met'; Reason=$reason }
    }

    return $items
}

function Get-MenuActionAvailability {
    param(
        [Parameter(Mandatory=$true)]$State,
        [Parameter(Mandatory=$true)][string]$Key
    )
    $keyUpper = $Key.ToUpperInvariant()
    $result = [ordered]@{ Key=$keyUpper; Actionable=$true; Category='Ready'; Reason=''; Note='' }

    switch ($keyUpper) {
        '2' {
            if ($State.Features.MemoryIntegrity.Running) { $result.Actionable=$false; $result.Category='Already'; $result.Reason='Memory Integrity is already running.' }
            elseif ($State.Features.MemoryIntegrity.ManagedByPolicy) { $result.Actionable=$false; $result.Category='Policy'; $result.Reason='Memory Integrity/VBS is managed by organization policy.' }
            elseif ($State.Computer.BuildNumber -lt 14393) { $result.Actionable=$false; $result.Category='Prerequisite'; $result.Reason='This Windows build does not support the WinDSH HVCI configuration path.' }
            elseif (-not $State.Virtualization.VirtualizationFirmwareEnabled) { $result.Note='Selectable, but CPU virtualization appears disabled in BIOS/UEFI; it may not run until firmware is changed.' }
        }
        '3' {
            if ($State.Features.SecureLaunch.Running) { $result.Actionable=$false; $result.Category='Already'; $result.Reason='Secure Launch is already running.' }
            elseif ($State.Features.SecureLaunch.ManagedByPolicy) { $result.Actionable=$false; $result.Category='Policy'; $result.Reason='Secure Launch is managed by organization policy.' }
            elseif ($State.Firmware.Type -match 'Legacy') { $result.Actionable=$false; $result.Category='Prerequisite'; $result.Reason='Secure Launch requires UEFI firmware mode.' }
            elseif (-not $State.TPM.IsTPM2) { $result.Actionable=$false; $result.Category='Prerequisite'; $result.Reason='TPM 2.0 is not confirmed.' }
            elseif (-not $State.Virtualization.VirtualizationFirmwareEnabled) { $result.Note='Selectable, but CPU virtualization appears disabled in BIOS/UEFI.' }
        }
        '4' {
            if ($State.Features.CredentialGuard.Running) { $result.Actionable=$false; $result.Category='Already'; $result.Reason='Credential Guard is already running.' }
            elseif ($State.Computer.IsDomainController) { $result.Actionable=$false; $result.Category='Prerequisite'; $result.Reason='WinDSH does not enable Credential Guard on domain controllers.' }
            elseif (-not $State.Features.CredentialGuard.EditionSupported) { $result.Actionable=$false; $result.Category='Prerequisite'; $result.Reason=('Unsupported/licensing not confirmed for edition {0}.' -f $State.Computer.EditionID) }
            elseif ($State.Features.CredentialGuard.ManagedByPolicy) { $result.Actionable=$false; $result.Category='Policy'; $result.Reason='Credential Guard is managed by organization policy.' }
            elseif (($null -ne $State.Policy.EnableVirtualizationBasedSecurity) -and ($State.Policy.EnableVirtualizationBasedSecurity -eq 0)) { $result.Actionable=$false; $result.Category='Policy'; $result.Reason='VBS is disabled by organization policy.' }
            elseif (-not $State.Virtualization.VirtualizationFirmwareEnabled) { $result.Note='Selectable, but CPU virtualization appears disabled in BIOS/UEFI.' }
        }
        '5' {
            if ($State.Features.MemoryIntegrity.Running) { $result.Actionable=$false; $result.Category='Already'; $result.Reason='The vulnerable-driver blocklist is already enforced with running HVCI.' }
            elseif ($State.Features.VulnerableDriverBlocklist.RegistryValue -eq 1) { $result.Actionable=$false; $result.Category='Already'; $result.Reason='The explicit local vulnerable-driver blocklist preference is already enabled.' }
        }
        'A' {
            $mi = Get-MenuActionAvailability -State $State -Key '2'
            $sg = Get-MenuActionAvailability -State $State -Key '3'
            if (-not $mi.Actionable -and -not $sg.Actionable) {
                $result.Actionable=$false
                if ($mi.Category -eq 'Policy' -or $sg.Category -eq 'Policy') { $result.Category='Policy' } else { $result.Category='Already' }
                $result.Reason='No Safe action is currently locally actionable. See the grayed items above for details.'
            }
            elseif (-not $mi.Actionable) {
                $result.Note=('Secure Launch remains actionable; Memory Integrity will be skipped: {0}' -f $mi.Reason)
            }
            elseif (-not $sg.Actionable) {
                $result.Note=('Memory Integrity remains actionable; Secure Launch will be skipped: {0}' -f $sg.Reason)
            }
        }
        'P' {
            $a = Get-MenuActionAvailability -State $State -Key 'A'
            if (-not $a.Actionable) { $result.Actionable=$false; $result.Category=$a.Category; $result.Reason=$a.Reason }
        }
    }
    return [pscustomobject]$result
}

function Write-MenuAction {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)]$Availability
    )
    if (-not $Availability.Actionable) {
        Write-Host ('  [{0}] {1}  [UNAVAILABLE: {2}]' -f $Key,$Text,$Availability.Reason) -ForegroundColor DarkGray
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Availability.Note)) {
        Write-Host ('  [{0}] {1}' -f $Key,$Text) -ForegroundColor Yellow
        Write-Host ('      Note: {0}' -f $Availability.Note) -ForegroundColor DarkYellow
    }
    else {
        Write-Host ('  [{0}] {1}' -f $Key,$Text)
    }
}

function Test-MenuActionSelectable {
    param(
        [Parameter(Mandatory=$true)]$State,
        [Parameter(Mandatory=$true)][string]$Key
    )
    $availability = Get-MenuActionAvailability -State $State -Key $Key
    if ($availability.Actionable) { return $true }
    Write-Host ('This action is unavailable: {0}' -f $availability.Reason) -ForegroundColor Yellow
    return $false
}

function Get-FirmwareActions {
    param([Parameter(Mandatory=$true)]$State)
    Write-DebugLog 'Get-FirmwareActions: BEGIN'
    $items = @()

    if ($State.Firmware.Type -match 'Legacy') {
        $items += [pscustomobject]@{
            Item = 'UEFI firmware mode'
            Current = $State.Firmware.Type
            Needed = 'UEFI mode is required for Secure Boot and several modern protections.'
            Action = 'Technician action required. Do not simply switch an installed Legacy/MBR system to UEFI without checking boot-disk compatibility.'
        }
    }

    if ($State.Firmware.SecureBootSupported -and -not $State.Firmware.SecureBootEnabled) {
        $items += [pscustomobject]@{
            Item = 'Secure Boot'
            Current = 'Supported, but OFF'
            Needed = 'Recommended/required by several hardware-backed protections.'
            Action = 'Enable Secure Boot in UEFI firmware. This script does not modify Secure Boot keys or firmware state.'
        }
    }
    elseif (-not $State.Firmware.SecureBootSupported) {
        $items += [pscustomobject]@{
            Item = 'Secure Boot'
            Current = 'Not available to Windows'
            Needed = 'Secure Boot requires native UEFI firmware mode.'
            Action = 'Check whether the PC is using Legacy/CSM mode or whether the platform lacks Secure Boot.'
        }
    }

    if (-not $State.Virtualization.VirtualizationFirmwareEnabled) {
        $items += [pscustomobject]@{
            Item = 'CPU virtualization'
            Current = 'OFF or not reported to Windows'
            Needed = 'Required for VBS, Memory Integrity and related protections.'
            Action = 'Enable Intel Virtualization Technology/VT-x or AMD SVM/AMD-V in UEFI/BIOS.'
        }
    }

    if (-not $State.TPM.Present) {
        $items += [pscustomobject]@{
            Item = 'TPM / Security Processor'
            Current = 'Not visible to Windows'
            Needed = 'TPM 2.0 strengthens measured boot and is required for System Guard DRTM scenarios.'
            Action = 'Check UEFI for Intel PTT, AMD fTPM, Security Device Support, or a discrete TPM. Hardware may also be absent.'
        }
    }
    elseif (-not $State.TPM.Ready) {
        $items += [pscustomobject]@{
            Item = 'TPM / Security Processor'
            Current = 'Present, but not ready'
            Needed = 'Windows cannot fully use the security processor in the current state.'
            Action = 'Check TPM/firmware status and Windows TPM management. This tool will never clear the TPM.'
        }
    }

    if (-not $State.HardwareCapabilities.DMACapability) {
        $dmaAction = 'Check whether the platform supports Kernel DMA Protection / IOMMU.'
        if (-not $State.Virtualization.VirtualizationFirmwareEnabled) {
            $dmaAction = 'Enable CPU virtualization and Intel VT-d / AMD IOMMU in UEFI/BIOS, then re-check.'
        }
        else {
            $dmaAction = 'If available in firmware, enable Intel VT-d / AMD IOMMU. Some platforms do not support Kernel DMA Protection.'
        }
        $items += [pscustomobject]@{
            Item = 'Kernel DMA / Memory Access Protection'
            Current = 'DMA protection capability not reported by Device Guard'
            Needed = 'Protects memory from DMA-capable external peripherals on supported hardware.'
            Action = $dmaAction
        }
    }

    # Native PowerShell arrays are used here for Windows PowerShell 5.1 compatibility.
    Write-DebugLog ('Get-FirmwareActions: END; items={0}' -f $items.Count)
    return $items
}

function Get-QuickSummary {
    param([Parameter(Mandatory=$true)]$State)
    Write-DebugLog 'Get-QuickSummary: BEGIN'
    $rows = @()

    if ($State.TPM.Present -and $State.TPM.Ready) {
        $version = if ($State.TPM.SpecVersion) { $State.TPM.SpecVersion } else { 'version unknown' }
        $rows += [pscustomobject]@{Name='Security processor (TPM)';Status=('Ready - {0}' -f $version);Kind='Good';Next=''}
    }
    elseif ($State.TPM.Present) {
        $rows += [pscustomobject]@{Name='Security processor (TPM)';Status='Present but not ready';Kind='Warn';Next='Check TPM status. Do not clear it as a generic fix.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Security processor (TPM)';Status='Not visible to Windows';Kind='Warn';Next='Check Intel PTT / AMD fTPM / TPM setting in UEFI/BIOS.'}
    }

    if ($State.Firmware.SecureBootSupported -and $State.Firmware.SecureBootEnabled) {
        $rows += [pscustomobject]@{Name='Secure Boot';Status='ON';Kind='Good';Next=''}
    }
    elseif ($State.Firmware.SecureBootSupported) {
        $rows += [pscustomobject]@{Name='Secure Boot';Status='OFF - firmware action required';Kind='Warn';Next='Enable Secure Boot in UEFI firmware.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Secure Boot';Status='Unavailable / Legacy or unsupported';Kind='Warn';Next='Check UEFI/Legacy boot mode and platform support.'}
    }

    if ($State.Virtualization.VirtualizationFirmwareEnabled) {
        $rows += [pscustomobject]@{Name='CPU virtualization';Status='ON';Kind='Good';Next=''}
    }
    else {
        $rows += [pscustomobject]@{Name='CPU virtualization';Status='OFF or not reported';Kind='Warn';Next='Enable Intel VT-x or AMD SVM/AMD-V in UEFI/BIOS.'}
    }

    if ($State.VBS.StatusCode -eq 2) {
        $rows += [pscustomobject]@{Name='Virtualization-based security';Status='RUNNING';Kind='Good';Next=''}
    }
    elseif ($State.VBS.StatusCode -eq 1) {
        $rows += [pscustomobject]@{Name='Virtualization-based security';Status='Configured, not running';Kind='Warn';Next='Restart and check firmware prerequisites.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Virtualization-based security';Status='OFF / not configured';Kind='Info';Next='Enable Memory Integrity to configure the recommended VBS baseline.'}
    }

    $mi = $State.Features.MemoryIntegrity
    if ($mi.Running) {
        $rows += [pscustomobject]@{Name='Memory Integrity / HVCI';Status='RUNNING';Kind='Good';Next=''}
    }
    elseif ($mi.Configured) {
        $rows += [pscustomobject]@{Name='Memory Integrity / HVCI';Status='Configured, not running';Kind='Warn';Next='Restart; if still off, review BIOS virtualization and incompatible drivers.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Memory Integrity / HVCI';Status='OFF / not configured';Kind='Info';Next='This tool can enable it.'}
    }

    $sg = $State.Features.SecureLaunch
    if ($sg.Running) {
        $rows += [pscustomobject]@{Name='Firmware protection / Secure Launch';Status='RUNNING';Kind='Good';Next=''}
    }
    elseif ($sg.Configured) {
        $rows += [pscustomobject]@{Name='Firmware protection / Secure Launch';Status='Configured, not running';Kind='Warn';Next='Restart and verify platform/firmware prerequisites.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Firmware protection / Secure Launch';Status='OFF / not configured';Kind='Info';Next='This tool can configure it if baseline prerequisites are present.'}
    }

    $cg = $State.Features.CredentialGuard
    if ($cg.Running) {
        $rows += [pscustomobject]@{Name='Credential Guard';Status='RUNNING';Kind='Good';Next=''}
    }
    elseif ($cg.Configured) {
        $rows += [pscustomobject]@{Name='Credential Guard';Status='Configured, not running';Kind='Warn';Next='Restart and verify VBS/Secure Boot requirements.'}
    }
    elseif ($cg.EditionSupported) {
        $rows += [pscustomobject]@{Name='Credential Guard';Status='OFF - advanced optional';Kind='Info';Next='Can be enabled separately after authentication compatibility review.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Credential Guard';Status='Local enable action unavailable for this edition';Kind='Unavailable';Next='Audit only; WinDSH enables Credential Guard only on supported Enterprise/Education editions.'}
    }

    $ks = $State.Features.KernelStackProtection
    if ($ks.Running) {
        $rows += [pscustomobject]@{Name='Kernel hardware stack protection';Status='RUNNING';Kind='Good';Next=''}
    }
    elseif ($ks.AuditMode) {
        $rows += [pscustomobject]@{Name='Kernel hardware stack protection';Status='AUDIT MODE';Kind='Warn';Next='Review Windows Security Core isolation before enforcing.'}
    }
    elseif ($ks.Configured) {
        $rows += [pscustomobject]@{Name='Kernel hardware stack protection';Status='Configured, not running';Kind='Warn';Next='Restart and check CPU/driver support.'}
    }
    elseif ($ks.WindowsVersionEligible) {
        $rows += [pscustomobject]@{Name='Kernel hardware stack protection';Status='Not configured / support depends on CPU';Kind='Info';Next='Use Windows Security Core isolation if Windows exposes the switch.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Kernel hardware stack protection';Status='Not available on this Windows build';Kind='Unavailable';Next=''}
    }

    if ($State.HardwareCapabilities.DMACapability) {
        $rows += [pscustomobject]@{Name='Kernel DMA / Memory Access';Status='Platform capability reported';Kind='Good';Next='Windows manages this automatically on supported hardware.'}
    }
    else {
        $rows += [pscustomobject]@{Name='Kernel DMA / Memory Access';Status='Capability not reported';Kind='Warn';Next='Check VT-d/IOMMU in firmware and platform support.'}
    }

    if ($State.DEP.Available -eq $true -or $State.HardwareCapabilities.NXAvailable) {
        $rows += [pscustomobject]@{Name='DEP / NX';Status='Available';Kind='Good';Next=''}
    }
    else {
        $rows += [pscustomobject]@{Name='DEP / NX';Status='Not reported available';Kind='Warn';Next='Check platform/firmware support.'}
    }

    # Native PowerShell arrays avoid collection binder differences in Windows PowerShell 5.1.
    Write-DebugLog ('Get-QuickSummary: END; rows={0}' -f $rows.Count)
    return $rows
}

function Show-State {
    param([Parameter(Mandatory=$true)]$State)

    Write-Section 'Windows Device Security - Easy Summary'
    Write-Host ('Computer : {0} - {1} {2}' -f $State.Computer.Name,$State.Computer.Manufacturer,$State.Computer.Model) -ForegroundColor Gray
    Write-Host ('Windows  : {0} {1} ({2}, build {3})' -f $State.Computer.ProductName,$State.Computer.DisplayVersion,$State.Computer.EditionID,$State.Computer.Build) -ForegroundColor Gray
    Write-Host ('Firmware : {0}' -f $State.Firmware.Type) -ForegroundColor Gray
    if ($script:IntegrityState) {
        $integrityColor = if ($script:IntegrityState.Status -eq 'OK') { 'Green' } else { 'Yellow' }
        Write-Host ('Integrity: {0} (accidental-corruption check)' -f $script:IntegrityState.Status) -ForegroundColor $integrityColor
    }
    if ($State.VirtualMachine -and $State.VirtualMachine.Detected) {
        Write-Host ''
        Write-Host ('[INFO] Virtual machine detected: {0}' -f $State.VirtualMachine.PlatformHint) -ForegroundColor Yellow
        Write-Host '       TPM, Secure Boot and other hardware-security capabilities may be virtualized and depend on the hypervisor configuration.' -ForegroundColor DarkYellow
    }
    Write-Host ''
    Write-Host 'Meaning of labels: [OK] protected/available, [ACTION] needs attention, [N/A] unavailable, [INFO] informational.' -ForegroundColor DarkGray
    Write-Host ''

    Write-DebugLog 'Show-State: rendering Easy Summary rows'
    foreach ($row in (Get-QuickSummary -State $State)) {
        Write-SummaryItem -Name $row.Name -Status $row.Status -Kind $row.Kind -NextStep $row.Next
    }

    Write-DebugLog 'Show-State: collecting BIOS/UEFI actions'
    $firmwareActions = @(Get-FirmwareActions -State $State)
    Write-SubSection 'BIOS / UEFI items'
    if (@($firmwareActions).Count -eq 0) {
        Write-Host 'No obvious firmware action is required from the checks available to this script.' -ForegroundColor Green
    }
    else {
        $n = 1
        foreach ($item in $firmwareActions) {
            Write-Host ('{0}. {1}' -f $n,$item.Item) -ForegroundColor Yellow
            Write-Host ('   Current : {0}' -f $item.Current) -ForegroundColor Gray
            Write-Host ('   Why     : {0}' -f $item.Needed) -ForegroundColor DarkGray
            Write-Host ('   Action  : {0}' -f $item.Action) -ForegroundColor Yellow
            $n++
        }
    }

    $unsupported = @(Get-UnsupportedCapabilities -State $State)
    Write-SubSection 'Unavailable / not-confirmed capabilities'
    if ($unsupported.Count -eq 0) {
        Write-Host 'No unavailable capability was identified by the checks WinDSH can make.' -ForegroundColor Green
    }
    else {
        foreach ($item in $unsupported) {
            Write-Host ('[N/A] {0}: {1}' -f $item.Feature,$item.Status) -ForegroundColor DarkGray
            Write-Host ('      {0}' -f $item.Reason) -ForegroundColor DarkGray
        }
    }

    Write-SubSection 'Technical details'
    Write-StatusLine 'Firmware type' $State.Firmware.Type
    Write-StatusLine 'Secure Boot supported' ([string]$State.Firmware.SecureBootSupported)
    Write-StatusLine 'Secure Boot enabled' ([string]$State.Firmware.SecureBootEnabled) $(if ($State.Firmware.SecureBootEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'TPM present' ([string]$State.TPM.Present) $(if ($State.TPM.Present) {'Good'} else {'Warn'})
    Write-StatusLine 'TPM ready' ([string]$State.TPM.Ready) $(if ($State.TPM.Ready) {'Good'} else {'Warn'})
    Write-StatusLine 'TPM specification' $(if ($State.TPM.SpecVersion) {$State.TPM.SpecVersion} else {'Unknown'})
    Write-StatusLine 'Virtualization enabled in firmware' ([string]$State.Virtualization.VirtualizationFirmwareEnabled) $(if ($State.Virtualization.VirtualizationFirmwareEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'CPU VM monitor extensions reported' ([string]$State.Virtualization.VMMonitorModeExtensions)
    Write-StatusLine 'Hypervisor present' ([string]$State.Virtualization.HypervisorPresent)
    Write-StatusLine 'SLAT' ([string]$State.Virtualization.SLATAssessment)
    Write-StatusLine 'Kernel DMA capability (Device Guard)' ([string]$State.HardwareCapabilities.DMACapability) $(if ($State.HardwareCapabilities.DMACapability) {'Good'} else {'Warn'})
    Write-StatusLine 'Secure memory overwrite capability' ([string]$State.HardwareCapabilities.SecureMemoryOverwrite)
    Write-StatusLine 'NX capability (Device Guard)' ([string]$State.HardwareCapabilities.NXAvailable)
    Write-StatusLine 'DEP available (Win32_OperatingSystem)' ([string]$State.DEP.Available)
    Write-StatusLine 'DEP enabled for drivers' ([string]$State.DEP.Drivers)
    Write-StatusLine 'DEP enabled for 32-bit applications' ([string]$State.DEP.Applications32Bit)
    Write-StatusLine 'SMM mitigations (Device Guard)' ([string]$State.HardwareCapabilities.SMMMitigations)
    Write-StatusLine 'MBEC / GMET (Device Guard)' ([string]$State.HardwareCapabilities.MBECorGMET)
    Write-StatusLine 'APIC virtualization (Device Guard)' ([string]$State.HardwareCapabilities.APICVirtualization)

    Write-Host ''
    Write-StatusLine 'VBS' $State.VBS.Status $(if ($State.VBS.StatusCode -eq 2) {'Good'} elseif ($State.VBS.StatusCode -eq 1) {'Warn'} else {'Info'})

    $mi = $State.Features.MemoryIntegrity
    $miText = if ($mi.Running) {'RUNNING'} elseif ($mi.Configured) {'CONFIGURED - NOT RUNNING'} else {'DISABLED / NOT CONFIGURED'}
    Write-StatusLine 'Memory Integrity / HVCI' $miText $(if ($mi.Running) {'Good'} elseif ($mi.Configured) {'Warn'} else {'Info'})
    Write-StatusLine '  HVCI registry Enabled' ([string]$mi.RegistryEnabled)
    Write-StatusLine '  HVCI managed by policy' ([string]$mi.ManagedByPolicy)

    $sg = $State.Features.SecureLaunch
    $sgText = if ($sg.Running) {'RUNNING'} elseif ($sg.Configured) {'CONFIGURED - NOT RUNNING'} else {'DISABLED / NOT CONFIGURED'}
    Write-StatusLine 'System Guard Secure Launch' $sgText $(if ($sg.Running) {'Good'} elseif ($sg.Configured) {'Warn'} else {'Info'})
    Write-StatusLine '  Secure Launch managed by policy' ([string]$sg.ManagedByPolicy)

    $cg = $State.Features.CredentialGuard
    $cgText = if ($cg.Running) {'RUNNING'} elseif ($cg.Configured) {'CONFIGURED - NOT RUNNING'} else {'DISABLED / NOT CONFIGURED'}
    Write-StatusLine 'Credential Guard' $cgText $(if ($cg.Running) {'Good'} elseif ($cg.Configured) {'Warn'} else {'Info'})
    Write-StatusLine '  Credential Guard edition supported' ([string]$cg.EditionSupported)
    Write-StatusLine '  LsaCfgFlags' ([string]$cg.LsaCfgFlags)
    Write-StatusLine '  Credential Guard managed by policy' ([string]$cg.ManagedByPolicy)

    $smm = $State.Features.SMMFirmwareMeasurement
    $smmText = if ($smm.Running) {'RUNNING'} elseif ($smm.Configured) {'CONFIGURED - NOT RUNNING'} else {'NOT RUNNING / NOT CONFIGURED'}
    Write-StatusLine 'SMM Firmware Measurement' $smmText $(if ($smm.Running) {'Good'} else {'Info'})

    $ks = $State.Features.KernelStackProtection
    $ksText = if ($ks.Running) {'RUNNING'} elseif ($ks.AuditMode) {'AUDIT MODE'} elseif ($ks.Configured) {'CONFIGURED - NOT RUNNING'} elseif ($ks.WindowsVersionEligible) {'NOT CONFIGURED / HARDWARE SUPPORT UNKNOWN'} else {'NOT AVAILABLE ON THIS WINDOWS VERSION'}
    Write-StatusLine 'Kernel Hardware Stack Protection' $ksText $(if ($ks.Running) {'Good'} elseif ($ks.Configured -or $ks.AuditMode) {'Warn'} else {'Info'})

    $hp = $State.Features.HypervisorEnforcedPagingTranslation
    $hpText = if ($hp.Running) {'RUNNING'} elseif ($hp.Configured) {'CONFIGURED - NOT RUNNING'} else {'NOT REPORTED AS RUNNING'}
    Write-StatusLine 'Hypervisor-Enforced Paging Translation' $hpText $(if ($hp.Running) {'Good'} else {'Info'})

    Write-StatusLine 'Vulnerable Driver Blocklist' $State.Features.VulnerableDriverBlocklist.EffectiveAssessment $(if ($State.Features.VulnerableDriverBlocklist.EffectiveAssessment -match 'Enabled|Enforced|default is enabled') {'Good'} else {'Warn'})
    Write-StatusLine 'Windows pending restart detected' ([string]$State.Restart.Pending) $(if ($State.Restart.Pending) {'Warn'} else {'Info'})

    if ($mi.ManagedByPolicy -or $sg.ManagedByPolicy -or $cg.ManagedByPolicy) {
        Write-Host ''
        Write-Host 'NOTICE: One or more settings are policy-managed. The tool will not intentionally override those policy values.' -ForegroundColor Yellow
    }
}
function Confirm-Action {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [string]$RequiredWord = 'Y',
        [switch]$DefaultYes
    )
    $answer = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($answer) -and $DefaultYes) { return $true }
    return ($answer.Trim() -ieq $RequiredWord)
}

function Get-HvciDiagnostics {
    param(
        [int]$LookbackDays = 14,
        [int]$MaxEventsPerLog = 80
    )

    $startTime = (Get-Date).AddDays(-1 * [Math]::Abs($LookbackDays))
    $logs = @('Microsoft-Windows-CodeIntegrity/Operational','Microsoft-Windows-DeviceGuard/Operational')
    $logStatus = @()
    $events = @()
    $driverPaths = @()

    foreach ($logName in $logs) {
        try {
            $rawEvents = @(Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$startTime} -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
            $logStatus += [pscustomobject]@{ LogName=$logName; Available=$true; Error=$null }
            foreach ($event in $rawEvents) {
                $message = [string]$event.Message
                $propertyText = ''
                try { $propertyText = (@($event.Properties | ForEach-Object { [string]$_.Value }) -join ' ') }
                catch { Write-DebugException -Stage ('Read event properties: {0}/{1}' -f $logName,$event.Id) -ErrorRecord $_ }
                $combined = ($message + ' ' + $propertyText)

                $isCompatibility = ($logName -eq 'Microsoft-Windows-CodeIntegrity/Operational' -and [int]$event.Id -eq 3087)
                $isRelated = [bool]($combined -match '(?i)HVCI|memory integrity|hypervisor.?protected code integrity|hypervisor.?enforced code integrity|incompatible.{0,40}driver|driver.{0,40}incompatible')
                if (-not $isCompatibility -and -not $isRelated) { continue }

                # Extract only file names/paths Windows actually placed in the event data.
                $matches = [regex]::Matches($combined,'(?i)(?:[A-Z]:\\|\\\\\?\\|\\Device\\)[^\r\n"''<>|]*?\.sys\b|\b[A-Za-z0-9_.-]+\.sys\b')
                foreach ($m in $matches) {
                    $value = $m.Value.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($value) -and -not ($driverPaths -contains $value)) { $driverPaths += $value }
                }

                $cleanMessage = ($message -replace '[\r\n]+',' ').Trim()
                if ($cleanMessage.Length -gt 700) { $cleanMessage = $cleanMessage.Substring(0,700) + '...' }
                $events += [pscustomobject]@{
                    TimeCreated = $event.TimeCreated
                    LogName = $logName
                    Id = [int]$event.Id
                    Level = [string]$event.LevelDisplayName
                    CompatibilityEvent3087 = $isCompatibility
                    Message = $cleanMessage
                }
                if ($events.Count -ge 25) { break }
            }
        }
        catch {
            Write-DebugException -Stage ('Read HVCI event log {0}' -f $logName) -ErrorRecord $_
            $logStatus += [pscustomobject]@{ LogName=$logName; Available=$false; Error=$_.Exception.Message }
        }
    }

    $compatEvents = @($events | Where-Object { $_.CompatibilityEvent3087 })
    $assessment = if ($compatEvents.Count -gt 0) {
        'Recent Code Integrity Event ID 3087 compatibility events were found. Review the referenced drivers before broad HVCI deployment.'
    }
    elseif ($events.Count -gt 0) {
        'Related Code Integrity/Device Guard events were found, but no recent Event ID 3087 compatibility event was collected.'
    }
    else {
        'No recent HVCI-related events were collected. This does not prove that every installed third-party driver is compatible.'
    }

    $result = [pscustomobject]@{
        CollectedAt = (Get-Date).ToString('s')
        LookbackDays = $LookbackDays
        Assessment = $assessment
        CompatibilityEventCount = $compatEvents.Count
        RelatedEventCount = @($events).Count
        CandidateDriverReferences = @($driverPaths)
        Logs = @($logStatus)
        Events = @($events)
    }
    $script:LastHvciDiagnostics = $result
    return $result
}

function Show-HvciDiagnostics {
    param([Parameter(Mandatory=$true)]$Diagnostics)
    Write-SubSection 'Memory Integrity / HVCI driver diagnostics'
    Write-Host $Diagnostics.Assessment -ForegroundColor $(if ($Diagnostics.CompatibilityEventCount -gt 0) {'Yellow'} else {'Gray'})
    Write-Host ('Lookback window: {0} days; compatibility events (3087): {1}; related events: {2}' -f $Diagnostics.LookbackDays,$Diagnostics.CompatibilityEventCount,$Diagnostics.RelatedEventCount) -ForegroundColor DarkGray

    foreach ($log in $Diagnostics.Logs) {
        if (-not $log.Available) { Write-Host ('Log unavailable: {0} ({1})' -f $log.LogName,$log.Error) -ForegroundColor DarkGray }
    }
    if (@($Diagnostics.CandidateDriverReferences).Count -gt 0) {
        Write-Host 'Driver/file references reported by Windows events:' -ForegroundColor Yellow
        foreach ($driver in $Diagnostics.CandidateDriverReferences) { Write-Host ('  - {0}' -f $driver) -ForegroundColor Yellow }
    }
    else {
        Write-Host 'No .sys driver name/path was extracted from the collected events.' -ForegroundColor DarkGray
    }
    Write-Host 'These events are diagnostic evidence, not a guarantee that a listed file is the only blocker or that an unlisted driver is compatible.' -ForegroundColor DarkGray
}

function Open-CodeIntegrityEventViewer {
    try {
        Start-Process -FilePath 'eventvwr.msc' -ArgumentList '/c:Microsoft-Windows-CodeIntegrity/Operational' -ErrorAction Stop
        Write-Host 'Event Viewer was opened for the Code Integrity Operational log when supported by this Windows build.' -ForegroundColor Green
        Write-Host 'Path: Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational' -ForegroundColor Gray
    }
    catch {
        Write-DebugException -Stage 'Open Code Integrity Event Viewer' -ErrorRecord $_
        try { Start-Process -FilePath 'eventvwr.msc' -ErrorAction Stop } catch { Write-DebugException -Stage 'Open Event Viewer fallback' -ErrorRecord $_ }
        Write-Host 'Event Viewer was opened. Navigate to: Applications and Services Logs > Microsoft > Windows > CodeIntegrity > Operational' -ForegroundColor Yellow
    }
}

function New-PlanItem {
    param(
        [string]$Feature,
        [string]$Path,
        [string]$Name,
        [int]$Proposed,
        [string]$Note
    )
    $current = Get-RegistryValueSafe -Path $Path -Name $Name
    return [pscustomobject]@{
        Feature = $Feature
        Path = $Path
        Name = $Name
        Current = $current
        Proposed = $Proposed
        WillChange = [bool]($null -eq $current -or [int]$current -ne $Proposed)
        Note = $Note
    }
}

function Get-ChangePlan {
    param(
        [Parameter(Mandatory=$true)]$State,
        [ValidateSet('Safe','CredentialGuard')][string]$Target = 'Safe'
    )
    $items = @()
    $skipped = @()
    $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'

    if ($Target -eq 'Safe') {
        $miAvailability = Get-MenuActionAvailability -State $State -Key '2'
        if ($miAvailability.Actionable) {
            # Preview follows the same conservative rule as Enable All Safe: recent Event ID
            # 3087 compatibility evidence means HVCI is skipped pending technician review.
            $previewDiagnostics = Get-HvciDiagnostics
            if ($previewDiagnostics.CompatibilityEventCount -gt 0) {
                $skipped += [pscustomobject]@{Feature='Memory Integrity';Reason=('Recent Code Integrity Event ID 3087 compatibility events found: {0}. Technician review required.' -f $previewDiagnostics.CompatibilityEventCount);Category='Compatibility'}
            }
            else {
                $hvciPath = Join-Path $dgPath 'Scenarios\HypervisorEnforcedCodeIntegrity'
                $items += New-PlanItem 'Memory Integrity' $dgPath 'EnableVirtualizationBasedSecurity' 1 'Enable VBS.'
                $items += New-PlanItem 'Memory Integrity' $dgPath 'RequirePlatformSecurityFeatures' 1 'Require Secure Boot-capable platform baseline without UEFI lock.'
                $items += New-PlanItem 'Memory Integrity' $dgPath 'Locked' 0 'Do not use UEFI lock.'
                $items += New-PlanItem 'Memory Integrity' $hvciPath 'Enabled' 1 'Enable HVCI / Memory Integrity.'
                $items += New-PlanItem 'Memory Integrity' $hvciPath 'Locked' 0 'Do not use UEFI lock.'
            }
        }
        else { $skipped += [pscustomobject]@{Feature='Memory Integrity';Reason=$miAvailability.Reason;Category=$miAvailability.Category} }

        $sgAvailability = Get-MenuActionAvailability -State $State -Key '3'
        if ($sgAvailability.Actionable) {
            if ($null -eq $State.Policy.EnableVirtualizationBasedSecurity) {
                $items += New-PlanItem 'Secure Launch' $dgPath 'EnableVirtualizationBasedSecurity' 1 'Enable VBS prerequisite.'
                $items += New-PlanItem 'Secure Launch' $dgPath 'RequirePlatformSecurityFeatures' 1 'Use documented platform security baseline.'
                $items += New-PlanItem 'Secure Launch' $dgPath 'Locked' 0 'Do not use UEFI lock.'
            }
            $systemGuardPath = Join-Path $dgPath 'Scenarios\SystemGuard'
            $items += New-PlanItem 'Secure Launch' $systemGuardPath 'Enabled' 1 'Configure System Guard Secure Launch; Windows verifies hardware support at boot.'
        }
        else { $skipped += [pscustomobject]@{Feature='Secure Launch';Reason=$sgAvailability.Reason;Category=$sgAvailability.Category} }
    }
    else {
        $cgAvailability = Get-MenuActionAvailability -State $State -Key '4'
        if ($cgAvailability.Actionable) {
            if ($null -eq $State.Policy.EnableVirtualizationBasedSecurity) {
                $items += New-PlanItem 'Credential Guard' $dgPath 'EnableVirtualizationBasedSecurity' 1 'Enable VBS prerequisite.'
                $items += New-PlanItem 'Credential Guard' $dgPath 'RequirePlatformSecurityFeatures' 1 'Use documented platform security baseline.'
                $items += New-PlanItem 'Credential Guard' $dgPath 'Locked' 0 'Do not use UEFI lock.'
            }
            $items += New-PlanItem 'Credential Guard' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 2 'Enable Credential Guard without UEFI lock.'
        }
        else { $skipped += [pscustomobject]@{Feature='Credential Guard';Reason=$cgAvailability.Reason;Category=$cgAvailability.Category} }
    }

    # Deduplicate registry targets shared by more than one feature while retaining feature names.
    $unique = @()
    $seen = @{}
    foreach ($item in $items) {
        $key = ('{0}|{1}' -f $item.Path,$item.Name).ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $unique.Count
            $unique += $item
        }
        else {
            $i = [int]$seen[$key]
            if ($unique[$i].Feature -notmatch [regex]::Escape($item.Feature)) {
                $unique[$i].Feature = ('{0}; {1}' -f $unique[$i].Feature,$item.Feature)
            }
        }
    }

    return [pscustomobject]@{
        Generated = (Get-Date).ToString('s')
        Target = $Target
        RegistryChanges = @($unique)
        Skipped = @($skipped)
        WouldWriteCount = @($unique | Where-Object {$_.WillChange}).Count
        RequiresRestart = [bool](@($unique | Where-Object {$_.WillChange}).Count -gt 0)
    }
}

function Show-ChangePlan {
    param([Parameter(Mandatory=$true)]$Plan)
    Write-Section ('Preview / WhatIf - {0}' -f $Plan.Target)
    Write-Host 'No Windows security setting is changed in this preview.' -ForegroundColor Green
    if (@($Plan.RegistryChanges).Count -eq 0) {
        Write-Host 'No registry change is currently planned.' -ForegroundColor Gray
    }
    else {
        foreach ($item in $Plan.RegistryChanges) {
            $status = if ($item.WillChange) {'WOULD CHANGE'} else {'already desired value'}
            $color = if ($item.WillChange) {'Yellow'} else {'DarkGray'}
            Write-Host ('[{0}] {1}' -f $status,$item.Feature) -ForegroundColor $color
            Write-Host ('  {0}\{1}' -f $item.Path,$item.Name) -ForegroundColor Gray
            Write-Host ('  Current: {0}   Proposed: {1}' -f $(if ($null -eq $item.Current) {'<not set>'} else {$item.Current}),$item.Proposed) -ForegroundColor Gray
            if ($item.Note) { Write-Host ('  Note: {0}' -f $item.Note) -ForegroundColor DarkGray }
        }
    }
    foreach ($skip in $Plan.Skipped) {
        Write-Host ('[SKIP] {0}: {1}' -f $skip.Feature,$skip.Reason) -ForegroundColor DarkGray
    }
}

function Enable-MemoryIntegrity {
    param([Parameter(Mandatory=$true)]$State, [switch]$ForceConfirmed, [switch]$FromAllSafe)
    if (-not (Test-RemediationAllowed)) { return }

    if ($State.Features.MemoryIntegrity.Running) {
        Write-Host 'Memory Integrity is already running.' -ForegroundColor Green
        return
    }
    if ($State.Features.MemoryIntegrity.ManagedByPolicy) {
        $reason = 'Memory Integrity/VBS is managed by organization policy.'
        Write-Host ($reason + ' Local remediation was skipped.') -ForegroundColor Yellow
        Add-Change 'Memory Integrity' 'Enable' 'Managed by policy' 'Unchanged' 'Skipped - policy managed'
        Set-OutcomeIssue -Type Policy -Reason $reason
        return
    }

    Write-SubSection 'Memory Integrity prerequisites'
    Write-StatusLine 'CPU virtualization in firmware' ([string]$State.Virtualization.VirtualizationFirmwareEnabled) $(if ($State.Virtualization.VirtualizationFirmwareEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'Secure Boot' $(if ($State.Firmware.SecureBootEnabled) {'Enabled'} else {'Disabled / unavailable'}) $(if ($State.Firmware.SecureBootEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'SLAT' $State.Virtualization.SLATAssessment
    Write-Host 'Checking recent Code Integrity / Device Guard diagnostics for driver compatibility evidence...' -ForegroundColor Gray
    $diagnostics = Get-HvciDiagnostics
    Show-HvciDiagnostics -Diagnostics $diagnostics
    Write-Host 'Driver note: the event check cannot prove compatibility of every installed third-party driver.' -ForegroundColor Yellow

    $compatibilityOverrideConfirmed = $false
    if ($diagnostics.CompatibilityEventCount -gt 0) {
        $compatReason = ('Recent Code Integrity compatibility events (Event ID 3087) were found: {0}. Review the reported drivers before enabling Memory Integrity.' -f $diagnostics.CompatibilityEventCount)
        if ($FromAllSafe) {
            Write-Host 'Enable All Safe will SKIP Memory Integrity because recent driver-compatibility evidence was found.' -ForegroundColor Yellow
            Add-Change 'Memory Integrity' 'Enable' ([string]$State.Features.MemoryIntegrity.RegistryEnabled) 'Unchanged' 'Skipped - recent HVCI compatibility events require technician review'
            Set-OutcomeIssue -Type Unsupported -Reason ('Memory Integrity skipped: {0}' -f $compatReason)
            return
        }
        Write-Host $compatReason -ForegroundColor Yellow
        if (-not $ForceConfirmed) {
            if (-not (Confirm-Action 'Type HVCI to continue anyway after reviewing the driver evidence, or anything else to cancel' 'HVCI')) { return }
            $compatibilityOverrideConfirmed = $true
        }
    }

    if (-not $ForceConfirmed -and -not $compatibilityOverrideConfirmed) {
        if (-not (Confirm-Action 'Enable VBS + Memory Integrity without UEFI lock? [Y/N]')) { return }
    }

    $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $hvciPath = Join-Path $dgPath 'Scenarios\HypervisorEnforcedCodeIntegrity'
    $before = Get-RegistryValueSafe -Path $hvciPath -Name 'Enabled'

    try {
        Set-DwordValue -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1
        Set-DwordValue -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value 1
        Set-DwordValue -Path $dgPath -Name 'Locked' -Value 0
        Set-DwordValue -Path $hvciPath -Name 'Enabled' -Value 1
        Set-DwordValue -Path $hvciPath -Name 'Locked' -Value 0

        Add-Change 'Memory Integrity' 'Enable VBS + HVCI without UEFI lock' ([string]$before) '1' 'Configuration written; restart verification required'
        Set-RestartRecommended 'Memory Integrity / HVCI was configured and must be verified after restart.'
        Write-Host 'Memory Integrity configuration was written successfully.' -ForegroundColor Green
        Write-Host 'A restart is required before the RUNNING state can be verified.' -ForegroundColor Yellow
    }
    catch {
        $reason = ('Memory Integrity configuration failed: {0}' -f $_.Exception.Message)
        Write-DebugException -Stage 'Enable Memory Integrity' -ErrorRecord $_
        Add-Change 'Memory Integrity' 'Enable VBS + HVCI' ([string]$before) 'Unknown' ('FAILED: {0}' -f $_.Exception.Message)
        Set-OutcomeIssue -Type Failure -Reason $reason
        Write-Host $reason -ForegroundColor Red
    }
}

function Enable-SecureLaunch {
    param([Parameter(Mandatory=$true)]$State, [switch]$ForceConfirmed, [switch]$FromAllSafe)
    if (-not (Test-RemediationAllowed)) { return }

    if ($State.Features.SecureLaunch.Running) {
        Write-Host 'System Guard Secure Launch is already running.' -ForegroundColor Green
        return
    }
    if ($State.Features.SecureLaunch.ManagedByPolicy) {
        $reason = 'Secure Launch is managed by organization policy.'
        Write-Host ($reason + ' Local remediation was skipped.') -ForegroundColor Yellow
        Add-Change 'Secure Launch' 'Enable' 'Managed by policy' 'Unchanged' 'Skipped - policy managed'
        Set-OutcomeIssue -Type Policy -Reason $reason
        return
    }
    if ($State.Firmware.Type -match 'Legacy') {
        $reason = 'Secure Launch requires a compatible UEFI platform; this system appears to use Legacy BIOS.'
        Write-Host $reason -ForegroundColor Yellow
        if ($FromAllSafe) { Set-OutcomeIssue -Type Unsupported -Reason $reason } else { Set-OutcomeIssue -Type Prerequisite -Reason $reason }
        return
    }
    if (-not $State.TPM.Present -or -not $State.TPM.IsTPM2) {
        $reason = 'TPM 2.0 is not confirmed; Secure Launch/DRTM cannot be treated as applicable by WinDSH.'
        Write-Host $reason -ForegroundColor Yellow
        if ($FromAllSafe) { Set-OutcomeIssue -Type Unsupported -Reason $reason } else { Set-OutcomeIssue -Type Prerequisite -Reason $reason }
        return
    }

    Write-SubSection 'Secure Launch prerequisites'
    Write-StatusLine 'UEFI firmware' $State.Firmware.Type $(if ($State.Firmware.Type -match 'UEFI') {'Good'} else {'Warn'})
    Write-StatusLine 'TPM 2.0 confirmed' ([string]$State.TPM.IsTPM2) $(if ($State.TPM.IsTPM2) {'Good'} else {'Warn'})
    Write-StatusLine 'Secure Boot' $(if ($State.Firmware.SecureBootEnabled) {'Enabled'} else {'Disabled / unavailable'}) $(if ($State.Firmware.SecureBootEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'CPU virtualization in firmware' ([string]$State.Virtualization.VirtualizationFirmwareEnabled) $(if ($State.Virtualization.VirtualizationFirmwareEnabled) {'Good'} else {'Warn'})
    Write-Host 'Processor/firmware DRTM support cannot be fully proven by this generic pre-check. Windows decides at boot.' -ForegroundColor DarkGray

    if (-not $ForceConfirmed) {
        if (-not (Confirm-Action 'Configure System Guard Secure Launch / Firmware protection? [Y/N]')) { return }
    }

    if (($null -ne $State.Policy.EnableVirtualizationBasedSecurity) -and ($State.Policy.EnableVirtualizationBasedSecurity -eq 0)) {
        $reason = 'VBS is disabled by organization policy, so Secure Launch cannot be activated by this local tool.'
        Write-Host $reason -ForegroundColor Yellow
        Add-Change 'Secure Launch' 'Enable' 'VBS disabled by policy' 'Unchanged' 'Skipped - policy prerequisite blocks activation'
        Set-OutcomeIssue -Type Policy -Reason $reason
        return
    }

    $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $path = Join-Path $dgPath 'Scenarios\SystemGuard'
    $before = Get-RegistryValueSafe -Path $path -Name 'Enabled'
    try {
        if ($null -eq $State.Policy.EnableVirtualizationBasedSecurity) {
            Set-DwordValue -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1
            Set-DwordValue -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value 1
            Set-DwordValue -Path $dgPath -Name 'Locked' -Value 0
        }
        Set-DwordValue -Path $path -Name 'Enabled' -Value 1
        Add-Change 'Secure Launch' 'Enable SystemGuard scenario' ([string]$before) '1' 'Configuration written; hardware/restart verification required'
        Set-RestartRecommended 'System Guard Secure Launch was configured and must be verified after restart.'
        Write-Host 'Secure Launch configuration was written.' -ForegroundColor Green
        Write-Host 'Windows will activate it only if the processor and firmware satisfy Secure Launch requirements.' -ForegroundColor Yellow
    }
    catch {
        $reason = ('Secure Launch configuration failed: {0}' -f $_.Exception.Message)
        Write-DebugException -Stage 'Enable Secure Launch' -ErrorRecord $_
        Add-Change 'Secure Launch' 'Enable' ([string]$before) 'Unknown' ('FAILED: {0}' -f $_.Exception.Message)
        Set-OutcomeIssue -Type Failure -Reason $reason
        Write-Host $reason -ForegroundColor Red
    }
}

function Enable-CredentialGuardFeature {
    param([Parameter(Mandatory=$true)]$State, [switch]$ForceConfirmed)
    if (-not (Test-RemediationAllowed)) { return }

    if ($State.Features.CredentialGuard.Running) { Write-Host 'Credential Guard is already running.' -ForegroundColor Green; return }
    if ($State.Computer.IsDomainController) {
        $reason='WinDSH does not enable Credential Guard on domain controllers.'
        Write-Host $reason -ForegroundColor Yellow
        Set-OutcomeIssue -Type Prerequisite -Reason $reason
        return
    }
    if (-not $State.Features.CredentialGuard.EditionSupported) {
        $reason=('Credential Guard local enable action is unavailable for detected edition {0}; WinDSH restricts this action to supported Enterprise/Education editions.' -f $State.Computer.EditionID)
        Write-Host $reason -ForegroundColor Yellow
        Set-OutcomeIssue -Type Prerequisite -Reason $reason
        return
    }
    if ($State.Features.CredentialGuard.ManagedByPolicy) {
        $reason='Credential Guard is managed by organization policy.'
        Write-Host ($reason + ' Local remediation was skipped.') -ForegroundColor Yellow
        Add-Change 'Credential Guard' 'Enable' 'Managed by policy' 'Unchanged' 'Skipped - policy managed'
        Set-OutcomeIssue -Type Policy -Reason $reason
        return
    }
    if (($null -ne $State.Policy.EnableVirtualizationBasedSecurity) -and ($State.Policy.EnableVirtualizationBasedSecurity -eq 0)) {
        $reason='VBS is disabled by organization policy, so Credential Guard cannot be activated by this local tool.'
        Write-Host $reason -ForegroundColor Yellow
        Add-Change 'Credential Guard' 'Enable' 'VBS disabled by policy' 'Unchanged' 'Skipped - policy prerequisite blocks activation'
        Set-OutcomeIssue -Type Policy -Reason $reason
        return
    }

    Write-SubSection 'Credential Guard - advanced compatibility warning'
    Write-Host 'Credential Guard protects domain credentials using VBS.' -ForegroundColor Gray
    Write-Host 'It can affect legacy authentication/delegation scenarios, so it remains outside Enable All Safe.' -ForegroundColor Yellow
    Write-StatusLine 'Secure Boot' $(if ($State.Firmware.SecureBootEnabled) {'Enabled'} else {'Disabled / unavailable'}) $(if ($State.Firmware.SecureBootEnabled) {'Good'} else {'Warn'})
    Write-StatusLine 'CPU virtualization in firmware' ([string]$State.Virtualization.VirtualizationFirmwareEnabled) $(if ($State.Virtualization.VirtualizationFirmwareEnabled) {'Good'} else {'Warn'})

    if (-not $ForceConfirmed) {
        if (-not (Confirm-Action 'Type CREDENTIAL to enable Credential Guard WITHOUT UEFI lock, or anything else to cancel' 'CREDENTIAL')) { return }
    }

    $dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $before = Get-RegistryValueSafe -Path $lsaPath -Name 'LsaCfgFlags'
    try {
        if ($null -eq $State.Policy.EnableVirtualizationBasedSecurity) {
            Set-DwordValue -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1
            Set-DwordValue -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value 1
            Set-DwordValue -Path $dgPath -Name 'Locked' -Value 0
        }
        Set-DwordValue -Path $lsaPath -Name 'LsaCfgFlags' -Value 2
        Add-Change 'Credential Guard' 'Enable without UEFI lock' ([string]$before) '2' 'Configuration written; restart verification required'
        Set-RestartRecommended 'Credential Guard was configured and requires restart.'
        Write-Host 'Credential Guard was configured without UEFI lock.' -ForegroundColor Green
        Write-Host 'A restart is required before the RUNNING state can be verified.' -ForegroundColor Yellow
    }
    catch {
        $reason=('Credential Guard configuration failed: {0}' -f $_.Exception.Message)
        Write-DebugException -Stage 'Enable Credential Guard' -ErrorRecord $_
        Add-Change 'Credential Guard' 'Enable without UEFI lock' ([string]$before) 'Unknown' ('FAILED: {0}' -f $_.Exception.Message)
        Set-OutcomeIssue -Type Failure -Reason $reason
        Write-Host $reason -ForegroundColor Red
    }
}

function Enable-VulnerableDriverBlocklist {
    param([Parameter(Mandatory=$true)]$State, [switch]$ForceConfirmed)
    if (-not (Test-RemediationAllowed)) { return }

    if ($State.Features.MemoryIntegrity.Running) {
        Write-Host 'Memory Integrity is running; the Microsoft vulnerable driver blocklist is already enforced with HVCI.' -ForegroundColor Green
        return
    }
    if ($State.Features.VulnerableDriverBlocklist.RegistryValue -eq 1) {
        Write-Host 'The explicit local Vulnerable Driver Blocklist preference is already enabled.' -ForegroundColor Green
        return
    }
    if (-not $ForceConfirmed) {
        Write-Host 'This setting can block known vulnerable drivers. Old vendor software or drivers may need updating.' -ForegroundColor Yellow
        if (-not (Confirm-Action 'Set the explicit local Vulnerable Driver Blocklist preference to enabled? [Y/N]')) { return }
    }

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $before = Get-RegistryValueSafe -Path $path -Name 'VulnerableDriverBlocklistEnable'
    try {
        Set-DwordValue -Path $path -Name 'VulnerableDriverBlocklistEnable' -Value 1
        Add-Change 'Vulnerable Driver Blocklist' 'Enable explicit local preference' ([string]$before) '1' 'Registry value written'
        Set-RestartRecommended 'Vulnerable Driver Blocklist preference changed; restart is recommended for clean enforcement verification.'
        Write-Host 'Vulnerable Driver Blocklist local preference was set to enabled.' -ForegroundColor Green
    }
    catch {
        $reason=('Vulnerable Driver Blocklist configuration failed: {0}' -f $_.Exception.Message)
        Write-DebugException -Stage 'Enable Vulnerable Driver Blocklist' -ErrorRecord $_
        Add-Change 'Vulnerable Driver Blocklist' 'Enable' ([string]$before) 'Unknown' ('FAILED: {0}' -f $_.Exception.Message)
        Set-OutcomeIssue -Type Failure -Reason $reason
        Write-Host $reason -ForegroundColor Red
    }
}

function Open-CoreIsolation {
    try {
        Start-Process 'windowsdefender://coreisolation/'
        Write-Host 'Windows Security Core isolation page opened.' -ForegroundColor Green
        Write-Host 'Use it to review incompatible drivers and Kernel-mode Hardware-enforced Stack Protection when Windows exposes the option.' -ForegroundColor Gray
    }
    catch {
        Write-Host ('Could not open Windows Security Core isolation page: {0}' -f $_.Exception.Message) -ForegroundColor Red
    }
}

function Enable-AllRecommended {
    param([Parameter(Mandatory=$true)]$State, [switch]$ForceConfirmed)
    if (-not (Test-RemediationAllowed)) { return }

    Write-Section 'Enable All Safe - generic helpdesk remediation'
    Write-Host 'This action enables every locally applicable Safe protection:' -ForegroundColor White
    Write-Host '  1. VBS + Memory Integrity / HVCI (without UEFI lock)' -ForegroundColor Gray
    Write-Host '  2. System Guard Secure Launch / Firmware protection when its basic prerequisites are confirmed' -ForegroundColor Gray
    Write-Host ''
    Write-Host 'Unsupported or firmware-dependent actions are skipped and reported; they are not treated as generic failures.' -ForegroundColor Yellow
    Write-Host 'Credential Guard, Kernel Shadow Stacks, Secure Boot, TPM provisioning and encryption are NOT changed.' -ForegroundColor Yellow

    if (-not $ForceConfirmed) {
        if (-not (Confirm-Action 'Type ENABLE to continue, or anything else to cancel' 'ENABLE')) { Write-Host 'Cancelled.' -ForegroundColor Gray; return }
    }

    $miAvailability = Get-MenuActionAvailability -State $State -Key '2'
    if ($miAvailability.Actionable) {
        Enable-MemoryIntegrity -State $State -ForceConfirmed -FromAllSafe
    }
    else {
        Write-Host ('Memory Integrity skipped: {0}' -f $miAvailability.Reason) -ForegroundColor DarkGray
        if ($miAvailability.Category -eq 'Policy') { Set-OutcomeIssue -Type Policy -Reason $miAvailability.Reason }
        elseif ($miAvailability.Category -eq 'Prerequisite') { Set-OutcomeIssue -Type Unsupported -Reason ('Memory Integrity: {0}' -f $miAvailability.Reason) }
    }

    $state2 = Get-SystemState
    $sgAvailability = Get-MenuActionAvailability -State $state2 -Key '3'
    if ($sgAvailability.Actionable) {
        Enable-SecureLaunch -State $state2 -ForceConfirmed -FromAllSafe
    }
    else {
        Write-Host ('Secure Launch skipped: {0}' -f $sgAvailability.Reason) -ForegroundColor DarkGray
        if ($sgAvailability.Category -eq 'Policy') { Set-OutcomeIssue -Type Policy -Reason $sgAvailability.Reason }
        elseif ($sgAvailability.Category -eq 'Prerequisite') { Set-OutcomeIssue -Type Unsupported -Reason ('Secure Launch: {0}' -f $sgAvailability.Reason) }
    }
}

function Get-ReportSummaryRows {
    param([Parameter(Mandatory=$true)]$State)
    return @(Get-QuickSummary -State $State | ForEach-Object {
        [pscustomobject]@{
            Feature = $_.Name
            Status = $_.Status
            Category = $_.Kind
            Attention = [bool]($_.Kind -eq 'Warn' -or $_.Kind -eq 'Bad' -or $_.Kind -eq 'Unavailable')
            NextStep = $_.Next
        }
    })
}

function ConvertTo-StateSnapshotLines {
    param(
        [Parameter(Mandatory=$true)]$State,
        [Parameter(Mandatory=$true)][string]$Title
    )
    $lines = @()
    $lines += $Title
    $lines += ('=' * 82)
    $lines += ('Captured:      {0}' -f $State.Timestamp)
    $lines += ('Computer:      {0}' -f $State.Computer.Name)
    $lines += ('Manufacturer:  {0}' -f $State.Computer.Manufacturer)
    $lines += ('Model:         {0}' -f $State.Computer.Model)
    $lines += ('Windows:       {0} {1} ({2}) build {3}' -f $State.Computer.ProductName,$State.Computer.DisplayVersion,$State.Computer.EditionID,$State.Computer.Build)
    $lines += ('Virtual machine detected:             {0}' -f $State.VirtualMachine.Detected)
    if ($State.VirtualMachine.Detected) { $lines += ('Virtual platform hint:                 {0}' -f $State.VirtualMachine.PlatformHint) }
    $lines += ''
    $lines += 'Summary:'
    foreach ($row in (Get-ReportSummaryRows -State $State)) {
        $lines += ('  {0,-36} {1}' -f $row.Feature,$row.Status)
        if (-not [string]::IsNullOrWhiteSpace($row.NextStep)) { $lines += ('    Next: {0}' -f $row.NextStep) }
    }
    $lines += ''
    $lines += 'Firmware / hardware:'
    $lines += ('  Firmware type:                       {0}' -f $State.Firmware.Type)
    $lines += ('  Secure Boot supported:               {0}' -f $State.Firmware.SecureBootSupported)
    $lines += ('  Secure Boot enabled:                 {0}' -f $State.Firmware.SecureBootEnabled)
    $lines += ('  TPM present:                         {0}' -f $State.TPM.Present)
    $lines += ('  TPM ready:                           {0}' -f $State.TPM.Ready)
    $lines += ('  TPM spec version:                    {0}' -f $State.TPM.SpecVersion)
    $lines += ('  TPM 2.0 confirmed:                   {0}' -f $State.TPM.IsTPM2)
    $lines += ('  Virtualization firmware enabled:     {0}' -f $State.Virtualization.VirtualizationFirmwareEnabled)
    $lines += ('  Hypervisor present:                  {0}' -f $State.Virtualization.HypervisorPresent)
    $lines += ('  SLAT:                                {0}' -f $State.Virtualization.SLATAssessment)
    $lines += ('  Kernel DMA capability:               {0}' -f $State.HardwareCapabilities.DMACapability)
    $lines += ('  Secure memory overwrite capability:  {0}' -f $State.HardwareCapabilities.SecureMemoryOverwrite)
    $lines += ('  NX capability:                       {0}' -f $State.HardwareCapabilities.NXAvailable)
    $lines += ('  SMM mitigations:                     {0}' -f $State.HardwareCapabilities.SMMMitigations)
    $lines += ('  MBEC/GMET:                           {0}' -f $State.HardwareCapabilities.MBECorGMET)
    $lines += ('  APIC virtualization:                 {0}' -f $State.HardwareCapabilities.APICVirtualization)
    $lines += ''
    $lines += 'VBS / Device Security:'
    $lines += ('  VBS:                                 {0}' -f $State.VBS.Status)
    $lines += ('  VBS registry enabled:                {0}' -f $State.VBS.RegistryEnabled)
    $lines += ('  RequirePlatformSecurityFeatures:     {0}' -f $State.VBS.RequirePlatformSecurityFeatures)
    $lines += ('  Memory Integrity configured:         {0}' -f $State.Features.MemoryIntegrity.Configured)
    $lines += ('  Memory Integrity running:            {0}' -f $State.Features.MemoryIntegrity.Running)
    $lines += ('  Secure Launch configured:            {0}' -f $State.Features.SecureLaunch.Configured)
    $lines += ('  Secure Launch running:               {0}' -f $State.Features.SecureLaunch.Running)
    $lines += ('  Credential Guard edition supported:  {0}' -f $State.Features.CredentialGuard.EditionSupported)
    $lines += ('  Credential Guard configured:         {0}' -f $State.Features.CredentialGuard.Configured)
    $lines += ('  Credential Guard running:            {0}' -f $State.Features.CredentialGuard.Running)
    $lines += ('  Credential Guard LsaCfgFlags:        {0}' -f $State.Features.CredentialGuard.LsaCfgFlags)
    $lines += ('  SMM Measurement configured:          {0}' -f $State.Features.SMMFirmwareMeasurement.Configured)
    $lines += ('  SMM Measurement running:             {0}' -f $State.Features.SMMFirmwareMeasurement.Running)
    $lines += ('  Kernel Stack configured:             {0}' -f $State.Features.KernelStackProtection.Configured)
    $lines += ('  Kernel Stack running:                {0}' -f $State.Features.KernelStackProtection.Running)
    $lines += ('  Kernel Stack audit mode:             {0}' -f $State.Features.KernelStackProtection.AuditMode)
    $lines += ('  HSPT configured:                     {0}' -f $State.Features.HypervisorEnforcedPagingTranslation.Configured)
    $lines += ('  HSPT running:                        {0}' -f $State.Features.HypervisorEnforcedPagingTranslation.Running)
    $lines += ('  Vulnerable Driver Blocklist:         {0}' -f $State.Features.VulnerableDriverBlocklist.EffectiveAssessment)
    $lines += ''
    $lines += 'Policy ownership:'
    $lines += ('  Policy VBS:                          {0}' -f $State.Policy.EnableVirtualizationBasedSecurity)
    $lines += ('  Policy HVCI:                         {0}' -f $State.Policy.HypervisorEnforcedCodeIntegrity)
    $lines += ('  Policy Secure Launch:                {0}' -f $State.Policy.ConfigureSystemGuardLaunch)
    $lines += ('  Policy Credential Guard:             {0}' -f $State.Policy.CredentialGuardLsaCfgFlags)
    $lines += ''
    $lines += 'Unavailable / not-confirmed capabilities:'
    $unsupported = @(Get-UnsupportedCapabilities -State $State)
    if ($unsupported.Count -eq 0) { $lines += '  None identified by WinDSH.' }
    else { foreach ($u in $unsupported) { $lines += ('  - {0}: {1}. {2}' -f $u.Feature,$u.Status,$u.Reason) } }
    return $lines
}

function ConvertTo-StateText {
    param([Parameter(Mandatory=$true)]$State)

    $lines = @()
    $lines += 'WinDSH - Windows Device Security Assessment'
    $lines += ('Tool version:   {0}' -f $script:ToolVersion)
    $lines += ('Schema version: {0}' -f $script:SchemaVersion)
    $lines += $script:ContactEmail
    if ($script:IntegrityState) {
        $lines += ('Integrity:      {0}' -f $script:IntegrityState.Status)
        $lines += ('Integrity SHA-256 (normalized): {0}' -f $script:IntegrityState.ActualHash)
    }
    $lines += ('Generated:      {0}' -f (Get-Date).ToString('s'))
    $lines += ''

    $initial = if ($script:InitialState) { $script:InitialState } else { $State }
    $lines += @(ConvertTo-StateSnapshotLines -State $initial -Title 'INITIAL STATE')

    if ($script:FinalState -and ($script:FinalState.Timestamp -ne $initial.Timestamp -or @($script:Changes).Count -gt 0 -or @($script:PlannedChanges).Count -gt 0)) {
        $lines += ''
        $lines += @(ConvertTo-StateSnapshotLines -State $script:FinalState -Title 'FINAL / CURRENT STATE')
    }

    $lines += ''
    $lines += 'BIOS / UEFI ACTIONS (CURRENT STATE)'
    $lines += ('=' * 82)
    $firmwareActions = @(Get-FirmwareActions -State $State)
    if ($firmwareActions.Count -eq 0) { $lines += 'No obvious firmware action is required from the checks available to WinDSH.' }
    else {
        foreach ($item in $firmwareActions) {
            $lines += ('- {0}' -f $item.Item)
            $lines += ('  Current: {0}' -f $item.Current)
            $lines += ('  Why:     {0}' -f $item.Needed)
            $lines += ('  Action:  {0}' -f $item.Action)
        }
    }

    if (@($script:PlannedChanges).Count -gt 0) {
        $lines += ''
        $lines += 'PREVIEW / WHATIF PLAN'
        $lines += ('=' * 82)
        foreach ($plan in $script:PlannedChanges) {
            $lines += ('Target: {0}; would-write count: {1}; restart if applied: {2}' -f $plan.Target,$plan.WouldWriteCount,$plan.RequiresRestart)
            foreach ($item in $plan.RegistryChanges) {
                $lines += ('  [{0}] {1}: {2}\{3}; Current={4}; Proposed={5}' -f $(if ($item.WillChange){'WOULD CHANGE'}else{'NO CHANGE'}),$item.Feature,$item.Path,$item.Name,$(if ($null -eq $item.Current){'<not set>'}else{$item.Current}),$item.Proposed)
            }
            foreach ($skip in $plan.Skipped) { $lines += ('  [SKIP] {0}: {1}' -f $skip.Feature,$skip.Reason) }
        }
    }

    if ($script:LastHvciDiagnostics) {
        $lines += ''
        $lines += 'HVCI / MEMORY INTEGRITY DRIVER DIAGNOSTICS'
        $lines += ('=' * 82)
        $lines += $script:LastHvciDiagnostics.Assessment
        $lines += ('Compatibility Event 3087 count: {0}' -f $script:LastHvciDiagnostics.CompatibilityEventCount)
        foreach ($driver in $script:LastHvciDiagnostics.CandidateDriverReferences) { $lines += ('  Driver/file reference: {0}' -f $driver) }
    }

    $lines += ''
    $lines += 'CHANGES MADE IN THIS RUN'
    $lines += ('=' * 82)
    if (@($script:Changes).Count -eq 0) { $lines += 'None.' }
    else { foreach ($c in $script:Changes) { $lines += ('[{0}] {1}: {2}; Before={3}; After={4}; Result={5}' -f $c.Time,$c.Feature,$c.Action,$c.Before,$c.After,$c.Result) } }

    $lines += ''
    $lines += 'RUN OUTCOME / AUTOMATION CONTRACT'
    $lines += ('=' * 82)
    $lines += ('Last calculated exit code:             {0}' -f $script:LastExitCode)
    $lines += ('Meaning:                               {0}' -f (Get-ExitCodeMeaning -Code $script:LastExitCode))
    $lines += ('Restart recommended by this run:       {0}' -f $script:RestartRecommended)
    foreach ($reason in $script:RestartReasons) { $lines += ('  Restart reason: {0}' -f $reason) }
    foreach ($reason in $script:Outcome.PolicyReasons) { $lines += ('  Policy block: {0}' -f $reason) }
    foreach ($reason in $script:Outcome.PrerequisiteReasons) { $lines += ('  Missing prerequisite: {0}' -f $reason) }
    foreach ($reason in $script:Outcome.UnsupportedSkipped) { $lines += ('  Unsupported/skipped: {0}' -f $reason) }
    foreach ($reason in $script:Outcome.FailureReasons) { $lines += ('  Failure: {0}' -f $reason) }

    $lines += ''
    $lines += 'IMPORTANT NOTES'
    $lines += '- Secure Boot, CPU virtualization, TPM firmware state and IOMMU/VT-d are firmware/platform settings. WinDSH reports them but does not force them.'
    $lines += '- Kernel DMA Protection is automatically managed by Windows on supported platforms; it is not treated as a generic software toggle.'
    $lines += '- HVCI event diagnostics provide evidence from Windows logs, not a guarantee that every installed driver is compatible.'
    $lines += '- Kernel-mode Hardware-enforced Stack Protection is audited but not force-enabled through undocumented registry changes.'
    $lines += '- Re-run WinDSH after restart to verify that CONFIGURED protections actually become RUNNING.'
    $lines += '- Drive/device encryption is intentionally outside WinDSH.'

    return ($lines -join [Environment]::NewLine)
}

function Save-Report {
    param(
        [Parameter(Mandatory=$true)]$State,
        [ValidateSet('Text','Json')][string]$Format
    )
    $root = Initialize-ReportFolder
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeComputer = ($State.Computer.Name -replace '[^A-Za-z0-9_.-]','_')
    $base = 'WinDSH-{0}-{1}' -f $safeComputer,$stamp

    if ($Format -eq 'Text') {
        $path = Join-Path $root ($base + '.txt')
        $text = ConvertTo-StateText -State $State
        [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
        $script:LastReportPath = $path
        if (-not $script:RmmMode) { Write-Host ('Plain-text report saved: {0}' -f $path) -ForegroundColor Green }
        return $path
    }

    $jsonPath = Join-Path $root ($base + '.json')
    $initial = if ($script:InitialState) { $script:InitialState } else { $State }
    $final = if ($script:FinalState) { $script:FinalState } else { $State }
    $reportObject = [pscustomobject]@{
        SchemaVersion = $script:SchemaVersion
        Tool = [pscustomobject]@{ Name=$script:ToolName; Version=$script:ToolVersion; Contact=$script:ContactEmail; Integrity=$script:IntegrityState }
        Generated = (Get-Date).ToString('s')
        ExitCode = $script:LastExitCode
        ExitMeaning = Get-ExitCodeMeaning -Code $script:LastExitCode
        Outcome = [pscustomobject]$script:Outcome
        InitialState = $initial
        FinalState = $final
        Summary = Get-ReportSummaryRows -State $final
        FirmwareActions = @(Get-FirmwareActions -State $final)
        UnsupportedCapabilities = @(Get-UnsupportedCapabilities -State $final)
        HVCIDiagnostics = $script:LastHvciDiagnostics
        PlannedChanges = @($script:PlannedChanges)
        Restart = [pscustomobject]@{
            RecommendedByThisRun = $script:RestartRecommended
            Reasons = @($script:RestartReasons)
            WindowsPendingRestart = $final.Restart.Pending
        }
        Changes = @($script:Changes)
    }
    $json = $reportObject | ConvertTo-Json -Depth 14
    [IO.File]::WriteAllText($jsonPath, $json, (New-Object Text.UTF8Encoding($false)))
    $script:LastReportPath = $jsonPath
    if (-not $script:RmmMode) { Write-Host ('JSON report saved: {0}' -f $jsonPath) -ForegroundColor Green }
    return $jsonPath
}

function Select-ReportFormatInteractive {
    Write-Host ''
    $choice = Read-Host 'Report format: [T]ext or [J]SON? (default: Text)'
    if ([string]::IsNullOrWhiteSpace($choice)) { return 'Text' }
    if ($choice.Trim().ToUpperInvariant().StartsWith('J')) { return 'Json' }
    return 'Text'
}

function Get-InteractiveOutcomeExitCode {
    if ($script:Outcome.IntegrityFailed) { return 3 }
    if ($script:Outcome.RemediationFailed) { return 5 }
    if ($script:Outcome.PolicyBlocked) { return 2 }
    if ($script:RestartRecommended) { return 3010 }
    return 0
}

function Save-ReportInteractive {
    param([Parameter(Mandatory=$true)]$State)
    $script:LastExitCode = Get-InteractiveOutcomeExitCode
    $format = Select-ReportFormatInteractive
    [void](Save-Report -State $State -Format $format)
}

function Show-RestartSummary {
    param([Parameter(Mandatory=$true)]$State)
    if (-not $script:RestartRecommended -and -not $State.Restart.Pending) { return }

    Write-Section 'Restart status'
    if ($script:RestartRecommended) {
        Write-Host 'A restart is recommended/required for changes made by this tool:' -ForegroundColor Yellow
        foreach ($reason in $script:RestartReasons) {
            Write-Host ('  - {0}' -f $reason) -ForegroundColor Yellow
        }
    }
    if ($State.Restart.Pending) {
        Write-Host 'Windows also reports an existing pending restart condition.' -ForegroundColor Yellow
    }
    Write-Host 'After restart, run the audit again to verify that configured protections show RUNNING.' -ForegroundColor Gray
}

function Invoke-InteractiveExit {
    param([Parameter(Mandatory=$true)]$State)

    $finalState = Get-SystemState
    $script:FinalState = $finalState
    $script:LastExitCode = Get-InteractiveOutcomeExitCode
    if (@($script:Changes).Count -gt 0) {
        Write-Host ''
        if (Confirm-Action 'Save a final report of this session? [Y/n]' 'Y' -DefaultYes) { Save-ReportInteractive -State $finalState }
    }

    Show-RestartSummary -State $finalState
    if ($script:RestartRecommended -or $finalState.Restart.Pending) {
        Write-Host ''
        Write-Host 'Restarting will close applications. Save your work first.' -ForegroundColor Yellow
        if (Confirm-Action 'Restart Windows now? [y/N]' 'Y') { Restart-Computer -Force; return }
    }
}

function Read-MenuChoice {
    param(
        [string]$Prompt = 'Select an action (single key): ',
        [string]$ValidChoices = '12345678PARQ'
    )

    Write-Host -NoNewline $Prompt
    while ($true) {
        try {
            $keyInfo = [Console]::ReadKey($true)
            $choice = [string]$keyInfo.KeyChar
            if ([string]::IsNullOrEmpty($choice)) { continue }
            $choice = $choice.Substring(0,1).ToUpperInvariant()
            if ($ValidChoices.IndexOf($choice) -ge 0) { Write-Host $choice; return $choice }
        }
        catch {
            Write-DebugException -Stage 'Read single-key menu choice' -ErrorRecord $_
            Write-Host ''
            $fallback = Read-Host ($Prompt.TrimEnd())
            if ([string]::IsNullOrWhiteSpace($fallback)) { Write-Host -NoNewline $Prompt; continue }
            $choice = $fallback.Trim().Substring(0,1).ToUpperInvariant()
            if ($ValidChoices.IndexOf($choice) -ge 0) { return $choice }
            Write-Host -NoNewline $Prompt
        }
    }
}

function Show-Menu {
    param([Parameter(Mandatory=$true)]$State)
    Write-Host ''
    Write-Host 'Actions' -ForegroundColor White
    Write-Host '  [1] Refresh / audit status'
    Write-MenuAction '2' 'Enable VBS + Memory Integrity (recommended)' (Get-MenuActionAvailability -State $State -Key '2')
    Write-MenuAction '3' 'Enable System Guard Secure Launch / Firmware protection' (Get-MenuActionAvailability -State $State -Key '3')
    Write-MenuAction '4' 'Enable Credential Guard WITHOUT UEFI lock (advanced; Enterprise/Education)' (Get-MenuActionAvailability -State $State -Key '4')
    Write-MenuAction '5' 'Enable Vulnerable Driver Blocklist explicit preference (advanced)' (Get-MenuActionAvailability -State $State -Key '5')
    Write-Host '  [6] Open Windows Security Core isolation page'
    Write-Host '  [7] Run Memory Integrity / HVCI driver-event diagnostics'
    Write-Host '  [8] Open Code Integrity Event Viewer log'
    Write-MenuAction 'P' 'Preview / WhatIf recommended Safe changes' (Get-MenuActionAvailability -State $State -Key 'P')
    Write-MenuAction 'A' 'Enable All Safe (all applicable safe protections)' (Get-MenuActionAvailability -State $State -Key 'A')
    Write-Host '  [R] Save report (asks Text or JSON; default Text)'
    Write-Host '  [Q] Quit'
    Write-Host ''
    Write-Host 'Grayed UNAVAILABLE actions cannot be applied locally; the reason is shown on the same line.' -ForegroundColor DarkGray
    Write-Host 'Press one listed key; Enter is not required.' -ForegroundColor DarkGray
}

function Get-UnattendedExitCode {
    param([switch]$RemediationRequested, [switch]$ExplicitPrerequisiteAction)
    if ($script:Outcome.IntegrityFailed) { return 3 }
    if ($RemediationRequested -and $script:Outcome.RemediationFailed) { return 5 }
    if ($RemediationRequested -and $script:Outcome.PolicyBlocked) { return 2 }
    if ($ExplicitPrerequisiteAction -and $script:Outcome.PrerequisiteUnavailable) { return 4 }
    if ($script:RestartRecommended) { return 3010 }
    return 0
}

function New-RmmResult {
    param(
        [Parameter(Mandatory=$true)]$State,
        [Parameter(Mandatory=$true)][int]$ExitCode
    )
    return [pscustomobject]@{
        schemaVersion = $script:SchemaVersion
        tool = $script:ToolName
        version = $script:ToolVersion
        generated = (Get-Date).ToString('s')
        computer = [pscustomobject]@{
            name = $State.Computer.Name
            windows = $State.Computer.ProductName
            version = $State.Computer.DisplayVersion
            build = $State.Computer.Build
            edition = $State.Computer.EditionID
            virtualMachine = $State.VirtualMachine.Detected
            virtualPlatform = $State.VirtualMachine.PlatformHint
        }
        exitCode = $ExitCode
        status = Get-ExitCodeMeaning -Code $ExitCode
        integrity = $script:IntegrityState
        rebootRequired = $script:RestartRecommended
        security = [pscustomobject]@{
            secureBootEnabled = $State.Firmware.SecureBootEnabled
            tpmPresent = $State.TPM.Present
            tpmReady = $State.TPM.Ready
            virtualizationFirmwareEnabled = $State.Virtualization.VirtualizationFirmwareEnabled
            vbsStatus = $State.VBS.Status
            memoryIntegrityRunning = $State.Features.MemoryIntegrity.Running
            secureLaunchRunning = $State.Features.SecureLaunch.Running
            credentialGuardRunning = $State.Features.CredentialGuard.Running
            kernelDmaCapability = $State.HardwareCapabilities.DMACapability
        }
        summary = @(Get-ReportSummaryRows -State $State)
        unsupportedCapabilities = @(Get-UnsupportedCapabilities -State $State)
        outcome = [pscustomobject]$script:Outcome
        changes = @($script:Changes)
        plannedChanges = @($script:PlannedChanges)
        hvciDiagnostics = if ($script:LastHvciDiagnostics) { [pscustomobject]@{
            assessment=$script:LastHvciDiagnostics.Assessment
            compatibilityEventCount=$script:LastHvciDiagnostics.CompatibilityEventCount
            candidateDriverReferences=@($script:LastHvciDiagnostics.CandidateDriverReferences)
        }} else { $null }
        reportPath = $script:LastReportPath
    }
}

function Invoke-WinDSHSelfTest {
    $tests = @()
    function Add-TestResult { param([string]$Name,[bool]$Passed,[string]$Detail); $script:SelfTestTemp += [pscustomobject]@{Name=$Name;Passed=$Passed;Detail=$Detail} }
    $script:SelfTestTemp = @()

    try {
        $state = [pscustomobject]@{
            Computer=[pscustomobject]@{BuildNumber=26200;EditionID='Enterprise';IsDomainController=$false}
            Firmware=[pscustomobject]@{Type='UEFI';SecureBootSupported=$true;SecureBootEnabled=$true}
            TPM=[pscustomobject]@{Present=$true;Ready=$true;IsTPM2=$true;SpecVersion='2.0'}
            Virtualization=[pscustomobject]@{VirtualizationFirmwareEnabled=$true;HypervisorPresent=$true;VMMonitorModeExtensions=$true;SLAT=$true;SLATAssessment='Supported'}
            HardwareCapabilities=[pscustomobject]@{DMACapability=$true;NXAvailable=$true}
            DEP=[pscustomobject]@{Available=$true}
            VBS=[pscustomobject]@{StatusCode=2;Status='Running'}
            Features=[pscustomobject]@{
                MemoryIntegrity=[pscustomobject]@{Running=$false;Configured=$false;ManagedByPolicy=$false;RegistryEnabled=$null}
                SecureLaunch=[pscustomobject]@{Running=$false;Configured=$false;ManagedByPolicy=$false;BasicPrerequisitesConfirmed=$true;RegistryEnabled=$null}
                CredentialGuard=[pscustomobject]@{Running=$false;Configured=$false;ManagedByPolicy=$false;EditionSupported=$true;LsaCfgFlags=$null}
                KernelStackProtection=[pscustomobject]@{Running=$false;Configured=$false;AuditMode=$false;WindowsVersionEligible=$true}
                VulnerableDriverBlocklist=[pscustomobject]@{RegistryValue=$null;EffectiveAssessment='Windows default is enabled; no explicit local override found'}
                SMMFirmwareMeasurement=[pscustomobject]@{Running=$false;Configured=$false}
                HypervisorEnforcedPagingTranslation=[pscustomobject]@{Running=$false;Configured=$false}
            }
            Policy=[pscustomobject]@{EnableVirtualizationBasedSecurity=$null;HypervisorEnforcedCodeIntegrity=$null;ConfigureSystemGuardLaunch=$null;CredentialGuardLsaCfgFlags=$null}
            Restart=[pscustomobject]@{Pending=$false}
        }
        $a2 = Get-MenuActionAvailability -State $state -Key '2'
        Add-TestResult 'Memory Integrity action available on baseline state' $a2.Actionable $a2.Reason
        $a3 = Get-MenuActionAvailability -State $state -Key '3'
        Add-TestResult 'Secure Launch action available with UEFI + TPM2' $a3.Actionable $a3.Reason
        $fw = @(Get-FirmwareActions -State $state)
        Add-TestResult 'Firmware action list can be empty without throwing' ($fw.Count -eq 0) ('Count={0}' -f $fw.Count)
        $summaryRows = @(Get-QuickSummary -State $state)
        Add-TestResult 'Easy Summary returns a stable multi-item array' ($summaryRows.Count -eq 10) ('Count={0}' -f $summaryRows.Count)
        $state.Firmware.SecureBootEnabled = $false
        $fwNeedsAction = @(Get-FirmwareActions -State $state)
        Add-TestResult 'Firmware action list handles a single action safely' ($fwNeedsAction.Count -eq 1) ('Count={0}' -f $fwNeedsAction.Count)
        $state.Firmware.SecureBootEnabled = $true
        $state.Features.CredentialGuard.EditionSupported = $false
        $a4 = Get-MenuActionAvailability -State $state -Key '4'
        Add-TestResult 'Credential Guard is unavailable when edition support is false' (-not $a4.Actionable) $a4.Reason
        Add-TestResult 'Empty array membership is safe' (-not (Test-ArrayContains @() 2)) 'Test-ArrayContains returned expected False.'
    }
    catch {
        Add-TestResult 'Self-test harness' $false $_.Exception.Message
    }

    $tests = @($script:SelfTestTemp)
    Remove-Variable -Name SelfTestTemp -Scope Script -ErrorAction SilentlyContinue
    Write-Host ('WinDSH v{0} synthetic self-test' -f $script:ToolVersion) -ForegroundColor Cyan
    foreach ($t in $tests) { Write-Host ('[{0}] {1} - {2}' -f $(if($t.Passed){'PASS'}else{'FAIL'}),$t.Name,$t.Detail) -ForegroundColor $(if($t.Passed){'Green'}else{'Red'}) }
    $failed = @($tests | Where-Object {-not $_.Passed}).Count
    if ($failed -gt 0) { Write-Host ('Self-test result: {0} failed.' -f $failed) -ForegroundColor Red; return 1 }
    Write-Host 'Self-test result: PASS.' -ForegroundColor Green
    return 0
}

function Invoke-Unattended {
    $state = Invoke-DebugStage -Name 'Initial system-state audit' -ScriptBlock { Get-SystemState }
    $script:InitialState = $state
    $script:FinalState = $state
    Write-SystemStateDebugSnapshot -State $state
    if (-not $script:RmmMode) { Invoke-DebugStage -Name 'Render audit output' -ScriptBlock { Show-State -State $state } }

    $preview = $script:PreviewRequested
    if ($preview) {
        if ($EnableAllSafe) {
            $plan = Get-ChangePlan -State $state -Target Safe
            $script:PlannedChanges += $plan
            if (-not $script:RmmMode) { Show-ChangePlan -Plan $plan }
        }
        if ($EnableCredentialGuard) {
            $planCg = Get-ChangePlan -State $state -Target CredentialGuard
            $script:PlannedChanges += $planCg
            if (-not $script:RmmMode) { Show-ChangePlan -Plan $planCg }
        }
    }
    else {
        if ($EnableAllSafe) {
            Enable-AllRecommended -State $state -ForceConfirmed
            $state = Get-SystemState
        }
        if ($EnableCredentialGuard) {
            Enable-CredentialGuardFeature -State $state -ForceConfirmed
            $state = Get-SystemState
        }
    }

    if (@($script:Changes).Count -gt 0 -and -not $script:RmmMode) {
        Write-Section 'Status after requested changes (before restart)'
        $state = Get-SystemState
        Show-State -State $state
    }

    $script:FinalState = $state
    $remediationRequested = [bool](($EnableAllSafe -or $EnableCredentialGuard) -and -not $preview)
    $explicitPrerequisite = [bool]($EnableCredentialGuard -and -not $EnableAllSafe -and -not $preview)
    $script:LastExitCode = Get-UnattendedExitCode -RemediationRequested:$remediationRequested -ExplicitPrerequisiteAction:$explicitPrerequisite

    if ($script:EffectiveReportFormat -and $script:EffectiveReportFormat -ne 'None') {
        [void](Save-Report -State $state -Format $script:EffectiveReportFormat)
    }

    if (-not $script:RmmMode) { Show-RestartSummary -State $state }

    if ($AutoReboot -and $script:RestartRecommended -and -not $script:Outcome.IntegrityFailed -and -not $script:Outcome.RemediationFailed) {
        if (-not $script:RmmMode) { Write-Host 'AutoReboot was requested. Restarting Windows now.' -ForegroundColor Yellow }
        Restart-Computer -Force
        return 0
    }

    if (-not $script:RmmMode) {
        Write-Host ('Unattended exit code: {0} - {1}' -f $script:LastExitCode,(Get-ExitCodeMeaning -Code $script:LastExitCode)) -ForegroundColor DarkGray
    }
    return $script:LastExitCode
}

function Show-InformationGatheringBanner {
    Write-Host ''
    Write-Host ('-' * 82) -ForegroundColor DarkCyan
    Write-Host ' Gathering Windows device-security information... Please wait.' -ForegroundColor Cyan
    Write-Host ('-' * 82) -ForegroundColor DarkCyan
}

function Show-InformationGatheringComplete {
    Write-Host ' Information gathering completed.' -ForegroundColor Green
    Write-Host ''
}

function Invoke-Interactive {
    Write-Host ('{0} v{1}' -f $script:ToolName,$script:ToolVersion) -ForegroundColor Cyan
    Write-Host ''
    Write-Host ("`t`t{0}" -f $script:ContactEmail) -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Windows Device Security audit and safe remediation' -ForegroundColor Gray
    Write-Host 'No downloads, AV changes, execution-policy bypass, TPM clear, Secure Boot modification, or encryption changes.' -ForegroundColor DarkGray

    Show-InformationGatheringBanner
    $state = Invoke-DebugStage -Name 'Initial system-state audit' -ScriptBlock { Get-SystemState }
    $script:InitialState = $state
    $script:FinalState = $state
    Write-SystemStateDebugSnapshot -State $state
    Show-InformationGatheringComplete
    Invoke-DebugStage -Name 'Render audit output' -ScriptBlock { Show-State -State $state }

    while ($true) {
        Show-Menu -State $state
        $choice = Read-MenuChoice
        switch ($choice) {
            '1' { $state = Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            '2' {
                if (Test-MenuActionSelectable -State $state -Key '2') { Enable-MemoryIntegrity -State $state; $state=Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            }
            '3' {
                if (Test-MenuActionSelectable -State $state -Key '3') { Enable-SecureLaunch -State $state; $state=Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            }
            '4' {
                if (Test-MenuActionSelectable -State $state -Key '4') { Enable-CredentialGuardFeature -State $state; $state=Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            }
            '5' {
                if (Test-MenuActionSelectable -State $state -Key '5') { Enable-VulnerableDriverBlocklist -State $state; $state=Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            }
            '6' { Open-CoreIsolation }
            '7' { $diag=Get-HvciDiagnostics; Show-HvciDiagnostics -Diagnostics $diag }
            '8' { Open-CodeIntegrityEventViewer }
            'P' {
                if (Test-MenuActionSelectable -State $state -Key 'P') { $plan=Get-ChangePlan -State $state -Target Safe; $script:PlannedChanges=@($plan); Show-ChangePlan -Plan $plan }
            }
            'A' {
                if (Test-MenuActionSelectable -State $state -Key 'A') { Enable-AllRecommended -State $state; $state=Get-SystemState; $script:FinalState=$state; Show-State -State $state }
            }
            'R' { $state=Get-SystemState; $script:FinalState=$state; Save-ReportInteractive -State $state }
            'Q' { Invoke-InteractiveExit -State $state; return }
        }
    }
}

function Main {
    if ($Version) {
        [Console]::Out.WriteLine(('{0} {1}' -f $script:ToolName,$script:ToolVersion))
        return 0
    }
    if ($SelfTest) { return (Invoke-WinDSHSelfTest) }

    Request-Elevation
    Initialize-DebugLogging
    [void](Invoke-SelfIntegrityCheck)
    $nonInteractive = Resolve-InvocationMode

    if ($nonInteractive) {
        if ($RMM) {
            # Suppress Write-Host/information-stream UI from nested remediation code.
            $rc = & { Invoke-Unattended } 6>$null
            $stateForOutput = if ($script:FinalState) { $script:FinalState } else { $script:InitialState }
            $rmmObject = New-RmmResult -State $stateForOutput -ExitCode $rc
            [Console]::Out.WriteLine(($rmmObject | ConvertTo-Json -Compress -Depth 14))
            return $rc
        }
        return (Invoke-Unattended)
    }

    Invoke-Interactive
    return 0
}

try {
    $mainResult = Main
    if ($null -eq $mainResult) { $mainResult = 0 }
    Exit-WinDSH -Code ([int]$mainResult) -Reason 'WinDSH has finished.'
}
catch {
    Write-DebugException -Stage 'Unhandled top-level failure' -ErrorRecord $_
    if ($RMM) {
        $obj = [ordered]@{
            schemaVersion = $script:SchemaVersion
            tool = $script:ToolName
            version = $script:ToolVersion
            exitCode = 1
            status = 'FatalError'
            message = $_.Exception.Message
        }
        [Console]::Out.WriteLine(($obj | ConvertTo-Json -Compress -Depth 5))
        exit 1
    }
    Write-Host ''
    Write-Host ('Fatal error: {0}' -f $_.Exception.Message) -ForegroundColor Red
    if ($_.InvocationInfo) {
        $where = $_.InvocationInfo.PositionMessage
        if (-not [string]::IsNullOrWhiteSpace($where)) {
            Write-Host 'Error location:' -ForegroundColor Yellow
            Write-Host $where -ForegroundColor DarkGray
        }
    }
    Write-Host 'The error is shown intentionally; this tool does not suppress or hide failures.' -ForegroundColor Gray
    if ($script:DebugEnabled -and $script:ResolvedDebugLogPath) { Write-Host ('Debug log: {0}' -f $script:ResolvedDebugLogPath) -ForegroundColor Cyan }
    Exit-WinDSH -Code 1 -Reason 'WinDSH stopped because of the error shown above.'
}
