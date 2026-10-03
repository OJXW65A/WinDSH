#requires -Version 5.1
<#
.SYNOPSIS
    WinDSH - Windows Device Security Helper. Audits and optionally configures
    Windows platform security features, with CIS Benchmark mapping.

.DESCRIPTION
    WinDSH reports the real state of Virtualization-based Security, Memory Integrity
    (HVCI), Credential Guard, System Guard Secure Launch, kernel shadow stacks and the
    Microsoft vulnerable driver blocklist, explains why a feature is not running, and can
    configure a conservative subset locally.

    Every setting lives in one declarative catalog. Audit, preview, apply, revert, scoring,
    CIS comparison and all report formats are projections over that catalog, so they
    cannot disagree with each other.

    WinDSH writes local machine configuration under
    HKLM\SYSTEM\CurrentControlSet\Control. It NEVER writes the Group Policy hive
    (HKLM\SOFTWARE\Policies) and refuses to change any value that policy manages.

    CIS NOTE: CIS Benchmark section 18.9.5 audits the Group Policy hive. Because WinDSH
    configures local values instead, a machine configured by WinDSH will have the features
    running but will NOT pass a CIS scan of 18.9.5. WinDSH reports that divergence
    explicitly rather than implying compliance.

.PARAMETER AuditOnly
    Report only. Makes no changes. Cannot be combined with a remediation switch.

.PARAMETER EnableAllSafe
    Unattended: apply the conservative recommended set.

.PARAMETER Enable
    Unattended: apply specific controls by id (see -ListControls).

.PARAMETER Revert
    Undo a previous run. Use -RunId, or the most recent run when omitted.

.PARAMETER RunId
    The change-journal run to revert.

.PARAMETER ListControls
    Print the control catalog and exit.

.PARAMETER Explain
    Explain one control by id and exit, e.g. -Explain secure-launch.

.PARAMETER HtmlReport
    Write an HTML report with a security score.

.PARAMETER JsonReport
    Write a machine-readable JSON report.

.PARAMETER TextReport
    Write a plain-text report.

.PARAMETER NoReport
    Suppress report files.

.PARAMETER ReportDirectory
    Where reports are written. Defaults to a WinDSH folder on the Desktop.

.PARAMETER Rmm
    Emit one compact JSON object on stdout. Implies unattended and no console output.

.PARAMETER Advanced
    Show full technical detail in the console instead of the plain-language summary.

.PARAMETER NoColor
    Disable colour. Also honours the NO_COLOR environment variable.

.PARAMETER AutoReboot
    Restart automatically when changes require it. Unattended only.

.PARAMETER DebugLogPath
    Write a diagnostic log.

.PARAMETER SelfTest
    Run built-in synthetic tests and exit.

.PARAMETER Version
    Print the version and exit.

.NOTES
    Exit codes:
      0    success, no restart required
      1    invalid usage or startup failure
      2    audit or remediation completed with warnings
      3    self-integrity check failed; remediation disabled
      4    elevation required
      5    revert failed
      3010 success, restart required
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$AuditOnly,
    [switch]$EnableAllSafe,
    [string[]]$Enable,
    [switch]$Revert,
    [string]$RunId,
    [switch]$ListControls,
    [string]$Explain,
    [switch]$HtmlReport,
    [switch]$JsonReport,
    [switch]$TextReport,
    [switch]$NoReport,
    [string]$ReportDirectory,
    [switch]$Rmm,
    [switch]$Advanced,
    [switch]$NoColor,
    [switch]$AutoReboot,
    [string]$DebugLogPath,
    [switch]$SelfTest,
    [switch]$Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName        = 'WinDSH'
$script:ToolVersion     = '2.0.0'
$script:SchemaVersion   = '2.0'
$script:CisBenchmark    = 'CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0'

# Replaced by build/Build-WinDSH.ps1. Detects accidental corruption, not tampering.
$script:ExpectedIntegrityHash = '0000000000000000000000000000000000000000000000000000000000000000'

$script:RemediationAllowed = $true
$script:RestartRequired    = $false
$script:Warnings           = @()
$script:AppliedChanges     = @()
$script:DebugEnabled       = $false
$script:DebugPath          = $null
$script:UseColor           = $true
$script:ExitCode           = 0
$script:Unattended         = $false

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

function Initialize-Console {
    param([bool]$DisableColor)
    $script:UseColor = -not ($DisableColor -or $env:NO_COLOR -or $Rmm)
}

function Write-Line {
    # Every status carries a text marker as well as colour, so the output is readable
    # when colour is unavailable, redirected, or the reader cannot distinguish it.
    param(
        [string]$Text = '',
        [ValidateSet('Plain', 'Good', 'Warn', 'Bad', 'Info', 'Head', 'Dim')]
        [string]$Kind = 'Plain',
        [int]$Indent = 0
    )
    if ($Rmm) { return }

    $prefix = switch ($Kind) {
        'Good' { '[ OK ] ' }
        'Warn' { '[ !  ] ' }
        'Bad'  { '[ X  ] ' }
        'Info' { '[ i  ] ' }
        default { '' }
    }
    $pad = ' ' * $Indent
    $line = '{0}{1}{2}' -f $pad, $prefix, $Text

    if (-not $script:UseColor) { Write-Host $line; return }

    $colour = switch ($Kind) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad'  { 'Red' }
        'Info' { 'Cyan' }
        'Head' { 'White' }
        'Dim'  { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $colour
}

function Write-Section {
    param([string]$Title)
    if ($Rmm) { return }
    Write-Host ''
    Write-Line ('== {0} ==' -f $Title) 'Head'
}

function Add-Warning {
    param([string]$Message)
    $script:Warnings += $Message
    Write-Debug-Log ('WARNING: {0}' -f $Message)
}

function Write-Debug-Log {
    param([string]$Message)
    if (-not $script:DebugEnabled -or -not $script:DebugPath) { return }
    try {
        $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        [IO.File]::AppendAllText($script:DebugPath, ('[{0}] {1}{2}' -f $stamp, $Message, "`n"))
    }
    catch { }
}

function Write-DebugError {
    param([string]$Stage, $ErrorRecord)
    if (-not $script:DebugEnabled) { return }
    $message = if ($ErrorRecord -and $ErrorRecord.Exception) { $ErrorRecord.Exception.Message } else { 'unknown' }
    Write-Debug-Log ('EXCEPTION during {0}: {1}' -f $Stage, $message)
}

# ---------------------------------------------------------------------------
# Safe accessors. PowerShell 5.1 with StrictMode throws on missing members and
# treats a single-item result as a scalar, which caused real defects in v1.
# ---------------------------------------------------------------------------

function Get-PropertySafe {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    # Catalog value entries are hashtables, not PSObjects; PSObject.Properties does not
    # see their keys, so check the hashtable first.
    if ($Object -is [hashtable]) {
        if ($Object.ContainsKey($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    try {
        $member = $Object.PSObject.Properties[$Name]
        if ($null -eq $member) { return $Default }
        if ($null -eq $member.Value) { return $Default }
        return $member.Value
    }
    catch { return $Default }
}

function ConvertTo-Array {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value)
}

function Test-Contains {
    param($Collection, $Value)
    return [bool](@(ConvertTo-Array $Collection) -contains $Value)
}

function Format-Bool {
    # Parameters are NOT named True/False/Null: those are automatic constants in
    # PowerShell and binding to them fails at runtime with "cannot overwrite variable".
    param($Value, [string]$TrueText = 'Yes', [string]$FalseText = 'No', [string]$UnknownText = 'Unknown')
    if ($null -eq $Value) { return $UnknownText }
    if ([bool]$Value) { return $TrueText }
    return $FalseText
}

# ---------------------------------------------------------------------------
# Registry access. Routed through a provider so the apply/revert engine can be
# unit tested without a real HKLM.
# ---------------------------------------------------------------------------

function New-RegistryProvider {
    return @{
        Kind = 'Windows'
        GetValue = {
            param([string]$Path, [string]$Name)
            try {
                if (-not (Test-Path -LiteralPath $Path)) { return $null }
                $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                return $item.$Name
            }
            catch { return $null }
        }
        ValueExists = {
            param([string]$Path, [string]$Name)
            try {
                if (-not (Test-Path -LiteralPath $Path)) { return $false }
                $key = Get-Item -LiteralPath $Path -ErrorAction Stop
                return [bool](@($key.GetValueNames()) -contains $Name)
            }
            catch { return $false }
        }
        GetKind = {
            param([string]$Path, [string]$Name)
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            return $key.GetValueKind($Name).ToString()
        }
        SetValue = {
            param([string]$Path, [string]$Name, [string]$Type, $Value)
            if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        RemoveValue = {
            param([string]$Path, [string]$Name)
            if (-not (Test-Path -LiteralPath $Path)) { return }
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
        }
    }
}

function New-InMemoryRegistryProvider {
    param([hashtable]$Seed)
    $store = @{}
    $kinds = @{}
    if ($Seed) { foreach ($k in $Seed.Keys) { $store[$k] = $Seed[$k]; $kinds[$k] = 'DWord' } }

    # GetNewClosure binds $store into each scriptblock; without it they resolve
    # $store in the caller's scope at invocation time and fail.
    return @{
        Kind = 'InMemory'
        Store = $store
        Kinds = $kinds
        GetValue = {
            param([string]$Path, [string]$Name)
            $key = '{0}|{1}' -f $Path, $Name
            if ($store.ContainsKey($key)) { return $store[$key] }
            return $null
        }.GetNewClosure()
        ValueExists = {
            param([string]$Path, [string]$Name)
            return $store.ContainsKey(('{0}|{1}' -f $Path, $Name))
        }.GetNewClosure()
        GetKind = {
            param([string]$Path, [string]$Name)
            return $kinds[('{0}|{1}' -f $Path, $Name)]
        }.GetNewClosure()
        SetValue = {
            param([string]$Path, [string]$Name, [string]$Type, $Value)
            $kinds[('{0}|{1}' -f $Path, $Name)] = $Type
            $store[('{0}|{1}' -f $Path, $Name)] = $Value
        }.GetNewClosure()
        RemoveValue = {
            param([string]$Path, [string]$Name)
            $key = '{0}|{1}' -f $Path, $Name
            if ($store.ContainsKey($key)) { $store.Remove($key); $kinds.Remove($key) }
        }.GetNewClosure()
    }
}

$script:Registry = New-RegistryProvider

function Set-RegistryProvider { param($Provider) $script:Registry = $Provider }
function Get-RegValue { param([string]$Path, [string]$Name) return (& $script:Registry.GetValue $Path $Name) }
function Get-RegKind { param([string]$Path, [string]$Name) return (& $script:Registry.GetKind $Path $Name) }
function Test-RegValue { param([string]$Path, [string]$Name) return [bool](& $script:Registry.ValueExists $Path $Name) }

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

function Test-IsElevated {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-DebugError 'Check elevation' $_
        return $false
    }
}

function Confirm-Action {
    <#
        Interactive confirmation. Returns $true without prompting when the run is
        unattended, because a prompt on an RMM or scheduled run would hang forever
        waiting for a user who is not there. Consent for those runs comes from the
        invocation itself.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Question,
        [switch]$DefaultYes,
        [string]$RequireTyped
    )

    # Invocation consent covers ordinary changes, never a typed safety override.
    if ($script:Unattended) { return [bool](-not $RequireTyped) }

    if ($RequireTyped) {
        Write-Line ('Type {0} to continue, or anything else to cancel.' -f $RequireTyped) 'Warn'
        $typed = Read-Host $Question
        return [bool]($typed.Trim() -eq $RequireTyped)
    }

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = Read-Host ('{0} {1}' -f $Question, $suffix)
        if ([string]::IsNullOrWhiteSpace($answer)) { return [bool]$DefaultYes }
        switch ($answer.Trim().ToUpperInvariant()) {
            'Y' { return $true }
            'YES' { return $true }
            'N' { return $false }
            'NO' { return $false }
            default { Write-Line 'Please answer yes or no.' 'Warn' }
        }
    }
}

function Get-ExitCodeMeaning {
    param([int]$Code)
    switch ($Code) {
        0    { 'Completed successfully. No restart needed.' }
        1    { 'Could not start: the options given were not valid.' }
        2    { 'Completed, but with warnings.' }
        3    { 'The file failed its integrity check, so changes were disabled.' }
        4    { 'Administrator rights were required but not available.' }
        5    { 'The undo operation failed.' }
        3010 { 'Completed. Windows must restart for the changes to take effect.' }
        default { 'Unrecognised exit code {0}.' -f $Code }
    }
}

function Get-RelaunchArgumentList {
    <#
        Rebuilds the invocation from bound parameters instead of concatenating a raw
        command line. v1's launcher forwarded %* unfiltered into the elevated process,
        which let a caller steer parameters of a process running with higher privilege.
        Each value is quoted and internal quotes doubled, so a value can never become
        a new argument.
    #>
    param([hashtable]$Bound)

    # NOT named $args: that is an automatic variable in PowerShell.
    $list = @()
    foreach ($key in $Bound.Keys) {
        $value = $Bound[$key]
        if ($value -is [switch]) {
            if ($value.IsPresent) { $list += ('-{0}' -f $key) }
        }
        elseif ($value -is [array]) {
            $list += ('-{0}' -f $key)
            foreach ($v in $value) { $list += ('"{0}"' -f ([string]$v -replace '"', '""')) }
        }
        elseif ($null -ne $value) {
            $list += ('-{0}' -f $key)
            $list += ('"{0}"' -f ([string]$value -replace '"', '""'))
        }
    }
    return $list
}

function Request-Elevation {
    <#
        Relaunches this script elevated and waits, so the exit code still reaches the
        caller. Returns $false when elevation is impossible or declined.

        Never attempted in RMM mode: a UAC prompt on an unattended run would hang the
        agent waiting for a user who is not there.
    #>
    param([hashtable]$Bound)

    if ($Rmm) { return $false }

    $host_ = $null
    try {
        if ($PSVersionTable.PSEdition -eq 'Core') { $host_ = (Get-Process -Id $PID).Path }
    }
    catch { Write-DebugError 'Resolve current host path' $_ }
    if ([string]::IsNullOrWhiteSpace($host_)) {
        $host_ = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    if (-not (Test-Path -LiteralPath $host_)) { return $false }
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { return $false }

    Write-Line 'WinDSH needs Administrator rights to read device security settings.' 'Info'
    Write-Line 'You will see a User Account Control prompt.' 'Info'

    # Process-scope Bypass only. This affects this one child process and ends with it;
    # it does not change any persistent execution policy.
    $list = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    $list += Get-RelaunchArgumentList -Bound $Bound

    try {
        $proc = Start-Process -FilePath $host_ -ArgumentList $list -Verb RunAs -PassThru -Wait -WhatIf:$false
        $script:ExitCode = [int]$proc.ExitCode
        return $true
    }
    catch {
        Write-DebugError 'Request elevation' $_
        Write-Line 'Elevation was cancelled or refused.' 'Warn'
        return $false
    }
}

function Get-SelfIntegrity {
    <#
        SHA-256 of this file with the stored hash line replaced by a placeholder and line
        endings normalized. Detects accidental corruption in transit. It is NOT a security
        boundary: anyone who can edit the script can recompute the value.
    #>
    $result = [pscustomobject]@{ Status = 'Unknown'; Expected = $script:ExpectedIntegrityHash; Actual = $null; Path = $null }
    try {
        $path = $PSCommandPath
        if ([string]::IsNullOrWhiteSpace($path)) { $result.Status = 'Skipped'; return $result }
        $result.Path = $path

        $text = [IO.File]::ReadAllText($path)
        $pattern = '(?m)^\$script:ExpectedIntegrityHash\s*=\s*''[0-9A-Fa-f]{64}''\s*$'
        if (-not [regex]::IsMatch($text, $pattern)) { $result.Status = 'Skipped'; return $result }

        $normalized = [regex]::Replace($text, $pattern, ("`$script:ExpectedIntegrityHash = '{0}'" -f ('0' * 64)), 1)
        $normalized = ($normalized -replace "`r`n", "`n") -replace "`r", "`n"

        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
            $result.Actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha.Dispose() }

        if ($script:ExpectedIntegrityHash -eq ('0' * 64)) { $result.Status = 'Unsigned' }
        elseif ($result.Actual -eq $script:ExpectedIntegrityHash.ToLowerInvariant()) { $result.Status = 'OK' }
        else { $result.Status = 'Failed' }
    }
    catch {
        Write-DebugError 'Self-integrity check' $_
        $result.Status = 'Error'
    }
    return $result
}
