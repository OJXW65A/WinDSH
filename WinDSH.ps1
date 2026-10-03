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
    Unattended: apply the conservative set; skip failed or unknown compatibility checks.

.PARAMETER Enable
    Unattended: apply specific controls by id. Typed safety overrides remain interactive.

.PARAMETER Revert
    Undo completed writes still matching current state. Defaults to the newest open run.

.PARAMETER RunId
    The change-journal run to revert.

.PARAMETER ListControls
    Print the control catalog and exit.

.PARAMETER Explain
    Explain one control by id and exit, e.g. -Explain secure-launch.

.PARAMETER HtmlReport
    Write an HTML report with an applicable protection score.

.PARAMETER JsonReport
    Write a machine-readable JSON report.

.PARAMETER TextReport
    Write a plain-text report.

.PARAMETER NoReport
    Suppress report files.

.PARAMETER ReportDirectory
    Where reports are written. Defaults to a WinDSH folder on the Desktop.

.PARAMETER Rmm
    Emit one compact JSON object on stdout. Explicit report-format switches also write files.

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
      1    invalid usage, startup/runtime failure, or remediation error
      2    audit or remediation completed with warnings
      3    self-integrity check failed; remediation disabled
      4    elevation required
      5    revert failed or conflicted
      3010 success, restart required

    MIT License notice:
    MIT License
    
    Copyright (c) 2026 OJXW65A
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
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

# Preserve script-level bound arguments; Invoke-Main has no bound parameters.
$script:InvocationParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) { $script:InvocationParameters[$parameterName] = $PSBoundParameters[$parameterName] }

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolName        = 'WinDSH'
$script:ToolVersion     = '2.0.0'
$script:SchemaVersion   = '2.1'
$script:CisBenchmark    = 'CIS Microsoft Windows 11 Enterprise Benchmark v5.1.0'

# Replaced by build/Build-WinDSH.ps1. Detects accidental corruption, not tampering.
$script:ExpectedIntegrityHash = '3fdc2691523b0e859d07a7b5c7d30ead6c1992b1ebddc184a1c42e38ec9071d3'
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
    if ($script:Warnings -contains $Message) { return }
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
            if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $null }
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if (@($key.GetValueNames()) -notcontains $Name) { return $null }
            return $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
        ValueExists = {
            param([string]$Path, [string]$Name)
            if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $false }
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            return [bool](@($key.GetValueNames()) -contains $Name)
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

function Test-CatalogValueSatisfied {
    param([hashtable]$Definition, $Current)
    if ($null -eq $Current) { return $false }
    if ($Definition.ContainsKey('AcceptedValues')) { return [bool](@($Definition.AcceptedValues) -contains [long]$Current) }
    if ($Definition.ContainsKey('Comparison') -and $Definition.Comparison -eq 'AtLeast') { return [bool]([long]$Current -ge [long]$Definition.Value) }
    return [bool]([long]$Current -eq [long]$Definition.Value)
}

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
        1    { 'Invalid options, startup/runtime failure, or remediation error.' }
        2    { 'Completed, but with warnings.' }
        3    { 'The file failed its integrity check, so changes were disabled.' }
        4    { 'Administrator rights were required but not available.' }
        5    { 'The undo operation failed or has unresolved conflicts.' }
        3010 { 'Completed. Windows must restart for the changes to take effect.' }
        default { 'Unrecognised exit code {0}.' -f $Code }
    }
}

function ConvertTo-NativeArgument {
    <# Quote one argv element using Windows CRT rules used by Start-Process. #>
    param([AllowEmptyString()][string]$Value)
    $escaped = [regex]::Replace($Value, '(\\*)"', {
        param($match)
        return (('\' * ($match.Groups[1].Value.Length * 2 + 1)) + '"')
    })
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return ('"{0}"' -f $escaped)
}

function Get-RelaunchArgumentList {
    <# Serialize validated script parameters as argv, never PowerShell expressions. #>
    param([hashtable]$Bound)
    $list = @()
    foreach ($key in $Bound.Keys) {
        if ($key -notin @('AuditOnly', 'EnableAllSafe', 'Enable', 'Revert', 'RunId', 'ListControls', 'Explain', 'HtmlReport', 'JsonReport', 'TextReport', 'NoReport', 'ReportDirectory', 'Rmm', 'Advanced', 'NoColor', 'AutoReboot', 'DebugLogPath', 'SelfTest', 'Version', 'WhatIf', 'Confirm')) { throw ('Cannot forward unknown parameter {0}.' -f $key) }
        $value = $Bound[$key]
        if ($value -is [switch]) {
            # Windows PowerShell 5.1 -File cannot bind explicit switch booleans.
            # False switches keep their default by omission in a fresh child.
            if ($value.IsPresent) { $list += ('-{0}' -f $key) }
        }
        elseif ($value -is [array]) {
            # powershell.exe -File does not bind several native argv elements to an
            # array parameter. Enable uses one comma-separated string on relaunch.
            if ($key -ne 'Enable') { throw 'Only the Enable parameter accepts an array.' }
            foreach ($controlId in $value) {
                if (-not (Test-Contains (Get-ControlIds) $controlId)) { throw ('Unknown control {0}.' -f $controlId) }
            }
            $list += '-Enable'
            $list += ConvertTo-NativeArgument -Value ($value -join ',')
        }
        elseif ($null -ne $value) {
            $list += ('-{0}' -f $key)
            $list += ConvertTo-NativeArgument -Value ([string]$value)
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
    $list = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (ConvertTo-NativeArgument -Value $PSCommandPath))
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

# ===== 20-catalog.ps1 =====
# ---------------------------------------------------------------------------
# Control catalog: the single source of truth.
#
# Audit, explain, preview, apply, revert, scoring, CIS comparison and every report
# format are projections over this table. Adding a control means adding one entry.
#
# LocalValues  - what WinDSH writes, under HKLM\SYSTEM\CurrentControlSet\Control
# PolicyValues - what CIS audits, under HKLM\SOFTWARE\Policies (READ ONLY, never written)
#
# Comparison semantics for a value:
#   Exact   - rewrite anything that differs (default)
#   AtLeast - the declared value is a floor; a stronger existing value is preserved
# ---------------------------------------------------------------------------

$script:RegDeviceGuard   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$script:RegHvci          = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$script:RegSystemGuard   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard'
$script:RegShadowStacks  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks'
$script:RegLsa           = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:RegCiConfig      = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$script:RegPolicyDG      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'

$script:ControlCatalog = @(

    [pscustomobject]@{
        Id          = 'vbs'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Virtualization-based Security'
        PlainName   = 'Core security container'
        Category    = 'Platform'
        Weight      = 25
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @()
        Summary     = 'Uses the Windows hypervisor to create a protected area of memory that the rest of Windows cannot reach.'
        Why         = 'Everything else on this list runs inside it. Without it, none of the other protections can start.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Vbs'
        LocalValues = @(
            @{ Path = $script:RegDeviceGuard; Name = 'EnableVirtualizationBasedSecurity'; Type = 'DWord'; Value = 1
               Note = 'Turns VBS on.' }
            @{ Path = $script:RegDeviceGuard; Name = 'Locked'; Type = 'DWord'; Value = 0; AcceptedValues = @(0, 1); KnownValues = @(0, 1)
               Note = 'Use no UEFI lock for new settings; preserve an existing lock.' }
        )
        PolicyValues = @(
            @{ Name = 'EnableVirtualizationBasedSecurity'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.1'; Profile = 'L1'
            Title = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
            Expected = 'EnableVirtualizationBasedSecurity = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'platform-security'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Platform Security Level'
        PlainName   = 'Secure Boot requirement'
        Category    = 'Platform'
        Weight      = 10
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Requires Secure Boot before the security container is allowed to start.'
        Why         = 'Stops the protection being started on a machine whose boot chain has not been verified.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'PlatformSecurity'
        LocalValues = @(
            # 1 = Secure Boot only, 3 = Secure Boot and DMA protection. CIS accepts either,
            # so accept 1 or 3 explicitly: an administrator who chose 3 keeps it.
            # Note 3 is stricter, not simply better - on hardware without an IOMMU it
            # prevents VBS from starting at all.
            @{ Path = $script:RegDeviceGuard; Name = 'RequirePlatformSecurityFeatures'; Type = 'DWord'; Value = 1
               AcceptedValues = @(1, 3); KnownValues = @(0, 1, 3)
               Note = 'Secure Boot required. An existing value of 3 (Secure Boot + DMA) is preserved.' }
        )
        PolicyValues = @(
            @{ Name = 'RequirePlatformSecurityFeatures'; Expected = 1; AlsoAccepted = @(3) }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.2'; Profile = 'L1'
            Title = "Ensure 'Select Platform Security Level' is set to 'Secure Boot' or higher"
            Expected = 'RequirePlatformSecurityFeatures = 1 or 3 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'hvci'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Memory Integrity (HVCI)'
        PlainName   = 'Driver protection'
        Category    = 'Kernel'
        Weight      = 25
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'platform-security')
        Summary     = 'Checks every driver inside the protected container before Windows will load it.'
        Why         = 'Blocks malicious or tampered drivers from running with kernel privileges.'
        Caution     = 'An incompatible driver can stop the computer from starting normally. WinDSH checks recent compatibility warnings before offering this.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Hvci'
        # Windows logs Event ID 3087 in CodeIntegrity/Operational when a driver is not
        # compatible with Memory Integrity. Enabling HVCI anyway can stop the machine
        # booting cleanly, so recent evidence blocks the safe set. Declared here rather
        # than special-cased inside the apply path, so any control can have one.
        Preflight   = @{
            Kind = 'CodeIntegrityEvents'
            EventIds = @(3087)
            LookbackDays = 14
            BlocksSafeSet = $true
            Message = 'Windows has recently reported a driver that is not compatible with Memory Integrity. Enabling it now could stop this computer starting normally.'
        }
        LocalValues = @(
            @{ Path = $script:RegHvci; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Turns Memory Integrity on.' }
            @{ Path = $script:RegHvci; Name = 'Locked'; Type = 'DWord'; Value = 0; AcceptedValues = @(0, 1); KnownValues = @(0, 1); Note = 'Use no UEFI lock for new settings; preserve an existing lock.' }
        )
        PolicyValues = @(
            # CIS wants 1 = Enabled with UEFI lock. WinDSH deliberately configures the
            # unlocked form locally so a machine that will not boot can be recovered.
            @{ Name = 'HypervisorEnforcedCodeIntegrity'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.3'; Profile = 'L1'
            Title = "Ensure 'Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
            Expected = 'HypervisorEnforcedCodeIntegrity = 1, with UEFI lock (Group Policy hive)'
            Divergence = 'WinDSH configures Memory Integrity WITHOUT a UEFI lock so it can be reverted from Windows. CIS requires the locked form, which can only be removed with a physically present user.'
        }
    }

    [pscustomobject]@{
        Id          = 'hvci-mat'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Require UEFI Memory Attributes Table'
        PlainName   = 'Firmware compatibility check'
        Category    = 'Kernel'
        Weight      = 5
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Only allows driver protection to start on firmware that reports a UEFI Memory Attributes Table.'
        Why         = 'A safety setting. Firmware without this table can be incompatible with Memory Integrity, which CIS notes may lead to crashes, data loss, or plug-in card incompatibility.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'HvciMat'
        LocalValues = @(
            @{ Path = $script:RegDeviceGuard; Name = 'HVCIMATRequired'; Type = 'DWord'; Value = 1
               Note = 'Refuses to start Memory Integrity on firmware that cannot support it safely.' }
        )
        PolicyValues = @(
            @{ Name = 'HVCIMATRequired'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.4'; Profile = 'L1'
            Title = "Ensure 'Require UEFI Memory Attributes Table' is set to 'True (checked)'"
            Expected = 'HVCIMATRequired = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'credential-guard'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization', 'CredentialGuardEdition')
        Name        = 'Credential Guard'
        PlainName   = 'Password and sign-in protection'
        Category    = 'Credentials'
        Weight      = 20
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'platform-security')
        Summary     = 'Moves your saved sign-in secrets into the protected container so malware on the computer cannot read them.'
        Why         = 'Defeats credential-theft tools that scrape passwords and Kerberos tickets from memory.'
        Caution     = 'Can break older network sign-in methods, some VPN clients, and legacy NTLM delegation.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/'
        DetectKey   = 'CredentialGuard'
        LocalValues = @(
            # 1 = enabled with UEFI lock, 2 = enabled without lock. Use 2 for new settings.
            @{ Path = $script:RegLsa; Name = 'LsaCfgFlags'; Type = 'DWord'; Value = 2; AcceptedValues = @(1, 2); KnownValues = @(0, 1, 2)
               Note = 'Enable without a UEFI lock for new settings; preserve an existing lock.' }
        )
        PolicyValues = @(
            @{ Name = 'LsaCfgFlags'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.5'; Profile = 'L1'
            Title = "Ensure 'Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
            Expected = 'LsaCfgFlags = 1 (Group Policy hive, UEFI lock)'
            Divergence = 'WinDSH sets LsaCfgFlags = 2 (enabled without UEFI lock) locally. CIS requires 1. The locked form cannot be removed remotely and needs a physically present user at the machine.'
        }
    }

    [pscustomobject]@{
        Id          = 'secure-launch'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization', 'Tpm2')
        Name        = 'System Guard Secure Launch'
        PlainName   = 'Firmware attack protection'
        Category    = 'Firmware'
        Weight      = 10
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Re-establishes trust in the computer after start-up, so a compromised firmware cannot undermine the other protections.'
        Why         = 'Protects the security container from exploited vulnerabilities in device firmware.'
        Caution     = 'Needs DRTM-capable firmware (Intel TXT or AMD SKINIT). Most consumer laptops do not have it, and Windows silently ignores the setting when it is absent.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection'
        DetectKey   = 'SecureLaunch'
        LocalValues = @(
            @{ Path = $script:RegSystemGuard; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Turns Secure Launch on.' }
        )
        PolicyValues = @(
            @{ Name = 'ConfigureSystemGuardLaunch'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.6'; Profile = 'L1'
            Title = "Ensure 'Secure Launch Configuration' is set to 'Enabled'"
            Expected = 'ConfigureSystemGuardLaunch = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'kernel-shadow-stacks'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Kernel-mode Hardware-enforced Stack Protection'
        PlainName   = 'Code hijacking protection'
        Category    = 'Kernel'
        Weight      = 10
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'hvci')
        Summary     = 'Keeps a hardware-protected copy of where kernel code is meant to return to, so an exploit cannot redirect it.'
        Why         = 'Stops memory-corruption exploits such as stack buffer overflows from hijacking kernel execution.'
        Caution     = 'Requires Windows 11 22H2 or newer and an Intel Tiger Lake or AMD Zen 3 processor or newer. Once enforcing, a shadow stack violation is fatal to the offending code.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection'
        DetectKey   = 'KernelShadowStacks'
        MinimumBuild = 22621
        LocalValues = @(
            @{ Path = $script:RegShadowStacks; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Enables kernel shadow stacks in enforcement mode.' }
        )
        PolicyValues = @(
            @{ Name = 'ConfigureKernelShadowStacksLaunch'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.7'; Profile = 'L1'
            Title = "Ensure 'Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode'"
            Expected = 'ConfigureKernelShadowStacksLaunch = 1 (Group Policy hive)'
        }
    }

    # ---- Detection only. WinDSH reports these but never configures them. -------
    # Weight 0 deliberately: they are informational and mostly not user-actionable, so
    # counting them would move the score without the user being able to do anything.

    [pscustomobject]@{
        Id          = 'hvpt'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'Hypervisor-enforced Paging Translation'
        PlainName   = 'Memory address protection'
        Category    = 'Kernel'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Moves control of memory address translation into the protected container.'
        Why         = 'Stops an attacker with kernel access from remapping memory to bypass other protections.'
        Caution     = 'Reported only. Windows enables this on supported hardware; WinDSH does not configure it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Hvpt'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'smm-firmware-measurement'
        PlatformRequirements = @('64Bit', 'Hypervisor', 'Uefi', 'Virtualization')
        Name        = 'SMM Firmware Measurement'
        PlainName   = 'Firmware self-check'
        Category    = 'Firmware'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Measures System Management Mode firmware so tampering with it can be detected.'
        Why         = 'System Management Mode runs beneath the operating system, so compromise there is invisible to Windows.'
        Caution     = 'Reported only. Provided by the platform firmware; WinDSH does not configure it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection'
        DetectKey   = 'SmmFirmware'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'dep'
        PlatformRequirements = @()
        Name        = 'Data Execution Prevention'
        PlainName   = 'Executable memory protection'
        Category    = 'Kernel'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Stops code running from memory that is only meant to hold data.'
        Why         = 'A long-standing defence against buffer-overflow exploits.'
        Caution     = 'Reported only. Configured in the boot configuration, not the registry; WinDSH does not change it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention'
        DetectKey   = 'Dep'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'driver-blocklist'
        PlatformRequirements = @('64Bit')
        Name        = 'Microsoft vulnerable driver blocklist'
        PlainName   = 'Known-bad driver blocking'
        Category    = 'Kernel'
        Weight      = 15
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @()
        Summary     = 'Blocks drivers Microsoft has identified as dangerous, even when they are correctly signed.'
        Why         = 'Attackers bring their own vulnerable signed driver to gain kernel access. This blocks the known ones.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/design/microsoft-recommended-driver-block-rules'
        DetectKey   = 'DriverBlocklist'
        LocalValues = @(
            @{ Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; Value = 1; Note = 'Turns the blocklist on.' }
        )
        PolicyValues = @()
        Cis = $null   # Not covered by CIS 18.9.5. WinDSH does more than the benchmark here.
    }
)

function Get-Control {
    param([Parameter(Mandatory = $true)][string]$Id)
    $match = @($script:ControlCatalog | Where-Object { $_.Id -eq $Id })
    if ($match.Count -ne 1) { throw "Unknown control id: $Id" }
    return $match[0]
}

function Get-ControlIds { return @($script:ControlCatalog | Select-Object -ExpandProperty Id) }

function Resolve-ControlOrder {
    <# Dependencies first, deduplicated, with cycle detection. #>
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [System.Collections.Generic.HashSet[string]]$Visiting
    )
    if (-not $Visiting) { $Visiting = New-Object 'System.Collections.Generic.HashSet[string]' }
    if (-not $Visiting.Add($Id)) { throw "Dependency cycle detected at control '$Id'." }

    $control = Get-Control -Id $Id
    $ordered = @()
    foreach ($dep in (ConvertTo-Array $control.Requires)) {
        $ordered += Resolve-ControlOrder -Id $dep -Visiting $Visiting
    }
    $ordered += $control
    $Visiting.Remove($Id) | Out-Null

    $seen = @{}
    $unique = @()
    foreach ($c in $ordered) {
        if (-not $seen.ContainsKey($c.Id)) { $seen[$c.Id] = $true; $unique += $c }
    }
    return $unique
}

# Applied by -EnableAllSafe. Deliberately excludes Credential Guard (compatibility risk)
# and kernel shadow stacks (fatal violations), which stay opt-in.
$script:SafeControlSet = @('vbs', 'platform-security', 'hvci-mat', 'hvci', 'driver-blocklist')

# ===== 30-state.ps1 =====
# ---------------------------------------------------------------------------
# State collection.
#
# Split into static and volatile. Hardware, firmware, TPM and OS identity cannot change
# while WinDSH is running, so they are collected once. Only the DeviceGuard state,
# registry values and restart status are re-read after a change. In v1 every menu action
# re-ran the whole collection, including Get-ComputerInfo and a bcdedit process spawn,
# to learn a handful of registry DWORDs.
# ---------------------------------------------------------------------------

$script:StaticState = $null

function Get-OsAndHardwareState {
    $os = $null; $cs = $null; $cpus = @()
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    catch { Write-DebugError 'Query Win32_OperatingSystem' $_ }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    catch { Write-DebugError 'Query Win32_ComputerSystem' $_ }
    try { $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) }
    catch { Write-DebugError 'Query Win32_Processor' $_ }

    $build = 0
    $buildText = [string](Get-PropertySafe $os 'BuildNumber' '0')
    [void][int]::TryParse($buildText, [ref]$build)

    $ubr = $null
    $editionId = $null
    $productName = $null
    try {
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ubr = Get-RegValue -Path $cv -Name 'UBR'
        $editionId = Get-RegValue -Path $cv -Name 'EditionID'
        $productName = Get-RegValue -Path $cv -Name 'ProductName'
    }
    catch { Write-DebugError 'Read CurrentVersion' $_ }

    $manufacturer = [string](Get-PropertySafe $cs 'Manufacturer' '')
    $model = [string](Get-PropertySafe $cs 'Model' '')
    $domainRole = Get-PropertySafe $cs 'DomainRole' $null
    $partOfDomain = [bool](Get-PropertySafe $cs 'PartOfDomain' $false)

    $cpuName = 'Unknown'
    if (@($cpus).Count -gt 0) { $cpuName = [string](Get-PropertySafe @($cpus)[0] 'Name' 'Unknown') }

    # Virtual machines cannot always expose the hardware these features need.
    $vmMarkers = 'VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Parallels|Hyper-V|Bochs|Google Compute|Amazon EC2'
    $isVm = [bool](("$manufacturer $model") -match $vmMarkers)

    return [pscustomobject]@{
        Name           = $env:COMPUTERNAME
        Manufacturer   = $manufacturer
        Model          = $model
        ProcessorName  = $cpuName
        ProcessorCount = @($cpus).Count
        OsCaption      = [string](Get-PropertySafe $os 'Caption' 'Unknown')
        ProductName    = [string]$productName
        EditionId      = [string]$editionId
        BuildNumber    = $build
        Ubr            = $ubr
        Is64Bit        = [Environment]::Is64BitOperatingSystem
        PartOfDomain   = $partOfDomain
        DomainRole     = $domainRole
        IsVirtual      = $isVm
    }
}

function Get-FirmwareState {
    # Type is a display string and must never drive logic: it can legitimately read
    # 'Legacy BIOS or unsupported UEFI', which contains the substring 'UEFI'.
    $type = 'Unknown'; $mode = 'Unknown'; $source = 'None'

    $envFirmware = [string]$env:firmware_type
    if ($envFirmware -eq 'UEFI') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Environment' }
    elseif ($envFirmware -eq 'Legacy') { $mode = 'Legacy'; $type = 'Legacy BIOS'; $source = 'Environment' }

    if ($mode -eq 'Unknown') {
        try {
            $ci = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
            $bios = [string](Get-PropertySafe $ci 'BiosFirmwareType' '')
            if ($bios -eq 'Uefi') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Get-ComputerInfo' }
            elseif ($bios -eq 'Bios') { $mode = 'Legacy'; $type = 'Legacy BIOS'; $source = 'Get-ComputerInfo' }
        }
        catch { Write-DebugError 'Determine firmware type' $_ }
    }

    $secureBootSupported = $false
    $secureBootEnabled = $null
    try {
        $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $secureBootSupported = $true
        if ($mode -eq 'Unknown') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Confirm-SecureBootUEFI' }
    }
    catch {
        Write-DebugError 'Query Secure Boot' $_
        if ($mode -eq 'Unknown') { $type = 'Legacy BIOS or unsupported UEFI' }
    }

    return [pscustomobject]@{
        Type = $type
        Mode = $mode
        IsUefiConfirmed = [bool]($mode -eq 'UEFI')
        IsLegacyConfirmed = [bool]($mode -eq 'Legacy')
        DetectionSource = $source
        SecureBootSupported = $secureBootSupported
        SecureBootEnabled = $secureBootEnabled
    }
}

function Get-TpmState {
    $present = $false; $ready = $null; $spec = $null; $isTpm2 = $false
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $present = [bool](Get-PropertySafe $tpm 'TpmPresent' $false)
        $ready = Get-PropertySafe $tpm 'TpmReady' $null
    }
    catch { Write-DebugError 'Get-Tpm' $_ }

    try {
        $wmi = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop
        $spec = [string](Get-PropertySafe $wmi 'SpecVersion' '')
        if ($spec -match '^\s*2\.0') { $isTpm2 = $true; $present = $true }
    }
    catch { Write-DebugError 'Query Win32_Tpm' $_ }

    return [pscustomobject]@{
        Present = $present
        Ready = $ready
        SpecVersion = $spec
        IsTPM2 = $isTpm2
    }
}

function Get-VirtualizationState {
    $hypervisorPresent = $false; $vmx = $null; $slat = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hypervisorPresent = [bool](Get-PropertySafe $cs 'HypervisorPresent' $false)
    }
    catch { Write-DebugError 'Query HypervisorPresent' $_ }

    try {
        $cpu = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)[0]
        $vmx = Get-PropertySafe $cpu 'VirtualizationFirmwareEnabled' $null
        $slat = Get-PropertySafe $cpu 'SecondLevelAddressTranslationExtensions' $null
    }
    catch { Write-DebugError 'Query processor virtualization' $_ }

    # When Hyper-V owns the CPU, VirtualizationFirmwareEnabled often reports false even
    # though virtualization is plainly working. Treat a running hypervisor as proof.
    $enabled = [bool]($vmx -or $hypervisorPresent)

    return [pscustomobject]@{
        HypervisorPresent = $hypervisorPresent
        FirmwareEnabled = $enabled
        FirmwareRaw = $vmx
        Slat = $slat
    }
}

function Get-HypervisorLaunchState {
    # hypervisorlaunchtype=Off blocks every VBS feature regardless of the registry, and is
    # invisible in the registry. This is one of the most common causes of a feature that
    # is configured but never runs.
    $launchType = $null; $source = 'Unavailable'; $errorText = $null
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $bcdedit = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
        if (Test-Path -LiteralPath $bcdedit) {
            $raw = @(& $bcdedit '/enum' '{current}' 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -eq 0) {
                $source = 'bcdedit'
                $line = @($raw | Where-Object { $_ -match '^\s*hypervisorlaunchtype\s+' }) | Select-Object -First 1
                if ($line) { $launchType = ($line -replace '^\s*hypervisorlaunchtype\s+', '').Trim() }
                else { $launchType = 'NotSet' }
            }
            else { $errorText = 'bcdedit exit code {0}' -f $LASTEXITCODE }
        }
        else { $errorText = 'bcdedit.exe not found' }
    }
    catch { $errorText = $_.Exception.Message; Write-DebugError 'Query hypervisorlaunchtype' $_ }
    finally { $ErrorActionPreference = $previousEap }

    $blocks = [bool]($launchType -and ($launchType -match '^(?i)off$'))
    return [pscustomobject]@{
        LaunchType = $launchType
        Source = $source
        BlocksVbs = $blocks
        Error = $errorText
    }
}

function Get-DeviceGuardState {
    $dg = $null
    $queryError = $null
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    }
    catch { $queryError = $_.Exception.Message; Write-DebugError 'Query Win32_DeviceGuard' $_ }

    $configured = ConvertTo-Array (Get-PropertySafe $dg 'SecurityServicesConfigured' @())
    $running    = ConvertTo-Array (Get-PropertySafe $dg 'SecurityServicesRunning' @())
    $available  = ConvertTo-Array (Get-PropertySafe $dg 'AvailableSecurityProperties' @())
    $required   = ConvertTo-Array (Get-PropertySafe $dg 'RequiredSecurityProperties' @())
    $vbsStatus  = Get-PropertySafe $dg 'VirtualizationBasedSecurityStatus' $null
    $ciPolicy   = Get-PropertySafe $dg 'CodeIntegrityPolicyEnforcementStatus' $null

    return [pscustomobject]@{
        Available = $null -ne $dg
        RunningKnown = [bool]($null -ne $dg -and $null -ne $dg.PSObject.Properties['SecurityServicesRunning'] -and $null -ne $dg.SecurityServicesRunning)
        Error = $queryError
        Configured = $configured
        Running = $running
        AvailableProperties = $available
        RequiredProperties = $required
        VbsStatusCode = $vbsStatus
        VbsStatusText = (ConvertTo-VbsStatusText $vbsStatus)
        CodeIntegrityPolicyEnforcement = $ciPolicy
        # AvailableSecurityProperties: 1 hypervisor, 2 Secure Boot, 3 DMA protection,
        # 4 secure memory overwrite, 5 NX, 6 SMM mitigations, 7 MBEC, 8 APIC virtualization
        HasHypervisorSupport = (Test-Contains $available 1)
        HasSecureBootProperty = (Test-Contains $available 2)
        HasDmaProtection = (Test-Contains $available 3)
        HasSmmMitigations = (Test-Contains $available 6)
        HasMbec = (Test-Contains $available 7)
    }
}

function ConvertTo-VbsStatusText {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    switch ([int]$Value) {
        0 { 'Not enabled' }
        1 { 'Configured, not running' }
        2 { 'Running' }
        default { 'Unknown ({0})' -f $Value }
    }
}

function Get-DepState {
    $policy = $null; $supported = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $policy = Get-PropertySafe $os 'DataExecutionPrevention_SupportPolicy' $null
        $supported = Get-PropertySafe $os 'DataExecutionPrevention_Available' $null
    }
    catch { Write-DebugError 'Query DEP state' $_ }

    # 0 AlwaysOff, 1 AlwaysOn, 2 OptIn (Windows components only), 3 OptOut (all programs)
    $text = switch ($policy) {
        0 { 'Always off' }
        1 { 'Always on' }
        2 { 'On for Windows programs only' }
        3 { 'On for all programs' }
        default { 'Unknown' }
    }
    return [pscustomobject]@{
        SupportPolicy = $policy
        Available = $supported
        Text = $text
        Enabled = [bool]($null -ne $policy -and [int]$policy -ne 0)
    }
}

function Get-VirtualMachineAssessment {
    param([Parameter(Mandatory = $true)]$Computer, [Parameter(Mandatory = $true)]$Virtualization)

    if (-not $Computer.IsVirtual) {
        return [pscustomobject]@{ IsVirtual = $false; Platform = $null; Notes = @() }
    }

    $platform = 'Unknown virtualization platform'
    $text = '{0} {1}' -f $Computer.Manufacturer, $Computer.Model
    if ($text -match 'VMware') { $platform = 'VMware' }
    elseif ($text -match 'VirtualBox') { $platform = 'VirtualBox' }
    elseif ($text -match 'Hyper-V|Virtual Machine') { $platform = 'Hyper-V' }
    elseif ($text -match 'KVM|QEMU') { $platform = 'KVM/QEMU' }
    elseif ($text -match 'Xen') { $platform = 'Xen' }
    elseif ($text -match 'Parallels') { $platform = 'Parallels' }
    elseif ($text -match 'Amazon EC2') { $platform = 'Amazon EC2' }
    elseif ($text -match 'Google Compute') { $platform = 'Google Compute Engine' }

    $notes = @(
        'This is a virtual machine, so these protections depend on what the host exposes to it.'
        'Nested virtualization must be enabled on the host for VBS to run inside the guest.'
    )
    if ($platform -eq 'Amazon EC2' -or $platform -eq 'Google Compute Engine') {
        $notes += 'Cloud instances frequently do not expose the hardware these features need.'
    }
    if (-not $Virtualization.FirmwareEnabled) {
        $notes += 'The host is not exposing hardware-assisted virtualization (Intel VT-x / AMD-V) to this guest.'
    }
    return [pscustomobject]@{ IsVirtual = $true; Platform = $platform; Notes = $notes }
}

function Get-CodeIntegrityEvents {
    <#
        Reads driver-compatibility evidence from the Code Integrity log. Feeds BOTH the
        Memory Integrity diagnostic and the pre-flight safety check, so the log is parsed
        once and the two can never disagree.

        Driver names are resolved to a publisher and version where possible: telling
        someone "vendor X driver 2.1.0 is blocking this" is far more actionable than
        showing them a bare .sys filename.
    #>
    param([int[]]$EventIds = @(3087), [int]$LookbackDays = 14, [int]$MaxEvents = 80)

    $result = [pscustomobject]@{
        Queried = $false
        LogAvailable = $false
        EventCount = 0
        Drivers = @()
        Newest = $null
        Error = $null
    }

    $start = (Get-Date).AddDays(-[math]::Abs($LookbackDays))
    $logs = @('Microsoft-Windows-CodeIntegrity/Operational')
    $messages = @()

    foreach ($log in $logs) {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start; Id = $EventIds } `
                        -MaxEvents $MaxEvents -ErrorAction Stop)
            $result.LogAvailable = $true
            $result.Queried = $true
            foreach ($e in $events) {
                $result.EventCount++
                if ($null -eq $result.Newest -or $e.TimeCreated -gt $result.Newest) { $result.Newest = $e.TimeCreated }
                $messages += [string](Get-PropertySafe $e 'Message' '')
            }
        }
        catch {
            # "No events were found" is a normal, healthy outcome, not an error.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $result.Queried = $true; $result.LogAvailable = $true }
            else { $result.Error = $_.Exception.Message; Write-DebugError ('Read {0}' -f $log) $_ }
        }
    }

    $names = @()
    foreach ($message in $messages) {
        foreach ($m in [regex]::Matches($message, '[A-Za-z0-9_\-\.]+\.sys')) {
            $name = $m.Value
            if ($names -notcontains $name) { $names += $name }
        }
    }

    $drivers = @()
    foreach ($name in $names) {
        $drivers += (Resolve-DriverDetail -FileName $name)
    }
    $result.Drivers = $drivers
    return $result
}

function Resolve-DriverDetail {
    <# Turns a bare .sys filename into something a person can act on. #>
    param([Parameter(Mandatory = $true)][string]$FileName)

    $detail = [pscustomobject]@{
        FileName = $FileName
        Path = $null
        Publisher = $null
        Version = $null
        Service = $null
        Found = $false
    }

    $candidates = @(
        (Join-Path $env:SystemRoot ('System32\drivers\' + $FileName))
        (Join-Path $env:SystemRoot ('System32\' + $FileName))
        (Join-Path $env:SystemRoot ('SysWOW64\drivers\' + $FileName))
    )
    foreach ($candidate in $candidates) {
        try {
            if (Test-Path -LiteralPath $candidate) {
                $detail.Path = $candidate
                $detail.Found = $true
                $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
                $detail.Version = [string](Get-PropertySafe $item.VersionInfo 'FileVersion' $null)
                $product = [string](Get-PropertySafe $item.VersionInfo 'CompanyName' $null)
                if ($product) { $detail.Publisher = $product }
                break
            }
        }
        catch { Write-DebugError ('Inspect driver {0}' -f $candidate) $_ }
    }

    if ($detail.Found -and -not $detail.Publisher) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $detail.Path -ErrorAction Stop
            if ($sig -and $sig.SignerCertificate) { $detail.Publisher = $sig.SignerCertificate.Subject }
        }
        catch { Write-DebugError 'Read driver signature' $_ }
    }

    try {
        $base = [IO.Path]::GetFileNameWithoutExtension($FileName)
        $svc = Get-CimInstance -ClassName Win32_SystemDriver -Filter ("Name='{0}'" -f $base) -ErrorAction Stop
        if ($svc) { $detail.Service = [string](Get-PropertySafe $svc 'DisplayName' $base) }
    }
    catch { Write-DebugError 'Resolve driver service' $_ }

    return $detail
}

function Get-PendingRestartState {
    # Component Based Servicing and Windows Update are authoritative.
    # PendingFileRenameOperations is NOT: Windows, installers and antivirus queue file
    # renames constantly, so keying off its existence reported a pending restart on
    # essentially every healthy machine. Collected for diagnostics only.
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

    $queued = 0
    try {
        $value = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        if ($null -ne $value) {
            $queued = @(ConvertTo-Array $value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
        }
    }
    catch { Write-DebugError 'Read PendingFileRenameOperations' $_ }

    $reasons = @()
    if ($cbs) { $reasons += 'Windows servicing has a restart pending.' }
    if ($wu) { $reasons += 'Windows Update has a restart pending.' }

    return [pscustomobject]@{
        Pending = [bool]($cbs -or $wu)
        Reasons = $reasons
        ComponentBasedServicing = [bool]$cbs
        WindowsUpdate = [bool]$wu
        QueuedFileRenameCount = $queued
    }
}

function Get-PolicyState {
    <#
        Reads the Group Policy hive. READ ONLY - WinDSH never writes here.
        Used both to back off from GPO-managed values and to evaluate CIS compliance,
        because CIS section 18.9.5 audits this hive rather than the local one.
    #>
    $values = @{}
    $errors = @{}
    foreach ($control in $script:ControlCatalog) {
        foreach ($pv in (ConvertTo-Array $control.PolicyValues)) {
            if (-not $values.ContainsKey($pv.Name)) {
                try {
                    $values[$pv.Name] = Get-RegValue -Path $script:RegPolicyDG -Name $pv.Name
                    if ($null -ne $values[$pv.Name] -and (Get-RegKind -Path $script:RegPolicyDG -Name $pv.Name) -ne 'DWord') { throw 'The policy registry value is not a DWORD.' }
                }
                catch {
                    $values[$pv.Name] = $null
                    $errors[$pv.Name] = $_.Exception.Message
                    Write-DebugError ('Read policy {0}' -f $pv.Name) $_
                }
            }
        }
    }
    return [pscustomobject]@{
        Path = $script:RegPolicyDG
        Values = $values
        Available = ($errors.Count -eq 0)
        Errors = $errors
        AnyConfigured = [bool](@($values.Values | Where-Object { $null -ne $_ }).Count -gt 0)
    }
}

function Get-StaticState {
    <# Collected once. Nothing here can change while WinDSH is running. #>
    if ($null -ne $script:StaticState) { return $script:StaticState }
    Write-Debug-Log 'Collecting static state'
    $computer = Get-OsAndHardwareState
    $virtualization = Get-VirtualizationState
    $script:StaticState = [pscustomobject]@{
        Computer = $computer
        Firmware = Get-FirmwareState
        Tpm = Get-TpmState
        Virtualization = $virtualization
        HypervisorLaunch = Get-HypervisorLaunchState
        Dep = Get-DepState
        VirtualMachine = Get-VirtualMachineAssessment -Computer $computer -Virtualization $virtualization
    }
    return $script:StaticState
}

function Get-SystemState {
    <#
        Full state. Pass -Volatile to re-read only what a configuration change can affect,
        reusing the cached static facts.
    #>
    param([switch]$Volatile)

    if (-not $Volatile) { $script:StaticState = $null }
    $static = Get-StaticState
    Write-Debug-Log ('Collecting volatile state (volatile-only={0})' -f [bool]$Volatile)

    return [pscustomobject]@{
        Generated = (Get-Date).ToUniversalTime().ToString('o')
        Computer = $static.Computer
        Firmware = $static.Firmware
        Tpm = $static.Tpm
        Virtualization = $static.Virtualization
        HypervisorLaunch = $static.HypervisorLaunch
        Dep = $static.Dep
        VirtualMachine = $static.VirtualMachine
        DeviceGuard = Get-DeviceGuardState
        Policy = Get-PolicyState
        Restart = Get-PendingRestartState
    }
}

# ===== 40-evaluate.ps1 =====
# ---------------------------------------------------------------------------
# Evaluation engine.
#
# One status function for every control, one explainer for every control, one score.
# v1 had a hand-written diagnostic per feature; adding a feature meant writing another.
# ---------------------------------------------------------------------------

function Get-ControlRunningState {
    <#
        Maps a control to the Win32_DeviceGuard service identifiers.
        SecurityServicesConfigured / Running: 1 Credential Guard, 2 HVCI,
        3 System Guard Secure Launch, 4 SMM firmware measurement,
        5 kernel shadow stacks, 6 kernel shadow stacks (audit), 7 HVPT.
    #>
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    $dg = $State.DeviceGuard
    $servicesKnown = [bool](Get-PropertySafe $dg 'RunningKnown' $dg.Available)
    switch ($Control.DetectKey) {
        'Vbs' {
            return [pscustomobject]@{
                Running = [bool]($dg.VbsStatusCode -eq 2)
                RunningKnown = [bool]($dg.Available -and $null -ne $dg.VbsStatusCode)
            }
        }
        'Hvci' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 2); RunningKnown = $servicesKnown }
        }
        'CredentialGuard' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 1); RunningKnown = $servicesKnown }
        }
        'SecureLaunch' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 3); RunningKnown = $servicesKnown }
        }
        'KernelShadowStacks' {
            return [pscustomobject]@{
                Running = (Test-Contains $dg.Running 5)
                RunningKnown = $servicesKnown
                AuditMode = [bool]((Test-Contains $dg.Running 6) -and -not (Test-Contains $dg.Running 5))
            }
        }
        'Hvpt' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 7); RunningKnown = $servicesKnown }
        }
        'SmmFirmware' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 4); RunningKnown = $servicesKnown }
        }
        'Dep' {
            return [pscustomobject]@{ Running = [bool]$State.Dep.Enabled; RunningKnown = [bool]($null -ne $State.Dep.SupportPolicy) }
        }
        default {
            # Registry-only controls have no separate running signal: configured is running.
            return [pscustomobject]@{ Running = $null; RunningKnown = $false; RegistryOnly = $true }
        }
    }
}

function Test-ControlConfigured {
    param([Parameter(Mandatory = $true)]$Control)
    return [bool](Get-ControlConfiguration -Control $Control).Configured
}

function Get-ControlConfiguration {
    param([Parameter(Mandatory = $true)]$Control)
    # A detection-only control has no values to write. Without this guard the loop below
    # would not execute and it would report as configured on every machine.
    if (Get-PropertySafe $Control 'DetectionOnly' $false) { return [pscustomobject]@{ Configured = $false; Error = $null } }
    $all = $true
    $errors = @()
    foreach ($value in (ConvertTo-Array $Control.LocalValues)) {
        try {
            $current = Get-RegValue -Path $value.Path -Name $value.Name
            if ($null -eq $current -or (Get-RegKind -Path $value.Path -Name $value.Name) -ne $value.Type) { $all = $false; continue }
            if ($value.ContainsKey('KnownValues') -and @($value.KnownValues) -notcontains [long]$current) {
                $errors += ('{0} has an unrecognized value ({1}); review it manually.' -f $value.Name, $current)
                $all = $false; continue
            }
            if (-not (Test-CatalogValueSatisfied -Definition $value -Current $current)) { $all = $false }
        }
        catch { $all = $false; $errors += ('Cannot read {0}: {1}' -f $value.Name, $_.Exception.Message) }
    }
    return [pscustomobject]@{ Configured = $all; Error = $(if ($errors.Count) { $errors -join ' ' } else { $null }) }
}

function Get-ControlPolicyOverride {
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)
    foreach ($pv in (ConvertTo-Array $Control.PolicyValues)) {
        $errors = Get-PropertySafe $State.Policy 'Errors' @{}
        if ($errors.ContainsKey($pv.Name)) {
            return [pscustomobject]@{ Name = $pv.Name; Value = $null; Path = $State.Policy.Path; Error = $errors[$pv.Name] }
        }
        if ($State.Policy.Values.ContainsKey($pv.Name)) {
            $value = $State.Policy.Values[$pv.Name]
            if ($null -ne $value) {
                return [pscustomobject]@{ Name = $pv.Name; Value = $value; Path = $State.Policy.Path; Error = $null }
            }
        }
    }
    return $null
}

function Get-ControlSupport {
    <#
        Hard prerequisites the machine itself imposes. Returns the FIRST blocking reason so
        the user is given one thing to act on rather than a checklist.
    #>
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    $requirements = @(ConvertTo-Array $Control.PlatformRequirements)
    foreach ($requirement in $requirements) {
        switch ($requirement) {
            '64Bit' {
                if (-not $State.Computer.Is64Bit) { return [pscustomobject]@{ Supported = $false; Reason = 'This protection requires a 64-bit version of Windows.'; Fix = $null } }
            }
            'Hypervisor' {
                if ($State.HypervisorLaunch.BlocksVbs) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'The Windows hypervisor is switched off in the boot configuration, so this protection cannot start.'; Fix = 'In an elevated Command Prompt run:  bcdedit /set hypervisorlaunchtype Auto   then restart.' }
                }
            }
            'Uefi' {
                if (-not $State.Firmware.IsUefiConfirmed) {
                    return [pscustomobject]@{ Supported = $false; Reason = ('Requires UEFI firmware mode; this PC reports {0}.' -f $State.Firmware.Mode); Fix = 'Switching from Legacy/CSM to UEFI also requires converting the disk from MBR to GPT. Back up first.' }
                }
            }
            'Virtualization' {
                if (-not $State.Virtualization.FirmwareEnabled) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'CPU virtualization is turned off in firmware.'; Fix = 'Enable Intel VT-x / AMD SVM in BIOS setup. Use -Explain or the firmware guide for where to find it.' }
                }
            }
            'Tpm2' {
                if (-not $State.Tpm.IsTPM2) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'TPM 2.0 was not confirmed, and this protection needs it to store boot measurements.'; Fix = 'Enable TPM (Intel PTT / AMD fTPM) in BIOS setup.' }
                }
            }
            'CredentialGuardEdition' {
                $edition = [string]$State.Computer.EditionId
                if ($edition -match '^(Core|CoreN|CoreSingleLanguage|CoreCountrySpecific|Home)') {
                    return [pscustomobject]@{ Supported = $false; Reason = ('Credential Guard is not available on Windows {0} editions.' -f $edition); Fix = 'Requires Windows Enterprise, Education, or Pro with a supported licence.' }
                }
            }
            default { throw ('Unknown platform requirement {0} in control {1}.' -f $requirement, $Control.Id) }
        }
    }
    $minBuild = Get-PropertySafe $Control 'MinimumBuild' $null
    if ($null -ne $minBuild -and $State.Computer.BuildNumber -gt 0 -and $State.Computer.BuildNumber -lt [int]$minBuild) {
        return [pscustomobject]@{ Supported = $false; Reason = ('Requires Windows build {0} or newer; this PC is build {1}.' -f $minBuild, $State.Computer.BuildNumber); Fix = 'Update Windows to a newer feature release.' }
    }

    return [pscustomobject]@{ Supported = $true; Reason = $null; Fix = $null }
}

function Get-ControlPreflight {
    <#
        Evaluates a control's declared pre-flight safety check. Returns $null when the
        control has none. A tripped check means applying the control now is risky, not
        that it is unsupported.
    #>
    param([Parameter(Mandatory = $true)]$Control)

    $preflight = Get-PropertySafe $Control 'Preflight' $null
    if ($null -eq $preflight) { return $null }

    switch ($preflight.Kind) {
        'CodeIntegrityEvents' {
            $ids = ConvertTo-Array $preflight.EventIds
            $days = if ($preflight.ContainsKey('LookbackDays')) { [int]$preflight.LookbackDays } else { 14 }
            $events = Get-CodeIntegrityEvents -EventIds $ids -LookbackDays $days

            return [pscustomobject]@{
                Kind = $preflight.Kind
                Tripped = [bool](-not $events.Queried -or $events.EventCount -gt 0)
                BlocksSafeSet = [bool]$preflight.BlocksSafeSet
                Message = if ($events.Queried) { $preflight.Message } else { 'Could not verify driver compatibility because the Code Integrity log could not be queried.' }
                EventCount = $events.EventCount
                Drivers = $events.Drivers
                Newest = $events.Newest
                Queried = $events.Queried
                Error = $events.Error
            }
        }
        default { return $null }
    }
}

function Get-ControlStatus {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)]$State)

    $control = Get-Control -Id $Id
    $support = Get-ControlSupport -Control $control -State $State
    $policy = Get-ControlPolicyOverride -Control $control -State $State
    $configuration = Get-ControlConfiguration -Control $control
    $configured = $configuration.Configured
    $run = Get-ControlRunningState -Control $control -State $State

    $registryOnly = [bool](Get-PropertySafe $run 'RegistryOnly' $false)
    $runningKnown = if ($registryOnly) { -not [bool]$configuration.Error } else { [bool]$run.RunningKnown }
    $running = if ($registryOnly) { [bool]($runningKnown -and $configured) } else { [bool]($runningKnown -and $run.Running) }
    $auditMode = [bool]($runningKnown -and (Get-PropertySafe $run 'AuditMode' $false))

    # NOT named $state: PowerShell variable names are case-insensitive, so a local
    # $state would shadow the $State parameter and the recursive dependency call below
    # would receive this string instead of the system state object.
    $controlState = if (-not $support.Supported) { 'NotSupported' }
                    elseif ($auditMode) { 'AuditMode' }
                    elseif (-not $runningKnown -or (-not $running -and $configuration.Error)) { 'Unknown' }
                    elseif ($running) { 'Running' }
                    elseif ($configured) { 'ConfiguredNotRunning' }
                    else { 'NotConfigured' }

    # A dependency that is not running explains a child that is not running.
    $blockedBy = $null
    if ($controlState -ne 'Running' -and $controlState -ne 'NotSupported') {
        foreach ($dep in (ConvertTo-Array $control.Requires)) {
            $depStatus = Get-ControlStatus -Id $dep -State $State
            if ($depStatus.State -ne 'Running') { $blockedBy = $depStatus; break }
        }
    }

    return [pscustomobject]@{
        Id = $control.Id
        Name = $control.Name
        PlainName = $control.PlainName
        Category = $control.Category
        Weight = $control.Weight
        State = $controlState
        Running = $running
        RunningKnown = $runningKnown
        Configured = $configured
        ConfigurationError = $configuration.Error
        Supported = $support.Supported
        SupportReason = $support.Reason
        SupportFix = $support.Fix
        ManagedByPolicy = [bool]($null -ne $policy)
        PolicyValue = if ($policy) { $policy.Value } else { $null }
        PolicyReadError = if ($policy) { Get-PropertySafe $policy 'Error' $null } else { $null }
        BlockedBy = $blockedBy
        Cis = $control.Cis
    }
}

function Get-AllControlStatus {
    param([Parameter(Mandatory = $true)]$State)
    $results = @()
    foreach ($id in (Get-ControlIds)) { $results += Get-ControlStatus -Id $id -State $State }
    return $results
}

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

function Get-SecurityScore {
    <#
        Weighted score over the controls this machine can actually run. Controls the
        hardware cannot support are excluded from the denominator rather than counted as
        failures: penalising someone for hardware they cannot change is not useful.
    #>
    param([Parameter(Mandatory = $true)]$Statuses)

    $earned = 0.0
    $possible = 0.0
    $breakdown = @()

    foreach ($s in $Statuses) {
        $fraction = switch ($s.State) {
            'Running' { 1.0 }
            'ConfiguredNotRunning' { 0.5 }
            'NotConfigured' { 0.0 }
            'Unknown' { 0.0 }
            'AuditMode' { 0.0 }
            default { $null }
        }
        if ($null -eq $fraction) {
            $breakdown += [pscustomobject]@{ Id = $s.Id; Name = $s.Name; State = $s.State; Weight = $s.Weight; Points = 0; Counted = $false }
            continue
        }
        $points = [double]$s.Weight * $fraction
        $earned += $points
        $possible += [double]$s.Weight
        $breakdown += [pscustomobject]@{ Id = $s.Id; Name = $s.Name; State = $s.State; Weight = $s.Weight; Points = [math]::Round($points, 1); Counted = $true }
    }

    $score = if ($possible -gt 0) { [int][math]::Round(($earned / $possible) * 100) } else { 0 }

    $grade = if ($score -ge 90) { 'Excellent' }
             elseif ($score -ge 75) { 'Good' }
             elseif ($score -ge 50) { 'Fair' }
             elseif ($score -gt 0) { 'Weak' }
             else { 'Unprotected' }
    $unknownCount = @($Statuses | Where-Object { $_.Weight -gt 0 -and $_.State -eq 'Unknown' }).Count
    if ($unknownCount -gt 0) { $grade = 'Incomplete assessment' }

    return [pscustomobject]@{
        Score = $score
        Grade = $grade
        UnknownCount = $unknownCount
        Earned = [math]::Round($earned, 1)
        Possible = [math]::Round($possible, 1)
        ExcludedCount = @($breakdown | Where-Object { -not $_.Counted }).Count
        Breakdown = $breakdown
        ApplicableCount = @($Statuses | Where-Object { $_.Weight -gt 0 -and $_.Supported }).Count
        TotalCount = @($Statuses | Where-Object { $_.Weight -gt 0 }).Count
    }
}

function Get-SecuredCoreVerdict {
    <# Secured-core PC requires the full hardware and software stack. #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Statuses)

    $checks = @(
        [pscustomobject]@{ Name = 'UEFI firmware mode'; Met = $State.Firmware.IsUefiConfirmed }
        [pscustomobject]@{ Name = 'Secure Boot enabled'; Met = [bool]$State.Firmware.SecureBootEnabled }
        [pscustomobject]@{ Name = 'TPM 2.0'; Met = $State.Tpm.IsTPM2 }
        [pscustomobject]@{ Name = 'Virtualization-based Security running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'vbs' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'Memory Integrity running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'hvci' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'System Guard Secure Launch running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'secure-launch' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'DMA protection available'; Met = $State.DeviceGuard.HasDmaProtection }
        [pscustomobject]@{ Name = 'SMM mitigations available'; Met = $State.DeviceGuard.HasSmmMitigations }
    )
    $unmet = @($checks | Where-Object { -not $_.Met })
    return [pscustomobject]@{
        Qualifies = [bool]($unmet.Count -eq 0)
        Checks = $checks
        UnmetCount = $unmet.Count
    }
}

# ---------------------------------------------------------------------------
# CIS comparison
# ---------------------------------------------------------------------------

function Get-CisComplianceReport {
    <#
        CIS section 18.9.5 audits HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard.
        WinDSH configures local values under HKLM\SYSTEM\CurrentControlSet\Control and
        never writes the policy hive, so a machine configured by WinDSH will have the
        features running but will NOT pass a CIS scan. That is reported, not hidden.
    #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Statuses)

    $rows = @()
    foreach ($control in $script:ControlCatalog) {
        if ($null -eq $control.Cis) { continue }
        $status = @($Statuses | Where-Object { $_.Id -eq $control.Id })[0]

        $policyName = $null; $policyValue = $null; $expected = $null; $accepted = @()
        foreach ($pv in (ConvertTo-Array $control.PolicyValues)) {
            $policyName = $pv.Name
            $expected = $pv.Expected
            $accepted = @($pv.Expected) + (ConvertTo-Array (Get-PropertySafe $pv 'AlsoAccepted' @()))
            if ($State.Policy.Values.ContainsKey($pv.Name)) { $policyValue = $State.Policy.Values[$pv.Name] }
            break
        }

        $policyKnown = -not [bool](Get-PropertySafe $status 'PolicyReadError' $null)
        $compliant = [bool]($policyKnown -and $null -ne $policyValue -and (@($accepted) -contains [int]$policyValue))

        $rows += [pscustomobject]@{
            CisId = $control.Cis.Id
            Profile = $control.Cis.Profile
            Title = $control.Cis.Title
            ControlId = $control.Id
            PolicyValueName = $policyName
            Expected = $expected
            Actual = $policyValue
            Compliant = $compliant
            PolicyKnown = $policyKnown
            FeatureRunning = [bool]($status -and $status.State -eq 'Running')
            Divergence = Get-PropertySafe $control.Cis 'Divergence' $null
        }
    }

    $compliantCount = @($rows | Where-Object { $_.Compliant }).Count
    return [pscustomobject]@{
        Benchmark = $script:CisBenchmark
        Section = '18.9.5 Device Guard'
        PolicyPath = $State.Policy.Path
        Rows = $rows
        TotalCount = @($rows).Count
        CompliantCount = $compliantCount
        UnknownCount = @($rows | Where-Object { -not $_.PolicyKnown }).Count
        RunningButNotCompliantCount = @($rows | Where-Object { $_.PolicyKnown -and $_.FeatureRunning -and -not $_.Compliant }).Count
        Note = 'CIS audits the Group Policy hive. WinDSH configures local machine values and never writes Group Policy, so features can be active while these checks still report non-compliant.'
    }
}

# ---------------------------------------------------------------------------
# Generic explainer - replaces the per-feature diagnostics in v1
# ---------------------------------------------------------------------------

function Get-ControlExplanation {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)]$State, $Status)

    $control = Get-Control -Id $Id
    $status = if ($Status) { $Status } else { Get-ControlStatus -Id $Id -State $State }

    $verdict = $null; $action = $null; $severity = 'Info'

    if ($status.PolicyReadError -or $status.ConfigurationError) {
        $verdict = ('Configuration evidence for {0} could not be verified.' -f $control.Name)
        $action = 'Review the registry or policy read error and restore access before remediation. WinDSH will skip this protection.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'Unknown') {
        $verdict = ('Windows did not provide the running state of {0}.' -f $control.Name)
        $action = 'Check access to the Windows security providers, then re-run the audit. Registry configuration alone does not prove this protection is active.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'AuditMode') {
        $verdict = ('{0} is in audit mode; enforcement is not active.' -f $control.Name)
        $action = 'Review compatibility and organization policy before enabling enforcement. Audit mode earns no enforcement points.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'Running') {
        $verdict = ('{0} is running. Nothing to do.' -f $control.Name)
        $severity = 'Good'
    }
    elseif ($status.ManagedByPolicy) {
        $verdict = ('{0} is managed by your organisation''s Group Policy.' -f $control.Name)
        $action = 'WinDSH will not override a policy-managed setting. Contact whoever manages this computer.'
        $severity = 'Info'
    }
    elseif (-not $status.Supported) {
        $verdict = $status.SupportReason
        $action = $status.SupportFix
        $severity = 'Warn'
    }
    elseif ($status.BlockedBy) {
        $verdict = ('{0} cannot run because {1} is not running.' -f $control.Name, $status.BlockedBy.Name)
        $action = ('Resolve {0} first. Run: -Explain {1}' -f $status.BlockedBy.Name, $status.BlockedBy.Id)
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'ConfiguredNotRunning') {
        if ($State.Restart.Pending -or $script:RestartRequired) {
            $verdict = ('{0} is configured but Windows has not restarted since the change.' -f $control.Name)
            $action = 'Restart Windows, then run the audit again.'
            $severity = 'Warn'
        }
        else {
            $verdict = ('{0} is configured, Windows has restarted, and it still is not running. Everything Windows can check is satisfied, so the remaining explanation is hardware or firmware capability.' -f $control.Name)
            $action = Get-HardwareCapabilityAdvice -Control $control -State $State
            $severity = 'Info'
        }
    }
    elseif (Get-PropertySafe $control 'DetectionOnly' $false) {
        $verdict = ('{0} is not active on this computer.' -f $control.Name)
        $action = 'WinDSH reports this but does not configure it. It is provided by Windows or the platform firmware.'
        $severity = 'Info'
    }
    else {
        $verdict = ('{0} is not configured.' -f $control.Name)
        $action = if ($control.Remediable) { ('This tool can configure it. Run with -Enable {0}' -f $control.Id) } else { 'Configure it through Windows Security.' }
        $severity = 'Info'

        $preflight = Get-ControlPreflight -Control $control
        if ($preflight -and $preflight.Tripped) {
            $verdict = ('{0} is not configured, and enabling it right now looks risky.' -f $control.Name)
            $lines = @($preflight.Message, '')
            if ($preflight.Queried) { $lines += ('  {0} compatibility event(s) in the last 14 days.' -f $preflight.EventCount) }
            elseif ($preflight.Error) { $lines += ('  Log query failed: {0}' -f $preflight.Error) }
            foreach ($d in (ConvertTo-Array $preflight.Drivers)) {
                $who = if ($d.Publisher) { $d.Publisher } else { 'unknown publisher' }
                $ver = if ($d.Version) { $d.Version } else { 'unknown version' }
                $svc = if ($d.Service) { (' - {0}' -f $d.Service) } else { '' }
                $lines += ('  - {0} ({1}, {2}){3}' -f $d.FileName, $who, $ver, $svc)
            }
            $lines += ''
            $lines += $(if ($preflight.Queried) { '  Update or remove the driver above, restart, then run the audit again.' } else { '  Restore access to the Code Integrity log, then run the audit again. Automatic remediation will skip this protection.' })
            $action = ($lines -join "`n")
            $severity = 'Warn'
        }
    }

    return [pscustomobject]@{
        Id = $control.Id
        Name = $control.Name
        PlainName = $control.PlainName
        Summary = $control.Summary
        Why = $control.Why
        Caution = Get-PropertySafe $control 'Caution' $null
        DocUrl = $control.DocUrl
        Verdict = $verdict
        Action = $action
        Severity = $severity
        Status = $status
        Cis = $control.Cis
    }
}

function Get-HardwareCapabilityAdvice {
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    switch ($Control.Id) {
        'secure-launch' {
            return @(
                'Secure Launch needs DRTM-capable firmware, which cannot be detected in advance.',
                '',
                ('  Your processor: {0}' -f $State.Computer.ProcessorName),
                '',
                '  1. DRTM requires Intel vPro (8th generation or newer) or AMD Zen 2 or newer.',
                '     Most consumer and non-vPro laptops do not have it, and it cannot be added',
                '     by a software or firmware update.',
                '  2. If your CPU does qualify, look in BIOS setup for "Intel TXT" or "Trusted',
                '     Execution" (AMD: "SKINIT"), usually under Security or Advanced. On Intel it',
                '     is often hidden until both TPM and VT-x are enabled, so enable those first.',
                '  3. Update to the newest BIOS from your manufacturer.',
                '',
                '  If none apply this is a hardware limit, not a fault. The setting is harmless',
                '  and your other protections are unaffected.'
            ) -join "`n"
        }
        'kernel-shadow-stacks' {
            return @(
                'Kernel shadow stacks need CPU hardware support for shadow stacks.',
                '',
                ('  Your processor: {0}' -f $State.Computer.ProcessorName),
                '',
                '  Requires an Intel Tiger Lake or AMD Zen 3 processor or newer (both late 2020),',
                '  and Memory Integrity must already be running. Without both, the setting has no',
                '  effect. This is a hardware limit, not a fault.'
            ) -join "`n"
        }
        'hvci' {
            return @(
                'Memory Integrity is configured but Windows declined to start it.',
                '',
                '  The usual cause is a driver that is not compatible. Windows records these in',
                '  Event Viewer under Applications and Services Logs > Microsoft > Windows >',
                '  CodeIntegrity > Operational, as event ID 3087.',
                '',
                '  Update or remove the driver named there, then restart.'
            ) -join "`n"
        }
        default {
            return 'Everything Windows can verify is in order. The remaining explanation is that this hardware or firmware does not provide the capability.'
        }
    }
}

function Get-Assessment {
    param([Parameter(Mandatory = $true)]$State)
    $statuses = @(Get-AllControlStatus -State $State)
    $unknown = @($statuses | Where-Object State -eq 'Unknown')
    if ($unknown.Count) { Add-Warning ('Running or configuration evidence is unavailable for {0} protection(s); the assessment is incomplete.' -f $unknown.Count) }
    foreach ($status in $statuses) {
        if ($status.PolicyReadError) { Add-Warning ('Cannot read policy for {0}: {1}' -f $status.Id, $status.PolicyReadError) }
        if ($status.ConfigurationError) { Add-Warning ('Cannot verify configuration for {0}: {1}' -f $status.Id, $status.ConfigurationError) }
    }
    return [pscustomobject]@{
        State = $State
        Statuses = $statuses
        Score = Get-SecurityScore -Statuses $statuses
        SecuredCore = Get-SecuredCoreVerdict -State $State -Statuses $statuses
        Cis = Get-CisComplianceReport -State $State -Statuses $statuses
        Explanations = @($statuses | ForEach-Object { Get-ControlExplanation -Id $_.Id -State $State -Status $_ })
    }
}

# ===== 45-firmware.ps1 =====
# ---------------------------------------------------------------------------
# Firmware (BIOS/UEFI) guidance.
#
# "Enable it in BIOS" is not usable guidance for a non-technical user. This answers
# how to get in, where the setting lives on their machine, what it is called there,
# and what could go wrong.
#
# Ported from v1.6.0 with one design fault corrected: there, Show-FirmwareGuidance
# could reboot the computer, so a Show-* function had side effects and the restart
# bypassed -WhatIf entirely. Here Get-FirmwareGuidance returns data, Show- renders it,
# and only the caller may act on it.
# ---------------------------------------------------------------------------

function Get-DriveEncryptionSummary {
    <#
        READ ONLY. WinDSH never manages BitLocker, but it must warn before sending
        someone into firmware: changing or clearing a TPM with BitLocker active can make
        Windows demand a 48-digit recovery key at next boot, and someone without that key
        is locked out of their own data.
    #>
    $protected = @()
    try {
        $volumes = @(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
                        -ClassName 'Win32_EncryptableVolume' -ErrorAction Stop)
        foreach ($v in $volumes) {
            if ([int](Get-PropertySafe $v 'ProtectionStatus' 0) -eq 1) {
                $protected += [string](Get-PropertySafe $v 'DriveLetter' '?')
            }
        }
        return [pscustomobject]@{ Queried = $true; AnyProtected = [bool](@($protected).Count -gt 0); ProtectedDrives = $protected }
    }
    catch {
        Write-DebugError 'Query BitLocker protection status' $_
        # Unknown is treated as "warn anyway": being over-cautious about a recovery-key
        # lockout costs nothing, being wrong the other way can cost the user their data.
        return [pscustomobject]@{ Queried = $false; AnyProtected = $null; ProtectedDrives = @() }
    }
}

function Get-FirmwareVendorHints {
    <#
        Maps a manufacturer to the menu locations its firmware normally uses. Layouts
        differ by model and firmware revision, so every hint is phrased as typical, and an
        unrecognised manufacturer returns nulls rather than an invented path.
    #>
    param([string]$Manufacturer, [string]$Model)

    $m = ('{0} {1}' -f $Manufacturer, $Model)

    if ($m -match 'Microsoft' -and $m -match 'Surface') {
        return [pscustomobject]@{
            Vendor = 'Microsoft Surface'
            EnterKey = 'Shut down fully, then hold Volume Up and press Power. Keep holding Volume Up until the Surface UEFI screen appears.'
            TPM = 'Security section. Surface devices have TPM 2.0 enabled by default.'
            Virtualization = 'Usually always on and not exposed as a setting.'
            SecureBoot = 'Security section, Secure Boot.'
        }
    }
    if ($m -match '\bDell\b|Alienware') {
        return [pscustomobject]@{
            Vendor = 'Dell'
            EnterKey = 'Tap F2 repeatedly as the Dell logo appears.'
            TPM = 'Security > TPM 2.0 Security (older models call it PTT Security). Set it to On.'
            Virtualization = 'Virtualization Support > Virtualization. Also enable VT for Direct I/O.'
            SecureBoot = 'Boot Configuration or Secure Boot > Secure Boot Enable.'
        }
    }
    if ($m -match '\bHP\b|Hewlett') {
        return [pscustomobject]@{
            Vendor = 'HP'
            EnterKey = 'Tap F10 repeatedly at power on. On some models press Esc first, then F10.'
            TPM = 'Security > TPM Device and TPM State, or Embedded Security Device.'
            Virtualization = 'Advanced > System Options > Virtualization Technology (VTx). Also enable VTd.'
            SecureBoot = 'Advanced > Secure Boot Configuration. Some HP models require a BIOS administrator password to be set before this can change.'
        }
    }
    if ($m -match 'Lenovo|ThinkPad|IdeaPad') {
        return [pscustomobject]@{
            Vendor = 'Lenovo'
            EnterKey = 'ThinkPad: tap F1 at the logo. IdeaPad: tap F2, or use the small Novo button next to the power socket.'
            TPM = 'Security > Security Chip. Set Security Chip Selection to Intel PTT or Discrete TPM, then set Security Chip to Enabled.'
            Virtualization = 'Security > Virtualization > Intel Virtualization Technology. Also enable Intel VT-d.'
            SecureBoot = 'Security > Secure Boot.'
        }
    }
    if ($m -match 'ASUS|ASUSTeK') {
        return [pscustomobject]@{
            Vendor = 'ASUS'
            EnterKey = 'Tap F2 or Delete at power on. Press F7 for Advanced Mode if you land on the simple EZ screen.'
            TPM = 'Intel: Advanced > PCH-FW Configuration > PTT. AMD: Advanced > AMD fTPM configuration.'
            Virtualization = 'Intel: Advanced > CPU Configuration > Intel (VMX) Virtualization Technology. AMD: Advanced > CPU Configuration > SVM Mode.'
            SecureBoot = 'Boot > Secure Boot. Set OS Type to Windows UEFI mode.'
        }
    }
    if ($m -match '\bAcer\b|Predator') {
        return [pscustomobject]@{
            Vendor = 'Acer'
            EnterKey = 'Tap F2 at the Acer logo.'
            TPM = 'Security > TPM State, or Main > TPM.'
            Virtualization = 'Main or Advanced > VT-x / Virtualization Technology.'
            SecureBoot = 'Boot > Secure Boot. IMPORTANT: on most Acer models Secure Boot stays greyed out until you set a Supervisor Password under Security. Set one, enable Secure Boot, then you may remove the password.'
        }
    }
    if ($m -match '\bMSI\b|Micro-Star') {
        return [pscustomobject]@{
            Vendor = 'MSI'
            EnterKey = 'Tap Delete at power on.'
            TPM = 'Settings > Security > Trusted Computing > Security Device Support. Intel: PTT. AMD: AMD fTPM switch.'
            Virtualization = 'OC > CPU Features > Intel Virtualization Tech, or SVM Mode on AMD.'
            SecureBoot = 'Settings > Advanced > Windows OS Configuration > Secure Boot.'
        }
    }
    if ($m -match 'Gigabyte|ASRock') {
        return [pscustomobject]@{
            Vendor = 'Gigabyte / ASRock'
            EnterKey = 'Tap Delete or F2 at power on.'
            TPM = 'Settings > Miscellaneous > Intel Platform Trust Technology (PTT), or AMD CPU fTPM. On ASRock look under Security or Advanced > CPU Configuration.'
            Virtualization = 'Tweaker or Advanced > CPU Configuration > SVM Mode (AMD) or Intel Virtualization Technology.'
            SecureBoot = 'Boot > Secure Boot. Set to Windows UEFI mode / Standard.'
        }
    }

    return [pscustomobject]@{
        Vendor = $(if ([string]::IsNullOrWhiteSpace($Manufacturer)) { 'Unknown' } else { $Manufacturer })
        EnterKey = $null; TPM = $null; Virtualization = $null; SecureBoot = $null
    }
}

function Get-FirmwareGuidance {
    <# Pure: returns what needs changing and where. Takes no action. #>
    param([Parameter(Mandatory = $true)]$State)

    $hints = Get-FirmwareVendorHints -Manufacturer $State.Computer.Manufacturer -Model $State.Computer.Model
    $encryption = Get-DriveEncryptionSummary
    $needed = @()

    if (-not $State.Tpm.Present -or -not $State.Tpm.IsTPM2) {
        $needed += [pscustomobject]@{
            What = 'Security processor (TPM 2.0)'
            Why = 'Stores boot measurements. Needed for Secure Launch, and used by BitLocker and Windows Hello.'
            AlsoCalled = 'Intel PTT, Platform Trust Technology, AMD fTPM, Security Device, Security Chip, Trusted Computing'
            Where = $hints.TPM
        }
    }
    if (-not $State.Virtualization.FirmwareEnabled) {
        $needed += [pscustomobject]@{
            What = 'CPU virtualization'
            Why = 'Required for Virtualization-based Security. Nothing VBS-related can run without it.'
            AlsoCalled = 'Intel VT-x, Intel Virtualization Technology, VMX, AMD SVM, SVM Mode, AMD-V'
            Where = $hints.Virtualization
        }
    }
    if ($State.Firmware.SecureBootSupported -and -not $State.Firmware.SecureBootEnabled) {
        $needed += [pscustomobject]@{
            What = 'Secure Boot'
            Why = 'Verifies the boot chain. WinDSH requires it for VBS, so VBS will not start while it is off.'
            AlsoCalled = 'Secure Boot Enable, Windows UEFI mode, OS Type'
            Where = $hints.SecureBoot
        }
    }
    if ($State.HypervisorLaunch.BlocksVbs) {
        $needed += [pscustomobject]@{
            What = 'Windows hypervisor (not a firmware setting)'
            Why = 'The boot configuration currently switches the hypervisor off, which blocks every VBS feature.'
            AlsoCalled = 'hypervisorlaunchtype'
            Where = 'Fix this in Windows, not firmware. In an elevated Command Prompt run:  bcdedit /set hypervisorlaunchtype Auto   then restart.'
        }
    }

    return [pscustomobject]@{
        Vendor = $hints.Vendor
        EnterKey = $hints.EnterKey
        Encryption = $encryption
        Needed = $needed
        LegacyWarning = [bool]$State.Firmware.IsLegacyConfirmed
        CanOfferReboot = [bool](@($needed).Count -gt 0)
    }
}

function Show-FirmwareGuidance {
    <# Renders only. The caller decides whether to offer a restart. #>
    param([Parameter(Mandatory = $true)]$Guidance, [Parameter(Mandatory = $true)]$State)

    Write-Section 'Changing firmware (BIOS/UEFI) settings'
    Write-Line ('Detected system : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) 'Dim'
    Write-Line ('Processor       : {0}' -f $State.Computer.ProcessorName) 'Dim'
    Write-Line ('Firmware mode   : {0}' -f $State.Firmware.Mode) 'Dim'

    Write-Line ''
    if ($Guidance.Encryption.AnyProtected) {
        Write-Line 'BEFORE YOU CHANGE ANYTHING' 'Bad'
        Write-Line ('BitLocker is protecting: {0}' -f (@($Guidance.Encryption.ProtectedDrives) -join ', ')) 'Bad' 2
        Write-Line 'Changing or clearing the TPM can make Windows ask for a 48-digit recovery key at the' 'Warn' 2
        Write-Line 'next start. Without that key the drive cannot be opened.' 'Warn' 2
        Write-Line 'Find your key first at https://aka.ms/myrecoverykey, or suspend BitLocker before' 'Warn' 2
        Write-Line 'entering firmware.' 'Warn' 2
    }
    elseif (-not $Guidance.Encryption.Queried) {
        Write-Line 'BEFORE YOU CHANGE ANYTHING' 'Warn'
        Write-Line 'Drive encryption status could not be read. If this PC uses BitLocker or Device' 'Warn' 2
        Write-Line 'Encryption, locate your recovery key first: https://aka.ms/myrecoverykey' 'Warn' 2
    }
    else {
        Write-Line 'Drive encryption is not active, so TPM changes will not trigger a recovery prompt.' 'Dim'
    }

    Write-Line ''
    Write-Line 'How to open firmware setup' 'Head'
    Write-Line 'Easiest, works on every PC:' 'Plain' 2
    Write-Line 'Settings > System > Recovery > Advanced startup > Restart now' 'Info' 4
    Write-Line 'then Troubleshoot > Advanced options > UEFI Firmware Settings > Restart' 'Info' 4
    if ($Guidance.EnterKey) { Write-Line ('On your {0}: {1}' -f $Guidance.Vendor, $Guidance.EnterKey) 'Info' 2 }
    else { Write-Line 'Key at power on varies by manufacturer: F2, F10, F12 or Delete are the usual ones.' 'Info' 2 }

    Write-Line ''
    if (@($Guidance.Needed).Count -eq 0) {
        Write-Line 'Nothing needs changing in firmware. Every setting WinDSH can see is already correct.' 'Good'
    }
    else {
        Write-Line 'What to change on this PC' 'Head'
        $n = 0
        foreach ($item in $Guidance.Needed) {
            $n++
            Write-Line ''
            Write-Line ('{0}. {1}' -f $n, $item.What) 'Warn' 2
            Write-Line ('Why        : {0}' -f $item.Why) 'Dim' 5
            Write-Line ('Also called: {0}' -f $item.AlsoCalled) 'Dim' 5
            if ($item.Where) { Write-Line ('Where      : {0}' -f $item.Where) 'Info' 5 }
            else {
                Write-Line 'Where      : Menu layout unknown for this manufacturer. Search your model' 'Info' 5
                Write-Line '             number plus the setting name on the support site.' 'Info' 5
            }
        }
    }

    if ($Guidance.LegacyWarning) {
        Write-Line ''
        Write-Line 'This PC is running in Legacy/CSM mode, not UEFI.' 'Warn'
        Write-Line 'Secure Boot cannot be enabled until that changes, but switching the firmware to UEFI' 'Warn' 2
        Write-Line 'will stop Windows starting unless the disk is converted from MBR to GPT first' 'Warn' 2
        Write-Line '(mbr2gpt). Back up before attempting this, or ask a technician.' 'Warn' 2
    }

    Write-Line ''
    Write-Line 'General notes' 'Head'
    Write-Line 'Change one setting at a time, save and exit (usually F10), then restart into Windows.' 'Dim' 2
    Write-Line 'Run the audit again after each change so you can see what it actually did.' 'Dim' 2
    Write-Line 'If a setting you need is missing entirely, update to the newest BIOS from your maker.' 'Dim' 2
    Write-Line 'Some settings stay hidden until related ones are on. Intel TXT commonly does not appear' 'Dim' 2
    Write-Line 'until both TPM and VT-x are enabled.' 'Dim' 2
    Write-Line 'WinDSH never changes firmware, Secure Boot keys or the TPM. All of this is manual.' 'Dim' 2
}

function Invoke-RebootToFirmware {
    <# The side effect, kept out of the Show- function and behind explicit confirmation. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Guidance)

    if ($Guidance.Encryption.AnyProtected) {
        Write-Line 'Reminder: have your BitLocker recovery key available before continuing.' 'Bad'
    }
    Write-Line 'Restarting will close all applications. Save your work first.' 'Warn'
    if (-not (Confirm-Action 'Restart now directly into firmware setup?')) { return $false }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart into firmware setup')) { return $false }

    Write-Line 'Restarting into firmware setup...' 'Info'
    & (Join-Path $env:SystemRoot 'System32\shutdown.exe') '/r' '/fw' '/t' '5'
    if ($LASTEXITCODE -ne 0) {
        Write-Line 'Windows refused the request to boot into firmware setup.' 'Warn'
        Write-Line 'Use the Settings > Recovery > Advanced startup route described above instead.' 'Warn'
        return $false
    }
    return $true
}

function Open-CodeIntegrityEventViewer {
    try {
        Start-Process -FilePath 'eventvwr.msc' -ArgumentList '/c:Microsoft-Windows-CodeIntegrity/Operational' -ErrorAction Stop | Out-Null
        Write-Line 'Opened Event Viewer at the Code Integrity log.' 'Good'
        return $true
    }
    catch {
        Write-DebugError 'Open Event Viewer' $_
        Write-Line 'Could not open Event Viewer automatically.' 'Warn'
        Write-Line 'Open it manually: Applications and Services Logs > Microsoft > Windows >' 'Info' 2
        Write-Line 'CodeIntegrity > Operational, and look for event ID 3087.' 'Info' 2
        return $false
    }
}

function Show-CodeIntegrityDiagnostics {
    param([Parameter(Mandatory = $true)]$State)

    Write-Section 'Memory Integrity driver diagnostics'
    $events = Get-CodeIntegrityEvents -EventIds @(3087) -LookbackDays 14

    if (-not $events.Queried) {
        Write-Line 'The Code Integrity log could not be read.' 'Warn'
        if ($events.Error) { Write-Line $events.Error 'Dim' 2 }
        return
    }
    if ($events.EventCount -eq 0) {
        Write-Line 'No driver-compatibility warnings in the last 14 days.' 'Good'
        Write-Line 'Nothing is recorded as blocking Memory Integrity on this computer.' 'Dim'
        return
    }

    Write-Line ('{0} compatibility event(s) in the last 14 days.' -f $events.EventCount) 'Warn'
    if ($events.Newest) { Write-Line ('Most recent: {0}' -f $events.Newest) 'Dim' }
    Write-Line ''
    Write-Line 'Drivers named in those events:' 'Head'
    foreach ($d in (ConvertTo-Array $events.Drivers)) {
        Write-Line $d.FileName 'Warn' 2
        if ($d.Publisher) { Write-Line ('Publisher: {0}' -f $d.Publisher) 'Dim' 5 }
        if ($d.Version) { Write-Line ('Version  : {0}' -f $d.Version) 'Dim' 5 }
        if ($d.Service) { Write-Line ('Used by  : {0}' -f $d.Service) 'Dim' 5 }
        if ($d.Path) { Write-Line ('Path     : {0}' -f $d.Path) 'Dim' 5 }
        if (-not $d.Found) { Write-Line 'This file is no longer present, so the problem may already be resolved.' 'Dim' 5 }
    }
    Write-Line ''
    Write-Line 'Update or remove the driver above, restart, then run the audit again.' 'Info'
}

# ===== 50-apply.ps1 =====
# ---------------------------------------------------------------------------
# Plan, apply and revert.
#
# The plan is a projection of the catalog, so -WhatIf cannot disagree with what apply
# actually writes. Intent is flushed before writing; completion/revert markers distinguish
# confirmed changes from ambiguous interrupted writes and prevent stale replay.
# ---------------------------------------------------------------------------

function Get-ControlDelta {
    param([Parameter(Mandatory = $true)][string]$Id)

    $control = Get-Control -Id $Id
    $rows = @()
    foreach ($value in (ConvertTo-Array $control.LocalValues)) {
        $exists = $false; $current = $null; $currentType = $null; $readError = $null
        try {
            $exists = Test-RegValue -Path $value.Path -Name $value.Name
            $current = if ($exists) { Get-RegValue -Path $value.Path -Name $value.Name } else { $null }
            $currentType = if ($exists) { Get-RegKind -Path $value.Path -Name $value.Name } else { $null }
        }
        catch { $readError = $_.Exception.Message }
        $comparison = if ($value.ContainsKey('Comparison')) { $value.Comparison } else { 'Exact' }
        $invalid = [bool]($exists -and $currentType -eq $value.Type -and $value.ContainsKey('KnownValues') -and @($value.KnownValues) -notcontains [long]$current)
        $needs = if ($readError) { $false }
                 elseif (-not $exists -or $currentType -ne $value.Type) { $true }
                 else { -not (Test-CatalogValueSatisfied -Definition $value -Current $current) }

        $rows += [pscustomobject]@{
            ControlId = $control.Id
            ControlName = $control.Name
            Path = $value.Path
            Name = $value.Name
            Type = $value.Type
            Comparison = $comparison
            CurrentValue = $current
            CurrentExists = $exists
            CurrentType = $currentType
            DesiredValue = $value.Value
            NeedsChange = [bool]$needs
            ReadError = $readError
            InvalidValue = $invalid
            Note = $value.Note
        }
    }
    return $rows
}

function Get-ChangePlan {
    param(
        [Parameter(Mandatory = $true)][string[]]$Ids,
        [Parameter(Mandatory = $true)]$State,
        [string[]]$ExplicitIds = @()
    )
    $plan = @()
    $seen = @{}
    foreach ($id in $Ids) {
        foreach ($control in (Resolve-ControlOrder -Id $id)) {
            if ($seen.ContainsKey($control.Id)) { continue }
            $seen[$control.Id] = $true

            $status = Get-ControlStatus -Id $control.Id -State $State
            $preflight = $null
            $deltas = @(Get-ControlDelta -Id $control.Id)
            if ($status.Supported -and -not $status.ManagedByPolicy -and @($deltas | Where-Object { $_.NeedsChange }).Count -gt 0 -and @($deltas | Where-Object { $_.CurrentExists -and $_.CurrentType -ne $_.Type }).Count -eq 0) {
                $preflight = Get-ControlPreflight -Control $control
            }
            $requiresOverride = [bool]($preflight -and $preflight.Tripped -and $preflight.BlocksSafeSet)
            $explicit = [bool]($ExplicitIds -contains $control.Id)
            $skip = if ($status.PolicyReadError) { 'Cannot verify organization policy; restore read access before remediation.' }
                    elseif (@($deltas | Where-Object ReadError).Count -gt 0) { 'Cannot read the existing registry state; remediation is blocked to preserve rollback data.' }
                    elseif (@($deltas | Where-Object InvalidValue).Count -gt 0) { 'An existing registry value is unrecognized. Review it manually before remediation.' }
                    elseif ($status.ManagedByPolicy) { 'Managed by Group Policy' }
                    elseif (-not $status.Supported) { $status.SupportReason }
                    elseif (@($deltas | Where-Object { $_.CurrentExists -and $_.CurrentType -ne $_.Type }).Count -gt 0) { 'An existing registry value has an unexpected type. Review it manually before remediation.' }
                    elseif ($requiresOverride) {
                        if ($explicit -and -not $script:Unattended) { $preflight.Message + ' A typed override is required.' }
                        else { $preflight.Message + ' Skipped for safety; use the interactive specific-control menu to confirm an override.' }
                    }
                    else { $null }
            foreach ($row in $deltas) {
                $plan += [pscustomobject]@{
                    ControlId = $row.ControlId
                    ControlName = $row.ControlName
                    Path = $row.Path
                    Name = $row.Name
                    Type = $row.Type
                    CurrentValue = $row.CurrentValue
                    CurrentExists = $row.CurrentExists
                    CurrentType = $row.CurrentType
                    DesiredValue = $row.DesiredValue
                    NeedsChange = $row.NeedsChange
                    Note = $row.Note
                    ManagedByPolicy = $status.ManagedByPolicy
                    Supported = $status.Supported
                    ExplicitlyRequested = $explicit
                    Preflight = $preflight
                    RequiresOverride = $requiresOverride
                    DependencyReady = [bool]($status.Supported -and $status.Running -and -not $status.PolicyReadError -and -not $status.ConfigurationError -and (-not $status.ManagedByPolicy -or $status.PolicyValue -ne 0))
                    SkipReason = $skip
                }
            }
        }
    }
    # A dependent cannot be enabled when its required protection is blocked.
    foreach ($row in $plan) {
        if ($row.SkipReason) { continue }
        foreach ($dep in (ConvertTo-Array (Get-Control -Id $row.ControlId).Requires)) {
            $blockedDep = @($plan | Where-Object { $_.ControlId -eq $dep -and $_.SkipReason -and -not $_.DependencyReady })
            if ($blockedDep.Count -gt 0) {
                $row.SkipReason = ('Required control {0} is blocked: {1}' -f $dep, $blockedDep[0].SkipReason)
                break
            }
        }
    }
    return $plan
}

# ---------------------------------------------------------------------------
# Change journal
# ---------------------------------------------------------------------------

# Tests inject a private path only with the in-memory registry provider. An inherited
# WINDSH_JOURNAL_PATH never controls an elevated production write.
$script:TestJournalPath = $null

function Get-JournalPath {
    if ($script:Registry.Kind -eq 'InMemory' -and $script:TestJournalPath) { return $script:TestJournalPath }
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programData) { throw 'ProgramData is unavailable; refusing to use a temporary production journal.' }
    return (Join-Path (Join-Path $programData 'WinDSH') 'changes.jsonl')
}

function Enter-JournalLock {
    $path = Get-JournalPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    if ($script:Registry.Kind -eq 'Windows') {
        # The journal contains privileged rollback data. Reject links and restrict
        # writes to administrators/SYSTEM, including an existing pre-created folder.
        $item = Get-Item -LiteralPath $dir -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The journal folder cannot be a reparse point.' }
        foreach ($file in @($path, ($path + '.lock'))) {
            if (Test-Path -LiteralPath $file) {
                if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Journal files cannot be reparse points.' }
            }
        }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidText in @('S-1-5-32-544', 'S-1-5-18')) {
            $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        Set-Acl -LiteralPath $dir -AclObject $acl -ErrorAction Stop
        foreach ($file in @($path, ($path + '.lock'))) {
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $fileAcl = New-Object Security.AccessControl.FileSecurity
            $fileAcl.SetAccessRuleProtection($false, $false)
            $fileAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
            Set-Acl -LiteralPath $file -AclObject $fileAcl -ErrorAction Stop
        }
    }
    try { $handle = [IO.File]::Open(($path + '.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'Another WinDSH change operation is running, or the journal lock is inaccessible. No changes were made.' }
    try {
        # Validate the existing journal before any new change. Remove only an invalid
        # unterminated tail, otherwise the next append would turn it into middle damage.
        [void](Get-Journal)
        if (Test-Path -LiteralPath $path) {
            $raw = [IO.File]::ReadAllText($path)
            if ($raw.Length -gt 0 -and -not $raw.EndsWith("`n")) {
                $lastLf = $raw.LastIndexOf("`n")
                $tail = $raw.Substring($lastLf + 1)
                try {
                    $tailRecord = $tail | ConvertFrom-Json -ErrorAction Stop
                    if (-not (Get-PropertySafe $tailRecord 'RunId' $null)) { throw 'Missing RunId.' }
                    $repaired = $raw + "`n"
                }
                catch { $repaired = $raw.Substring(0, $lastLf + 1) }
                [IO.File]::WriteAllText($path, $repaired, (New-Object Text.UTF8Encoding($false)))
            }
        }
        return $handle
    }
    catch { $handle.Dispose(); throw }
}

function Write-JournalEntry {
    param([Parameter(Mandatory = $true)]$Entry)
    $path = Get-JournalPath
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Entry | ConvertTo-Json -Compress -Depth 5) + "`n")
    $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Get-Journal {
    param([string]$RunId)
    $path = Get-JournalPath
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $raw = [IO.File]::ReadAllText($path)
    $lines = @($raw -split "`n")
    $entries = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if (-not (Get-PropertySafe $record 'RunId' $null)) { throw 'Missing RunId.' }
            $entries += $record
        }
        catch {
            # Only a torn final append may be ignored; a corrupt middle/terminated
            # record could hide an applied/reverted marker, so do not guess.
            if ($i -eq $lines.Count - 1 -and -not $raw.EndsWith("`n")) { break }
            throw ('The change journal is malformed at line {0}. Revert is disabled until it is repaired.' -f ($i + 1))
        }
    }
    if ($RunId) { $entries = @($entries | Where-Object { $_.RunId -eq $RunId }) }
    return $entries
}

function Get-JournalChanges {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records)
    $changes = @(); $seen = @{}; $index = 0
    foreach ($record in $Records) {
        $index++
        $kind = Get-PropertySafe $record 'RecordType' 'LegacyChange'
        if ($kind -notin @('Change', 'LegacyChange')) { continue }
        $id = Get-PropertySafe $record 'ChangeId' ('legacy-{0}' -f $index)
        if ($seen.ContainsKey($id)) { throw 'The journal contains duplicate change identifiers.' }
        $seen[$id] = $true
        $markers = @($Records | Where-Object { (Get-PropertySafe $_ 'ChangeId' '') -eq $id })
        $changes += [pscustomobject]@{
            Id = $id
            Entry = $record
            Applied = [bool]($kind -eq 'LegacyChange' -or @($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'Applied' }).Count -gt 0)
            RevertStarted = [bool](@($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertStarted' }).Count -gt 0)
            Reverted = [bool](@($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'Reverted' }).Count -gt 0)
        }
    }
    return $changes
}

function Get-JournalRuns {
    $runs = @()
    foreach ($group in (Get-Journal | Group-Object RunId)) {
        $changes = @(Get-JournalChanges -Records @($group.Group) | Where-Object { -not $_.Reverted })
        if ($changes.Count -eq 0) { continue }
        if (@($group.Group | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertCompleted' }).Count -gt 0) { continue }
        $first = @($group.Group)[0]
        $runs += [pscustomobject]@{
            RunId = $group.Name
            Time = $first.Time
            ChangeCount = $changes.Count
            Controls = (@($changes | ForEach-Object { $_.Entry.ControlId } | Select-Object -Unique) -join ', ')
        }
    }
    return @($runs | Sort-Object Time -Descending)
}

function Write-JournalMarker {
    param([string]$RunId, [string]$RecordType, [string]$ChangeId)
    Write-JournalEntry ([pscustomobject]@{ RunId = $RunId; Time = (Get-Date).ToUniversalTime().ToString('o'); RecordType = $RecordType; ChangeId = $ChangeId })
}

function Test-JournalChange {
    param($Entry)
    # A journal is data, not authority to write arbitrary registry paths or policies.
    $control = Get-Control -Id $Entry.ControlId
    $allowed = @($control.LocalValues | Where-Object { $_.Path -eq $Entry.Path -and $_.Name -eq $Entry.Name -and $_.Type -eq $Entry.Type -and $_.Value -eq $Entry.AfterValue })
    if ($allowed.Count -ne 1 -or $Entry.BeforeExists -isnot [bool]) { throw 'The journal contains a change outside the control catalog.' }
    $beforeType = Get-PropertySafe $Entry 'BeforeType' $Entry.Type
    if ($Entry.BeforeExists -and ($beforeType -ne 'DWord' -or $Entry.BeforeValue -isnot [ValueType] -or [long]$Entry.BeforeValue -lt [int]::MinValue -or [long]$Entry.BeforeValue -gt [uint32]::MaxValue)) {
        throw 'The journal contains an unsupported prior registry value. Restore it manually.'
    }
}

# ---------------------------------------------------------------------------
# Apply / revert
# ---------------------------------------------------------------------------

function Invoke-ControlApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string[]]$Ids,
        [Parameter(Mandatory = $true)]$State,
        [string]$RunId,
        [string[]]$ExplicitIds = @()
    )

    if (-not $script:RemediationAllowed) { throw 'Remediation is disabled because the self-integrity check failed.' }
    if (-not $RunId) { $RunId = [Guid]::NewGuid().ToString('N').Substring(0, 12) }

    $lock = $null
    if (-not $WhatIfPreference) { $lock = Enter-JournalLock }
    try {
        $applied = @(); $skipped = @()
        $plan = @(Get-ChangePlan -Ids $Ids -State $State -ExplicitIds $ExplicitIds)

        # Both preview and apply consume the same safety decision. Only a specifically
        # selected control in an interactive session can override a tripped check.
        foreach ($group in ($plan | Group-Object ControlId)) {
            $row = @($group.Group)[0]
            if (-not $row.RequiresOverride -or -not $row.ExplicitlyRequested -or $script:Unattended -or $WhatIfPreference) { continue }
            Write-Line $row.Preflight.Message 'Warn'
            if (Confirm-Action ('Enable {0} anyway?' -f $row.ControlName) -RequireTyped $row.ControlId) {
                foreach ($value in $group.Group) { $value.SkipReason = $null }
            }
        }
        # Rebuild dependency decisions after a genuine override without repeating queries.
        foreach ($row in $plan) {
            if ($row.SkipReason -notlike 'Required control *') { continue }
            $blockedDeps = @((Get-Control -Id $row.ControlId).Requires | Where-Object {
                $depId = $_
                @($plan | Where-Object { $_.ControlId -eq $depId -and $_.SkipReason -and -not $_.DependencyReady }).Count -gt 0
            })
            if ($blockedDeps.Count -eq 0) { $row.SkipReason = $null }
        }

        # --- confirmation -----------------------------------------------------
        $pending = @($plan | Where-Object { $_.NeedsChange -and -not $_.SkipReason })
        if (@($pending).Count -gt 0 -and -not $script:Unattended -and -not $WhatIfPreference) {
            Write-Section 'About to change'
            foreach ($controlId in (@($pending | Select-Object -ExpandProperty ControlId -Unique))) {
                $control = Get-Control -Id $controlId
                Write-Line $control.Name 'Info' 2
                $caution = Get-PropertySafe $control 'Caution' $null
                if ($caution) { Write-Line $caution 'Warn' 5 }
            }
            Write-Line ''
            Write-Line ('{0} registry value(s) will change. A restart will be needed.' -f @($pending).Count) 'Plain'
            if (-not (Confirm-Action 'Continue?' -DefaultYes)) {
                Write-Line 'Cancelled. Nothing was changed.' 'Info'
                return [pscustomobject]@{ RunId = $RunId; Applied = @(); Skipped = @(); ChangeCount = 0; RestartRequired = $false; Cancelled = $true }
            }
        }

        foreach ($row in $plan) {
            if ($row.SkipReason) {
                if (-not @($skipped | Where-Object { $_.ControlId -eq $row.ControlId }).Count) {
                    $skipped += [pscustomobject]@{ ControlId = $row.ControlId; ControlName = $row.ControlName; Reason = $row.SkipReason }
                }
                continue
            }
            if (-not $row.NeedsChange) { continue }

            $target = '{0}\{1}' -f $row.Path, $row.Name
            if (-not $PSCmdlet.ShouldProcess($target, ('Set {0} to {1}' -f $row.Type, $row.DesiredValue))) { continue }

            # Check again under the run lock: another administrator can change state
            # after planning even though other WinDSH processes are serialized.
            $existsNow = Test-RegValue -Path $row.Path -Name $row.Name
            $currentNow = if ($existsNow) { Get-RegValue -Path $row.Path -Name $row.Name } else { $null }
            $kindNow = if ($existsNow) { Get-RegKind -Path $row.Path -Name $row.Name } else { $null }
            if ($existsNow -ne $row.CurrentExists -or $currentNow -ne $row.CurrentValue -or $kindNow -ne $row.CurrentType) { throw 'Registry state changed since planning. Run the audit again.' }
            if ($existsNow -and $kindNow -ne 'DWord') { throw 'The existing registry value is not a DWORD. Review it manually before remediation.' }
            $changeId = [Guid]::NewGuid().ToString('N')
            Write-JournalEntry ([pscustomobject]@{
                RecordType = 'Change'
                ChangeId = $changeId
                RunId = $RunId
                Time = (Get-Date).ToUniversalTime().ToString('o')
                ToolVersion = $script:ToolVersion
                ControlId = $row.ControlId
                Path = $row.Path
                Name = $row.Name
                Type = $row.Type
                BeforeType = $row.CurrentType
                BeforeExists = $row.CurrentExists
                BeforeValue = $row.CurrentValue
                AfterValue = $row.DesiredValue
            })
            & $script:Registry.SetValue $row.Path $row.Name $row.Type $row.DesiredValue
            $script:RestartRequired = $true

            $applied += [pscustomobject]@{
                ControlId = $row.ControlId
                ControlName = $row.ControlName
                Path = $row.Path
                Name = $row.Name
                Before = if ($row.CurrentExists) { $row.CurrentValue } else { '(not set)' }
                After = $row.DesiredValue
            }
            $script:AppliedChanges += $applied[-1]
            Write-JournalMarker -RunId $RunId -RecordType 'Applied' -ChangeId $changeId
        }

        if ($applied.Count -gt 0) { $script:RestartRequired = $true }
        if ($applied.Count -gt 0) { Write-JournalMarker -RunId $RunId -RecordType 'RunCompleted' }

        return [pscustomobject]@{
            RunId = $RunId
            Applied = $applied
            Skipped = $skipped
            ChangeCount = $applied.Count
            RestartRequired = [bool]($applied.Count -gt 0)
            Cancelled = $false
        }
    }
    finally { if ($lock) { $lock.Dispose() } }
}


function Invoke-ControlRevert {
    <# Restore only values still matching completed writes, once per entry. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$RunId)

    if (-not $script:RemediationAllowed) { throw 'Revert is disabled because the self-integrity check failed.' }
    $lock = $null
    if (-not $WhatIfPreference) { $lock = Enter-JournalLock }
    try {
        if (-not $RunId) {
            $runs = @(Get-JournalRuns)
            if ($runs.Count -eq 0) { throw 'There is nothing to revert: no open change runs remain.' }
            $RunId = $runs[0].RunId
        }
        $records = @(Get-Journal -RunId $RunId)
        if (@($records | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertCompleted' }).Count -gt 0) { throw 'This run has already been reverted.' }
        $changes = @(Get-JournalChanges -Records $records | Where-Object { -not $_.Reverted })
        if ($changes.Count -eq 0) { throw ('No open changes found for run {0}.' -f $RunId) }
        # Validate every change before restoring anything, including legacy records.
        foreach ($change in $changes) { Test-JournalChange -Entry $change.Entry }
        [array]::Reverse($changes)
        $reverted = @(); $conflicts = @(); $recovered = 0
        foreach ($change in $changes) {
            $entry = $change.Entry
            $target = '{0}\{1}' -f $entry.Path, $entry.Name
            $exists = Test-RegValue -Path $entry.Path -Name $entry.Name
            $current = if ($exists) { Get-RegValue -Path $entry.Path -Name $entry.Name } else { $null }
            $kind = if ($exists) { Get-RegKind -Path $entry.Path -Name $entry.Name } else { $null }
            $beforeType = Get-PropertySafe $entry 'BeforeType' $entry.Type
            $matchesBefore = [bool]($exists -eq $entry.BeforeExists -and (-not $exists -or ($current -eq $entry.BeforeValue -and $kind -eq $beforeType)))
            if ($change.RevertStarted -and $matchesBefore) {
                if ($Rmm -and $WhatIfPreference) { continue }
                if ($PSCmdlet.ShouldProcess($target, 'Record recovery of an interrupted revert')) {
                    Write-JournalMarker -RunId $RunId -RecordType 'Reverted' -ChangeId $change.Id
                    $recovered++
                }
                continue
            }
            $reason = if (-not $change.Applied) { 'The original registry write was not confirmed. Review this interrupted change manually.' }
                      elseif (-not $exists -or $current -ne $entry.AfterValue -or $kind -ne $entry.Type) { 'Current state differs from the value WinDSH wrote; leaving it unchanged.' }
                      else { $null }
            if ($reason) {
                $conflicts += [pscustomobject]@{ ControlId = $entry.ControlId; Path = $entry.Path; Name = $entry.Name; Reason = $reason }
                continue
            }
            $action = if ($entry.BeforeExists) { 'Restore to {0}' -f $entry.BeforeValue } else { 'Remove value (did not exist before)' }
            if ($Rmm -and $WhatIfPreference) { continue }
            if (-not $PSCmdlet.ShouldProcess($target, $action)) { continue }
            Write-JournalMarker -RunId $RunId -RecordType 'RevertStarted' -ChangeId $change.Id
            if ($entry.BeforeExists) { & $script:Registry.SetValue $entry.Path $entry.Name $beforeType $entry.BeforeValue }
            else { & $script:Registry.RemoveValue $entry.Path $entry.Name }
            $script:RestartRequired = $true
            Write-JournalMarker -RunId $RunId -RecordType 'Reverted' -ChangeId $change.Id
            $restored = if ($entry.BeforeExists) { $entry.BeforeValue } else { '(removed)' }
            $reverted += [pscustomobject]@{ ControlId = $entry.ControlId; Path = $entry.Path; Name = $entry.Name; RestoredTo = $restored }
        }
        if (-not $WhatIfPreference -and $conflicts.Count -eq 0 -and $reverted.Count + $recovered -eq $changes.Count) {
            Write-JournalMarker -RunId $RunId -RecordType 'RevertCompleted'
        }
        return [pscustomobject]@{
            RunId = $RunId; Reverted = $reverted; Conflicts = $conflicts
            ChangeCount = $reverted.Count; RecoveredCount = $recovered
            RestartRequired = [bool]($reverted.Count -gt 0)
        }
    }
    finally { if ($lock) { $lock.Dispose() } }
}

# ===== 55-report-text.ps1 =====
# ---------------------------------------------------------------------------
# Plain-text report. Another projection over the same data as the HTML and JSON
# reports, so the three cannot describe the machine differently.
# ---------------------------------------------------------------------------

function New-TextReport {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Statuses,
        [Parameter(Mandatory = $true)]$Score,
        [Parameter(Mandatory = $true)]$SecuredCore,
        [Parameter(Mandatory = $true)]$Cis,
        [Parameter(Mandatory = $true)]$Explanations
    )

    $lines = @()
    $rule = '-' * 78
    $lines += $rule
    $lines += ('{0} {1} - Windows device security report' -f $script:ToolName, $script:ToolVersion)
    $lines += ('Computer  : {0}' -f $State.Computer.Name)
    $lines += ('Generated : {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $lines += $rule
    $lines += ''

    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count
    $lines += 'APPLICABLE PROTECTION SCORE'
    $lines += ('  {0} / 100 ({1})' -f $Score.Score, $Score.Grade)
    $lines += ('  {0} of {1} scored controls are applicable; unsupported controls are excluded.' -f $Score.ApplicableCount, $Score.TotalCount)
    $lines += ('  {0} of {1} applicable protections are active.' -f $running, $countable)
    if ($Score.UnknownCount -gt 0) { $lines += ('  {0} scored protection(s) could not be verified; no points are credited, and they remain in the total.' -f $Score.UnknownCount) }
    if ($Score.ExcludedCount -gt 0) {
        $lines += ('  {0} excluded: current platform requirements are not met, so they are not counted against you.' -f $Score.ExcludedCount)
    }
    $lines += ('  Secured-core PC: {0}' -f $(if ($SecuredCore.Qualifies) { 'qualifies' } else { ('does not qualify, {0} requirement(s) unmet' -f $SecuredCore.UnmetCount) }))
    $lines += ''

    $lines += 'THIS COMPUTER'
    $lines += ('  Make and model  : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model)
    $lines += ('  Processor       : {0}' -f $State.Computer.ProcessorName)
    $lines += ('  Windows         : {0} build {1} ({2})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber, $State.Computer.EditionId)
    $lines += ('  Firmware mode   : {0} (detected via {1})' -f $State.Firmware.Mode, $State.Firmware.DetectionSource)
    $lines += ('  Secure Boot     : {0}' -f (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable'))
    $lines += ('  TPM             : {0} (spec {1})' -f (Format-Bool $State.Tpm.IsTPM2 'TPM 2.0 present' 'not confirmed'), $State.Tpm.SpecVersion)
    $lines += ('  Hypervisor      : launch type {0}' -f $State.HypervisorLaunch.LaunchType)
    $lines += ('  DEP             : {0}' -f $State.Dep.Text)
    $lines += ('  Restart pending : {0}' -f (Format-Bool $State.Restart.Pending))
    if ($State.VirtualMachine.IsVirtual) {
        $lines += ('  Virtual machine : yes ({0})' -f $State.VirtualMachine.Platform)
        foreach ($note in (ConvertTo-Array $State.VirtualMachine.Notes)) { $lines += ('      - {0}' -f $note) }
    }
    $lines += ''

    if ($State.HypervisorLaunch.BlocksVbs) {
        $lines += 'BLOCKING ISSUE'
        $lines += '  The Windows hypervisor is switched off in the boot configuration, so none of the'
        $lines += '  virtualization-based protections can start, whatever else is configured.'
        $lines += '  Fix: run  bcdedit /set hypervisorlaunchtype Auto  elevated, then restart.'
        $lines += ''
    }

    $lines += 'PROTECTIONS'
    foreach ($s in $Statuses) {
        $marker = switch ($s.State) {
            'Running' { '[ OK ]' }
            'ConfiguredNotRunning' { '[ !  ]' }
            'NotConfigured' { '[ X  ]' }
            default { '[ -  ]' }
        }
        $label = (Get-StateLabel $s.State).Text
        $policy = if ($s.ManagedByPolicy) { ' (Group Policy)' } else { '' }
        $lines += ('  {0} {1,-34} {2}{3}' -f $marker, $s.PlainName, $label, $policy)
        $lines += ('         {0}' -f $s.Name)
    }
    $lines += ''

    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    $lines += 'WHAT TO DO NEXT'
    if (@($todo).Count -eq 0) { $lines += '  Nothing. Every protection this computer supports is already active.' }
    else {
        $n = 0
        foreach ($e in $todo) {
            $n++
            $lines += ''
            $lines += ('  {0}. {1}' -f $n, $e.PlainName)
            $lines += ('     {0}' -f $e.Verdict)
            if ($e.Action) { foreach ($l in ($e.Action -split "`n")) { $lines += ('     {0}' -f $l) } }
        }
    }
    $lines += ''

    $lines += 'CIS BENCHMARK COMPARISON'
    $lines += ('  {0}, section {1}' -f $Cis.Benchmark, $Cis.Section)
    $lines += ('  {0} of {1} checks pass.' -f $Cis.CompliantCount, $Cis.TotalCount)
    $lines += ''
    $lines += '  IMPORTANT: CIS audits the Group Policy hive. WinDSH configures local machine'
    $lines += '  values and never writes Group Policy, so a protection can be active on this'
    $lines += '  computer while its CIS check still reports non-compliant.'
    $lines += ''
    foreach ($r in $Cis.Rows) {
        $verdict = if (-not $r.PolicyKnown) { 'UNKNOWN' } elseif ($r.Compliant) { 'PASS' } else { 'FAIL' }
        $actual = if (-not $r.PolicyKnown) { 'unavailable' } elseif ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        $lines += ('  {0} {1,-9} {2,-38} policy = {3}, running = {4}' -f `
            $verdict, $r.CisId, $r.PolicyValueName, $actual, (Format-Bool $r.FeatureRunning))
        if ($r.Divergence) { $lines += ('           Deliberate difference: {0}' -f $r.Divergence) }
    }
    $lines += ''

    $lines += 'SECURED-CORE PC CRITERIA'
    foreach ($c in $SecuredCore.Checks) {
        $lines += ('  {0} {1}' -f $(if ($c.Met) { '[ OK ]' } else { '[ X  ]' }), $c.Name)
    }
    $lines += ''

    if (@($script:AppliedChanges).Count -gt 0) {
        $lines += 'CHANGES MADE IN THIS SESSION'
        foreach ($c in $script:AppliedChanges) {
            $lines += ('  {0}\{1}: {2} -> {3}' -f $c.Path, $c.Name, $c.Before, $c.After)
        }
        $lines += ''
    }

    $lines += $rule
    $lines += 'This report describes configuration state only. It is not a vulnerability assessment.'
    $lines += 'WinDSH writes local machine settings and never modifies Group Policy.'
    $lines += $rule

    return ($lines -join "`r`n")
}

# ===== 60-report-html.ps1 =====
# ---------------------------------------------------------------------------
# HTML report. Self-contained single file: no external CSS, fonts, scripts or images,
# so it renders identically on a machine with no internet access and can be attached to
# a ticket or emailed without anything breaking.
# ---------------------------------------------------------------------------

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).
        Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').
        Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-StateLabel {
    param([string]$State)
    switch ($State) {
        'Running' { return @{ Text = 'Active'; Class = 'ok' } }
        'ConfiguredNotRunning' { return @{ Text = 'Needs restart or unsupported'; Class = 'warn' } }
        'NotConfigured' { return @{ Text = 'Off'; Class = 'bad' } }
        'NotSupported' { return @{ Text = 'Not available on this PC'; Class = 'na' } }
        'Unknown' { return @{ Text = 'Unable to verify'; Class = 'warn' } }
        'AuditMode' { return @{ Text = 'Audit only; not enforcing'; Class = 'warn' } }
        default { return @{ Text = $State; Class = 'na' } }
    }
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Statuses,
        [Parameter(Mandatory = $true)]$Score,
        [Parameter(Mandatory = $true)]$SecuredCore,
        [Parameter(Mandatory = $true)]$Cis,
        [Parameter(Mandatory = $true)]$Explanations
    )

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $scoreColour = if ($Score.Score -ge 90) { '#1a7f43' } elseif ($Score.Score -ge 75) { '#2f855a' } elseif ($Score.Score -ge 50) { '#b7791f' } else { '#c53030' }

    # Donut geometry: circumference of r=70 is 2*pi*70.
    $circumference = [math]::Round(2 * [math]::PI * 70, 2)
    $filled = [math]::Round($circumference * ($Score.Score / 100.0), 2)
    $gap = [math]::Round($circumference - $filled, 2)

    $sb = New-Object Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine(('<title>WinDSH security report - {0}</title>' -f (ConvertTo-HtmlText $State.Computer.Name)))
    $null = $sb.AppendLine(@'
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1a202c;--muted:#5a6472;--line:#e2e6ec;
--ok:#1a7f43;--warn:#b7791f;--bad:#c53030;--na:#718096;}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--ink:#e8eaed;
--muted:#9aa4b2;--line:#2d333d;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--na:#94a3b8;}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--ink);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;
padding-bottom:6px;border-bottom:2px solid var(--line)}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:16px}
.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.gauge{flex:0 0 180px;text-align:center}
.gv{font-size:40px;font-weight:700;line-height:1}
.gl{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.hero-txt{flex:1;min-width:260px}
.verdict{font-size:17px;margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{background:rgba(26,127,67,.13);color:var(--ok)}
.warn{background:rgba(183,121,31,.15);color:var(--warn)}
.bad{background:rgba(197,48,48,.13);color:var(--bad)}
.na{background:rgba(113,128,150,.15);color:var(--na)}
.kv{display:grid;grid-template-columns:200px 1fr;gap:6px 16px;font-size:14px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
.note{background:rgba(183,121,31,.1);border-left:3px solid var(--warn);padding:12px 14px;
border-radius:0 6px 6px 0;font-size:14px;margin:12px 0}
.item{border-top:1px solid var(--line);padding:14px 0}
.item:first-child{border-top:0}
.item h3{margin:0 0 4px;font-size:15px}
.why{color:var(--muted);font-size:13.5px;margin:4px 0}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;
font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:8px 0 0}
.tiny{font-size:12px;color:var(--muted)}
a{color:inherit}
@media print{body{background:#fff;padding:0}.card{break-inside:avoid;border-color:#ccc}}
</style></head><body><div class="wrap">
'@)

    # ---- header + score ----
    $null = $sb.AppendLine(('<h1>Windows device security report</h1>'))
    $null = $sb.AppendLine(('<div class="sub">{0} &middot; generated {1} &middot; {2} {3}</div>' -f `
        (ConvertTo-HtmlText $State.Computer.Name), (ConvertTo-HtmlText $generated),
        (ConvertTo-HtmlText $script:ToolName), (ConvertTo-HtmlText $script:ToolVersion)))

    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count

    $null = $sb.AppendLine('<div class="card hero">')
    $null = $sb.AppendLine('<div class="gauge"><svg viewBox="0 0 180 180" width="160" height="160" role="img" aria-label="Applicable protection score">')
    $null = $sb.AppendLine('<circle cx="90" cy="90" r="70" fill="none" stroke="var(--line)" stroke-width="16"/>')
    $null = $sb.AppendLine(('<circle cx="90" cy="90" r="70" fill="none" stroke="{0}" stroke-width="16" stroke-linecap="round" stroke-dasharray="{1} {2}" transform="rotate(-90 90 90)"/>' -f $scoreColour, $filled, $gap))
    $null = $sb.AppendLine(('<text x="90" y="86" text-anchor="middle" font-size="40" font-weight="700" fill="currentColor">{0}</text>' -f $Score.Score))
    $null = $sb.AppendLine('<text x="90" y="108" text-anchor="middle" font-size="13" fill="currentColor" opacity="0.65">out of 100</text>')
    $null = $sb.AppendLine('</svg>')
    $null = $sb.AppendLine(('<div class="gl">{0}</div></div>' -f (ConvertTo-HtmlText $Score.Grade)))

    $null = $sb.AppendLine('<div class="hero-txt">')
    $null = $sb.AppendLine('<h2>Applicable protection score</h2>')
    $null = $sb.AppendLine(('<p class="tiny">{0} of {1} scored controls are applicable; unsupported controls are excluded.</p>' -f $Score.ApplicableCount, $Score.TotalCount))
    $null = $sb.AppendLine(('<p class="verdict">{0} of {1} applicable protections are active on this computer.</p>' -f $running, $countable))
    if ($Score.UnknownCount -gt 0) { $null = $sb.AppendLine(('<p class="note">{0} scored protection(s) could not be verified. No points are credited for them, and they remain in the total.</p>' -f $Score.UnknownCount)) }
    if ($Score.ExcludedCount -gt 0) {
        $null = $sb.AppendLine(('<p class="tiny">{0} protection(s) are excluded from the score because current platform requirements are not met. They are not counted against you.</p>' -f $Score.ExcludedCount))
    }
    $scVerdict = if ($SecuredCore.Qualifies) { 'This computer meets the Secured-core PC criteria.' } else { ('This computer does not meet the Secured-core PC criteria ({0} requirement(s) unmet).' -f $SecuredCore.UnmetCount) }
    $null = $sb.AppendLine(('<p class="tiny">{0}</p>' -f (ConvertTo-HtmlText $scVerdict)))
    $null = $sb.AppendLine('</div></div>')

    # ---- system ----
    $null = $sb.AppendLine('<h2>This computer</h2><div class="card"><dl class="kv">')
    $rows = @(
        @{ K = 'Computer name'; V = $State.Computer.Name }
        @{ K = 'Make and model'; V = ('{0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) }
        @{ K = 'Processor'; V = $State.Computer.ProcessorName }
        @{ K = 'Windows'; V = ('{0} (build {1})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber) }
        @{ K = 'Edition'; V = $State.Computer.EditionId }
        @{ K = 'Firmware mode'; V = $State.Firmware.Mode }
        @{ K = 'Secure Boot'; V = (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable') }
        @{ K = 'TPM 2.0'; V = (Format-Bool $State.Tpm.IsTPM2 'Present' 'Not confirmed') }
        @{ K = 'Hypervisor launch type'; V = $(if ($State.HypervisorLaunch.LaunchType) { $State.HypervisorLaunch.LaunchType } else { 'Unknown' }) }
        @{ K = 'Virtual machine'; V = (Format-Bool $State.Computer.IsVirtual) }
        @{ K = 'Restart pending'; V = (Format-Bool $State.Restart.Pending) }
    )
    foreach ($r in $rows) {
        $null = $sb.AppendLine(('<dt>{0}</dt><dd>{1}</dd>' -f (ConvertTo-HtmlText $r.K), (ConvertTo-HtmlText ([string]$r.V))))
    }
    $null = $sb.AppendLine('</dl></div>')

    if ($State.HypervisorLaunch.BlocksVbs) {
        $null = $sb.AppendLine('<div class="note"><strong>Blocking issue.</strong> The Windows hypervisor is switched off in this computer&#39;s boot configuration, so none of the virtualization-based protections can start, whatever else is configured. In an elevated Command Prompt run <code>bcdedit /set hypervisorlaunchtype Auto</code> and restart.</div>')
    }

    # ---- protections ----
    $null = $sb.AppendLine('<h2>Protections</h2><div class="card"><table><thead><tr>')
    $null = $sb.AppendLine('<th>Protection</th><th>What it does</th><th>Status</th><th>Points</th></tr></thead><tbody>')
    foreach ($s in $Statuses) {
        $label = Get-StateLabel $s.State
        $control = Get-Control -Id $s.Id
        $pts = @($Score.Breakdown | Where-Object { $_.Id -eq $s.Id })
        $ptsText = if (@($pts).Count -gt 0 -and $pts[0].Counted) { '{0} / {1}' -f $pts[0].Points, $s.Weight } else { 'n/a' }
        $policy = if ($s.ManagedByPolicy) { ' <span class="badge na">Group Policy</span>' } else { '' }
        $null = $sb.AppendLine(('<tr><td><strong>{0}</strong><br><span class="tiny">{1}</span></td><td>{2}</td><td><span class="badge {3}">{4}</span>{5}</td><td>{6}</td></tr>' -f `
            (ConvertTo-HtmlText $s.PlainName), (ConvertTo-HtmlText $s.Name), (ConvertTo-HtmlText $control.Summary),
            $label.Class, (ConvertTo-HtmlText $label.Text), $policy, $ptsText))
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    # ---- what to do ----
    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    $null = $sb.AppendLine('<h2>What to do next</h2><div class="card">')
    if (@($todo).Count -eq 0) {
        $null = $sb.AppendLine('<p>Nothing. Every protection this computer supports is already active.</p>')
    }
    else {
        foreach ($e in $todo) {
            $null = $sb.AppendLine('<div class="item">')
            $null = $sb.AppendLine(('<h3>{0}</h3>' -f (ConvertTo-HtmlText $e.PlainName)))
            $null = $sb.AppendLine(('<p class="why">{0}</p>' -f (ConvertTo-HtmlText $e.Verdict)))
            if ($e.Action) { $null = $sb.AppendLine(('<pre>{0}</pre>' -f (ConvertTo-HtmlText $e.Action))) }
            if ($e.Caution) { $null = $sb.AppendLine(('<p class="tiny"><strong>Note:</strong> {0}</p>' -f (ConvertTo-HtmlText $e.Caution))) }
            $null = $sb.AppendLine('</div>')
        }
    }
    $null = $sb.AppendLine('</div>')

    # ---- CIS ----
    $null = $sb.AppendLine(('<h2>CIS Benchmark comparison</h2>'))
    $null = $sb.AppendLine('<div class="card">')
    $null = $sb.AppendLine(('<p class="tiny">{0} &middot; section {1}</p>' -f (ConvertTo-HtmlText $Cis.Benchmark), (ConvertTo-HtmlText $Cis.Section)))
    $null = $sb.AppendLine(('<div class="note"><strong>Read this before using these results.</strong> {0}</div>' -f (ConvertTo-HtmlText $Cis.Note)))
    $null = $sb.AppendLine(('<p>{0} of {1} checks pass. {2} protection(s) are actually running on this computer but still fail their CIS check for the reason above.</p>' -f $Cis.CompliantCount, $Cis.TotalCount, $Cis.RunningButNotCompliantCount))
    $null = $sb.AppendLine('<table><thead><tr><th>CIS</th><th>Requirement</th><th>Policy value</th><th>CIS result</th><th>Actually running</th></tr></thead><tbody>')
    foreach ($r in $Cis.Rows) {
        $cls = if (-not $r.PolicyKnown) { 'warn' } elseif ($r.Compliant) { 'ok' } else { 'bad' }
        $txt = if (-not $r.PolicyKnown) { 'Unknown' } elseif ($r.Compliant) { 'Pass' } else { 'Fail' }
        $actual = if (-not $r.PolicyKnown) { 'unavailable' } elseif ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        $runCls = if ($r.FeatureRunning) { 'ok' } else { 'na' }
        $runTxt = if ($r.FeatureRunning) { 'Yes' } else { 'No' }
        $null = $sb.AppendLine(('<tr><td>{0}<br><span class="tiny">{1}</span></td><td>{2}</td><td><code>{3}</code> = {4}</td><td><span class="badge {5}">{6}</span></td><td><span class="badge {7}">{8}</span></td></tr>' -f `
            (ConvertTo-HtmlText $r.CisId), (ConvertTo-HtmlText $r.Profile), (ConvertTo-HtmlText $r.Title),
            (ConvertTo-HtmlText $r.PolicyValueName), (ConvertTo-HtmlText $actual), $cls, $txt, $runCls, $runTxt))
        if ($r.Divergence) {
            $null = $sb.AppendLine(('<tr><td></td><td colspan="4" class="tiny"><strong>Deliberate difference:</strong> {0}</td></tr>' -f (ConvertTo-HtmlText $r.Divergence)))
        }
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    # ---- secured core ----
    $null = $sb.AppendLine('<h2>Secured-core PC criteria</h2><div class="card"><table><thead><tr><th>Requirement</th><th>Status</th></tr></thead><tbody>')
    foreach ($c in $SecuredCore.Checks) {
        $cls = if ($c.Met) { 'ok' } else { 'bad' }
        $txt = if ($c.Met) { 'Met' } else { 'Not met' }
        $null = $sb.AppendLine(('<tr><td>{0}</td><td><span class="badge {1}">{2}</span></td></tr>' -f (ConvertTo-HtmlText $c.Name), $cls, $txt))
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    $null = $sb.AppendLine(('<p class="tiny">Generated by {0} {1}. This report describes configuration state only and is not a vulnerability assessment. WinDSH writes local machine settings and never modifies Group Policy.</p>' -f `
        (ConvertTo-HtmlText $script:ToolName), (ConvertTo-HtmlText $script:ToolVersion)))
    $null = $sb.AppendLine('</div></body></html>')

    return $sb.ToString()
}

# ===== 65-selftest.ps1 =====
# ---------------------------------------------------------------------------
# Synthetic self-test. Uses the in-memory registry provider, so apply/revert and the
# whole evaluation chain are exercised without touching a real machine. Runs on any host.
# ---------------------------------------------------------------------------

function New-SyntheticState {
    param([hashtable]$Override)

    $state = [pscustomobject]@{
        Generated = (Get-Date).ToUniversalTime().ToString('o')
        Computer = [pscustomobject]@{
            Name = 'SELFTEST'; Manufacturer = 'Contoso'; Model = 'TestBook 1'
            ProcessorName = 'Contoso CPU 1.0'; ProcessorCount = 1
            OsCaption = 'Windows 11 Enterprise'; ProductName = 'Windows 11 Enterprise'
            EditionId = 'Enterprise'; BuildNumber = 26100; Ubr = 1
            Is64Bit = $true; PartOfDomain = $false; DomainRole = 1; IsVirtual = $false
        }
        Firmware = [pscustomobject]@{
            Type = 'UEFI'; Mode = 'UEFI'; IsUefiConfirmed = $true; IsLegacyConfirmed = $false
            DetectionSource = 'SelfTest'; SecureBootSupported = $true; SecureBootEnabled = $true
        }
        Tpm = [pscustomobject]@{ Present = $true; Ready = $true; SpecVersion = '2.0'; IsTPM2 = $true }
        Virtualization = [pscustomobject]@{ HypervisorPresent = $true; FirmwareEnabled = $true; FirmwareRaw = $true; Slat = $true }
        HypervisorLaunch = [pscustomobject]@{ LaunchType = 'NotSet'; Source = 'SelfTest'; BlocksVbs = $false; Error = $null }
        Dep = [pscustomobject]@{ SupportPolicy = 3; Available = $true; Text = 'On for all programs'; Enabled = $true }
        VirtualMachine = [pscustomobject]@{ IsVirtual = $false; Platform = $null; Notes = @() }
        DeviceGuard = [pscustomobject]@{
            Available = $true; Configured = @(); Running = @()
            AvailableProperties = @(1, 2, 3); RequiredProperties = @()
            VbsStatusCode = 0; VbsStatusText = 'Not enabled'; CodeIntegrityPolicyEnforcement = 0
            HasHypervisorSupport = $true; HasSecureBootProperty = $true; HasDmaProtection = $true
            HasSmmMitigations = $false; HasMbec = $true
        }
        Policy = [pscustomobject]@{ Path = $script:RegPolicyDG; Values = @{}; AnyConfigured = $false }
        Restart = [pscustomobject]@{ Pending = $false; Reasons = @(); ComponentBasedServicing = $false; WindowsUpdate = $false; QueuedFileRenameCount = 0 }
    }

    if ($Override) { foreach ($k in $Override.Keys) { $state.$k = $Override[$k] } }
    return $state
}

function Invoke-SelfTest {
    # Scoped event provider: self-tests never query the real host's compatibility log.
    $ciEvidence = [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null }
    function Get-CodeIntegrityEvents { param($EventIds, $LookbackDays) return $ciEvidence }
    $pass = 0; $fail = 0
    function Assert-That {
        param([string]$Name, [bool]$Condition, [string]$Detail = '')
        if ($Condition) { $script:stPass++; Write-Line ('{0}{1}' -f $Name, $(if ($Detail) { " - $Detail" } else { '' })) 'Good' }
        else { $script:stFail++; Write-Line ('{0}{1}' -f $Name, $(if ($Detail) { " - $Detail" } else { '' })) 'Bad' }
    }
    $script:stPass = 0; $script:stFail = 0

    # The self-test is unattended by definition: it must never block on a prompt.
    $selfTestPriorUnattended = $script:Unattended
    $script:Unattended = $true

    Write-Section ('{0} {1} self-test' -f $script:ToolName, $script:ToolVersion)

    # --- catalog integrity ---
    $ids = Get-ControlIds
    Assert-That 'Catalog ids are unique' ((@($ids | Select-Object -Unique)).Count -eq @($ids).Count) ('count={0}' -f @($ids).Count)

    $dangling = @()
    foreach ($c in $script:ControlCatalog) {
        foreach ($d in (ConvertTo-Array $c.Requires)) { if ($ids -notcontains $d) { $dangling += "$($c.Id)->$d" } }
    }
    Assert-That 'All declared dependencies exist' ($dangling.Count -eq 0) ($dangling -join ', ')
    Assert-That 'Every control has a documentation link' (@($script:ControlCatalog | Where-Object { $_.DocUrl -notmatch '^https://' }).Count -eq 0)
    Assert-That 'Every control has a plain-language name and summary' (@($script:ControlCatalog | Where-Object { -not $_.PlainName -or -not $_.Summary }).Count -eq 0)
    Assert-That 'Safe set contains only known controls' (@($script:SafeControlSet | Where-Object { $ids -notcontains $_ }).Count -eq 0)

    $order = @(Resolve-ControlOrder -Id 'hvci' | Select-Object -ExpandProperty Id)
    Assert-That 'Dependencies resolve before dependants' (($order[-1] -eq 'hvci') -and ($order -contains 'vbs')) ($order -join ' -> ')

    # --- evaluation on a clean machine ---
    Set-RegistryProvider (New-InMemoryRegistryProvider)
    $clean = New-SyntheticState
    $statuses = Get-AllControlStatus -State $clean
    Assert-That 'All controls evaluate on a clean machine' (@($statuses).Count -eq @($ids).Count) ('count={0}' -f @($statuses).Count)
    # Detection-only controls reflect what Windows already does, so DEP is legitimately
    # running on a machine where WinDSH has configured nothing.
    $configurable = @($statuses | Where-Object { -not (Get-PropertySafe (Get-Control -Id $_.Id) 'DetectionOnly' $false) })
    Assert-That 'No configurable control reports running on a clean machine' (@($configurable | Where-Object { $_.State -eq 'Running' }).Count -eq 0)

    $score = Get-SecurityScore -Statuses $statuses
    Assert-That 'Clean machine scores zero' ($score.Score -eq 0) ('score={0}' -f $score.Score)
    Assert-That 'Clean machine grade is Unprotected' ($score.Grade -eq 'Unprotected') $score.Grade

    # --- hardware limits are excluded from the score, not counted as failures ---
    $homeState = New-SyntheticState
    $homeState.Computer.EditionId = 'Core'
    $homeStatuses = Get-AllControlStatus -State $homeState
    $cgHome = @($homeStatuses | Where-Object { $_.Id -eq 'credential-guard' })[0]
    Assert-That 'Credential Guard is unsupported on Home' ($cgHome.State -eq 'NotSupported') $cgHome.SupportReason
    $homeScore = Get-SecurityScore -Statuses $homeStatuses
    Assert-That 'Unsupported controls are excluded from scoring' ($homeScore.ExcludedCount -ge 1) ('excluded={0}' -f $homeScore.ExcludedCount)

    # --- hypervisor off blocks everything VBS-based ---
    $offState = New-SyntheticState
    $offState.HypervisorLaunch = [pscustomobject]@{ LaunchType = 'Off'; Source = 'SelfTest'; BlocksVbs = $true; Error = $null }
    $offStatuses = Get-AllControlStatus -State $offState
    $vbsOff = @($offStatuses | Where-Object { $_.Id -eq 'vbs' })[0]
    Assert-That 'hypervisorlaunchtype=Off makes VBS unsupported' ($vbsOff.State -eq 'NotSupported') $vbsOff.SupportReason
    $blOff = @($offStatuses | Where-Object { $_.Id -eq 'driver-blocklist' })[0]
    Assert-That 'Driver blocklist is unaffected by the hypervisor' ($blOff.State -ne 'NotSupported') $blOff.State
    $expOff = Get-ControlExplanation -Id 'vbs' -State $offState
    Assert-That 'Explainer gives the bcdedit fix for a disabled hypervisor' ($expOff.Action -match 'hypervisorlaunchtype Auto') $expOff.Verdict

    # --- legacy BIOS must not be read as UEFI ---
    $legacy = New-SyntheticState
    $legacy.Firmware = [pscustomobject]@{
        Type = 'Legacy BIOS or unsupported UEFI'; Mode = 'Unknown'; IsUefiConfirmed = $false
        IsLegacyConfirmed = $false; DetectionSource = 'SelfTest'; SecureBootSupported = $false; SecureBootEnabled = $false
    }
    $legacyStatus = Get-ControlStatus -Id 'secure-launch' -State $legacy
    Assert-That 'Ambiguous firmware text is not treated as confirmed UEFI' ($legacyStatus.State -eq 'NotSupported') $legacyStatus.SupportReason

    # --- plan and apply ---
    Set-RegistryProvider (New-InMemoryRegistryProvider)
    $plan = @(Get-ChangePlan -Ids @('hvci') -State $clean)
    Assert-That 'Plan covers HVCI and its dependencies' (@($plan | Select-Object -ExpandProperty ControlId -Unique).Count -eq 3) (@($plan | Select-Object -ExpandProperty ControlId -Unique) -join ',')
    Assert-That 'Every value needs changing on a clean machine' (@($plan | Where-Object { -not $_.NeedsChange }).Count -eq 0)

    $journal = Join-Path ([IO.Path]::GetTempPath()) ('windsh-selftest-{0}.jsonl' -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $script:TestJournalPath = $journal
    try {
        $applied = Invoke-ControlApply -Ids @('hvci') -State $clean
        Assert-That 'Apply writes the planned values' ($applied.ChangeCount -eq @($plan).Count) ('changes={0}' -f $applied.ChangeCount)
        Assert-That 'VBS is on after apply' ((Get-RegValue -Path $script:RegDeviceGuard -Name 'EnableVirtualizationBasedSecurity') -eq 1)
        Assert-That 'HVCI is on after apply' ((Get-RegValue -Path $script:RegHvci -Name 'Enabled') -eq 1)
        Assert-That 'Locked stays 0 so changes can be undone' ((Get-RegValue -Path $script:RegHvci -Name 'Locked') -eq 0)

        $second = Invoke-ControlApply -Ids @('hvci') -State $clean
        Assert-That 'Applying twice is idempotent' ($second.ChangeCount -eq 0) ('changes={0}' -f $second.ChangeCount)

        $revert = Invoke-ControlRevert -RunId $applied.RunId
        Assert-That 'Revert restores every journalled value' ($revert.ChangeCount -eq $applied.ChangeCount) ('reverted={0}' -f $revert.ChangeCount)
        Assert-That 'Values that never existed are removed, not zeroed' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))

        $closedRejected = $false
        try { [void](Invoke-ControlRevert -RunId $applied.RunId) } catch { $closedRejected = $true }
        Assert-That 'A completed run cannot be reverted twice' $closedRejected
        Assert-That 'Completed runs are excluded from default rollback selection' (@(Get-JournalRuns).Count -eq 0)

        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegCiConfig + '|VulnerableDriverBlocklistEnable') = 0 })
        $conflictApply = Invoke-ControlApply -Ids @('driver-blocklist') -State $clean
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 2
        $conflictRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'Rollback preserves later administrator changes' ((Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 2 -and $conflictRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'String' '1'
        $typeRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'Rollback detects a registry type conflict' ($typeRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        $retryRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'A conflicted entry can be retried when expected state is restored' ($retryRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 0)

        # An intent without a completion marker is ambiguous, even when the live
        # value happens to equal AfterValue. It must never erase a later change.
        $pendingId = 'selftest-pending'
        $pending = [pscustomobject]@{ RecordType = 'Change'; ChangeId = 'pending-write'; RunId = $pendingId; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $pending
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 2
        $pendingRevert = Invoke-ControlRevert -RunId $pendingId
        Assert-That 'Journal-before-write cannot overwrite an unrelated later value' ($pendingRevert.ChangeCount -eq 0 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 2)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        $ambiguousRevert = Invoke-ControlRevert -RunId $pendingId
        Assert-That 'Unconfirmed writes require manual review even if the value matches' ($ambiguousRevert.ChangeCount -eq 0 -and $ambiguousRevert.Conflicts.Count -eq 1)

        # Legacy v2 journals stay usable, but are subject to conflict and catalog checks.
        $legacyEntry = [pscustomobject]@{ RunId = 'selftest-legacy'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $legacyEntry
        $legacyRevert = Invoke-ControlRevert -RunId $legacyEntry.RunId
        Assert-That 'Legacy journal entries can be safely reverted' ($legacyRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 0)

        # Partial revert recovery never repeats already-restored registry writes.
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $partialApply = Invoke-ControlApply -Ids @('vbs') -State $clean
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 2
        $partialRevert = Invoke-ControlRevert -RunId $partialApply.RunId
        Assert-That 'Partial rollback restores matching entries and reports conflicts' ($partialRevert.ChangeCount -eq 1 -and $partialRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegDeviceGuard 'EnableVirtualizationBasedSecurity' 'DWord' 2
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 0
        $finishRevert = Invoke-ControlRevert -RunId $partialApply.RunId
        Assert-That 'Retrying a partial revert never repeats completed entries' ($finishRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegDeviceGuard 'EnableVirtualizationBasedSecurity') -eq 2)

        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $crashApply = Invoke-ControlApply -Ids @('driver-blocklist') -State $clean
        $crashChange = @(Get-JournalChanges -Records @(Get-Journal -RunId $crashApply.RunId))[0]
        Write-JournalMarker -RunId $crashApply.RunId -RecordType 'RevertStarted' -ChangeId $crashChange.Id
        & $script:Registry.RemoveValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable'
        $crashRevert = Invoke-ControlRevert -RunId $crashApply.RunId
        Assert-That 'An interrupted revert is finalized without rewriting registry state' ($crashRevert.ChangeCount -eq 0 -and $crashRevert.RecoveredCount -eq 1)

        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegCiConfig + '|VulnerableDriverBlocklistEnable') = 2 })
        foreach ($pair in @(@(0, 1), @(1, 2))) {
            Write-JournalEntry ([pscustomobject]@{ RunId = 'selftest-repeated-value'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = $pair[0]; AfterValue = $pair[1] })
        }
        # Catalog validation rejects arbitrary AfterValue, even for a known path.
        $badAfterRejected = $false
        try { [void](Invoke-ControlRevert -RunId 'selftest-repeated-value') } catch { $badAfterRejected = $true }
        Assert-That 'Rollback validates recorded target values against the catalog' $badAfterRejected

        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $baseSet = $script:Registry.SetValue
        $failureCounter = @{ Count = 0 }
        $script:Registry.SetValue = {
            param($Path, $Name, $Type, $Value)
            $failureCounter.Count++
            if ($failureCounter.Count -eq 2) { throw 'Synthetic write failure' }
            & $baseSet $Path $Name $Type $Value
        }.GetNewClosure()
        $partialRejected = $false
        try { [void](Invoke-ControlApply -Ids @('vbs') -State $clean -RunId 'selftest-partial-apply') } catch { $partialRejected = $true }
        $script:Registry.SetValue = $baseSet
        $partialWriteRevert = Invoke-ControlRevert -RunId 'selftest-partial-apply'
        Assert-That 'Partial apply records completed writes and leaves pending writes untouched' ($partialRejected -and $partialWriteRevert.ChangeCount -eq 1 -and $partialWriteRevert.Conflicts.Count -eq 1)

        # A process holding the lock excludes other apply/revert operations.
        $heldLock = Enter-JournalLock
        $lockedOut = $false
        try { [void](Invoke-ControlApply -Ids @('vbs') -State $clean) } catch { $lockedOut = $true }
        finally { $heldLock.Dispose() }
        Assert-That 'Concurrent change operations are rejected before writing' $lockedOut

        $validJournal = [IO.File]::ReadAllText($journal)
        try {
            [IO.File]::AppendAllText($journal, '{broken' + "`n")
            $corruptRejected = $false
            try { [void](Invoke-ControlRevert -RunId $pendingId) } catch { $corruptRejected = $true }
            Assert-That 'Malformed terminated journal records block rollback' $corruptRejected
            [IO.File]::WriteAllText($journal, $validJournal + '{torn')
            $repairLock = Enter-JournalLock
            $repairLock.Dispose()
            Assert-That 'A torn journal tail is repaired before subsequent appends' ([IO.File]::ReadAllText($journal) -eq $validJournal)
        }
        finally { [IO.File]::WriteAllText($journal, $validJournal) }
        $malicious = [pscustomobject]@{ RunId = 'selftest-invalid'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegPolicyDG; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $malicious
        $invalidRejected = $false
        try { [void](Invoke-ControlRevert -RunId $malicious.RunId) } catch { $invalidRejected = $true }
        Assert-That 'Journal content cannot authorize writes outside the catalog' $invalidRejected

        $priorOverride = $env:WINDSH_JOURNAL_PATH
        try {
            $env:WINDSH_JOURNAL_PATH = 'untrusted-environment-path'
            Assert-That 'Inherited journal environment overrides are ignored' ((Get-JournalPath) -eq $journal)
        }
        finally { $env:WINDSH_JOURNAL_PATH = $priorOverride }

        # A stronger platform security level must survive.
        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegDeviceGuard + '|RequirePlatformSecurityFeatures') = 3 })
        $planStrong = @(Get-ChangePlan -Ids @('platform-security') -State $clean | Where-Object { $_.Name -eq 'RequirePlatformSecurityFeatures' -and $_.NeedsChange })
        Assert-That 'An existing stronger Secure Boot + DMA setting is preserved' (@($planStrong).Count -eq 0) 'value 3 must not be downgraded to 1'

        # Group policy is never overwritten.
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $policyState = New-SyntheticState
        $policyState.Policy = [pscustomobject]@{ Path = $script:RegPolicyDG; Values = @{ 'HypervisorEnforcedCodeIntegrity' = 0 }; AnyConfigured = $true }
        $applyPolicy = Invoke-ControlApply -Ids @('hvci') -State $policyState
        Assert-That 'Apply skips a policy-managed control' (@($applyPolicy.Skipped | Where-Object { $_.ControlId -eq 'hvci' }).Count -eq 1)
        Assert-That 'No HVCI value is written under policy' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        Assert-That 'The unmanaged dependency still applies' ((Get-RegValue -Path $script:RegDeviceGuard -Name 'EnableVirtualizationBasedSecurity') -eq 1)
    }
    finally {
        Remove-Item -LiteralPath $journal, ($journal + '.lock') -Force -ErrorAction SilentlyContinue
        $script:TestJournalPath = $null
        Set-RegistryProvider (New-InMemoryRegistryProvider)
    }

    # --- detection-only controls (restored from v1.6.0) ---
    $detOnly = @($script:ControlCatalog | Where-Object { Get-PropertySafe $_ 'DetectionOnly' $false })
    Assert-That 'Detection-only controls are present' (@($detOnly).Count -eq 3) (@($detOnly | Select-Object -ExpandProperty Id) -join ', ')
    Assert-That 'Detection-only controls are never remediable' (@($detOnly | Where-Object { $_.Remediable }).Count -eq 0)
    Assert-That 'Detection-only controls carry no scoring weight' (@($detOnly | Where-Object { $_.Weight -ne 0 }).Count -eq 0)

    $depState = New-SyntheticState
    $depStatus = Get-ControlStatus -Id 'dep' -State $depState
    Assert-That 'DEP is reported running when the policy is on' ($depStatus.State -eq 'Running') $depStatus.State
    $depOff = New-SyntheticState
    $depOff.Dep = [pscustomobject]@{ SupportPolicy = 0; Available = $true; Text = 'Always off'; Enabled = $false }
    Assert-That 'DEP off is not reported as configured' ((Get-ControlStatus -Id 'dep' -State $depOff).State -ne 'Running')
    $depLegacy = New-SyntheticState
    $depLegacy.Firmware.IsUefiConfirmed = $false
    $depLegacy.Virtualization.FirmwareEnabled = $false
    $depLegacy.HypervisorLaunch.BlocksVbs = $true
    $depLegacy.Computer.Is64Bit = $false
    Assert-That 'DEP does not inherit VBS platform prerequisites' ((Get-ControlStatus -Id 'dep' -State $depLegacy).State -eq 'Running')

    Set-RegistryProvider (New-InMemoryRegistryProvider)
    $assessmentBefore = Get-Assessment -State $clean
    & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
    $assessmentAfter = Get-Assessment -State $clean
    Assert-That 'Assessment refresh recalculates statuses and score together' ($assessmentAfter.Score.Score -gt $assessmentBefore.Score.Score -and @($assessmentAfter.Statuses | Where-Object { $_.Id -eq 'driver-blocklist' -and $_.Running }).Count -eq 1)
    $freshExplain = @($assessmentAfter.Explanations | Where-Object { $_.Id -eq 'driver-blocklist' })[0]
    Assert-That 'Assessment explanations use the same refreshed status snapshot' ($freshExplain.Status -eq @($assessmentAfter.Statuses | Where-Object { $_.Id -eq 'driver-blocklist' })[0])
    $clean.DeviceGuard.Running = @(2, 3)
    $clean.DeviceGuard.VbsStatusCode = 2
    $clean.DeviceGuard.HasSmmMitigations = $true
    $coreAssessment = Get-Assessment -State $clean
    Assert-That 'Assessment refresh updates Secured-core and CIS derived state' ($coreAssessment.SecuredCore.Qualifies -and @($coreAssessment.Cis.Rows | Where-Object { $_.ControlId -eq 'hvci' -and $_.FeatureRunning }).Count -eq 1)
    $clean.DeviceGuard.Running = @()
    $clean.DeviceGuard.VbsStatusCode = 0
    $clean.DeviceGuard.HasSmmMitigations = $false
    & $script:Registry.RemoveValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable'

    $hvptState = New-SyntheticState
    $hvptState.DeviceGuard.Running = @(7)
    Assert-That 'HVPT is detected from security service 7' ((Get-ControlStatus -Id 'hvpt' -State $hvptState).State -eq 'Running')
    $smmState = New-SyntheticState
    $smmState.DeviceGuard.Running = @(4)
    Assert-That 'SMM firmware measurement is detected from service 4' ((Get-ControlStatus -Id 'smm-firmware-measurement' -State $smmState).State -eq 'Running')

    $detExplain = Get-ControlExplanation -Id 'hvpt' -State $depOff
    Assert-That 'Detection-only explainer does not offer to configure it' ($detExplain.Action -match 'does not configure') $detExplain.Action

    # --- pre-flight safety check declaration (restored from v1.6.0) ---
    $hvciControl = Get-Control -Id 'hvci'
    Assert-That 'Memory Integrity declares a driver pre-flight check' ($null -ne $hvciControl.Preflight)
    Assert-That 'Pre-flight watches Event ID 3087' (@($hvciControl.Preflight.EventIds) -contains 3087)
    Assert-That 'Pre-flight blocks the safe set when tripped' ([bool]$hvciControl.Preflight.BlocksSafeSet)

    $ciEvidence.EventCount = 1
    $riskPlan = @(Get-ChangePlan -Ids $script:SafeControlSet -State $clean)
    Assert-That 'Safe-set preview includes HVCI preflight blockers' (@($riskPlan | Where-Object { $_.ControlId -eq 'hvci' -and $_.SkipReason }).Count -eq 2)
    $riskJournal = Join-Path ([IO.Path]::GetTempPath()) ('windsh-preflight-{0}.jsonl' -f [Guid]::NewGuid())
    $script:TestJournalPath = $riskJournal
    try {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $safeRisk = Invoke-ControlApply -Ids $script:SafeControlSet -State $clean
        Assert-That 'EnableAllSafe skips HVCI when 3087 evidence is present' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        Assert-That 'Safe-set apply reports the same preflight blocker as preview' (@($safeRisk.Skipped | Where-Object { $_.ControlId -eq 'hvci' }).Count -eq 1)
        $explicitRisk = Invoke-ControlApply -Ids @('hvci') -State $clean -ExplicitIds @('hvci')
        Assert-That 'Explicit unattended HVCI cannot bypass a typed override' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        $ciEvidence.EventCount = 0
        $ciEvidence.Queried = $false
        $unknownRisk = Invoke-ControlApply -Ids $script:SafeControlSet -State $clean
        Assert-That 'Unknown compatibility fails closed for the safe set' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        $depRisk = @(Get-ChangePlan -Ids @('kernel-shadow-stacks') -State $clean)
        Assert-That 'A preflight-blocked dependency also blocks shadow stacks' (@($depRisk | Where-Object { $_.ControlId -eq 'kernel-shadow-stacks' -and $_.SkipReason }).Count -eq 1)
    }
    finally {
        $ciEvidence.Queried = $true
        $ciEvidence.EventCount = 0
        Remove-Item -LiteralPath $riskJournal, ($riskJournal + '.lock') -Force -ErrorAction SilentlyContinue
        $script:TestJournalPath = $null
        Set-RegistryProvider (New-InMemoryRegistryProvider)
    }

    # --- firmware guidance (restored from v1.6.0) ---
    $hintDell = Get-FirmwareVendorHints -Manufacturer 'Dell Inc.' -Model 'Latitude 7440'
    Assert-That 'Dell firmware hints are matched' (($hintDell.Vendor -eq 'Dell') -and ($hintDell.EnterKey -match 'F2')) $hintDell.Vendor
    $hintAcer = Get-FirmwareVendorHints -Manufacturer 'Acer' -Model 'Aspire A515'
    Assert-That 'Acer hint warns about the Supervisor Password' ($hintAcer.SecureBoot -match 'Supervisor Password')
    $hintSurface = Get-FirmwareVendorHints -Manufacturer 'Microsoft Corporation' -Model 'Surface Laptop 5'
    Assert-That 'Surface uses the volume-button entry method' ($hintSurface.EnterKey -match 'Volume Up')
    $hintUnknown = Get-FirmwareVendorHints -Manufacturer 'Acme Computers' -Model 'X1'
    Assert-That 'Unknown manufacturer gets no invented menu path' (($null -eq $hintUnknown.TPM) -and ($null -eq $hintUnknown.EnterKey))

    $fwState = New-SyntheticState
    $fwState.Tpm = [pscustomobject]@{ Present = $false; Ready = $false; SpecVersion = ''; IsTPM2 = $false }
    $fwState.Firmware.SecureBootEnabled = $false
    $guidance = Get-FirmwareGuidance -State $fwState
    Assert-That 'Firmware guidance lists only what is actually wrong' (@($guidance.Needed).Count -eq 2) (@($guidance.Needed | Select-Object -ExpandProperty What) -join '; ')
    Assert-That 'Firmware guidance is pure data, with no restart inside it' ($guidance.PSObject.Properties['CanOfferReboot'] -ne $null)

    $okState = New-SyntheticState
    Assert-That 'A correct machine needs no firmware changes' (@((Get-FirmwareGuidance -State $okState).Needed).Count -eq 0)

    # --- exit code meanings (restored from v1.6.0) ---
    Assert-That 'Exit code 3010 explains the restart' ((Get-ExitCodeMeaning -Code 3010) -match 'restart')
    Assert-That 'Exit code 4 explains the elevation failure' ((Get-ExitCodeMeaning -Code 4) -match 'Administrator')
    Assert-That 'Unknown exit codes do not throw' ((Get-ExitCodeMeaning -Code 99) -match 'Unrecognised')

    # --- confirmation must never prompt on an unattended run ---
    $previousUnattended = $script:Unattended
    $script:Unattended = $true
    Assert-That 'Unattended runs never block on a confirmation prompt' (Confirm-Action 'This must not prompt')
    Assert-That 'Unattended consent does not satisfy typed safety confirmation' (-not (Confirm-Action 'Risky' -RequireTyped 'hvci'))
    $script:Unattended = $previousUnattended

    # --- virtual machine assessment (restored from v1.6.0) ---
    $vm = Get-VirtualMachineAssessment -Computer ([pscustomobject]@{ IsVirtual = $true; Manufacturer = 'VMware, Inc.'; Model = 'VMware Virtual Platform' }) `
                                       -Virtualization ([pscustomobject]@{ FirmwareEnabled = $false })
    Assert-That 'VMware is identified' ($vm.Platform -eq 'VMware') $vm.Platform
    Assert-That 'VM guidance mentions nested virtualization' ((@($vm.Notes) -join ' ') -match 'Nested virtualization')
    $physical = Get-VirtualMachineAssessment -Computer ([pscustomobject]@{ IsVirtual = $false; Manufacturer = 'Dell Inc.'; Model = 'Latitude' }) `
                                             -Virtualization ([pscustomobject]@{ FirmwareEnabled = $true })
    Assert-That 'A physical machine gets no VM notes' (@($physical.Notes).Count -eq 0)

    # --- relaunch argument construction (privilege boundary) ---
    $quoted = Get-RelaunchArgumentList -Bound @{ ReportDirectory = 'C:\Temp\My Reports'; AuditOnly = [switch]$true }
    Assert-That 'Switch parameters relaunch without a value' (($quoted -contains '-AuditOnly') -and -not ($quoted -contains '"True"')) ($quoted -join ' ')
    Assert-That 'Paths with spaces are quoted as one argument' ($quoted -contains '"C:\Temp\My Reports"') ($quoted -join ' ')

    $hostile = Get-RelaunchArgumentList -Bound @{ ReportDirectory = 'C:\x" -Enable credential-guard "' }
    Assert-That 'Embedded quotes cannot inject a new argument' (-not ($hostile -contains '-Enable')) ($hostile -join ' ')
    Assert-That 'Embedded quotes use native argument escaping' (@($hostile | Where-Object { $_.Contains('\"') }).Count -eq 1) ($hostile -join ' ')

    $empty = Get-RelaunchArgumentList -Bound @{ AutoReboot = [switch]$false }
    Assert-That 'An unset switch is not relaunched' (@($empty).Count -eq 0) ('count={0}' -f @($empty).Count)
    $trailing = ConvertTo-NativeArgument 'C:\Reports\'
    Assert-That 'Trailing path backslashes cannot consume the closing argument quote' ($trailing -eq '"C:\Reports\\"')
    $arrayRelaunch = Get-RelaunchArgumentList -Bound @{ Enable = @('hvci', 'driver-blocklist') }
    Assert-That 'Multiple Enable controls survive native File argument binding' ($arrayRelaunch -contains '"hvci,driver-blocklist"')

    # --- CIS comparison ---
    $cisState = New-SyntheticState
    $cisStatuses = Get-AllControlStatus -State $cisState
    $cis = Get-CisComplianceReport -State $cisState -Statuses $cisStatuses
    Assert-That 'CIS report covers all seven 18.9.5 controls' ($cis.TotalCount -eq 7) ('count={0}' -f $cis.TotalCount)
    Assert-That 'Nothing is CIS compliant with an empty policy hive' ($cis.CompliantCount -eq 0) ('compliant={0}' -f $cis.CompliantCount)

    $cisState.Policy = [pscustomobject]@{
        Path = $script:RegPolicyDG
        Values = @{ 'EnableVirtualizationBasedSecurity' = 1; 'RequirePlatformSecurityFeatures' = 3 }
        AnyConfigured = $true
    }
    $cis2 = Get-CisComplianceReport -State $cisState -Statuses $cisStatuses
    Assert-That 'A configured policy value is reported compliant' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.1' -and $_.Compliant }).Count -eq 1)
    Assert-That 'Platform security level 3 also passes CIS' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.2' -and $_.Compliant }).Count -eq 1)
    Assert-That 'HVCI divergence from CIS is documented' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.3' -and $_.Divergence }).Count -eq 1)

    # --- HTML report ---
    $score2 = Get-SecurityScore -Statuses $cisStatuses
    $sc = Get-SecuredCoreVerdict -State $cisState -Statuses $cisStatuses
    $explanations = @(Get-ControlIds | ForEach-Object { Get-ControlExplanation -Id $_ -State $cisState })
    $html = New-HtmlReport -State $cisState -Statuses $cisStatuses -Score $score2 -SecuredCore $sc -Cis $cis2 -Explanations $explanations
    Assert-That 'HTML report is produced' ($html.Length -gt 3000) ('{0} bytes' -f $html.Length)
    Assert-That 'HTML report is self-contained' (($html -notmatch '<script') -and ($html -notmatch 'https?://[^"]*\.(css|js)')) 'no external css/js'
    Assert-That 'HTML report escapes markup in values' (-not ($html -match '<script>alert'))
    Assert-That 'HTML report states the CIS hive caveat' ($html -match 'Group Policy hive')

    $injected = New-SyntheticState
    $injected.Computer.Model = '<script>alert(1)</script>'
    $injStatuses = Get-AllControlStatus -State $injected
    $injHtml = New-HtmlReport -State $injected -Statuses $injStatuses -Score (Get-SecurityScore -Statuses $injStatuses) `
        -SecuredCore (Get-SecuredCoreVerdict -State $injected -Statuses $injStatuses) `
        -Cis (Get-CisComplianceReport -State $injected -Statuses $injStatuses) `
        -Explanations @(Get-ControlIds | ForEach-Object { Get-ControlExplanation -Id $_ -State $injected })
    Assert-That 'Hostile field content cannot inject markup' (-not ($injHtml -match '<script>alert\(1\)</script>')) 'model string is escaped'

    $textReport = New-TextReport -State $cisState -Statuses $cisStatuses -Score $score2 -SecuredCore $sc -Cis $cis2 -Explanations $explanations
    Assert-That 'Plain-text report is produced' ($textReport.Length -gt 1500) ('{0} bytes' -f $textReport.Length)
    Assert-That 'Text report states the CIS hive caveat' ($textReport -match 'Group Policy hive')
    Assert-That 'Text report includes the score' ($textReport -match 'APPLICABLE PROTECTION SCORE')
    Assert-That 'Text report includes DEP' ($textReport -match 'DEP')

    Set-RegistryProvider (New-RegistryProvider)
    $script:Unattended = $selfTestPriorUnattended

    Write-Line ''
    if ($script:stFail -eq 0) { Write-Line ('Self-test: {0} passed, 0 failed.' -f $script:stPass) 'Good'; return 0 }
    Write-Line ('Self-test: {0} passed, {1} FAILED.' -f $script:stPass, $script:stFail) 'Bad'
    return 1
}

# ===== 70-main.ps1 =====
# ---------------------------------------------------------------------------
# Console rendering. Two tiers: a plain-language summary by default, full technical
# detail behind -Advanced. v1 showed one uniform level of detail to everyone.
# ---------------------------------------------------------------------------

function Show-Summary {
    param($State, $Statuses, $Score, $SecuredCore)

    Write-Section 'Applicable protection score'
    $kind = if ($Score.UnknownCount -gt 0) { 'Warn' } elseif ($Score.Score -ge 75) { 'Good' } elseif ($Score.Score -ge 50) { 'Warn' } else { 'Bad' }
    Write-Line ('{0} / 100  ({1})' -f $Score.Score, $Score.Grade) $kind
    Write-Line ('{0} of {1} scored controls are applicable; unsupported controls are excluded.' -f $Score.ApplicableCount, $Score.TotalCount) 'Dim'
    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count
    Write-Line ('{0} of {1} applicable protections are active.' -f $running, $countable) 'Plain'
    if ($Score.UnknownCount -gt 0) { Write-Line ('{0} scored protection(s) could not be verified; they earn no points and remain in the total.' -f $Score.UnknownCount) 'Warn' }
    if ($Score.ExcludedCount -gt 0) {
        Write-Line ('{0} excluded: current platform requirements are not met, so they are not counted against you.' -f $Score.ExcludedCount) 'Dim'
    }

    if ($State.HypervisorLaunch.BlocksVbs) {
        Write-Line ''
        Write-Line 'The Windows hypervisor is switched off in the boot configuration.' 'Bad'
        Write-Line 'No virtualization-based protection can start until that is changed.' 'Bad' 2
    }

    Write-Section 'Protections'
    foreach ($s in $Statuses) {
        $kind = switch ($s.State) {
            'Running' { 'Good' }
            'ConfiguredNotRunning' { 'Warn' }
            'NotConfigured' { 'Bad' }
            default { 'Info' }
        }
        $label = (Get-StateLabel $s.State).Text
        $policy = if ($s.ManagedByPolicy) { ' (Group Policy)' } else { '' }
        Write-Line ('{0,-34} {1}{2}' -f $s.PlainName, $label, $policy) $kind
        if ($Advanced) {
            Write-Line ('{0}  [{1}]' -f $s.Name, $s.Id) 'Dim' 9
            if ($s.SupportReason) { Write-Line $s.SupportReason 'Dim' 9 }
        }
    }

    if ($Advanced) {
        Write-Section 'System'
        Write-Line ('Machine     : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) 'Dim'
        Write-Line ('Processor   : {0}' -f $State.Computer.ProcessorName) 'Dim'
        Write-Line ('Windows     : {0} build {1} ({2})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber, $State.Computer.EditionId) 'Dim'
        Write-Line ('Firmware    : {0} (mode {1}, via {2})' -f $State.Firmware.Type, $State.Firmware.Mode, $State.Firmware.DetectionSource) 'Dim'
        Write-Line ('Secure Boot : {0}' -f (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable')) 'Dim'
        Write-Line ('TPM         : {0} (spec {1})' -f (Format-Bool $State.Tpm.IsTPM2 'TPM 2.0' 'not confirmed'), $State.Tpm.SpecVersion) 'Dim'
        Write-Line ('Hypervisor  : launch type {0} via {1}' -f $State.HypervisorLaunch.LaunchType, $State.HypervisorLaunch.Source) 'Dim'
        Write-Line ('Secured-core: {0}' -f (Format-Bool $SecuredCore.Qualifies 'qualifies' ('does not qualify ({0} unmet)' -f $SecuredCore.UnmetCount))) 'Dim'
    }
}

function Show-NextSteps {
    param($Explanations)
    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    Write-Section 'What to do next'
    if (@($todo).Count -eq 0) { Write-Line 'Nothing. Every protection this computer supports is active.' 'Good'; return }

    $n = 0
    foreach ($e in $todo) {
        $n++
        Write-Line ''
        Write-Line ('{0}. {1}' -f $n, $e.PlainName) 'Head'
        Write-Line $e.Verdict $(if ($e.Severity -eq 'Warn') { 'Warn' } else { 'Info' }) 3
        if ($e.Action) {
            foreach ($line in ($e.Action -split "`n")) { Write-Line $line 'Plain' 6 }
        }
    }
}

function Show-CisSummary {
    param($Cis)
    Write-Section 'CIS Benchmark comparison'
    Write-Line ('{0}, section {1}' -f $Cis.Benchmark, $Cis.Section) 'Dim'
    Write-Line ('{0} of {1} checks pass.' -f $Cis.CompliantCount, $Cis.TotalCount) $(if ($Cis.CompliantCount -eq $Cis.TotalCount) { 'Good' } else { 'Warn' })
    if ($Cis.RunningButNotCompliantCount -gt 0) {
        Write-Line ('{0} protection(s) are running but still fail their CIS check.' -f $Cis.RunningButNotCompliantCount) 'Info'
    }
    Write-Line $Cis.Note 'Dim'
    foreach ($r in $Cis.Rows) {
        $kind = if (-not $r.PolicyKnown) { 'Warn' } elseif ($r.Compliant) { 'Good' } else { 'Bad' }
        $actual = if (-not $r.PolicyKnown) { 'unavailable' } elseif ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        Write-Line ('{0,-9} {1,-38} policy value = {2}' -f $r.CisId, $r.PolicyValueName, $actual) $kind 2
    }
}

function Show-Plan {
    param($Plan)
    Write-Section 'Planned changes'
    $changes = @($Plan | Where-Object { $_.NeedsChange -and -not $_.SkipReason })
    $skips = @($Plan | Where-Object { $_.SkipReason } | Group-Object ControlId)

    if (@($changes).Count -eq 0) { Write-Line 'No changes are needed.' 'Good' }
    foreach ($c in $changes) {
        $before = if ($c.CurrentExists) { [string]$c.CurrentValue } else { '(not set)' }
        Write-Line ('{0}\{1}: {2} -> {3}' -f $c.Path, $c.Name, $before, $c.DesiredValue) 'Info' 2
        if ($c.Note) { Write-Line $c.Note 'Dim' 6 }
    }
    foreach ($g in $skips) {
        Write-Line ('Skipping {0}: {1}' -f $g.Name, @($g.Group)[0].SkipReason) 'Warn' 2
    }
}

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

function Get-ReportFolder {
    if (-not [string]::IsNullOrWhiteSpace($ReportDirectory)) { return $ReportDirectory }
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = [IO.Path]::GetTempPath() }
    return (Join-Path $desktop 'WinDSH-Reports')
}

function Save-Reports {
    param($State, $Statuses, $Score, $SecuredCore, $Cis, $Explanations, [hashtable]$Formats)
    if ($NoReport) { return @() }

    # Interactive callers pass an explicit format selection; command-line runs fall back
    # to the switches, defaulting to HTML.
    $wantHtml = if ($Formats) { [bool]$Formats.Html } else { [bool]($HtmlReport -or -not ($JsonReport -or $TextReport)) }
    $wantText = if ($Formats) { [bool]$Formats.Text } else { [bool]$TextReport }
    $wantJson = if ($Formats) { [bool]$Formats.Json } else { [bool]$JsonReport }

    $folder = Get-ReportFolder
    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false | Out-Null
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $folder ('WinDSH-{0}-{1}' -f $State.Computer.Name, $stamp)
    $written = @()
    $encoding = New-Object Text.UTF8Encoding($false)

    if ($wantText) {
        $text = New-TextReport -State $State -Statuses $Statuses -Score $Score -SecuredCore $SecuredCore -Cis $Cis -Explanations $Explanations
        $path = $base + '.txt'
        [IO.File]::WriteAllText($path, $text, $encoding)
        $written += $path
    }
    if ($wantHtml) {
        $html = New-HtmlReport -State $State -Statuses $Statuses -Score $Score -SecuredCore $SecuredCore -Cis $Cis -Explanations $Explanations
        $path = $base + '.html'
        [IO.File]::WriteAllText($path, $html, $encoding)
        $written += $path
    }
    if ($wantJson) {
        $payload = [pscustomobject]@{
            SchemaVersion = $script:SchemaVersion
            Tool = [pscustomobject]@{ Name = $script:ToolName; Version = $script:ToolVersion; Integrity = (Get-SelfIntegrity).Status }
            Generated = $State.Generated
            Computer = $State.Computer
            Firmware = $State.Firmware
            Tpm = $State.Tpm
            HypervisorLaunch = $State.HypervisorLaunch
            Restart = $State.Restart
            Score = $Score
            SecuredCore = $SecuredCore
            Controls = $Statuses
            Cis = $Cis
            AppliedChanges = $script:AppliedChanges
            Warnings = $script:Warnings
        }
        $path = $base + '.json'
        [IO.File]::WriteAllText($path, ($payload | ConvertTo-Json -Depth 12), $encoding)
        $written += $path
    }
    return $written
}

function Write-RmmOutput {
    param($State, $Statuses, $Score, $Cis)
    $payload = [pscustomobject]@{
        schemaVersion = $script:SchemaVersion
        tool = $script:ToolName
        version = $script:ToolVersion
        computer = $State.Computer.Name
        generated = $State.Generated
        score = $Score.Score
        grade = $Score.Grade
        restartRequired = $script:RestartRequired
        hypervisorBlocksVbs = $State.HypervisorLaunch.BlocksVbs
        firmwareMode = $State.Firmware.Mode
        secureBoot = $State.Firmware.SecureBootEnabled
        tpm2 = $State.Tpm.IsTPM2
        cisCompliant = $Cis.CompliantCount
        cisTotal = $Cis.TotalCount
        controls = @($Statuses | ForEach-Object { [pscustomobject]@{ id = $_.Id; state = $_.State; policy = $_.ManagedByPolicy } })
        changes = @($script:AppliedChanges).Count
        warnings = @($script:Warnings).Count
        exitCode = $script:ExitCode
    }
    $script:RmmOutputWritten = $true
    Write-Output ($payload | ConvertTo-Json -Depth 8 -Compress)
}

# ---------------------------------------------------------------------------
# Interactive
# ---------------------------------------------------------------------------

function Wait-ForKey {
    param([string]$Message = 'Press any key to return to the menu...')
    Write-Line ''
    Write-Line $Message 'Info'
    try { [void][Console]::ReadKey($true) }
    catch { [void](Read-Host) }
}

function Show-Menu {
    param($Statuses, $Score)
    Write-Host ''
    Write-Line ('{0} {1}   applicable protection score {2}/100 ({3})' -f $script:ToolName, $script:ToolVersion, $Score.Score, $Score.Grade) 'Head'
    Write-Host ''
    Write-Line '  [1] Re-check this computer' 'Plain'
    Write-Line '  [2] Fix what can be fixed safely' 'Plain'
    Write-Line '  [3] Explain a protection' 'Plain'
    Write-Line '  [4] Save a report' 'Plain'
    Write-Line '  [5] More options' 'Plain'
    Write-Line '  [Q] Quit' 'Plain'
    Write-Host ''
}

function Show-MoreMenu {
    Write-Host ''
    Write-Line 'More options' 'Head'
    Write-Host ''
    Write-Line '  [A] Preview what "fix safely" would change' 'Plain'
    Write-Line '  [B] Turn on a specific protection' 'Plain'
    Write-Line '  [C] Undo a previous change' 'Plain'
    Write-Line '  [D] CIS Benchmark comparison' 'Plain'
    Write-Line '  [E] Open Windows Core isolation settings' 'Plain'
    Write-Line '  [F] How to change BIOS/UEFI settings on this PC' 'Plain'
    Write-Line '  [G] Why is Memory Integrity blocked? (driver diagnostics)' 'Plain'
    Write-Line '  [H] Open the Code Integrity event log' 'Plain'
    Write-Line '  [X] Back' 'Plain'
    Write-Host ''
}

function Read-Choice {
    param([string]$Valid)
    while ($true) {
        $raw = Read-Host 'Select'
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $c = $raw.Trim().ToUpperInvariant()
        if ($c.Length -eq 1 -and $Valid.Contains($c)) { return $c }
        Write-Line 'Not a valid choice.' 'Warn'
    }
}

function Select-ControlInteractive {
    Write-Line ''
    $ids = Get-ControlIds
    $n = 0
    foreach ($id in $ids) { $n++; Write-Line ('  {0}. {1}' -f $n, (Get-Control -Id $id).PlainName) 'Plain' }
    $raw = Read-Host 'Number (blank to cancel)'
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $index = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$index)) { return $null }
    if ($index -lt 1 -or $index -gt @($ids).Count) { return $null }
    return @($ids)[$index - 1]
}

function Show-Explanation {
    param($Explanation)
    Write-Section $Explanation.PlainName
    Write-Line $Explanation.Name 'Dim'
    Write-Line ''
    Write-Line $Explanation.Summary 'Plain'
    Write-Line ('Why it matters: {0}' -f $Explanation.Why) 'Dim'
    if ($Explanation.Caution) { Write-Line ('Caution: {0}' -f $Explanation.Caution) 'Warn' }
    Write-Line ''
    Write-Line $Explanation.Verdict $(switch ($Explanation.Severity) { 'Good' { 'Good' } 'Warn' { 'Warn' } default { 'Info' } })
    if ($Explanation.Action) {
        Write-Line ''
        Write-Line 'What to do:' 'Head'
        foreach ($line in ($Explanation.Action -split "`n")) { Write-Line $line 'Plain' 2 }
    }
    if ($Explanation.Cis) {
        Write-Line ''
        Write-Line ('CIS {0} ({1}): {2}' -f $Explanation.Cis.Id, $Explanation.Cis.Profile, $Explanation.Cis.Title) 'Dim'
    }
    Write-Line ('Reference: {0}' -f $Explanation.DocUrl) 'Dim'
}

function Invoke-Interactive {
    param($State)

    $assessment = Get-Assessment -State $State

    Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
    Show-NextSteps -Explanations $assessment.Explanations

    $changed = $false
    while ($true) {
        Show-Menu -Statuses $assessment.Statuses -Score $assessment.Score
        $choice = Read-Choice '12345Q'

        if ($choice -eq 'Q') {
            # No second full audit when nothing changed: the state we have is still true.
            if (-not $changed) {
                Write-Line ''
                Write-Line 'No changes were made to this computer.' 'Dim'
                if ($State.Restart.Pending) { Write-Line 'Note: Windows has its own restart pending, unrelated to this tool.' 'Dim' }
                return
            }
            $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations
            foreach ($p in $paths) { Write-Line ('Report saved: {0}' -f $p) 'Good' }
            if ($script:RestartRequired) {
                Write-Line ''
                Write-Line 'A restart is needed before the changes take effect.' 'Warn'
            }
            return
        }

        switch ($choice) {
            '1' {
                $State = Get-SystemState -Volatile
                $assessment = Get-Assessment -State $State
                Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
                Show-NextSteps -Explanations $assessment.Explanations
            }
            '2' {
                $result = Invoke-ControlApply -Ids $script:SafeControlSet -State $State
                if ($result.ChangeCount -gt 0) { $changed = $true }
                Write-Section 'Result'
                if ($result.ChangeCount -eq 0) { Write-Line 'Nothing needed changing.' 'Good' }
                foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                foreach ($s in $result.Skipped) { Write-Line ('Skipped {0}: {1}' -f $s.ControlName, $s.Reason) 'Warn' 2 }
                if ($result.RestartRequired) {
                    Write-Line ''
                    Write-Line ('Restart required. Undo with:  -Revert -RunId {0}' -f $result.RunId) 'Info'
                }
                $State = Get-SystemState -Volatile
                $assessment = Get-Assessment -State $State
            }
            '3' {
                $id = Select-ControlInteractive
                if ($id) { Show-Explanation (Get-ControlExplanation -Id $id -State $State) }
            }
            '4' {
                Write-Line ''
                Write-Line 'Report format:' 'Head'
                Write-Line '  [1] Web page (HTML) - easiest to read and share' 'Plain'
                Write-Line '  [2] Plain text' 'Plain'
                Write-Line '  [3] JSON - for other tools' 'Plain'
                Write-Line '  [4] All three' 'Plain'
                $fmt = Read-Choice '1234'
                $script:HtmlSelected = [bool]($fmt -eq '1' -or $fmt -eq '4')
                $script:TextSelected = [bool]($fmt -eq '2' -or $fmt -eq '4')
                $script:JsonSelected = [bool]($fmt -eq '3' -or $fmt -eq '4')
                $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations -Formats @{ Html = $script:HtmlSelected; Text = $script:TextSelected; Json = $script:JsonSelected }
                foreach ($p in $paths) { Write-Line ('Saved: {0}' -f $p) 'Good' }
            }
            '5' {
                Show-MoreMenu
                $sub = Read-Choice 'ABCDEFGHX'
                switch ($sub) {
                    'A' { Show-Plan (Get-ChangePlan -Ids $script:SafeControlSet -State $State) }
                    'B' {
                        $id = Select-ControlInteractive
                        if ($id) {
                            $result = Invoke-ControlApply -Ids @($id) -State $State -ExplicitIds @($id)
                            if ($result.ChangeCount -gt 0) { $changed = $true }
                            Write-Section 'Result'
                            if ($result.ChangeCount -eq 0) { Write-Line 'Nothing needed changing.' 'Good' }
                            foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                            foreach ($s in $result.Skipped) { Write-Line ('Skipped {0}: {1}' -f $s.ControlName, $s.Reason) 'Warn' 2 }
                            $State = Get-SystemState -Volatile
                            $assessment = Get-Assessment -State $State
                        }
                    }
                    'C' {
                        $runs = Get-JournalRuns
                        if (@($runs).Count -eq 0) { Write-Line 'No recorded changes to undo.' 'Info' }
                        else {
                            Write-Section 'Recorded change runs'
                            foreach ($r in $runs) { Write-Line ('{0}  {1}  {2} change(s)  [{3}]' -f $r.RunId, $r.Time, $r.ChangeCount, $r.Controls) 'Plain' 2 }
                            $rid = Read-Host 'Run id to undo (blank to cancel)'
                            if (-not [string]::IsNullOrWhiteSpace($rid)) {
                                $rev = Invoke-ControlRevert -RunId $rid.Trim()
                                if ($rev.ChangeCount -gt 0) { $changed = $true }
                                foreach ($conflict in $rev.Conflicts) { Write-Line $conflict.Reason 'Warn'; Add-Warning $conflict.Reason }
                                Write-Line ('Reverted {0} change(s).' -f $rev.ChangeCount) 'Good'
                                $State = Get-SystemState -Volatile
                                $assessment = Get-Assessment -State $State
                            }
                        }
                    }
                    'D' { Show-CisSummary -Cis $assessment.Cis }
                    'E' {
                        try { Start-Process 'windowsdefender://coreisolation' | Out-Null; Write-Line 'Opened Windows Security.' 'Good' }
                        catch { Write-Line 'Could not open Windows Security.' 'Warn' }
                    }
                    'F' {
                        $guidance = Get-FirmwareGuidance -State $State
                        Show-FirmwareGuidance -Guidance $guidance -State $State
                        # The restart is the caller's decision, never a side effect of rendering.
                        if ($guidance.CanOfferReboot) { [void](Invoke-RebootToFirmware -Guidance $guidance) }
                    }
                    'G' { Show-CodeIntegrityDiagnostics -State $State }
                    'H' { [void](Open-CodeIntegrityEventViewer) }
                }
            }
        }
        Wait-ForKey
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

function Invoke-Main {
    Initialize-Console -DisableColor:$NoColor

    if ($Version) { Write-Host ('{0} {1}' -f $script:ToolName, $script:ToolVersion); $script:ExitCode = 0; return }
    if ($SelfTest) { $script:ExitCode = (Invoke-SelfTest); return }

    if ($ListControls) {
        Write-Section 'Control catalog'
        foreach ($c in $script:ControlCatalog) {
            $cisText = if ($c.Cis) { $c.Cis.Id } else { '-' }
            Write-Line ('{0,-25} {1,-8} weight {2,-4} {3}' -f $c.Id, $cisText, $c.Weight, $c.Name) 'Plain'
            Write-Line $c.Summary 'Dim' 4
        }
        $script:ExitCode = 0; return
    }

    if ($AuditOnly -and ($EnableAllSafe -or $Enable -or $Revert)) {
        Write-Line '-AuditOnly cannot be combined with a change switch.' 'Bad'
        $script:ExitCode = 1; return
    }
    if ($AutoReboot -and -not ($EnableAllSafe -or $Enable -or $Revert)) {
        Write-Line '-AutoReboot only applies to an unattended change run.' 'Bad'
        $script:ExitCode = 1; return
    }

    if (($EnableAllSafe -and $Enable) -or ($Revert -and ($EnableAllSafe -or $Enable)) -or ($Explain -and ($EnableAllSafe -or $Enable -or $Revert)) -or ($RunId -and -not $Revert)) {
        Write-Line 'Use one change mode at a time; -RunId requires -Revert and -Explain cannot be combined with changes.' 'Bad'
        $script:ExitCode = 1; return
    }
    if ($Enable) { $Enable = @($Enable | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLowerInvariant() }) }
    foreach ($controlId in (ConvertTo-Array $Enable)) {
        if (-not (Test-Contains (Get-ControlIds) $controlId)) { Write-Line ('Unknown control "{0}".' -f $controlId) 'Bad'; $script:ExitCode = 1; return }
        if (-not (Get-Control -Id $controlId).Remediable) { Write-Line ('Control "{0}" is report-only.' -f $controlId) 'Bad'; $script:ExitCode = 1; return }
    }
    if ($Explain -and -not (Test-Contains (Get-ControlIds) $Explain.Trim().ToLowerInvariant())) {
        Write-Line ('Unknown control "{0}". Use -ListControls to see valid ids.' -f $Explain) 'Bad'
        $script:ExitCode = 1; return
    }

    if (-not [string]::IsNullOrWhiteSpace($DebugLogPath)) {
        $script:DebugEnabled = $true
        $script:DebugPath = $DebugLogPath
        Write-Debug-Log ('{0} {1} starting' -f $script:ToolName, $script:ToolVersion)
    }

    if (-not (Test-IsElevated)) {
        # Try to elevate ourselves first. Telling a non-technical user to "run as
        # administrator" and exiting is not a workable instruction for this audience.
        if (Request-Elevation -Bound $script:InvocationParameters) { return }
        Write-Line 'WinDSH needs to run as Administrator to read platform security state.' 'Bad'
        Write-Line 'Right-click PowerShell, choose "Run as administrator", then run it again.' 'Info'
        Write-Line 'Or use Run-WinDSH-AsAdmin.bat, which requests elevation for you.' 'Info'
        $script:ExitCode = 4; return
    }

    $integrity = Get-SelfIntegrity
    if ($integrity.Status -eq 'Failed') {
        Write-Line 'Self-integrity check FAILED: this file does not match its recorded hash.' 'Bad'
        Write-Line 'Auditing will continue, but making changes is disabled. Download a fresh copy.' 'Warn'
        $script:RemediationAllowed = $false
        $script:ExitCode = 3
    }

    $State = Get-SystemState
    if ($State.Computer.IsVirtual) {
        Add-Warning 'This is a virtual machine. Platform security features depend on what the host exposes.'
    }

    if (-not [string]::IsNullOrWhiteSpace($Explain)) {
        $id = $Explain.Trim().ToLowerInvariant()
        if (-not (Test-Contains (Get-ControlIds) $id)) {
            Write-Line ('Unknown control "{0}". Use -ListControls to see valid ids.' -f $Explain) 'Bad'
            $script:ExitCode = 1; return
        }
        Show-Explanation (Get-ControlExplanation -Id $id -State $State)
        $script:ExitCode = 0; return
    }

    $unattended = [bool]($AuditOnly -or $EnableAllSafe -or $Enable -or $Revert -or $Rmm)
    $script:Unattended = $unattended
    if ($Revert) {
        if (-not $script:RemediationAllowed) { Write-Line 'Revert is disabled because the integrity check failed.' 'Bad'; $script:ExitCode = 3; return }
        try {
            $result = Invoke-ControlRevert -RunId $RunId
            Write-Section 'Revert'
            foreach ($r in $result.Reverted) { Write-Line ('{0}\{1} restored to {2}' -f $r.Path, $r.Name, $r.RestoredTo) 'Good' 2 }
            foreach ($conflict in $result.Conflicts) {
                $message = '{0}\{1}: {2}' -f $conflict.Path, $conflict.Name, $conflict.Reason
                Write-Line $message 'Warn'; Add-Warning $message
            }
            if ($result.Conflicts.Count -gt 0) { $script:ExitCode = 5 }
            Write-Line ('Reverted {0} change(s) from run {1}.' -f $result.ChangeCount, $result.RunId) 'Info'
        }
        catch {
            Add-Warning ('Revert failed: {0}' -f $_.Exception.Message)
            $script:ExitCode = 5
        }
        $State = Get-SystemState -Volatile
    }
    elseif ($EnableAllSafe -or $Enable) {
        if (-not $script:RemediationAllowed) { Write-Line 'Changes are disabled because the integrity check failed.' 'Bad'; $script:ExitCode = 3; return }
        $ids = if ($Enable) { @($Enable) } else { $script:SafeControlSet }
        if ($WhatIfPreference) { Show-Plan (Get-ChangePlan -Ids $ids -State $State -ExplicitIds @($Enable)) }
        else {
            try {
                $result = Invoke-ControlApply -Ids $ids -State $State -ExplicitIds @($Enable)
                Write-Section 'Changes'
                if ($result.ChangeCount -eq 0 -and $result.Skipped.Count -eq 0) { Write-Line 'No changes were needed.' 'Good' }
                elseif ($result.ChangeCount -eq 0) { Write-Line 'No changes were made; see the skipped protections below.' 'Warn' }
                foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                foreach ($skip in $result.Skipped) {
                    $message = 'Skipped {0}: {1}' -f $skip.ControlName, $skip.Reason
                    Write-Line $message 'Warn'; Add-Warning $message
                }
                if ($result.ChangeCount -gt 0) { Write-Line ('Undo with:  -Revert -RunId {0}' -f $result.RunId) 'Info' }
            }
            catch {
                Add-Warning ('Remediation stopped: {0}' -f $_.Exception.Message)
                $script:ExitCode = 1
            }
            $State = Get-SystemState -Volatile
        }
    }

    $assessment = Get-Assessment -State $State
    if ($Rmm) {
        # Automation writes files only when a format was explicitly selected.
        if ($HtmlReport -or $JsonReport -or $TextReport) {
            [void](Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations)
        }
    }
    elseif ($unattended) {
        Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
        Show-NextSteps -Explanations $assessment.Explanations
        if ($Advanced) { Show-CisSummary -Cis $assessment.Cis }
        $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations
        foreach ($p in $paths) { Write-Line ('Report saved: {0}' -f $p) 'Good' }
    }
    else { Invoke-Interactive -State $State }

    $script:ExitCode = Get-FinalExitCode
    if ($AutoReboot -and $script:ExitCode -eq 3010 -and -not $WhatIfPreference) {
        try { Write-Line 'Restarting now.' 'Warn'; Restart-Computer -Force -ErrorAction Stop }
        catch { Add-Warning ('Automatic restart failed: {0}' -f $_.Exception.Message); $script:ExitCode = 1 }
    }
    if ($Rmm) {
        Write-RmmOutput -State $State -Statuses $assessment.Statuses -Score $assessment.Score -Cis $assessment.Cis
        return
    }
    foreach ($w in $script:Warnings) { Write-Line $w 'Warn' }
    if ($unattended) {
        Write-Line ''
        Write-Line ('Result: {0}' -f (Get-ExitCodeMeaning -Code $script:ExitCode)) 'Dim'
    }
}

function Get-FinalExitCode {
    # A partial failure must not be hidden behind a restart-required success code.
    if ($script:ExitCode -ne 0) { return $script:ExitCode }
    if ($script:RestartRequired) { return 3010 }
    if (@($script:Warnings).Count -gt 0) { return 2 }
    return 0
}

function Invoke-EntryPoint {
    $script:RmmOutputWritten = $false
    $failureMessage = $null
    try { Invoke-Main }
    catch {
        $script:ExitCode = 1
        $failureMessage = $_.Exception.Message
        if (-not $Rmm) { Write-Line ('WinDSH failed: {0}' -f $failureMessage) 'Bad' }
    }
    # Validation/elevation failures return before assessment. Automation still gets
    # one JSON result rather than a silent exit or mixed diagnostic output.
    if ($Rmm -and -not $script:RmmOutputWritten -and -not ($Version -or $ListControls -or $SelfTest)) {
        if (-not $failureMessage) { $failureMessage = Get-ExitCodeMeaning -Code $script:ExitCode }
        Write-Output (([pscustomobject]@{
            schemaVersion = $script:SchemaVersion; tool = $script:ToolName
            version = $script:ToolVersion; exitCode = $script:ExitCode
            restartRequired = $script:RestartRequired; error = $failureMessage
        }) | ConvertTo-Json -Compress)
    }
}

# Invoke-Main sets its exit code; do not capture stdout in the entry point.
Invoke-EntryPoint
exit $script:ExitCode
