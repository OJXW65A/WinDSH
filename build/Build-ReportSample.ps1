#requires -Version 5.1
<#
.SYNOPSIS
    Builds an illustrative HTML report using synthetic data, never host evidence.
.PARAMETER OutputPath
    Defaults to docs/samples/WinDSH-sample.html.
#>
[CmdletBinding()]
param([string]$OutputPath)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$sampleRepo = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $sampleRepo 'docs/samples/WinDSH-sample.html' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

# Load declarations only. The entry-point module would start a real audit.
foreach ($module in (Get-ChildItem (Join-Path $sampleRepo 'src') -Filter '*.ps1' | Sort-Object Name)) {
    if ($module.Name -ne '70-main.ps1') { . $module.FullName }
}

function Get-CodeIntegrityEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'EventIds',
        Justification = 'Synthetic provider preserves the real signature without querying event logs.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'LookbackDays',
        Justification = 'Synthetic provider preserves the real signature without querying event logs.')]
    param($EventIds, $LookbackDays)
    return [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null }
}

$sampleState = New-SyntheticState
$sampleState.Computer.Name = 'SAMPLE-PC'
$sampleState.Computer.Manufacturer = 'Example vendor'
$sampleState.Computer.Model = 'Synthetic workstation'
$sampleState.Computer.ProcessorName = 'Example 64-bit processor'
$sampleState.DeviceGuard.VbsStatusCode = 2
$sampleState.DeviceGuard.VbsStatusText = 'Running'
$sampleState.DeviceGuard.Running = @(1, 2)
$sampleState.Restart.Pending = $true
$sampleState.Policy | Add-Member -NotePropertyName Errors -NotePropertyValue @{
    ConfigureKernelShadowStacksLaunch = 'Synthetic example of unavailable policy evidence.'
}
$sampleSeed = @{
    "$script:RegDeviceGuard|EnableVirtualizationBasedSecurity" = 1
    "$script:RegDeviceGuard|Locked" = 0
    "$script:RegDeviceGuard|RequirePlatformSecurityFeatures" = 1
    "$script:RegHvci|Enabled" = 1
    "$script:RegHvci|Locked" = 0
    "$script:RegLsa|LsaCfgFlags" = 2
    "$script:RegCiConfig|VulnerableDriverBlocklistEnable" = 1
    "$script:RegSystemGuard|Enabled" = 1
}
$sampleProvider = New-InMemoryRegistryProvider -Seed $sampleSeed
$sampleReadValue = $sampleProvider.GetValue
$sampleUnavailablePath = $script:RegShadowStacks
$sampleProvider.GetValue = {
    param([string]$Path, [string]$Name)
    if ($Path -eq $sampleUnavailablePath -and $Name -eq 'Enabled') {
        throw 'Synthetic example of unavailable local configuration evidence.'
    }
    return (& $sampleReadValue $Path $Name)
}.GetNewClosure()
Set-RegistryProvider $sampleProvider
$sampleStatuses = @(Get-AllControlStatus -State $sampleState)
$sampleScore = Get-SecurityScore -Statuses $sampleStatuses
$sampleCore = Get-SecuredCoreVerdict -State $sampleState -Statuses $sampleStatuses
$sampleCis = Get-CisComplianceReport -State $sampleState -Statuses $sampleStatuses
$sampleExplanations = @($sampleStatuses | ForEach-Object {
    Get-ControlExplanation -Id $_.Id -State $sampleState -Status $_
})
$sampleHtml = New-HtmlReport -State $sampleState -Statuses $sampleStatuses -Score $sampleScore `
    -SecuredCore $sampleCore -Cis $sampleCis -Explanations $sampleExplanations

# Freeze only the fixture clock and add an explicit label. Production reports are unchanged.
$sampleHtml = [regex]::Replace($sampleHtml,
    '(?<=&middot; generated )\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '2026-10-07 00:00:00')
$sampleHtml = $sampleHtml.Replace('<h1>Windows device security report</h1>',
    '<div class="note" role="note"><strong>Illustrative sample - synthetic data.</strong> Not an audit of a real computer and not hardware-validation evidence.</div><h1>Windows device security report</h1>')
$sampleHtml = ($sampleHtml -replace "`r`n", "`n") -replace "`r", "`n"
$null = New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force
[IO.File]::WriteAllText($OutputPath, $sampleHtml, (New-Object Text.UTF8Encoding($false)))
Write-Output ('Created synthetic sample: {0}' -f $OutputPath)
