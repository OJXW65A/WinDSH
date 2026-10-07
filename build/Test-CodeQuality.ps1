#requires -Version 5.1
<#
.SYNOPSIS
    Checks source and build scripts with the repository's pinned PSScriptAnalyzer.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pin = (Get-Content -Raw (Join-Path $repoRoot '.github/psgallery-lock.json') | ConvertFrom-Json).PSScriptAnalyzer
$analyzer = @(Get-Module -Name PSScriptAnalyzer | Where-Object { $_.Version.ToString() -eq $pin.version })
if ($analyzer.Count -ne 1) {
    throw ('Import verified PSScriptAnalyzer {0} first: .\build\Install-CIDependencies.ps1 -Name PSScriptAnalyzer' -f $pin.version)
}

$findings = @(Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot 'src') -Recurse) +
            @(Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot 'build'))
$blocking = @($findings | Where-Object { $_.Severity -in @('Error', 'Warning') })
if ($blocking.Count -gt 0) {
    $blocking | Select-Object RuleName, Severity, Line, ScriptName, Message |
        Format-Table -AutoSize | Out-String -Width 240 | Write-Output
    throw ('PSScriptAnalyzer reported {0} error/warning finding(s).' -f $blocking.Count)
}
Write-Output 'PSScriptAnalyzer: 0 errors, 0 warnings.'
