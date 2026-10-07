#requires -Version 5.1
<#
.SYNOPSIS
    Packages the two files needed to run WinDSH into one ZIP.
.PARAMETER OutputPath
    Destination ZIP. Defaults to dist/WinDSH.zip in the repository root.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Packaging diagnostics are host output, not archive content or pipeline data.')]
[CmdletBinding()]
param([string]$OutputPath)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'dist/WinDSH.zip' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

$payload = @('Run-WinDSH-AsAdmin.bat', 'WinDSH.ps1') | ForEach-Object {
    $file = Join-Path $repoRoot $_
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Download payload file missing: $_"
    }
    $file
}

$null = New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force
# Explicit file paths keep both files at the archive root and exclude other content.
Compress-Archive -LiteralPath $payload -DestinationPath $OutputPath -CompressionLevel Optimal -Force
Write-Host "Created: $OutputPath"
