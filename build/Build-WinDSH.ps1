#requires -Version 5.1
<#
.SYNOPSIS
    Builds the single distributable WinDSH.ps1 from src/ and stamps the integrity hash.

.DESCRIPTION
    WinDSH ships as one file so users can download and run it without an installer, but
    a 3,000-line single file is unmaintainable. Source lives in src/ as ordered modules;
    this script concatenates them in filename order and computes the self-integrity hash,
    so the hash can never be out of date in a built artifact.

.PARAMETER OutputPath
    Where to write the built script. Defaults to WinDSH.ps1 in the repository root.

.PARAMETER Check
    Verify the existing built file matches a fresh build. Used by CI.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Check
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$srcDir = Join-Path $repoRoot 'src'
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'WinDSH.ps1' }

$modules = @(Get-ChildItem -Path $srcDir -Filter '*.ps1' | Sort-Object Name)
if (@($modules).Count -eq 0) { throw "No source modules found in $srcDir" }

Write-Host ('Building from {0} module(s):' -f @($modules).Count)
foreach ($m in $modules) { Write-Host ('  {0}' -f $m.Name) }

$sb = New-Object Text.StringBuilder
foreach ($module in $modules) {
    $text = [IO.File]::ReadAllText($module.FullName)
    $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"

    # Only the first module keeps its #requires and comment-based help; the rest are
    # appended as plain bodies so the built file has a single valid header.
    if ($module.Name -ne $modules[0].Name) {
        $null = $sb.AppendLine()
        $null = $sb.AppendLine(('# ===== {0} =====' -f $module.Name))
    }
    $null = $sb.AppendLine($text.TrimEnd())
}

# StringBuilder.AppendLine emits Environment.NewLine, which is CRLF on Windows and
# LF elsewhere, so $built would otherwise mix LF inside a module with CRLF between
# modules depending on who ran the build. Normalise once, here, so the hash, the
# -Check comparison and the bytes written below are identical on every platform.
# Without this, -Check can never pass on Windows, and a Windows build turns each
# CRLF into CR CR LF, which the runtime integrity check reads as doubled lines --
# a hash mismatch that disables all remediation for every user.
$built = ($sb.ToString() -replace "`r`n", "`n") -replace "`r", "`n"

# Compute the self-integrity hash exactly as Get-SelfIntegrity does at runtime.
$pattern = '(?m)^\$script:ExpectedIntegrityHash\s*=\s*''[0-9A-Fa-f]{64}''\s*$'
if (-not [regex]::IsMatch($built, $pattern)) { throw 'Integrity marker not found in the built output.' }

$placeholder = '0' * 64
$normalized = [regex]::Replace($built, $pattern, ("`$script:ExpectedIntegrityHash = '{0}'" -f $placeholder), 1)
$normalized = ($normalized -replace "`r`n", "`n") -replace "`r", "`n"

$sha = [Security.Cryptography.SHA256]::Create()
try {
    $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized)))).Replace('-', '').ToLowerInvariant()
}
finally { $sha.Dispose() }

$final = [regex]::Replace($built, $pattern, ("`$script:ExpectedIntegrityHash = '{0}'" -f $hash), 1)

if ($Check) {
    if (-not (Test-Path -LiteralPath $OutputPath)) { Write-Host '::error::Built file is missing. Run build/Build-WinDSH.ps1.'; exit 1 }
    $existing = ([IO.File]::ReadAllText($OutputPath) -replace "`r`n", "`n") -replace "`r", "`n"
    if ($existing -ne $final) {
        Write-Host '::error::WinDSH.ps1 is out of date with src/. Run build/Build-WinDSH.ps1 and commit the result.'
        exit 1
    }
    Write-Host ('Built output is current. Integrity hash: {0}' -f $hash)
    exit 0
}

[IO.File]::WriteAllText($OutputPath, ($final -replace "`n", "`r`n"), (New-Object Text.UTF8Encoding($false)))

$lines = @($final -split "`n").Count
Write-Host ''
Write-Host ('Wrote {0}' -f $OutputPath)
Write-Host ('  lines          : {0}' -f $lines)
Write-Host ('  integrity hash : {0}' -f $hash)
