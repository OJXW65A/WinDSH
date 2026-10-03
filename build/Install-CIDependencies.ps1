#requires -Version 5.1
<#
.SYNOPSIS
    Download, hash-verify, and import one CI module from the checked-in package lock.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Pester', 'PSScriptAnalyzer')]
    [string]$Name,
    [string]$Destination
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repoRoot = Split-Path -Parent $PSScriptRoot
$lock = Get-Content -Raw (Join-Path $repoRoot '.github/psgallery-lock.json') | ConvertFrom-Json
$pin = $lock.$Name
if ($pin.version -notmatch '^\d+\.\d+\.\d+$' -or $pin.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Invalid dependency lock entry.' }
if (-not $Destination) {
    $tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
    $Destination = Join-Path $tempRoot ('windsh-modules-{0}' -f [Guid]::NewGuid().ToString('N'))
}
$moduleDir = Join-Path (Join-Path $Destination $Name) $pin.version
if (Test-Path -LiteralPath $moduleDir) { throw 'Use a fresh module destination; refusing to import unverified existing files.' }
$null = New-Item -ItemType Directory -Path $Destination -Force
$package = Join-Path $Destination ('{0}.{1}.nupkg' -f $Name, $pin.version)
$url = 'https://www.powershellgallery.com/api/v2/package/{0}/{1}' -f $Name, $pin.version
try {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $package -ErrorAction Stop
    $actual = (Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $pin.sha256) { throw ('Package integrity check failed for {0} {1}; refusing to extract or import it.' -f $Name, $pin.version) }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $null = New-Item -ItemType Directory -Path $moduleDir -Force
    [IO.Compression.ZipFile]::ExtractToDirectory($package, $moduleDir)
    $manifest = Join-Path $moduleDir ($Name + '.psd1')
    $metadata = Test-ModuleManifest -Path $manifest -ErrorAction Stop
    if ($metadata.Version.ToString() -ne $pin.version) { throw 'Package manifest version differs from the lock.' }
    Import-Module -Name $manifest -Global -Force -ErrorAction Stop
    Write-Host ('Imported verified {0} {1} ({2}).' -f $Name, $pin.version, $actual)
}
finally { Remove-Item -LiteralPath $package -Force -ErrorAction SilentlyContinue }
