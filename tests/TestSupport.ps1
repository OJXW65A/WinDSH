# Get-Process.Path can be unavailable in containers or restricted process views.
# PSHOME belongs to the running host and works on both supported PowerShell editions.
function Get-TestPowerShellPath {
    $name = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' }
            elseif ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'pwsh.exe' }
            else { 'pwsh' }
    $path = Join-Path $PSHOME $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('PowerShell test host is missing: {0}' -f $path) }
    return $path
}
