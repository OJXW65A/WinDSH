# Exercise launcher process handling with inert children, never the security tool.
BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    $LauncherPath = Join-Path $RepoRoot 'Run-WinDSH-AsAdmin.bat'
    $Launcher = Get-Content -Raw -LiteralPath $LauncherPath
    $PowerShellExe = (Get-Process -Id $PID).Path

    function Invoke-LauncherTestProcess {
        param([string]$FileName, [string]$Arguments)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $FileName; $info.Arguments = $Arguments
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true
        $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        try {
            [void]$process.Start()
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            # PAUSE sees EOF instead of holding the CI process open.
            $process.StandardInput.Close()
            if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Launcher test timed out.' }
            [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult(); Error = $stderr.GetAwaiter().GetResult() }
        }
        finally { $process.Dispose() }
    }
}

Describe 'Launcher exit handling' {
    It 'returns child exit code <Code> from the actual elevated launcher' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) -TestCases @(
        @{ Code = 0 }, @{ Code = 1 }, @{ Code = 3010 }
    ) {
        param($Code)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | Should -BeTrue -Because 'CI needs an elevated token; this test must not trigger UAC'
        }
        finally { $identity.Dispose() }
        $folder = Join-Path $TestDrive ('launcher with spaces {0}' -f $Code)
        New-Item -ItemType Directory -Path $folder | Out-Null
        $batch = Join-Path $folder 'Run-WinDSH-AsAdmin.bat'
        Copy-Item -LiteralPath $LauncherPath -Destination $batch
        [IO.File]::WriteAllText((Join-Path $folder 'WinDSH.ps1'), ('exit {0}' -f $Code))
        $result = Invoke-LauncherTestProcess -FileName $env:ComSpec -Arguments ('/d /c ""{0}""' -f $batch)
        $result.ExitCode | Should -Be $Code -Because ($result.Output + $result.Error)
        $result.Output | Should -Match 'Running as Administrator'
    }

    It 'waits for the UAC child and returns its exit code <Code>' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) -TestCases @(
        @{ Code = 0 }, @{ Code = 1 }, @{ Code = 4 }, @{ Code = 3010 }
    ) {
        param($Code)
        $line = @($Launcher -split '\r?\n' | Where-Object { $_ -match '^"%PSEXE%".*Start-Process' })[0]
        $command = [regex]::Match($line, '-Command "(.*)"$').Groups[1].Value
        $command | Should -Not -BeNullOrEmpty
        # Run the real command with a fake UAC process in a separate PowerShell
        # host, because its exit statement must not terminate Pester.
        $stub = @'
function Start-Process {
    param($FilePath, $Verb, [switch]$Wait, [switch]$PassThru, $ErrorAction)
    if (-not $Wait -or -not $PassThru -or $Verb -ne 'RunAs') { throw 'Invalid elevation request' }
    [pscustomobject]@{ ExitCode = __CODE__ }
}
'@
        $child = Join-Path $TestDrive 'fake-uac.ps1'
        [IO.File]::WriteAllText($child, ($stub.Replace('__CODE__', [string]$Code) + "`n" + $command))
        $result = Invoke-LauncherTestProcess -FileName $PowerShellExe -Arguments ('-NoLogo -NoProfile -NonInteractive -File "{0}"' -f $child)
        $result.ExitCode | Should -Be $Code -Because $result.Error
    }

    It 'distinguishes an elevation failure from a child application failure' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $line = @($Launcher -split '\r?\n' | Where-Object { $_ -match '^"%PSEXE%".*Start-Process' })[0]
        $command = [regex]::Match($line, '-Command "(.*)"$').Groups[1].Value
        $child = Join-Path $TestDrive 'cancel-uac.ps1'
        [IO.File]::WriteAllText($child, ("function Start-Process { throw 'Synthetic UAC cancellation' }`n" + $command))
        $result = Invoke-LauncherTestProcess -FileName $PowerShellExe -Arguments ('-NoLogo -NoProfile -NonInteractive -File "{0}"' -f $child)
        $result.ExitCode | Should -Be 1223
    }
}
