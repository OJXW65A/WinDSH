BeforeAll {
    $WorkflowRepo = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'TestSupport.ps1')
    $WorkflowPowerShell = Get-TestPowerShellPath

    function Get-PesterWorkflowGuard {
        param([string]$Workflow)
        $path = Join-Path $WorkflowRepo ('.github/workflows/' + $Workflow)
        $lines = @(Get-Content -LiteralPath $path)
        $start = [array]::IndexOf($lines, '          $result = Invoke-Pester -Configuration $configuration')
        if ($start -lt 0) { throw ('Pester workflow step was not found in {0}.' -f $Workflow) }
        $guard = New-Object 'Collections.Generic.List[string]'
        for ($index = $start + 1; $index -lt $lines.Count; $index++) {
            $line = $lines[$index]
            if ([string]::IsNullOrWhiteSpace($line)) { $guard.Add(''); continue }
            if (-not $line.StartsWith('          ')) { break }
            $guard.Add($line.Substring(10))
        }
        if ($guard.Count -eq 0) { throw ('Pester workflow guard was not found in {0}.' -f $Workflow) }
        return ($guard -join "`n")
    }

    function Invoke-PesterGuardProcess {
        param([string]$Path)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $WorkflowPowerShell
        $info.Arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}"' -f $Path
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        try {
            [void]$process.Start()
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Workflow guard test timed out.' }
            return [pscustomobject]@{
                ExitCode = $process.ExitCode
                Output = $stdout.GetAwaiter().GetResult()
                Error = $stderr.GetAwaiter().GetResult()
            }
        }
        finally { $process.Dispose() }
    }
}

Describe 'Workflow Pester result guards' {
    It '<Workflow> returns <ExpectedExit> for <Case>' -TestCases @(
        foreach ($workflow in 'ci.yml', 'release.yml') {
            foreach ($case in @(
                @{ Case = 'a successful run'; Result = 'Passed'; Passed = 1; Failed = 0; Skipped = 0; ExpectedExit = 0 }
                @{ Case = 'an empty run'; Result = 'Passed'; Passed = 0; Failed = 0; Skipped = 0; ExpectedExit = 1 }
                @{ Case = 'an entirely skipped run'; Result = 'Passed'; Passed = 0; Failed = 0; Skipped = 1; ExpectedExit = 1 }
                @{ Case = 'a failed test'; Result = 'Failed'; Passed = 1; Failed = 1; Skipped = 0; ExpectedExit = 1 }
                @{ Case = 'a discovery failure alongside a passing test'; Result = 'Failed'; Passed = 1; Failed = 0; Skipped = 0; ExpectedExit = 1 }
            )) {
                $case.Workflow = $workflow
                $case
            }
        }
    ) {
        param($Workflow, $Case, $Result, $Passed, $Failed, $Skipped, $ExpectedExit)
        # Run the actual post-Pester workflow code in an inert child host. Its
        # exit statement must not stop Pester; no dependency downloads or audits run.
        $fixture = @'
$ErrorActionPreference = 'Stop'
$result = [pscustomobject]@{
    Result = '__RESULT__'
    PassedCount = __PASSED__
    FailedCount = __FAILED__
    SkippedCount = __SKIPPED__
}
'@
        $fixture = $fixture.Replace('__RESULT__', $Result).Replace('__PASSED__', [string]$Passed)
        $fixture = $fixture.Replace('__FAILED__', [string]$Failed).Replace('__SKIPPED__', [string]$Skipped)
        $child = Join-Path $TestDrive 'workflow-guard.ps1'
        [IO.File]::WriteAllText($child, ($fixture + "`n" + (Get-PesterWorkflowGuard -Workflow $Workflow) + "`nexit 0`n"))
        $actual = Invoke-PesterGuardProcess -Path $child
        $actual.ExitCode | Should -Be $ExpectedExit -Because ($Case + ': ' + $actual.Output + $actual.Error)
    }
}
