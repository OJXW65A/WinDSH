# WinDSH Pester regression/smoke tests
# Designed to run under both Windows PowerShell 5.1 and PowerShell 7.

BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    $WinDSHPath = Join-Path $RepoRoot 'WinDSH.ps1'

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    }
    else {
        $PowerShellExe = (Get-Command pwsh.exe -ErrorAction Stop).Source
    }

    function Invoke-WinDSHChild {
        param(
            [Parameter(Mandatory = $true)]
            [string[]]$Arguments
        )

        $processArgs = @(
            '-NoLogo'
            '-NoProfile'
            '-NonInteractive'
            '-File'
            $WinDSHPath
        ) + $Arguments

        $output = @(& $PowerShellExe @processArgs 2>&1)
        $exitCode = $LASTEXITCODE

        [pscustomobject]@{
            ExitCode = $exitCode
            Output   = ($output | Out-String)
        }
    }
}

Describe 'WinDSH source' {
    It 'exists in the repository root' {
        Test-Path -LiteralPath $WinDSHPath | Should -BeTrue
    }

    It 'parses without PowerShell syntax errors' {
        $tokens = $null
        $parseErrors = $null

        [System.Management.Automation.Language.Parser]::ParseFile(
            $WinDSHPath,
            [ref]$tokens,
            [ref]$parseErrors
        ) | Out-Null

        @($parseErrors).Count | Should -Be 0
    }
}

Describe 'WinDSH command-line smoke tests' {
    It '-Version exits successfully and identifies WinDSH' {
        $result = Invoke-WinDSHChild -Arguments @('-Version')

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match '\bWinDSH\b'
        $result.Output | Should -Match '\b1\.5\.0\b'
    }

    It '-SelfTest exits successfully' {
        $result = Invoke-WinDSHChild -Arguments @('-SelfTest')

        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'Self-test result:\s*PASS'
        $result.Output | Should -Not -Match '\[FAIL\]'
    }
}

Describe 'Known PowerShell 5.1 regression cases' {
    BeforeAll {
        $SelfTestResult = Invoke-WinDSHChild -Arguments @('-SelfTest')
    }

    It 'handles an empty firmware-action result' {
        $SelfTestResult.Output |
            Should -Match 'Firmware action list can be empty without throwing'
    }

    It 'handles a single firmware action without scalar/Count failure' {
        $SelfTestResult.Output |
            Should -Match 'Firmware action list handles a single action safely'
    }

    It 'returns the Easy Summary as a stable multi-item collection' {
        $SelfTestResult.Output |
            Should -Match 'Easy Summary returns a stable multi-item array'
    }

    It 'handles empty-array membership checks safely' {
        $SelfTestResult.Output |
            Should -Match 'Empty array membership is safe'
    }

    It 'handles an unsupported Credential Guard capability' {
        $SelfTestResult.Output |
            Should -Match 'Credential Guard is unavailable when edition support is false'
    }
}
