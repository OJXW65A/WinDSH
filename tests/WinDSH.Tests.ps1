# WinDSH Pester tests
# Runs under both Windows PowerShell 5.1 and PowerShell 7.
# The heavy logic coverage lives in the script's own -SelfTest, which uses an in-memory
# registry provider. These tests are the CI-facing wrapper around it.

BeforeAll {
    $RepoRoot   = Split-Path -Parent $PSScriptRoot
    $WinDSHPath = Join-Path $RepoRoot 'WinDSH.ps1'
    $SrcDir     = Join-Path $RepoRoot 'src'
    $BuildPath  = Join-Path $RepoRoot 'build\Build-WinDSH.ps1'

    $Source = Get-Content -Raw -LiteralPath $WinDSHPath
    $ExpectedVersion = [regex]::Match($Source, "ToolVersion\s*=\s*'([^']+)'").Groups[1].Value

    . (Join-Path $PSScriptRoot 'TestSupport.ps1')
    $PowerShellExe = Get-TestPowerShellPath

    function Invoke-WinDSHChild {
        param([Parameter(Mandatory = $true)][string[]]$Arguments)
        $processArgs = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $WinDSHPath) + $Arguments
        $output = @(& $PowerShellExe @processArgs 2>&1)
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output | Out-String) }
    }
}

Describe 'Repository layout' {
    It 'has the generated script in the root' { Test-Path -LiteralPath $WinDSHPath | Should -BeTrue }
    It 'has the source modules' { (Get-ChildItem $SrcDir -Filter *.ps1).Count | Should -BeGreaterThan 0 }
    It 'has the build script' { Test-Path -LiteralPath $BuildPath | Should -BeTrue }
    It 'has the launcher' { Test-Path -LiteralPath (Join-Path $RepoRoot 'Run-WinDSH-AsAdmin.bat') | Should -BeTrue }
}

Describe 'Build freshness' {
    It 'WinDSH.ps1 is current with src/' {
        # A stale build ships an incorrect integrity hash, which disables all remediation
        # for every user. This must never pass silently.
        & $PowerShellExe -NoLogo -NoProfile -NonInteractive -File $BuildPath -Check | Out-Null
        $LASTEXITCODE | Should -Be 0 -Because 'run build\Build-WinDSH.ps1 and commit the result'
    }

    It 'produces consistent CRLF line endings on any platform' {
        # StringBuilder.AppendLine emits Environment.NewLine. When that was left
        # unnormalised, a Windows build wrote CR CR LF, which the runtime integrity
        # check reads as doubled lines -- a hash mismatch that disables all
        # remediation. -Check could also never pass on Windows. Guard both here,
        # because the damage only appears on the platform maintainers build on.
        $temp = Join-Path ([IO.Path]::GetTempPath()) ('windsh-build-{0}.ps1' -f [Guid]::NewGuid())
        try {
            & $PowerShellExe -NoLogo -NoProfile -NonInteractive -File $BuildPath -OutputPath $temp | Out-Null
            $LASTEXITCODE | Should -Be 0

            $raw = [IO.File]::ReadAllText($temp)
            $raw | Should -Not -Match "`r`r"
            @([regex]::Matches($raw, "(?<!`r)`n")).Count |
                Should -Be 0 -Because 'every LF must be part of a CRLF pair'

            & $PowerShellExe -NoLogo -NoProfile -NonInteractive -File $BuildPath -Check -OutputPath $temp | Out-Null
            $LASTEXITCODE | Should -Be 0 -Because '-Check must accept a file the build just wrote'
        }
        finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Source syntax' {
    It 'every source module parses' {
        $bad = @()
        foreach ($file in (Get-ChildItem $SrcDir -Filter *.ps1)) {
            $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors) | Out-Null
            if (@($parseErrors).Count -gt 0) { $bad += $file.Name }
        }
        $bad -join ', ' | Should -BeNullOrEmpty
    }

    It 'the generated script parses' {
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($WinDSHPath, [ref]$null, [ref]$parseErrors) | Out-Null
        @($parseErrors).Count | Should -Be 0
    }

    It 'declares a parseable version' { $ExpectedVersion | Should -Match '^\d+\.\d+\.\d+$' }
}

Describe 'Declared safety boundaries' {
    # These assert the promises made in README.md and CLAUDE.md. Checked against parsed
    # command names, so comment-based help describing what WinDSH does NOT do cannot
    # cause a false positive.
    BeforeAll {
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($WinDSHPath, [ref]$tokens, [ref]$null)
        $InvokedCommands = $ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Select-Object -Unique
        $CodeText = ($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join "`n"
    }

    It 'never invokes forbidden cmdlets' {
        $forbidden = @(
            'Invoke-Expression', 'iex'
            'Invoke-WebRequest', 'Invoke-RestMethod', 'irm'
            'Set-MpPreference', 'Add-MpPreference'
            'Start-BitsTransfer'
            'Register-ScheduledTask', 'New-ScheduledTask'
            'Clear-Tpm', 'Set-SecureBootUEFI'
            'Enable-BitLocker', 'Disable-BitLocker', 'Set-ExecutionPolicy'
        )
        (@($InvokedCommands | Where-Object { $forbidden -contains $_ }) -join ', ') |
            Should -BeNullOrEmpty -Because 'these are outside WinDSH scope'
    }

    It 'contains no encoded or downloaded payloads' {
        foreach ($term in @('FromBase64String', 'DownloadString', 'DownloadFile', '-EncodedCommand')) {
            $CodeText | Should -Not -Match ([regex]::Escape($term))
        }
    }

    It 'never writes the Group Policy hive' {
        # Reading it is required for policy detection and CIS comparison; writing is not.
        $writes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Where-Object { $_.GetCommandName() -in @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty') } |
            Where-Object { $_.Extent.Text -match 'SOFTWARE\\+Policies' }
        @($writes).Count | Should -Be 0 -Because 'WinDSH must never modify Group Policy'
    }
}

Describe 'Command-line behaviour' {
    It '-Version reports the declared version' {
        $result = Invoke-WinDSHChild -Arguments @('-Version')
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match ([regex]::Escape($ExpectedVersion))
    }

    It '-SelfTest passes with no failures' {
        $result = Invoke-WinDSHChild -Arguments @('-SelfTest')
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match '0 failed'
        $result.Output | Should -Not -Match '^\[ X'
    }

    It '-ListControls lists the catalog' {
        $result = Invoke-WinDSHChild -Arguments @('-ListControls')
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'hvci'
        $result.Output | Should -Match 'credential-guard'
    }

    It 'rejects -AuditOnly combined with a change switch' {
        (Invoke-WinDSHChild -Arguments @('-AuditOnly', '-EnableAllSafe')).ExitCode | Should -Be 1
    }

    It 'rejects -AutoReboot without a change switch' {
        (Invoke-WinDSHChild -Arguments @('-AutoReboot')).ExitCode | Should -Be 1
    }

    It 'rejects an unknown control id' {
        (Invoke-WinDSHChild -Arguments @('-Explain', 'not-a-real-control')).ExitCode | Should -Be 1
    }
}

Describe 'Self-test coverage markers' {
    # Guards against a regression test being silently removed from the self-test.
    BeforeAll { $SelfTest = (Invoke-WinDSHChild -Arguments @('-SelfTest')).Output }

    It 'covers apply and revert round-trip' { $SelfTest | Should -Match 'Revert restores every journalled value' }
    It 'covers Group Policy being left alone' { $SelfTest | Should -Match 'policy-managed' }
    It 'covers the platform security downgrade guard' { $SelfTest | Should -Match 'stronger Secure Boot' }
    It 'covers the ambiguous firmware string' { $SelfTest | Should -Match 'Ambiguous firmware text remains unknown' }
    It 'covers hypervisorlaunchtype Off' { $SelfTest | Should -Match 'hypervisorlaunchtype' }
    It 'covers CIS comparison' { $SelfTest | Should -Match 'CIS' }
    It 'covers HTML report escaping' { $SelfTest | Should -Match 'inject markup' }
    It 'covers the unattended no-prompt rule' { $SelfTest | Should -Match 'never block on a confirmation prompt' }
    It 'covers relaunch argument quoting' { $SelfTest | Should -Match 'cannot inject a new argument' }
}
