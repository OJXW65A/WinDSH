BeforeAll {
    $QualityRepo = Split-Path -Parent $PSScriptRoot
    $QualityCheck = Join-Path $QualityRepo 'build/Test-CodeQuality.ps1'
    $QualityPin = (Get-Content -Raw (Join-Path $QualityRepo '.github/psgallery-lock.json') | ConvertFrom-Json).PSScriptAnalyzer.version
    if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
        function Invoke-ScriptAnalyzer {
            [CmdletBinding()]
            param([string]$Path, [switch]$Recurse)
            throw 'Unit tests must replace the analyzer with a test double.'
        }
    }
}

Describe 'Code quality gate' {
    BeforeEach {
        Mock Get-Module { [pscustomobject]@{ Version = [version]$QualityPin } } -ParameterFilter { $Name -eq 'PSScriptAnalyzer' }
        Mock Invoke-ScriptAnalyzer { @() }
    }

    It 'accepts a clean analysis using the pinned module' {
        { & $QualityCheck } | Should -Not -Throw
        Should -Invoke Invoke-ScriptAnalyzer -Times 2 -Exactly
    }

    It 'rejects analyzer warnings instead of allowing the baseline to grow' {
        Mock Invoke-ScriptAnalyzer { [pscustomobject]@{ Severity = 'Warning'; RuleName = 'SyntheticRule'; Line = 1; ScriptName = 'fixture.ps1'; Message = 'Synthetic warning' } }
        { & $QualityCheck } | Should -Throw '*error/warning finding*'
    }

    It 'rejects analyzer errors' {
        Mock Invoke-ScriptAnalyzer { [pscustomobject]@{ Severity = 'Error'; RuleName = 'SyntheticRule'; Line = 1; ScriptName = 'fixture.ps1'; Message = 'Synthetic error' } }
        { & $QualityCheck } | Should -Throw '*error/warning finding*'
    }

    It 'refuses an unpinned analyzer before running it' {
        Mock Get-Module { [pscustomobject]@{ Version = [version]'0.0.1' } } -ParameterFilter { $Name -eq 'PSScriptAnalyzer' }
        { & $QualityCheck } | Should -Throw '*Import verified PSScriptAnalyzer*'
        Should -Invoke Invoke-ScriptAnalyzer -Times 0 -Exactly
    }
}
