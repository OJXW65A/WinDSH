BeforeAll {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'build/Test-ReleaseTarget.ps1')
}

Describe 'Release asset safeguards' {
    BeforeEach {
        $previousToken = $env:GH_TOKEN
        $env:GH_TOKEN = 'synthetic-test-token'
        Mock Invoke-RestMethod { Write-Output -NoEnumerate @() }
    }
    AfterEach { $env:GH_TOKEN = $previousToken }

    It 'allows a new version without writing to GitHub' {
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Not -Throw
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://api.github.com/repos/OJXW65A/WinDSH/releases?per_page=100&page=1' -and
            $Headers.Authorization -eq 'Bearer synthetic-test-token'
        }
    }

    It 'refuses an already published version' {
        Mock Invoke-RestMethod { Write-Output -NoEnumerate @([pscustomobject]@{ tag_name = 'v2.0.1'; draft = $false }) }
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*already published*'
    }

    It 'refuses to mix new files into an existing draft' {
        Mock Invoke-RestMethod { Write-Output -NoEnumerate @([pscustomobject]@{ tag_name = 'v2.0.1'; draft = $true }) }
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*draft already exists*'
    }

    It 'checks subsequent pages before allowing a release' {
        Mock Invoke-RestMethod {
            if ($Uri -like '*page=1') { Write-Output -NoEnumerate @(1..100 | ForEach-Object { [pscustomobject]@{ tag_name = "v0.0.$_"; draft = $false } }) }
            else { Write-Output -NoEnumerate @([pscustomobject]@{ tag_name = 'v2.0.1'; draft = $false }) }
        }
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*already published*'
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
    }

    It 'blocks upload when the API check fails' {
        Mock Invoke-RestMethod { throw 'Synthetic API failure' }
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*Could not verify*'
    }

    It 'blocks an unexpected API response instead of treating it as no releases' {
        Mock Invoke-RestMethod { [pscustomobject]@{ message = 'Synthetic invalid response' } }
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*unexpected release response*'
    }

    It 'requires authentication so drafts cannot be hidden from the check' {
        $env:GH_TOKEN = $null
        { Test-ReleaseTarget -Repository 'OJXW65A/WinDSH' -Tag 'v2.0.1' } | Should -Throw '*authenticated release check*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
}
