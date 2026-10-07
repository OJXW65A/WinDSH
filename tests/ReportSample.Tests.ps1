BeforeAll {
    $SampleRepo = Split-Path -Parent $PSScriptRoot
    $SampleBuild = Join-Path $SampleRepo 'build/Build-ReportSample.ps1'
    . (Join-Path $PSScriptRoot 'TestSupport.ps1')
    $SampleHost = Get-TestPowerShellPath
}

Describe 'Public report sample' {
    It 'rebuilds the checked-in fixture from synthetic inputs' {
        $samplePath = Join-Path $TestDrive 'sample.html'
        & $SampleHost -NoLogo -NoProfile -NonInteractive -File $SampleBuild -OutputPath $samplePath | Out-Null
        $LASTEXITCODE | Should -Be 0
        $actual = [IO.File]::ReadAllText($samplePath)
        $expected = [IO.File]::ReadAllText((Join-Path $SampleRepo 'docs/samples/WinDSH-sample.html'))
        $actual | Should -BeExactly $expected
        $actual | Should -Match 'Illustrative sample - synthetic data'
        $actual | Should -Match 'SAMPLE-PC'
        $actual | Should -Match '2026-10-07 00:00:00'
    }

    It 'keeps incomplete evidence visible in a self-contained sample' {
        $html = Get-Content -Raw (Join-Path $SampleRepo 'docs/samples/WinDSH-sample.html')
        $html | Should -Match 'Incomplete assessment'
        $html | Should -Match 'Unable to verify'
        $html | Should -Match 'Configured; not active'
        $html | Should -Not -Match '<script|https?://[^"\s]*\.(css|js)'
    }

    It 'has a PNG preview at the documented viewport size' {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $SampleRepo 'assets/report-preview.png'))
        ([BitConverter]::ToString($bytes[0..7])) | Should -Be '89-50-4E-47-0D-0A-1A-0A'
        $width = [int]$bytes[16] * 16777216 + [int]$bytes[17] * 65536 + [int]$bytes[18] * 256 + [int]$bytes[19]
        $height = [int]$bytes[20] * 16777216 + [int]$bytes[21] * 65536 + [int]$bytes[22] * 256 + [int]$bytes[23]
        $width | Should -Be 1080
        $height | Should -Be 1280
    }
}
