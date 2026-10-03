# Runs on Windows PowerShell 5.1 and PowerShell 7 in the existing CI matrix.
BeforeAll {
    $DownloadRepo = Split-Path -Parent $PSScriptRoot
    $DownloadBuild = Join-Path $DownloadRepo 'build/Build-Download.ps1'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
}

Describe 'Public download ZIP' {
    It 'contains exactly the launcher and application at the archive root, byte for byte' {
        $zipPath = Join-Path $TestDrive 'download/WinDSH.zip'
        & $DownloadBuild -OutputPath $zipPath
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            @($archive.Entries).Count | Should -Be 2
            (@($archive.Entries.FullName) | Sort-Object) -join ',' |
                Should -Be 'Run-WinDSH-AsAdmin.bat,WinDSH.ps1'
            foreach ($entry in $archive.Entries) {
                $stream = $entry.Open()
                $sha = [Security.Cryptography.SHA256]::Create()
                try {
                    $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '')
                    $hash | Should -Be (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $DownloadRepo $entry.FullName)).Hash
                }
                finally { $sha.Dispose(); $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }

    It 'replaces an existing archive without retaining extra files' {
        $zipPath = Join-Path $TestDrive 'replace.zip'
        $extra = Join-Path $TestDrive 'extra.txt'
        Set-Content -LiteralPath $extra -Value 'Old archive content'
        Compress-Archive -LiteralPath $extra -DestinationPath $zipPath
        & $DownloadBuild -OutputPath $zipPath
        $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            (@($archive.Entries.FullName) | Sort-Object) -join ',' |
                Should -Be 'Run-WinDSH-AsAdmin.bat,WinDSH.ps1'
        }
        finally { $archive.Dispose() }
    }

    It 'fails before creating a ZIP when a required file is missing' {
        $fixture = Join-Path $TestDrive 'missing'
        $buildDir = Join-Path $fixture 'build'
        $null = New-Item -ItemType Directory -Path $buildDir
        $fixtureBuild = Join-Path $buildDir 'Build-Download.ps1'
        Copy-Item -LiteralPath $DownloadBuild -Destination $fixtureBuild
        Copy-Item -LiteralPath (Join-Path $DownloadRepo 'Run-WinDSH-AsAdmin.bat') -Destination $fixture
        $zipPath = Join-Path $fixture 'WinDSH.zip'
        { & $fixtureBuild -OutputPath $zipPath } | Should -Throw '*Download payload file missing: WinDSH.ps1*'
        Test-Path -LiteralPath $zipPath | Should -BeFalse
    }
}
