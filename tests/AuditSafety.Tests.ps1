# Behaviour regressions run on both supported PowerShell runtimes. Only the
# disposable-key provider test and native Windows argv test need Windows.
BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    foreach ($module in (Get-ChildItem (Join-Path $RepoRoot 'src') -Filter *.ps1 | Sort-Object Name)) {
        if ($module.Name -eq '70-main.ps1') {
            $body = (Get-Content -Raw $module.FullName) -split '# Invoke-Main sets', 2
            . ([scriptblock]::Create($body[0]))
        }
        else { . $module.FullName }
    }
    $PowerShellExe = (Get-Process -Id $PID).Path
    $OnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

Describe 'Safety decisions and consistent projections' {
    BeforeEach {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $script:TestJournalPath = Join-Path $TestDrive ('changes-{0}.jsonl' -f [Guid]::NewGuid())
        $script:RemediationAllowed = $true
        $script:Unattended = $true
        $script:RestartRequired = $false
        $script:AppliedChanges = @()
        $script:Warnings = @()
        $script:ExitCode = 0
        $script:UseColor = $false
        $AuditOnly = $false; $Rmm = $false; $Revert = $false
        $EnableAllSafe = $false; $Enable = $null; $RunId = $null
        $NoReport = $true; $AutoReboot = $false; $Explain = $null
        $HtmlReport = $false; $JsonReport = $false; $TextReport = $false
        $ReportDirectory = Join-Path $TestDrive ('reports-{0}' -f [Guid]::NewGuid())
        $SelfTest = $false; $Version = $false; $ListControls = $false
        $NoColor = $true; $DebugLogPath = $null; $Advanced = $false
        $WhatIfPreference = $false
        $testState = New-SyntheticState
        Mock Test-IsElevated { $true }
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = 'Verified' } }
        Mock Get-SystemState { $testState }
        Mock Get-CodeIntegrityEvents { [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null } }
        Mock Write-Line {}
        Mock Write-Section {}
    }

    It 'requires actual typed consent for an explicit interactive HVCI override' {
        Mock Get-CodeIntegrityEvents { [pscustomobject]@{ Queried = $true; EventCount = 1; Drivers = @(); Newest = $null; Error = $null } }
        $script:Unattended = $false
        Mock Read-Host { 'hvci' } -ParameterFilter { $Prompt -like 'Enable * anyway?' }
        Mock Read-Host { 'yes' } -ParameterFilter { $Prompt -like 'Continue?*' }
        $result = Invoke-ControlApply -Ids @('hvci') -State $testState -ExplicitIds @('hvci')
        $result.ChangeCount | Should -Be 5
        Get-RegValue $script:RegHvci 'Enabled' | Should -Be 1
        Should -Invoke Read-Host -Times 1 -ParameterFilter { $Prompt -like 'Enable * anyway?' }
    }

    It 'declining a typed override leaves HVCI unchanged' {
        Mock Get-CodeIntegrityEvents { [pscustomobject]@{ Queried = $true; EventCount = 1; Drivers = @(); Newest = $null; Error = $null } }
        $script:Unattended = $false
        Mock Read-Host { 'no' } -ParameterFilter { $Prompt -like 'Enable * anyway?' }
        Mock Read-Host { 'yes' } -ParameterFilter { $Prompt -like 'Continue?*' }
        $result = Invoke-ControlApply -Ids @('hvci') -State $testState -ExplicitIds @('hvci')
        $result.Skipped.ControlId | Should -Contain 'hvci'
        Test-RegValue $script:RegHvci 'Enabled' | Should -BeFalse
    }

    It 'safe-set preview and execution share the failed-query safety decision' {
        Mock Get-CodeIntegrityEvents { [pscustomobject]@{ Queried = $false; EventCount = 0; Drivers = @(); Newest = $null; Error = 'Access denied' } }
        $plan = @(Get-ChangePlan -Ids $script:SafeControlSet -State $testState)
        $result = Invoke-ControlApply -Ids $script:SafeControlSet -State $testState
        $blocked = @($plan | Where-Object ControlId -eq 'hvci')[0]
        @($result.Skipped | Where-Object ControlId -eq 'hvci')[0].Reason | Should -Be $blocked.SkipReason
        Test-RegValue $script:RegHvci 'Enabled' | Should -BeFalse
    }

    It 'WhatIf never creates a journal or lock or changes the provider' {
        $result = Invoke-ControlApply -Ids @('driver-blocklist') -State $testState -WhatIf
        $result.ChangeCount | Should -Be 0
        $script:Registry.Store.Count | Should -Be 0
        Test-Path $script:TestJournalPath | Should -BeFalse
        Test-Path ($script:TestJournalPath + '.lock') | Should -BeFalse
    }

    It 'records and returns the same final exit code in RMM output' {
        $AuditOnly = $true; $Rmm = $true
        $testState.Computer.IsVirtual = $true
        $lines = @(Invoke-Main)
        $lines.Count | Should -Be 1
        $payload = $lines[0] | ConvertFrom-Json
        $payload.exitCode | Should -Be 2
        $script:ExitCode | Should -Be $payload.exitCode
    }

    It 'writes explicitly requested RMM reports while emitting only one JSON object' {
        $AuditOnly = $true; $Rmm = $true; $NoReport = $false; $TextReport = $true
        $lines = @(Invoke-Main)
        $lines.Count | Should -Be 1
        @((Get-ChildItem $ReportDirectory -Filter *.txt)).Count | Should -Be 1
        @((Get-ChildItem $ReportDirectory -Filter *.html)).Count | Should -Be 0
        ($lines[0] | ConvertFrom-Json).exitCode | Should -Be $script:ExitCode
    }

    It 'does not write default report files for RMM audit' {
        $AuditOnly = $true; $Rmm = $true; $NoReport = $false
        $lines = @(Invoke-Main)
        $lines.Count | Should -Be 1
        Test-Path $ReportDirectory | Should -BeFalse
    }

    It 'returns revert conflicts as failure instead of restart success in RMM mode' {
        $run = Invoke-ControlApply -Ids @('vbs') -State $testState
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 2
        $script:RestartRequired = $false
        $Revert = $true; $RunId = $run.RunId; $Rmm = $true
        $lines = @(Invoke-Main)
        $lines.Count | Should -Be 1
        ($lines[0] | ConvertFrom-Json).exitCode | Should -Be 5
        ($lines[0] | ConvertFrom-Json).restartRequired | Should -BeTrue
        Get-RegValue $script:RegDeviceGuard 'Locked' | Should -Be 2
    }

    It 'refreshes all report projections after interactive safe remediation' {
        $script:Unattended = $false
        $script:MenuReads = 0
        Mock Read-Choice {
            $script:MenuReads++
            if ($script:MenuReads -eq 1) { '2' } else { 'Q' }
        }
        Mock Read-Host { 'yes' }
        Mock Wait-ForKey {}
        Mock Save-Reports {
            $script:SavedAssessment = [pscustomobject]@{ Statuses = $Statuses; Cis = $Cis; Score = $Score; SecuredCore = $SecuredCore; Explanations = $Explanations }
            @()
        }
        Invoke-Interactive -State $testState
        $fresh = Get-Assessment -State $testState
        $script:SavedAssessment.Score.Score | Should -Be $fresh.Score.Score
        @($script:SavedAssessment.Explanations | Where-Object Id -eq 'driver-blocklist')[0].Status.Configured | Should -BeTrue
        @($script:SavedAssessment.Explanations | Where-Object Id -eq 'hvci')[0].Status.Configured | Should -BeTrue
        $script:SavedAssessment.Cis.RunningButNotCompliantCount | Should -Be $fresh.Cis.RunningButNotCompliantCount
    }

    It 'reverts repeated writes to the same registry value in reverse order' {
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        # Two independent completed intents on the same target in one run.
        foreach ($change in @(@('first', 0), @('second', 1))) {
            Write-JournalEntry ([pscustomobject]@{ RecordType = 'Change'; ChangeId = $change[0]; RunId = 'repeated'; Time = (Get-Date).ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = $change[1]; AfterValue = 1 })
            Write-JournalMarker -RunId 'repeated' -RecordType 'Applied' -ChangeId $change[0]
        }
        $result = Invoke-ControlRevert -RunId 'repeated'
        $result.ChangeCount | Should -Be 2
        Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' | Should -Be 0
    }
}

Describe 'Windows provider and privilege-boundary argv' {
    It 'round-trips hostile scalar values through a real Windows child process' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $child = Join-Path $TestDrive 'argv-child.ps1'
        [IO.File]::WriteAllText($child, 'param([string]$ReportDirectory,[string]$DebugLogPath,[string[]]$Enable,[switch]$AuditOnly,[switch]$AutoReboot) $PSBoundParameters | ConvertTo-Json -Compress')
        $cases = @('C:\Reports with spaces\', 'C:\x" -Enable credential-guard "', '" -AutoReboot #', 'literal $() ` ; & | <>', '', 'ends in backslashes\\')
        foreach ($value in $cases) {
            $bound = @{ ReportDirectory = $value; DebugLogPath = $value; AuditOnly = [switch]$true; AutoReboot = [switch]$false; Enable = @('hvci', 'driver-blocklist') }
            $stdout = Join-Path $TestDrive 'stdout.txt'; $stderr = Join-Path $TestDrive 'stderr.txt'
            $argv = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', (ConvertTo-NativeArgument $child)) + @(Get-RelaunchArgumentList -Bound $bound)
            $proc = Start-Process -FilePath $PowerShellExe -ArgumentList $argv -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            $proc.ExitCode | Should -Be 0 -Because ([IO.File]::ReadAllText($stderr))
            $received = [IO.File]::ReadAllText($stdout) | ConvertFrom-Json
            $received.ReportDirectory | Should -BeExactly $value
            $received.DebugLogPath | Should -BeExactly $value
            $received.AuditOnly | Should -BeTrue
            (Get-PropertySafe $received 'AutoReboot' $false) | Should -BeFalse
            @($received.Enable)[0] | Should -Be 'hvci,driver-blocklist'
        }
    }

    It 'applies and reverts using the real Windows provider on a disposable key' -Skip:([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $key = 'HKLM:\SOFTWARE\WinDSHTests\' + [Guid]::NewGuid().ToString('N')
        $journalPath = Join-Path $TestDrive 'private-journal\changes.jsonl'
        $savedCatalog = $script:ControlCatalog
        $savedProvider = $script:Registry
        $savedUnattended = $script:Unattended
        try {
            $script:ControlCatalog += [pscustomobject]@{
                Id = 'provider-test'; Name = 'Provider test'; PlainName = 'Provider test'; Category = 'Test'
                PlatformRequirements = @(); Weight = 0; Remediable = $true; DetectionOnly = $false
                Requires = @(); DetectKey = 'ProviderTest'; PolicyValues = @(); Cis = $null
                LocalValues = @(@{ Path = $key; Name = 'Disposable'; Type = 'DWord'; Value = 1; Note = 'CI fixture' })
            }
            Set-RegistryProvider (New-RegistryProvider)
            $script:RemediationAllowed = $true; $script:Unattended = $true
            Mock Get-JournalPath { $journalPath }
            $result = Invoke-ControlApply -Ids @('provider-test') -State (New-SyntheticState)
            $result.ChangeCount | Should -Be 1
            (Get-ItemProperty $key).Disposable | Should -Be 1
            $acl = Get-Acl (Split-Path $journalPath -Parent)
            $acl.AreAccessRulesProtected | Should -BeTrue
            @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544') }).Count | Should -Be 0
            $revertResult = Invoke-ControlRevert -RunId $result.RunId
            $revertResult.ChangeCount | Should -Be 1
            Test-RegValue $key 'Disposable' | Should -BeFalse
        }
        finally {
            Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
            $script:ControlCatalog = $savedCatalog
            Set-RegistryProvider $savedProvider
            $script:Unattended = $savedUnattended
        }
    }
}
