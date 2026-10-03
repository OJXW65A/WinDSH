# Edge cases found in the v2 audit. Registry writes use only the in-memory provider.
BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    foreach ($module in (Get-ChildItem (Join-Path $RepoRoot 'src') -Filter *.ps1 | Sort-Object Name)) {
        if ($module.Name -eq '70-main.ps1') {
            $body = (Get-Content -Raw $module.FullName) -split '# Invoke-Main sets', 2
            . ([scriptblock]::Create($body[0]))
        }
        else { . $module.FullName }
    }
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function Get-CimInstance { [CmdletBinding()]param([string]$Namespace, [string]$ClassName) throw 'CIM is unavailable on this test host.' }
    }
    function Initialize-CatalogValues {
        foreach ($control in $script:ControlCatalog) {
            foreach ($value in (ConvertTo-Array $control.LocalValues)) { & $script:Registry.SetValue $value.Path $value.Name $value.Type $value.Value }
        }
    }
}

Describe 'Audit defect regressions' {
    BeforeEach {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $script:TestJournalPath = Join-Path $TestDrive ('changes-{0}.jsonl' -f [Guid]::NewGuid())
        $script:RemediationAllowed = $true; $script:Unattended = $true
        $script:RestartRequired = $false; $script:AppliedChanges = @(); $script:RevertedChanges = @()
        $script:Warnings = @(); $script:ExitCode = 0; $script:UseColor = $false
        $script:InvocationParameters = @{}
        $AuditOnly = $false; $Rmm = $false; $Revert = $false
        $EnableAllSafe = $false; $Enable = $null; $RunId = $null
        $NoReport = $true; $AutoReboot = $false; $Explain = $null
        $HtmlReport = $false; $JsonReport = $false; $TextReport = $false
        $ReportDirectory = Join-Path $TestDrive ('reports-{0}' -f [Guid]::NewGuid())
        $SelfTest = $false; $Version = $false; $ListControls = $false
        $NoColor = $true; $DebugLogPath = $null; $Advanced = $false; $WhatIfPreference = $false
        $testState = New-SyntheticState
        Mock Test-IsElevated { $true }
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = 'OK' } }
        Mock Get-SystemState { $testState }
        Mock Get-CodeIntegrityEvents { [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null } }
        Mock Write-Line {}
        Mock Write-Section {}
    }

    It 'does not certify configured protections when Device Guard cannot be queried' {
        Initialize-CatalogValues
        Mock Get-CimInstance { throw 'Synthetic WMI failure' }
        $testState.DeviceGuard = Get-DeviceGuardState
        $testState.DeviceGuard.Error | Should -Match 'Synthetic WMI failure'
        $assessment = Get-Assessment $testState
        foreach ($id in @('vbs','hvci','credential-guard','secure-launch','kernel-shadow-stacks')) {
            $status = @($assessment.Statuses | Where-Object Id -eq $id)[0]
            $status.Configured | Should -BeTrue
            $status.RunningKnown | Should -BeFalse
            $status.Running | Should -BeFalse
            $status.State | Should -Be 'Unknown'
        }
        $assessment.Score.Score | Should -BeLessThan 100
        $assessment.Score.UnknownCount | Should -Be 5
        $assessment.Score.Grade | Should -Be 'Incomplete assessment'
        $assessment.SecuredCore.Qualifies | Should -BeFalse
        @($assessment.Cis.Rows | Where-Object { $_.ControlId -in @('vbs','hvci','credential-guard','secure-launch','kernel-shadow-stacks') -and $_.FeatureRunning }).Count | Should -Be 0
        (Get-StateLabel 'Unknown').Text | Should -Be 'Unable to verify'
    }

    It 'keeps a missing services property unknown even when the CIM instance exists' {
        Mock Get-CimInstance { [pscustomobject]@{ VirtualizationBasedSecurityStatus = 2 } }
        $testState.DeviceGuard = Get-DeviceGuardState
        $testState.DeviceGuard.Available | Should -BeTrue
        (Get-ControlStatus 'vbs' $testState).State | Should -Be 'Running'
        (Get-ControlStatus 'hvci' $testState).State | Should -Be 'Unknown'
    }

    It 'distinguishes shadow-stack <Expected> for services <Services>' -TestCases @(
        @{ Services = @(6); Expected = 'AuditMode'; Points = 0 }
        @{ Services = @(5); Expected = 'Running'; Points = 10 }
        @{ Services = @(5,6); Expected = 'Running'; Points = 10 }
    ) {
        param($Services, $Expected, $Points)
        $testState.DeviceGuard.Running = $Services
        $assessment = Get-Assessment $testState
        @($assessment.Statuses | Where-Object Id -eq 'kernel-shadow-stacks')[0].State | Should -Be $Expected
        @($assessment.Score.Breakdown | Where-Object Id -eq 'kernel-shadow-stacks')[0].Points | Should -Be $Points
        if ($Expected -eq 'AuditMode') {
            @($assessment.Explanations | Where-Object Id -eq 'kernel-shadow-stacks')[0].Verdict | Should -Match 'enforcement is not active'
            (Get-StateLabel $Expected).Text | Should -Match 'Audit only'
        }
    }

    It 'preserves existing locked enablement in preview and safe or explicit apply' {
        Initialize-CatalogValues
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 1
        & $script:Registry.SetValue $script:RegHvci 'Locked' 'DWord' 1
        & $script:Registry.SetValue $script:RegLsa 'LsaCfgFlags' 'DWord' 1
        $testState.DeviceGuard.VbsStatusCode = 2
        $testState.DeviceGuard.Running = @(1,2)
        @((Get-ChangePlan -Ids $script:SafeControlSet -State $testState) | Where-Object NeedsChange).Count | Should -Be 0
        (Invoke-ControlApply -Ids $script:SafeControlSet -State $testState).ChangeCount | Should -Be 0
        (Invoke-ControlApply -Ids @('credential-guard') -State $testState -ExplicitIds @('credential-guard')).ChangeCount | Should -Be 0
        Get-RegValue $script:RegDeviceGuard 'Locked' | Should -Be 1
        Get-RegValue $script:RegHvci 'Locked' | Should -Be 1
        Get-RegValue $script:RegLsa 'LsaCfgFlags' | Should -Be 1
        (Get-ControlStatus 'credential-guard' $testState).Configured | Should -BeTrue
    }

    It 'uses reversible defaults only for newly enabled settings' {
        $null = Invoke-ControlApply -Ids @('hvci','credential-guard') -State $testState
        Get-RegValue $script:RegDeviceGuard 'Locked' | Should -Be 0
        Get-RegValue $script:RegHvci 'Locked' | Should -Be 0
        Get-RegValue $script:RegLsa 'LsaCfgFlags' | Should -Be 2
    }

    It 'preserves documented platform-security value <Value>' -TestCases @(@{Value=1},@{Value=3}) {
        param($Value)
        & $script:Registry.SetValue $script:RegDeviceGuard 'RequirePlatformSecurityFeatures' 'DWord' $Value
        (Get-ControlStatus 'platform-security' $testState).Configured | Should -BeTrue
        (Get-ControlDelta 'platform-security').NeedsChange | Should -BeFalse
    }

    It 'blocks unrecognized platform-security value <Value> instead of treating it as stronger' -TestCases @(@{Value=2},@{Value=4}) {
        param($Value)
        & $script:Registry.SetValue $script:RegDeviceGuard 'RequirePlatformSecurityFeatures' 'DWord' $Value
        (Get-ControlStatus 'platform-security' $testState).State | Should -Be 'Unknown'
        foreach ($definition in (Get-Control 'vbs').LocalValues) { & $script:Registry.SetValue $definition.Path $definition.Name $definition.Type $definition.Value }
        $plan = @(Get-ChangePlan -Ids @('platform-security') -State $testState)
        @($plan | Where-Object ControlId -eq 'platform-security')[0].SkipReason | Should -Match 'unrecognized'
        (Invoke-ControlApply -Ids @('platform-security') -State $testState).ChangeCount | Should -Be 0
        Get-RegValue $script:RegDeviceGuard 'RequirePlatformSecurityFeatures' | Should -Be $Value
    }

    It 'propagates Windows provider access errors instead of reporting missing values' {
        Mock Test-Path { throw [UnauthorizedAccessException]::new('Synthetic access denied') } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
        $provider = New-RegistryProvider
        { & $provider.GetValue $script:RegPolicyDG 'EnableVirtualizationBasedSecurity' } | Should -Throw '*access denied*'
        { & $provider.ValueExists $script:RegPolicyDG 'EnableVirtualizationBasedSecurity' } | Should -Throw '*access denied*'
    }

    It 'blocks unreadable policy and its dependencies while retaining a diagnostic assessment' {
        Mock Test-Path { throw [UnauthorizedAccessException]::new('Synthetic policy access denied') } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
        Set-RegistryProvider (New-RegistryProvider)
        $testState.Policy = Get-PolicyState
        $testState.Policy.Available | Should -BeFalse
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $assessment = Get-Assessment $testState
        @($assessment.Cis.Rows | Where-Object PolicyKnown).Count | Should -Be 0
        @($script:Warnings | Where-Object { $_ -match 'Cannot read policy' }).Count | Should -BeGreaterThan 0
        $plan = @(Get-ChangePlan -Ids @('hvci') -State $testState)
        @($plan | Where-Object { -not $_.SkipReason }).Count | Should -Be 0
        (Invoke-ControlApply -Ids @('hvci') -State $testState).ChangeCount | Should -Be 0
        $script:Registry.Store.Count | Should -Be 0
    }

    It 'distinguishes genuine policy absence from unavailable policy' {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like 'HKLM:*' }
        Set-RegistryProvider (New-RegistryProvider)
        $testState.Policy = Get-PolicyState
        $testState.Policy.Available | Should -BeTrue
        $testState.Policy.AnyConfigured | Should -BeFalse
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        (Invoke-ControlApply -Ids @('vbs') -State $testState).ChangeCount | Should -Be 2
    }

    It 'blocks a local before-state read failure without overwriting the value' {
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 0
        $script:Registry.GetValue = { throw 'Synthetic local registry failure' }
        $plan = @(Get-ChangePlan -Ids @('driver-blocklist') -State $testState)
        $plan[0].SkipReason | Should -Match 'Cannot read'
        (Invoke-ControlApply -Ids @('driver-blocklist') -State $testState).ChangeCount | Should -Be 0
        $script:Registry.Store[($script:RegCiConfig + '|VulnerableDriverBlocklistEnable')] | Should -Be 0
        @(Get-Journal).Count | Should -Be 0
    }

    It 'normalizes comma-separated and spaced IDs before native relaunch' -TestCases @(
        @{ Ids = @(' HVCI, driver-blocklist ') }
        @{ Ids = @(' HVCI ', ' driver-blocklist ') }
        @{ Ids = @('hvci,driver-blocklist,hvci') }
    ) {
        param($Ids)
        $argv = @(Get-RelaunchArgumentList -Bound @{ Enable = $Ids })
        $argv.Count | Should -Be 2
        $argv[0] | Should -Be '-Enable'
        $argv[1] | Should -Be '"hvci,driver-blocklist"'
    }

    It 'forwards the same canonical Enable intent validated by main' {
        $Enable = @(' HVCI, driver-blocklist ')
        $script:InvocationParameters = @{ Enable = $Enable; ReportDirectory = 'C:\Reports with spaces' }
        Mock Test-IsElevated { $false }
        Mock Request-Elevation { $script:ForwardedArguments = $Bound; $true }
        Invoke-Main
        $script:ForwardedArguments.Enable -join ',' | Should -Be 'hvci,driver-blocklist'
        $script:ForwardedArguments.ReportDirectory | Should -Be 'C:\Reports with spaces'
    }

    It 'rejects invalid native Enable content before it can cross elevation' -TestCases @(
        @{ Ids = @('hvci,,driver-blocklist') }
        @{ Ids = @('hvci,not-a-control') }
        @{ Ids = @('hvci" -AutoReboot') }
    ) {
        param($Ids)
        { Get-RelaunchArgumentList -Bound @{ Enable = $Ids } } | Should -Throw '*Unknown control*'
    }

    It 'disables changes for every unverified integrity status: <Status>' -TestCases @(
        @{ Status = 'Failed' }, @{ Status = 'Error' }, @{ Status = 'Skipped' }
        @{ Status = 'Unsigned' }, @{ Status = 'Unknown' }
    ) {
        param($Status)
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = $Status } }
        $Enable = @('driver-blocklist'); $Rmm = $true
        $lines = @(Invoke-EntryPoint)
        $lines.Count | Should -Be 1
        ($lines[0] | ConvertFrom-Json).exitCode | Should -Be 3
        $script:RemediationAllowed | Should -BeFalse
        $script:Registry.Store.Count | Should -Be 0
        Test-Path $script:TestJournalPath | Should -BeFalse
    }

    It 'blocks revert on unverified integrity without opening a journal' {
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = 'Error' } }
        $Revert = $true; $RunId = 'unused'; $Rmm = $true
        $lines = @(Invoke-EntryPoint)
        ($lines[0] | ConvertFrom-Json).exitCode | Should -Be 3
        Test-Path $script:TestJournalPath | Should -BeFalse
    }

    It 'retains the integrity failure exit code during a read-only explanation' {
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = 'Failed' } }
        $Explain = 'driver-blocklist'
        Invoke-Main
        $script:ExitCode | Should -Be 3
    }

    It 'continues a read-only audit while reporting unverifiable integrity' {
        Mock Get-SelfIntegrity { [pscustomobject]@{ Status = 'Error' } }
        $AuditOnly = $true; $Rmm = $true
        $lines = @(Invoke-EntryPoint)
        $payload = $lines[0] | ConvertFrom-Json
        $payload.exitCode | Should -Be 3
        $payload.controls.Count | Should -Be 11
        $script:Registry.Store.Count | Should -Be 0
    }

    It 'reports the actual writes made by an unattended rollback' {
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 0
        $run = Invoke-ControlApply -Ids @('driver-blocklist') -State $testState
        $script:AppliedChanges = @(); $script:RestartRequired = $false
        $Revert = $true; $RunId = $run.RunId; $Rmm = $true
        $lines = @(Invoke-EntryPoint)
        $lines.Count | Should -Be 1
        $payload = $lines[0] | ConvertFrom-Json
        $payload.exitCode | Should -Be 3010
        $payload.changes | Should -Be 1
        $payload.appliedChangeCount | Should -Be 0
        $payload.revertedChangeCount | Should -Be 1
        Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' | Should -Be 0
        $script:RevertedChanges[0].RunId | Should -Be $run.RunId
        $script:RevertedChanges[0].Before | Should -Be 1
        $script:RevertedChanges[0].RestoredTo | Should -Be 0

        $NoReport = $false
        $assessment = Get-Assessment $testState
        $args = @{ State = $testState; Statuses = $assessment.Statuses; Score = $assessment.Score; SecuredCore = $assessment.SecuredCore; Cis = $assessment.Cis; Explanations = $assessment.Explanations }
        $paths = @(Save-Reports @args -Formats @{ Html = $true; Text = $true; Json = $true })
        $json = Get-Content -Raw ($paths | Where-Object { $_ -like '*.json' }) | ConvertFrom-Json
        $json.RevertedChanges.Count | Should -Be 1
        $json.RevertedChanges[0].RestoredTo | Should -Be 0
        (Get-Content -Raw ($paths | Where-Object { $_ -like '*.txt' })) | Should -Match 'CHANGES REVERTED IN THIS SESSION'
        (Get-Content -Raw ($paths | Where-Object { $_ -like '*.html' })) | Should -Match 'Changes reverted in this session'
    }

    It 'counts successful rollback writes even when another value conflicts' {
        $run = Invoke-ControlApply -Ids @('vbs') -State $testState
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 2
        $script:AppliedChanges = @(); $script:RestartRequired = $false
        $Revert = $true; $RunId = $run.RunId; $Rmm = $true
        $payload = (Invoke-EntryPoint) | ConvertFrom-Json
        $payload.exitCode | Should -Be 5
        $payload.changes | Should -Be 1
        $payload.revertedChangeCount | Should -Be 1
        Get-RegValue $script:RegDeviceGuard 'Locked' | Should -Be 2
    }

    It 'does not count a rollback preview as a registry change' {
        $run = Invoke-ControlApply -Ids @('driver-blocklist') -State $testState
        $script:AppliedChanges = @(); $script:RestartRequired = $false
        $Revert = $true; $RunId = $run.RunId; $Rmm = $true; $WhatIfPreference = $true
        $payload = (Invoke-EntryPoint) | ConvertFrom-Json
        $payload.changes | Should -Be 0
        $payload.revertedChangeCount | Should -Be 0
        Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' | Should -Be 1
    }

    It 'does not count recovery of a completed but unmarked rollback as another write' {
        $run = Invoke-ControlApply -Ids @('driver-blocklist') -State $testState
        $entry = @(Get-Journal -RunId $run.RunId | Where-Object RecordType -eq 'Change')[0]
        Write-JournalMarker -RunId $run.RunId -RecordType 'RevertStarted' -ChangeId $entry.ChangeId
        & $script:Registry.RemoveValue $entry.Path $entry.Name
        $script:AppliedChanges = @(); $script:RestartRequired = $false
        $result = Invoke-ControlRevert -RunId $run.RunId
        $result.RecoveredCount | Should -Be 1
        $result.ChangeCount | Should -Be 0
        $script:RevertedChanges.Count | Should -Be 0
    }

    It 'preserves each report when two assessments are saved in the same second' {
        Mock Get-Date { [datetime]'2026-10-03T12:00:00' }
        $NoReport = $false
        $assessment = Get-Assessment $testState
        $args = @{ State = $testState; Statuses = $assessment.Statuses; Score = $assessment.Score; SecuredCore = $assessment.SecuredCore; Cis = $assessment.Cis; Explanations = $assessment.Explanations }
        $first = @(Save-Reports @args -Formats @{ Html = $true; Text = $true; Json = $true })
        $snapshot = @{}
        foreach ($path in $first) { $snapshot[$path] = [IO.File]::ReadAllText($path) }
        $testState.Computer.Model = 'Second assessment'
        $second = @(Save-Reports @args -Formats @{ Html = $true; Text = $true; Json = $true })
        @($first + $second | Select-Object -Unique).Count | Should -Be 6
        foreach ($path in $first) { [IO.File]::ReadAllText($path) | Should -BeExactly $snapshot[$path] }
        $json = Get-Content -Raw ($second | Where-Object { $_ -like '*.json' }) | ConvertFrom-Json
        $json.Computer.Model | Should -Be 'Second assessment'
    }

    It 'refuses to replace an existing report even with an explicitly colliding path' {
        $path = Join-Path $TestDrive 'existing-report.txt'
        [IO.File]::WriteAllText($path, 'Original report')
        { Write-ReportFile -Path $path -Content 'Replacement' } | Should -Throw
        [IO.File]::ReadAllText($path) | Should -BeExactly 'Original report'
    }

    It 'requests a full refresh when the user chooses Re-check' {
        $script:MenuReads = 0
        Mock Read-Choice { $script:MenuReads++; if ($script:MenuReads -eq 1) { '1' } else { 'Q' } }
        Mock Wait-ForKey {}
        Mock Show-Menu {}
        Mock Show-Summary {}
        Mock Show-NextSteps {}
        Invoke-Interactive -State $testState
        Should -Invoke Get-SystemState -Times 1 -Exactly -ParameterFilter { -not [bool]$Volatile }
        Should -Invoke Get-SystemState -Times 0 -Exactly -ParameterFilter { [bool]$Volatile }
    }

    It 'renders valid fractional SVG numbers with the <Culture> locale' -TestCases @(
        @{ Culture = 'fr-FR' }, @{ Culture = 'de-DE' }, @{ Culture = 'en-US' }
    ) {
        param($Culture)
        $previous = [Globalization.CultureInfo]::CurrentCulture
        try {
            [Globalization.CultureInfo]::CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo($Culture)
            & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
            $assessment = Get-Assessment $testState
            $assessment.Score.Score | Should -BeGreaterThan 0
            $assessment.Score.Score | Should -BeLessThan 100
            $html = New-HtmlReport -State $testState -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations
            $dash = [regex]::Match($html, 'stroke-dasharray="([0-9]+\.[0-9]+) ([0-9]+\.[0-9]+)"')
            $dash.Success | Should -BeTrue
            $sum = [double]::Parse($dash.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) + [double]::Parse($dash.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
            [math]::Abs($sum - 439.82) | Should -BeLessThan 0.01
        }
        finally { [Globalization.CultureInfo]::CurrentCulture = $previous }
    }
}

Describe 'Shared hardware collection' {
    BeforeEach {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $script:StaticState = $null
        $script:BootBlocks = $false
        $sample = New-SyntheticState
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_OperatingSystem' { [pscustomobject]@{ BuildNumber = '22631'; Caption = 'Windows 11'; DataExecutionPrevention_SupportPolicy = 3; DataExecutionPrevention_Available = $true } }
                'Win32_ComputerSystem' { [pscustomobject]@{ Manufacturer = 'Test'; Model = 'Test PC'; HypervisorPresent = $true } }
                'Win32_Processor' { [pscustomobject]@{ Name = 'Test CPU'; VirtualizationFirmwareEnabled = $false; SecondLevelAddressTranslationExtensions = $true } }
                default { throw ('Unexpected CIM query: {0}' -f $ClassName) }
            }
        }
        Mock Get-FirmwareState { $sample.Firmware }
        Mock Get-TpmState { $sample.Tpm }
        Mock Get-HypervisorLaunchState { [pscustomobject]@{ BlocksVbs = $script:BootBlocks; LaunchType = $(if ($script:BootBlocks) { 'Off' } else { 'Auto' }); Source = 'Test'; Error = $null } }
        Mock Get-DeviceGuardState { $sample.DeviceGuard }
        Mock Get-PolicyState { $sample.Policy }
        Mock Get-PendingRestartState { $sample.Restart }
    }

    It 'queries each hardware class once and reuses the snapshot after local changes' {
        $state = Get-SystemState
        $state.Computer.BuildNumber | Should -Be 22631
        $state.Computer.ProcessorName | Should -Be 'Test CPU'
        $state.Virtualization.FirmwareEnabled | Should -BeTrue
        $state.Virtualization.Slat | Should -BeTrue
        $state.Dep.SupportPolicy | Should -Be 3
        $state.Dep.Enabled | Should -BeTrue
        $null = Get-SystemState -Volatile
        foreach ($class in @('Win32_OperatingSystem','Win32_ComputerSystem','Win32_Processor')) {
            Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter { $ClassName -eq $class }
        }
    }

    It 'refreshes externally changed boot settings during a full re-check' {
        (Get-SystemState).HypervisorLaunch.BlocksVbs | Should -BeFalse
        $script:BootBlocks = $true
        (Get-SystemState -Volatile).HypervisorLaunch.BlocksVbs | Should -BeFalse
        (Get-SystemState).HypervisorLaunch.BlocksVbs | Should -BeTrue
        Should -Invoke Get-HypervisorLaunchState -Times 2 -Exactly
    }

    It 'does not retry failed hardware queries or invent missing evidence' {
        Mock Get-CimInstance { throw 'Synthetic unavailable OS' } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        $state = Get-SystemState
        $state.Computer.BuildNumber | Should -Be 0
        $state.Dep.SupportPolicy | Should -BeNullOrEmpty
        $state.Dep.Enabled | Should -BeFalse
        (Get-ControlStatus 'dep' $state).State | Should -Be 'Unknown'
        Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
    }
}

Describe 'Self-integrity metadata validation' {
    BeforeAll {
        $tokens = $null; $parseErrors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'src/10-core.ps1'), [ref]$tokens, [ref]$parseErrors)
        $integrityFunction = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-SelfIntegrity' }, $true).Extent.Text
        $PowerShellExe = (Get-Process -Id $PID).Path
    }
    It 'validates a complete marker and rejects <Mutation>' -TestCases @(
        @{ Mutation = 'none'; Expected = 'OK' }
        @{ Mutation = 'short'; Expected = 'Failed' }
        @{ Mutation = 'nonhex'; Expected = 'Failed' }
        @{ Mutation = 'missing'; Expected = 'Failed' }
        @{ Mutation = 'duplicate'; Expected = 'Failed' }
        @{ Mutation = 'placeholder'; Expected = 'Unsigned' }
    ) {
        param($Mutation, $Expected)
        $placeholder = "`$script:ExpectedIntegrityHash = '{0}'" -f ('0' * 64)
        $body = $placeholder + "`nfunction Write-DebugError {} `n" + $integrityFunction + "`nGet-SelfIntegrity | ConvertTo-Json -Compress`n"
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($body)))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $marker = "`$script:ExpectedIntegrityHash = '$hash'"
        $body = $body.Replace($placeholder, $marker)
        switch ($Mutation) {
            'short' { $body = $body.Replace($hash, $hash.Substring(0, 63)) }
            'nonhex' { $body = $body.Replace($hash, ('z' * 64)) }
            'missing' { $body = $body.Replace($marker, '') }
            'duplicate' { $body = $marker + "`n" + $body }
            'placeholder' { $body = $body.Replace($marker, $placeholder) }
        }
        $path = Join-Path $TestDrive ('integrity-{0}.ps1' -f $Mutation)
        [IO.File]::WriteAllText($path, $body)
        $lines = @(& $PowerShellExe -NoProfile -NonInteractive -File $path)
        $LASTEXITCODE | Should -Be 0
        ($lines[0] | ConvertFrom-Json).Status | Should -Be $Expected
    }
}
