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
