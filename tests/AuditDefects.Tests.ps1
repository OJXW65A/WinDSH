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
}
