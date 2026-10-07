# Missing evidence must not look like a confirmed hardware limit or a safe firmware change.
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
        function Get-CimInstance { [CmdletBinding()]param([string]$Namespace, [string]$ClassName) throw 'CIM unavailable.' }
    }
    if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) {
        function Get-Tpm { [CmdletBinding()]param() throw 'TPM provider unavailable.' }
    }
}

Describe 'Platform evidence safety' {
    BeforeEach {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $testState = New-SyntheticState
        $script:Warnings = @(); $script:RestartRequired = $false
        Mock Get-CodeIntegrityEvent { [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null } }
    }

    It 'retains unverified prerequisites in scoring and blocks remediation: <Case>' -TestCases @(
        @{ Case = 'firmware'; Id = 'vbs'; Missing = 'Firmware' }
        @{ Case = 'virtualization'; Id = 'hvci'; Missing = 'Virtualization' }
        @{ Case = 'TPM'; Id = 'secure-launch'; Missing = 'Tpm' }
        @{ Case = 'edition'; Id = 'credential-guard'; Missing = 'Edition' }
        @{ Case = 'build'; Id = 'kernel-shadow-stacks'; Missing = 'Build' }
        @{ Case = 'boot configuration'; Id = 'vbs'; Missing = 'Boot' }
    ) {
        param($Case, $Id, $Missing)
        switch ($Missing) {
            'Firmware' { $testState.Firmware.Mode = 'Unknown'; $testState.Firmware.IsUefiConfirmed = $false }
            'Virtualization' { $testState.Virtualization = [pscustomobject]@{ FirmwareEnabled = $false; FirmwareKnown = $false; FirmwareRaw = $null; HypervisorPresent = $false; Slat = $null } }
            'Tpm' { $testState.Tpm = [pscustomobject]@{ Present = $false; IsTPM2 = $false; IsTPM2Known = $false; SpecVersion = $null; Ready = $null } }
            'Edition' { $testState.Computer.EditionId = '' }
            'Build' { $testState.Computer.BuildNumber = 0 }
            'Boot' { $testState.HypervisorLaunch = [pscustomobject]@{ LaunchType = $null; Source = 'Unavailable'; BlocksVbs = $false; Error = 'Access denied' } }
        }
        $status = Get-ControlStatus $Id $testState
        $status.State | Should -Be 'Unknown'
        $status.SupportKnown | Should -BeFalse
        $status.Supported | Should -BeFalse
        $score = Get-SecurityScore @($status)
        $score.Possible | Should -Be $status.Weight
        $score.ExcludedCount | Should -Be 0
        $score.ApplicableCount | Should -Be 1
        $score.Grade | Should -Be 'Incomplete assessment'
        @(Get-ChangePlan @($Id) $testState | Where-Object { $_.ControlId -eq $Id -and -not $_.SkipReason }).Count | Should -Be 0
        (Get-ControlExplanation $Id $testState).Verdict | Should -Match 'prerequisite'
    }

    It 'keeps confirmed Legacy firmware excluded' {
        $testState.Firmware.Mode = 'Legacy'; $testState.Firmware.IsUefiConfirmed = $false; $testState.Firmware.IsLegacyConfirmed = $true
        $status = Get-ControlStatus 'vbs' $testState
        $status.State | Should -Be 'NotSupported'
        $status.SupportKnown | Should -BeTrue
    }

    It 'does not infer disabled virtualization from missing CPU evidence' {
        $probe = Get-VirtualizationState ([pscustomobject]@{ ComputerSystem = $null; Processors = @() })
        $probe.FirmwareKnown | Should -BeFalse
        $testState.Virtualization = $probe
        (Get-ControlStatus 'vbs' $testState).State | Should -Be 'Unknown'
    }

    It 'accepts an active hypervisor as proof even with missing CPU evidence' {
        $probe = Get-VirtualizationState ([pscustomobject]@{ ComputerSystem = [pscustomobject]@{ HypervisorPresent = $true }; Processors = @() })
        $probe.FirmwareKnown | Should -BeTrue
        $probe.FirmwareEnabled | Should -BeTrue
    }

    It 'keeps a failed TPM query unknown' {
        Mock Get-Tpm { throw 'Access denied' }
        Mock Get-CimInstance { throw 'Access denied' }
        (Get-TpmState).IsTPM2Known | Should -BeFalse
    }

    It 'recognizes confirmed absence and a confirmed TPM 1.2' {
        Mock Get-Tpm { [pscustomobject]@{ TpmPresent = $false; TpmReady = $false } }
        Mock Get-CimInstance { $null }
        $absent = Get-TpmState
        $absent.IsTPM2Known | Should -BeTrue
        $absent.IsTPM2 | Should -BeFalse
        Mock Get-CimInstance { [pscustomobject]@{ SpecVersion = '1.2, 2, 0' } }
        $older = Get-TpmState
        $older.Present | Should -BeTrue
        $older.IsTPM2Known | Should -BeTrue
        $older.IsTPM2 | Should -BeFalse
    }

    It 'cannot award a perfect score when hardware and runtime providers fail' {
        $testState.Firmware.Mode = 'Unknown'; $testState.Firmware.IsUefiConfirmed = $false
        $testState.Virtualization = Get-VirtualizationState ([pscustomobject]@{ ComputerSystem = $null; Processors = @() })
        Mock Get-Tpm { throw 'Unavailable' }; Mock Get-CimInstance { throw 'Unavailable' }
        $testState.Tpm = Get-TpmState; $testState.DeviceGuard = Get-DeviceGuardState
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        $assessment = Get-Assessment $testState
        $assessment.Score.Score | Should -BeLessThan 100
        $assessment.Score.Grade | Should -Be 'Incomplete assessment'
        $assessment.Score.UnknownCount | Should -BeGreaterThan 0
    }

    It 'does not turn missing runtime evidence into a CIS running No' {
        Mock Get-CimInstance { throw 'Unavailable' }
        $testState.DeviceGuard = Get-DeviceGuardState
        $assessment = Get-Assessment $testState
        $row = @($assessment.Cis.Rows | Where-Object ControlId -eq 'hvci')[0]
        $row.FeatureRunningKnown | Should -BeFalse
        $text = New-TextReport $testState $assessment.Statuses $assessment.Score $assessment.SecuredCore $assessment.Cis $assessment.Explanations
        $text | Should -Match 'HypervisorEnforcedCodeIntegrity\s+policy = not set, running = Unknown'
    }

    It 'does not assert that a reboot happened when no pending marker exists' {
        foreach ($value in (Get-Control 'vbs').LocalValues) { & $script:Registry.SetValue $value.Path $value.Name $value.Type $value.Value }
        $explanation = Get-ControlExplanation 'vbs' $testState
        $explanation.Status.State | Should -Be 'ConfiguredNotRunning'
        $explanation.Verdict | Should -Not -Match 'Windows has restarted|Everything Windows can check'
        $explanation.Action | Should -Match 'Restart'
        (Get-StateLabel 'ConfiguredNotRunning').Text | Should -Be 'Configured; not active'
    }

    It 'uses a warning gauge for an incomplete assessment even with a high score' {
        $assessment = Get-Assessment $testState
        $assessment.Score.Score = 95; $assessment.Score.UnknownCount = 1; $assessment.Score.Grade = 'Incomplete assessment'
        $html = New-HtmlReport $testState $assessment.Statuses $assessment.Score $assessment.SecuredCore $assessment.Cis $assessment.Explanations
        $html | Should -Match 'stroke="#b7791f"'
        $html | Should -Not -Match 'stroke="#1a7f43"'
    }
}

Describe 'Firmware guidance evidence safety' {
    BeforeEach {
        $testState = New-SyntheticState
        $script:Warnings = @(); $script:UseColor = $false
        Mock Get-CimInstance { @() }
        Mock Write-Line {}
        Mock Write-Section {}
    }

    It 'preserves unknown BitLocker states: <Case>' -TestCases @(
        @{ Case = 'unknown enum'; Volume = @{ ProtectionStatus = 2; DriveLetter = 'C:' } }
        @{ Case = 'missing property'; Volume = @{ DriveLetter = 'C:' } }
        @{ Case = 'null property'; Volume = @{ ProtectionStatus = $null; DriveLetter = 'C:' } }
    ) {
        param($Case, $Volume)
        Mock Get-CimInstance { [pscustomobject]$Volume }
        $summary = Get-DriveEncryptionSummary
        $summary.Queried | Should -BeTrue
        $summary.AnyProtected | Should -BeNullOrEmpty
        $guidance = Get-FirmwareGuidance $testState
        Show-FirmwareGuidance $guidance $testState
        Should -Invoke Write-Line -ParameterFilter { $Text -match 'status could not be' } -Times 1 -Exactly
        Should -Invoke Write-Line -ParameterFilter { $Text -match 'will not trigger' } -Times 0 -Exactly
    }

    It 'still warns when any volume is known protected among unknown volumes' {
        Mock Get-CimInstance { @([pscustomobject]@{ ProtectionStatus = 2; DriveLetter = 'D:' }, [pscustomobject]@{ ProtectionStatus = 1; DriveLetter = 'C:' }) }
        $summary = Get-DriveEncryptionSummary
        $summary.AnyProtected | Should -BeTrue
        $summary.ProtectedDrives | Should -Contain 'C:'
    }

    It 'does not promise that protection off rules out a recovery prompt' {
        Mock Get-CimInstance { [pscustomobject]@{ ProtectionStatus = 0; DriveLetter = 'C:' } }
        (Get-DriveEncryptionSummary).AnyProtected | Should -BeFalse
        Show-FirmwareGuidance (Get-FirmwareGuidance $testState) $testState
        Should -Invoke Write-Line -ParameterFilter { $Text -match 'will not trigger' } -Times 0 -Exactly
    }

    It 'does not recommend firmware changes based on failed probes' {
        $testState.Tpm = [pscustomobject]@{ Present = $false; IsTPM2 = $false; IsTPM2Known = $false }
        $testState.Virtualization = [pscustomobject]@{ FirmwareEnabled = $false; FirmwareKnown = $false }
        $guidance = Get-FirmwareGuidance $testState
        @($guidance.Needed).Count | Should -Be 0
        @($guidance.Unknown).Count | Should -Be 2
        $guidance.CanOfferReboot | Should -BeFalse
        Show-FirmwareGuidance $guidance $testState
        Should -Invoke Write-Line -ParameterFilter { $Text -match 'Every setting.*already correct' } -Times 0 -Exactly
    }

    It 'does not offer a firmware reboot to fix only Windows boot configuration' {
        $testState.HypervisorLaunch.BlocksVbs = $true
        $guidance = Get-FirmwareGuidance $testState
        @($guidance.Needed).Count | Should -Be 1
        $guidance.CanOfferReboot | Should -BeFalse
    }
}
