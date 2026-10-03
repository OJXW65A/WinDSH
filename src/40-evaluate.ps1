# ---------------------------------------------------------------------------
# Evaluation engine.
#
# One status function for every control, one explainer for every control, one score.
# v1 had a hand-written diagnostic per feature; adding a feature meant writing another.
# ---------------------------------------------------------------------------

function Get-ControlRunningState {
    <#
        Maps a control to the Win32_DeviceGuard service identifiers.
        SecurityServicesConfigured / Running: 1 Credential Guard, 2 HVCI,
        3 System Guard Secure Launch, 4 SMM firmware measurement,
        5 kernel shadow stacks, 6 kernel shadow stacks (audit), 7 HVPT.
    #>
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    $dg = $State.DeviceGuard
    $servicesKnown = [bool](Get-PropertySafe $dg 'RunningKnown' $dg.Available)
    switch ($Control.DetectKey) {
        'Vbs' {
            return [pscustomobject]@{
                Running = [bool]($dg.VbsStatusCode -eq 2)
                RunningKnown = [bool]($dg.Available -and $null -ne $dg.VbsStatusCode)
            }
        }
        'Hvci' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 2); RunningKnown = $servicesKnown }
        }
        'CredentialGuard' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 1); RunningKnown = $servicesKnown }
        }
        'SecureLaunch' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 3); RunningKnown = $servicesKnown }
        }
        'KernelShadowStacks' {
            return [pscustomobject]@{
                Running = (Test-Contains $dg.Running 5)
                RunningKnown = $servicesKnown
                AuditMode = [bool]((Test-Contains $dg.Running 6) -and -not (Test-Contains $dg.Running 5))
            }
        }
        'Hvpt' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 7); RunningKnown = $servicesKnown }
        }
        'SmmFirmware' {
            return [pscustomobject]@{ Running = (Test-Contains $dg.Running 4); RunningKnown = $servicesKnown }
        }
        'Dep' {
            return [pscustomobject]@{ Running = [bool]$State.Dep.Enabled; RunningKnown = [bool]($null -ne $State.Dep.SupportPolicy) }
        }
        default {
            # Registry-only controls have no separate running signal: configured is running.
            return [pscustomobject]@{ Running = $null; RunningKnown = $false; RegistryOnly = $true }
        }
    }
}

function Test-ControlConfigured {
    param([Parameter(Mandatory = $true)]$Control)
    return [bool](Get-ControlConfiguration -Control $Control).Configured
}

function Get-ControlConfiguration {
    param([Parameter(Mandatory = $true)]$Control)
    # A detection-only control has no values to write. Without this guard the loop below
    # would not execute and it would report as configured on every machine.
    if (Get-PropertySafe $Control 'DetectionOnly' $false) { return [pscustomobject]@{ Configured = $false; Error = $null } }
    $all = $true
    $errors = @()
    foreach ($value in (ConvertTo-Array $Control.LocalValues)) {
        try {
            $current = Get-RegValue -Path $value.Path -Name $value.Name
            if ($null -eq $current -or (Get-RegKind -Path $value.Path -Name $value.Name) -ne $value.Type) { $all = $false; continue }
            if ($value.ContainsKey('KnownValues') -and @($value.KnownValues) -notcontains [long]$current) {
                $errors += ('{0} has an unrecognized value ({1}); review it manually.' -f $value.Name, $current)
                $all = $false; continue
            }
            if (-not (Test-CatalogValueSatisfied -Definition $value -Current $current)) { $all = $false }
        }
        catch { $all = $false; $errors += ('Cannot read {0}: {1}' -f $value.Name, $_.Exception.Message) }
    }
    return [pscustomobject]@{ Configured = $all; Error = $(if ($errors.Count) { $errors -join ' ' } else { $null }) }
}

function Get-ControlPolicyOverride {
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)
    foreach ($pv in (ConvertTo-Array $Control.PolicyValues)) {
        $errors = Get-PropertySafe $State.Policy 'Errors' @{}
        if ($errors.ContainsKey($pv.Name)) {
            return [pscustomobject]@{ Name = $pv.Name; Value = $null; Path = $State.Policy.Path; Error = $errors[$pv.Name] }
        }
        if ($State.Policy.Values.ContainsKey($pv.Name)) {
            $value = $State.Policy.Values[$pv.Name]
            if ($null -ne $value) {
                return [pscustomobject]@{ Name = $pv.Name; Value = $value; Path = $State.Policy.Path; Error = $null }
            }
        }
    }
    return $null
}

function Get-ControlSupport {
    <#
        Hard prerequisites the machine itself imposes. Returns the FIRST blocking reason so
        the user is given one thing to act on rather than a checklist.
    #>
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    $requirements = @(ConvertTo-Array $Control.PlatformRequirements)
    foreach ($requirement in $requirements) {
        switch ($requirement) {
            '64Bit' {
                if (-not $State.Computer.Is64Bit) { return [pscustomobject]@{ Supported = $false; Reason = 'This protection requires a 64-bit version of Windows.'; Fix = $null } }
            }
            'Hypervisor' {
                if ($State.HypervisorLaunch.BlocksVbs) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'The Windows hypervisor is switched off in the boot configuration, so this protection cannot start.'; Fix = 'In an elevated Command Prompt run:  bcdedit /set hypervisorlaunchtype Auto   then restart.' }
                }
            }
            'Uefi' {
                if (-not $State.Firmware.IsUefiConfirmed) {
                    return [pscustomobject]@{ Supported = $false; Reason = ('Requires UEFI firmware mode; this PC reports {0}.' -f $State.Firmware.Mode); Fix = 'Switching from Legacy/CSM to UEFI also requires converting the disk from MBR to GPT. Back up first.' }
                }
            }
            'Virtualization' {
                if (-not $State.Virtualization.FirmwareEnabled) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'CPU virtualization is turned off in firmware.'; Fix = 'Enable Intel VT-x / AMD SVM in BIOS setup. Use -Explain or the firmware guide for where to find it.' }
                }
            }
            'Tpm2' {
                if (-not $State.Tpm.IsTPM2) {
                    return [pscustomobject]@{ Supported = $false; Reason = 'TPM 2.0 was not confirmed, and this protection needs it to store boot measurements.'; Fix = 'Enable TPM (Intel PTT / AMD fTPM) in BIOS setup.' }
                }
            }
            'CredentialGuardEdition' {
                $edition = [string]$State.Computer.EditionId
                if ($edition -match '^(Core|CoreN|CoreSingleLanguage|CoreCountrySpecific|Home)') {
                    return [pscustomobject]@{ Supported = $false; Reason = ('Credential Guard is not available on Windows {0} editions.' -f $edition); Fix = 'Requires Windows Enterprise, Education, or Pro with a supported licence.' }
                }
            }
            default { throw ('Unknown platform requirement {0} in control {1}.' -f $requirement, $Control.Id) }
        }
    }
    $minBuild = Get-PropertySafe $Control 'MinimumBuild' $null
    if ($null -ne $minBuild -and $State.Computer.BuildNumber -gt 0 -and $State.Computer.BuildNumber -lt [int]$minBuild) {
        return [pscustomobject]@{ Supported = $false; Reason = ('Requires Windows build {0} or newer; this PC is build {1}.' -f $minBuild, $State.Computer.BuildNumber); Fix = 'Update Windows to a newer feature release.' }
    }

    return [pscustomobject]@{ Supported = $true; Reason = $null; Fix = $null }
}

function Get-ControlPreflight {
    <#
        Evaluates a control's declared pre-flight safety check. Returns $null when the
        control has none. A tripped check means applying the control now is risky, not
        that it is unsupported.
    #>
    param([Parameter(Mandatory = $true)]$Control)

    $preflight = Get-PropertySafe $Control 'Preflight' $null
    if ($null -eq $preflight) { return $null }

    switch ($preflight.Kind) {
        'CodeIntegrityEvents' {
            $ids = ConvertTo-Array $preflight.EventIds
            $days = if ($preflight.ContainsKey('LookbackDays')) { [int]$preflight.LookbackDays } else { 14 }
            $events = Get-CodeIntegrityEvents -EventIds $ids -LookbackDays $days

            return [pscustomobject]@{
                Kind = $preflight.Kind
                Tripped = [bool](-not $events.Queried -or $events.EventCount -gt 0)
                BlocksSafeSet = [bool]$preflight.BlocksSafeSet
                Message = if ($events.Queried) { $preflight.Message } else { 'Could not verify driver compatibility because the Code Integrity log could not be queried.' }
                EventCount = $events.EventCount
                Drivers = $events.Drivers
                Newest = $events.Newest
                Queried = $events.Queried
                Error = $events.Error
            }
        }
        default { return $null }
    }
}

function Get-ControlStatus {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)]$State)

    $control = Get-Control -Id $Id
    $support = Get-ControlSupport -Control $control -State $State
    $policy = Get-ControlPolicyOverride -Control $control -State $State
    $configuration = Get-ControlConfiguration -Control $control
    $configured = $configuration.Configured
    $run = Get-ControlRunningState -Control $control -State $State

    $registryOnly = [bool](Get-PropertySafe $run 'RegistryOnly' $false)
    $runningKnown = if ($registryOnly) { -not [bool]$configuration.Error } else { [bool]$run.RunningKnown }
    $running = if ($registryOnly) { [bool]($runningKnown -and $configured) } else { [bool]($runningKnown -and $run.Running) }
    $auditMode = [bool]($runningKnown -and (Get-PropertySafe $run 'AuditMode' $false))

    # NOT named $state: PowerShell variable names are case-insensitive, so a local
    # $state would shadow the $State parameter and the recursive dependency call below
    # would receive this string instead of the system state object.
    $controlState = if (-not $support.Supported) { 'NotSupported' }
                    elseif ($auditMode) { 'AuditMode' }
                    elseif (-not $runningKnown -or (-not $running -and $configuration.Error)) { 'Unknown' }
                    elseif ($running) { 'Running' }
                    elseif ($configured) { 'ConfiguredNotRunning' }
                    else { 'NotConfigured' }

    # A dependency that is not running explains a child that is not running.
    $blockedBy = $null
    if ($controlState -ne 'Running' -and $controlState -ne 'NotSupported') {
        foreach ($dep in (ConvertTo-Array $control.Requires)) {
            $depStatus = Get-ControlStatus -Id $dep -State $State
            if ($depStatus.State -ne 'Running') { $blockedBy = $depStatus; break }
        }
    }

    return [pscustomobject]@{
        Id = $control.Id
        Name = $control.Name
        PlainName = $control.PlainName
        Category = $control.Category
        Weight = $control.Weight
        State = $controlState
        Running = $running
        RunningKnown = $runningKnown
        Configured = $configured
        ConfigurationError = $configuration.Error
        Supported = $support.Supported
        SupportReason = $support.Reason
        SupportFix = $support.Fix
        ManagedByPolicy = [bool]($null -ne $policy)
        PolicyValue = if ($policy) { $policy.Value } else { $null }
        PolicyReadError = if ($policy) { Get-PropertySafe $policy 'Error' $null } else { $null }
        BlockedBy = $blockedBy
        Cis = $control.Cis
    }
}

function Get-AllControlStatus {
    param([Parameter(Mandatory = $true)]$State)
    $results = @()
    foreach ($id in (Get-ControlIds)) { $results += Get-ControlStatus -Id $id -State $State }
    return $results
}

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

function Get-SecurityScore {
    <#
        Weighted score over the controls this machine can actually run. Controls the
        hardware cannot support are excluded from the denominator rather than counted as
        failures: penalising someone for hardware they cannot change is not useful.
    #>
    param([Parameter(Mandatory = $true)]$Statuses)

    $earned = 0.0
    $possible = 0.0
    $breakdown = @()

    foreach ($s in $Statuses) {
        $fraction = switch ($s.State) {
            'Running' { 1.0 }
            'ConfiguredNotRunning' { 0.5 }
            'NotConfigured' { 0.0 }
            'Unknown' { 0.0 }
            'AuditMode' { 0.0 }
            default { $null }
        }
        if ($null -eq $fraction) {
            $breakdown += [pscustomobject]@{ Id = $s.Id; Name = $s.Name; State = $s.State; Weight = $s.Weight; Points = 0; Counted = $false }
            continue
        }
        $points = [double]$s.Weight * $fraction
        $earned += $points
        $possible += [double]$s.Weight
        $breakdown += [pscustomobject]@{ Id = $s.Id; Name = $s.Name; State = $s.State; Weight = $s.Weight; Points = [math]::Round($points, 1); Counted = $true }
    }

    $score = if ($possible -gt 0) { [int][math]::Round(($earned / $possible) * 100) } else { 0 }

    $grade = if ($score -ge 90) { 'Excellent' }
             elseif ($score -ge 75) { 'Good' }
             elseif ($score -ge 50) { 'Fair' }
             elseif ($score -gt 0) { 'Weak' }
             else { 'Unprotected' }
    $unknownCount = @($Statuses | Where-Object { $_.Weight -gt 0 -and $_.State -eq 'Unknown' }).Count
    if ($unknownCount -gt 0) { $grade = 'Incomplete assessment' }

    return [pscustomobject]@{
        Score = $score
        Grade = $grade
        UnknownCount = $unknownCount
        Earned = [math]::Round($earned, 1)
        Possible = [math]::Round($possible, 1)
        ExcludedCount = @($breakdown | Where-Object { -not $_.Counted }).Count
        Breakdown = $breakdown
        ApplicableCount = @($Statuses | Where-Object { $_.Weight -gt 0 -and $_.Supported }).Count
        TotalCount = @($Statuses | Where-Object { $_.Weight -gt 0 }).Count
    }
}

function Get-SecuredCoreVerdict {
    <# Secured-core PC requires the full hardware and software stack. #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Statuses)

    $checks = @(
        [pscustomobject]@{ Name = 'UEFI firmware mode'; Met = $State.Firmware.IsUefiConfirmed }
        [pscustomobject]@{ Name = 'Secure Boot enabled'; Met = [bool]$State.Firmware.SecureBootEnabled }
        [pscustomobject]@{ Name = 'TPM 2.0'; Met = $State.Tpm.IsTPM2 }
        [pscustomobject]@{ Name = 'Virtualization-based Security running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'vbs' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'Memory Integrity running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'hvci' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'System Guard Secure Launch running'; Met = [bool](@($Statuses | Where-Object { $_.Id -eq 'secure-launch' -and $_.State -eq 'Running' }).Count -gt 0) }
        [pscustomobject]@{ Name = 'DMA protection available'; Met = $State.DeviceGuard.HasDmaProtection }
        [pscustomobject]@{ Name = 'SMM mitigations available'; Met = $State.DeviceGuard.HasSmmMitigations }
    )
    $unmet = @($checks | Where-Object { -not $_.Met })
    return [pscustomobject]@{
        Qualifies = [bool]($unmet.Count -eq 0)
        Checks = $checks
        UnmetCount = $unmet.Count
    }
}

# ---------------------------------------------------------------------------
# CIS comparison
# ---------------------------------------------------------------------------

function Get-CisComplianceReport {
    <#
        CIS section 18.9.5 audits HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard.
        WinDSH configures local values under HKLM\SYSTEM\CurrentControlSet\Control and
        never writes the policy hive, so a machine configured by WinDSH will have the
        features running but will NOT pass a CIS scan. That is reported, not hidden.
    #>
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Statuses)

    $rows = @()
    foreach ($control in $script:ControlCatalog) {
        if ($null -eq $control.Cis) { continue }
        $status = @($Statuses | Where-Object { $_.Id -eq $control.Id })[0]

        $policyName = $null; $policyValue = $null; $expected = $null; $accepted = @()
        foreach ($pv in (ConvertTo-Array $control.PolicyValues)) {
            $policyName = $pv.Name
            $expected = $pv.Expected
            $accepted = @($pv.Expected) + (ConvertTo-Array (Get-PropertySafe $pv 'AlsoAccepted' @()))
            if ($State.Policy.Values.ContainsKey($pv.Name)) { $policyValue = $State.Policy.Values[$pv.Name] }
            break
        }

        $policyKnown = -not [bool](Get-PropertySafe $status 'PolicyReadError' $null)
        $compliant = [bool]($policyKnown -and $null -ne $policyValue -and (@($accepted) -contains [int]$policyValue))

        $rows += [pscustomobject]@{
            CisId = $control.Cis.Id
            Profile = $control.Cis.Profile
            Title = $control.Cis.Title
            ControlId = $control.Id
            PolicyValueName = $policyName
            Expected = $expected
            Actual = $policyValue
            Compliant = $compliant
            PolicyKnown = $policyKnown
            FeatureRunning = [bool]($status -and $status.State -eq 'Running')
            Divergence = Get-PropertySafe $control.Cis 'Divergence' $null
        }
    }

    $compliantCount = @($rows | Where-Object { $_.Compliant }).Count
    return [pscustomobject]@{
        Benchmark = $script:CisBenchmark
        Section = '18.9.5 Device Guard'
        PolicyPath = $State.Policy.Path
        Rows = $rows
        TotalCount = @($rows).Count
        CompliantCount = $compliantCount
        UnknownCount = @($rows | Where-Object { -not $_.PolicyKnown }).Count
        RunningButNotCompliantCount = @($rows | Where-Object { $_.PolicyKnown -and $_.FeatureRunning -and -not $_.Compliant }).Count
        Note = 'CIS audits the Group Policy hive. WinDSH configures local machine values and never writes Group Policy, so features can be active while these checks still report non-compliant.'
    }
}

# ---------------------------------------------------------------------------
# Generic explainer - replaces the per-feature diagnostics in v1
# ---------------------------------------------------------------------------

function Get-ControlExplanation {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)]$State, $Status)

    $control = Get-Control -Id $Id
    $status = if ($Status) { $Status } else { Get-ControlStatus -Id $Id -State $State }

    $verdict = $null; $action = $null; $severity = 'Info'

    if ($status.PolicyReadError -or $status.ConfigurationError) {
        $verdict = ('Configuration evidence for {0} could not be verified.' -f $control.Name)
        $action = 'Review the registry or policy read error and restore access before remediation. WinDSH will skip this protection.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'Unknown') {
        $verdict = ('Windows did not provide the running state of {0}.' -f $control.Name)
        $action = 'Check access to the Windows security providers, then re-run the audit. Registry configuration alone does not prove this protection is active.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'AuditMode') {
        $verdict = ('{0} is in audit mode; enforcement is not active.' -f $control.Name)
        $action = 'Review compatibility and organization policy before enabling enforcement. Audit mode earns no enforcement points.'
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'Running') {
        $verdict = ('{0} is running. Nothing to do.' -f $control.Name)
        $severity = 'Good'
    }
    elseif ($status.ManagedByPolicy) {
        $verdict = ('{0} is managed by your organisation''s Group Policy.' -f $control.Name)
        $action = 'WinDSH will not override a policy-managed setting. Contact whoever manages this computer.'
        $severity = 'Info'
    }
    elseif (-not $status.Supported) {
        $verdict = $status.SupportReason
        $action = $status.SupportFix
        $severity = 'Warn'
    }
    elseif ($status.BlockedBy) {
        $verdict = ('{0} cannot run because {1} is not running.' -f $control.Name, $status.BlockedBy.Name)
        $action = ('Resolve {0} first. Run: -Explain {1}' -f $status.BlockedBy.Name, $status.BlockedBy.Id)
        $severity = 'Warn'
    }
    elseif ($status.State -eq 'ConfiguredNotRunning') {
        if ($State.Restart.Pending -or $script:RestartRequired) {
            $verdict = ('{0} is configured but Windows has not restarted since the change.' -f $control.Name)
            $action = 'Restart Windows, then run the audit again.'
            $severity = 'Warn'
        }
        else {
            $verdict = ('{0} is configured, Windows has restarted, and it still is not running. Everything Windows can check is satisfied, so the remaining explanation is hardware or firmware capability.' -f $control.Name)
            $action = Get-HardwareCapabilityAdvice -Control $control -State $State
            $severity = 'Info'
        }
    }
    elseif (Get-PropertySafe $control 'DetectionOnly' $false) {
        $verdict = ('{0} is not active on this computer.' -f $control.Name)
        $action = 'WinDSH reports this but does not configure it. It is provided by Windows or the platform firmware.'
        $severity = 'Info'
    }
    else {
        $verdict = ('{0} is not configured.' -f $control.Name)
        $action = if ($control.Remediable) { ('This tool can configure it. Run with -Enable {0}' -f $control.Id) } else { 'Configure it through Windows Security.' }
        $severity = 'Info'

        $preflight = Get-ControlPreflight -Control $control
        if ($preflight -and $preflight.Tripped) {
            $verdict = ('{0} is not configured, and enabling it right now looks risky.' -f $control.Name)
            $lines = @($preflight.Message, '')
            if ($preflight.Queried) { $lines += ('  {0} compatibility event(s) in the last 14 days.' -f $preflight.EventCount) }
            elseif ($preflight.Error) { $lines += ('  Log query failed: {0}' -f $preflight.Error) }
            foreach ($d in (ConvertTo-Array $preflight.Drivers)) {
                $who = if ($d.Publisher) { $d.Publisher } else { 'unknown publisher' }
                $ver = if ($d.Version) { $d.Version } else { 'unknown version' }
                $svc = if ($d.Service) { (' - {0}' -f $d.Service) } else { '' }
                $lines += ('  - {0} ({1}, {2}){3}' -f $d.FileName, $who, $ver, $svc)
            }
            $lines += ''
            $lines += $(if ($preflight.Queried) { '  Update or remove the driver above, restart, then run the audit again.' } else { '  Restore access to the Code Integrity log, then run the audit again. Automatic remediation will skip this protection.' })
            $action = ($lines -join "`n")
            $severity = 'Warn'
        }
    }

    return [pscustomobject]@{
        Id = $control.Id
        Name = $control.Name
        PlainName = $control.PlainName
        Summary = $control.Summary
        Why = $control.Why
        Caution = Get-PropertySafe $control 'Caution' $null
        DocUrl = $control.DocUrl
        Verdict = $verdict
        Action = $action
        Severity = $severity
        Status = $status
        Cis = $control.Cis
    }
}

function Get-HardwareCapabilityAdvice {
    param([Parameter(Mandatory = $true)]$Control, [Parameter(Mandatory = $true)]$State)

    switch ($Control.Id) {
        'secure-launch' {
            return @(
                'Secure Launch needs DRTM-capable firmware, which cannot be detected in advance.',
                '',
                ('  Your processor: {0}' -f $State.Computer.ProcessorName),
                '',
                '  1. DRTM requires Intel vPro (8th generation or newer) or AMD Zen 2 or newer.',
                '     Most consumer and non-vPro laptops do not have it, and it cannot be added',
                '     by a software or firmware update.',
                '  2. If your CPU does qualify, look in BIOS setup for "Intel TXT" or "Trusted',
                '     Execution" (AMD: "SKINIT"), usually under Security or Advanced. On Intel it',
                '     is often hidden until both TPM and VT-x are enabled, so enable those first.',
                '  3. Update to the newest BIOS from your manufacturer.',
                '',
                '  If none apply this is a hardware limit, not a fault. The setting is harmless',
                '  and your other protections are unaffected.'
            ) -join "`n"
        }
        'kernel-shadow-stacks' {
            return @(
                'Kernel shadow stacks need CPU hardware support for shadow stacks.',
                '',
                ('  Your processor: {0}' -f $State.Computer.ProcessorName),
                '',
                '  Requires an Intel Tiger Lake or AMD Zen 3 processor or newer (both late 2020),',
                '  and Memory Integrity must already be running. Without both, the setting has no',
                '  effect. This is a hardware limit, not a fault.'
            ) -join "`n"
        }
        'hvci' {
            return @(
                'Memory Integrity is configured but Windows declined to start it.',
                '',
                '  The usual cause is a driver that is not compatible. Windows records these in',
                '  Event Viewer under Applications and Services Logs > Microsoft > Windows >',
                '  CodeIntegrity > Operational, as event ID 3087.',
                '',
                '  Update or remove the driver named there, then restart.'
            ) -join "`n"
        }
        default {
            return 'Everything Windows can verify is in order. The remaining explanation is that this hardware or firmware does not provide the capability.'
        }
    }
}

function Get-Assessment {
    param([Parameter(Mandatory = $true)]$State)
    $statuses = @(Get-AllControlStatus -State $State)
    $unknown = @($statuses | Where-Object State -eq 'Unknown')
    if ($unknown.Count) { Add-Warning ('Running or configuration evidence is unavailable for {0} protection(s); the assessment is incomplete.' -f $unknown.Count) }
    foreach ($status in $statuses) {
        if ($status.PolicyReadError) { Add-Warning ('Cannot read policy for {0}: {1}' -f $status.Id, $status.PolicyReadError) }
        if ($status.ConfigurationError) { Add-Warning ('Cannot verify configuration for {0}: {1}' -f $status.Id, $status.ConfigurationError) }
    }
    return [pscustomobject]@{
        State = $State
        Statuses = $statuses
        Score = Get-SecurityScore -Statuses $statuses
        SecuredCore = Get-SecuredCoreVerdict -State $State -Statuses $statuses
        Cis = Get-CisComplianceReport -State $State -Statuses $statuses
        Explanations = @($statuses | ForEach-Object { Get-ControlExplanation -Id $_.Id -State $State -Status $_ })
    }
}
