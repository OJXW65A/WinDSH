# ---------------------------------------------------------------------------
# Synthetic self-test. Uses the in-memory registry provider, so apply/revert and the
# whole evaluation chain are exercised without touching a real machine. Runs on any host.
# ---------------------------------------------------------------------------

function New-SyntheticState {
    param([hashtable]$Override)

    $state = [pscustomobject]@{
        Generated = (Get-Date).ToUniversalTime().ToString('o')
        Computer = [pscustomobject]@{
            Name = 'SELFTEST'; Manufacturer = 'Contoso'; Model = 'TestBook 1'
            ProcessorName = 'Contoso CPU 1.0'; ProcessorCount = 1
            OsCaption = 'Windows 11 Enterprise'; ProductName = 'Windows 11 Enterprise'
            EditionId = 'Enterprise'; BuildNumber = 26100; Ubr = 1
            Is64Bit = $true; PartOfDomain = $false; DomainRole = 1; IsVirtual = $false
        }
        Firmware = [pscustomobject]@{
            Type = 'UEFI'; Mode = 'UEFI'; IsUefiConfirmed = $true; IsLegacyConfirmed = $false
            DetectionSource = 'SelfTest'; SecureBootSupported = $true; SecureBootEnabled = $true
        }
        Tpm = [pscustomobject]@{ Present = $true; Ready = $true; SpecVersion = '2.0'; IsTPM2 = $true }
        Virtualization = [pscustomobject]@{ HypervisorPresent = $true; FirmwareEnabled = $true; FirmwareRaw = $true; Slat = $true }
        HypervisorLaunch = [pscustomobject]@{ LaunchType = 'NotSet'; Source = 'SelfTest'; BlocksVbs = $false; Error = $null }
        Dep = [pscustomobject]@{ SupportPolicy = 3; Available = $true; Text = 'On for all programs'; Enabled = $true }
        VirtualMachine = [pscustomobject]@{ IsVirtual = $false; Platform = $null; Notes = @() }
        DeviceGuard = [pscustomobject]@{
            Available = $true; Configured = @(); Running = @()
            AvailableProperties = @(1, 2, 3); RequiredProperties = @()
            VbsStatusCode = 0; VbsStatusText = 'Not enabled'; CodeIntegrityPolicyEnforcement = 0
            HasHypervisorSupport = $true; HasSecureBootProperty = $true; HasDmaProtection = $true
            HasSmmMitigations = $false; HasMbec = $true
        }
        Policy = [pscustomobject]@{ Path = $script:RegPolicyDG; Values = @{}; AnyConfigured = $false }
        Restart = [pscustomobject]@{ Pending = $false; Reasons = @(); ComponentBasedServicing = $false; WindowsUpdate = $false; QueuedFileRenameCount = 0 }
    }

    if ($Override) { foreach ($k in $Override.Keys) { $state.$k = $Override[$k] } }
    return $state
}

function Invoke-SelfTest {
    # Scoped event provider: self-tests never query the real host's compatibility log.
    $ciEvidence = [pscustomobject]@{ Queried = $true; EventCount = 0; Drivers = @(); Newest = $null; Error = $null }
    function Get-CodeIntegrityEvents { param($EventIds, $LookbackDays) return $ciEvidence }
    $pass = 0; $fail = 0
    function Assert-That {
        param([string]$Name, [bool]$Condition, [string]$Detail = '')
        if ($Condition) { $script:stPass++; Write-Line ('{0}{1}' -f $Name, $(if ($Detail) { " - $Detail" } else { '' })) 'Good' }
        else { $script:stFail++; Write-Line ('{0}{1}' -f $Name, $(if ($Detail) { " - $Detail" } else { '' })) 'Bad' }
    }
    $script:stPass = 0; $script:stFail = 0

    # The self-test is unattended by definition: it must never block on a prompt.
    $selfTestPriorUnattended = $script:Unattended
    $script:Unattended = $true

    Write-Section ('{0} {1} self-test' -f $script:ToolName, $script:ToolVersion)

    # --- catalog integrity ---
    $ids = Get-ControlIds
    Assert-That 'Catalog ids are unique' ((@($ids | Select-Object -Unique)).Count -eq @($ids).Count) ('count={0}' -f @($ids).Count)

    $dangling = @()
    foreach ($c in $script:ControlCatalog) {
        foreach ($d in (ConvertTo-Array $c.Requires)) { if ($ids -notcontains $d) { $dangling += "$($c.Id)->$d" } }
    }
    Assert-That 'All declared dependencies exist' ($dangling.Count -eq 0) ($dangling -join ', ')
    Assert-That 'Every control has a documentation link' (@($script:ControlCatalog | Where-Object { $_.DocUrl -notmatch '^https://' }).Count -eq 0)
    Assert-That 'Every control has a plain-language name and summary' (@($script:ControlCatalog | Where-Object { -not $_.PlainName -or -not $_.Summary }).Count -eq 0)
    Assert-That 'Safe set contains only known controls' (@($script:SafeControlSet | Where-Object { $ids -notcontains $_ }).Count -eq 0)

    $order = @(Resolve-ControlOrder -Id 'hvci' | Select-Object -ExpandProperty Id)
    Assert-That 'Dependencies resolve before dependants' (($order[-1] -eq 'hvci') -and ($order -contains 'vbs')) ($order -join ' -> ')

    # --- evaluation on a clean machine ---
    Set-RegistryProvider (New-InMemoryRegistryProvider)
    $clean = New-SyntheticState
    $statuses = Get-AllControlStatus -State $clean
    Assert-That 'All controls evaluate on a clean machine' (@($statuses).Count -eq @($ids).Count) ('count={0}' -f @($statuses).Count)
    # Detection-only controls reflect what Windows already does, so DEP is legitimately
    # running on a machine where WinDSH has configured nothing.
    $configurable = @($statuses | Where-Object { -not (Get-PropertySafe (Get-Control -Id $_.Id) 'DetectionOnly' $false) })
    Assert-That 'No configurable control reports running on a clean machine' (@($configurable | Where-Object { $_.State -eq 'Running' }).Count -eq 0)

    $score = Get-SecurityScore -Statuses $statuses
    Assert-That 'Clean machine scores zero' ($score.Score -eq 0) ('score={0}' -f $score.Score)
    Assert-That 'Clean machine grade is Unprotected' ($score.Grade -eq 'Unprotected') $score.Grade

    # --- hardware limits are excluded from the score, not counted as failures ---
    $homeState = New-SyntheticState
    $homeState.Computer.EditionId = 'Core'
    $homeStatuses = Get-AllControlStatus -State $homeState
    $cgHome = @($homeStatuses | Where-Object { $_.Id -eq 'credential-guard' })[0]
    Assert-That 'Credential Guard is unsupported on Home' ($cgHome.State -eq 'NotSupported') $cgHome.SupportReason
    $homeScore = Get-SecurityScore -Statuses $homeStatuses
    Assert-That 'Unsupported controls are excluded from scoring' ($homeScore.ExcludedCount -ge 1) ('excluded={0}' -f $homeScore.ExcludedCount)

    # --- hypervisor off blocks everything VBS-based ---
    $offState = New-SyntheticState
    $offState.HypervisorLaunch = [pscustomobject]@{ LaunchType = 'Off'; Source = 'SelfTest'; BlocksVbs = $true; Error = $null }
    $offStatuses = Get-AllControlStatus -State $offState
    $vbsOff = @($offStatuses | Where-Object { $_.Id -eq 'vbs' })[0]
    Assert-That 'hypervisorlaunchtype=Off makes VBS unsupported' ($vbsOff.State -eq 'NotSupported') $vbsOff.SupportReason
    $blOff = @($offStatuses | Where-Object { $_.Id -eq 'driver-blocklist' })[0]
    Assert-That 'Driver blocklist is unaffected by the hypervisor' ($blOff.State -ne 'NotSupported') $blOff.State
    $expOff = Get-ControlExplanation -Id 'vbs' -State $offState
    Assert-That 'Explainer gives the bcdedit fix for a disabled hypervisor' ($expOff.Action -match 'hypervisorlaunchtype Auto') $expOff.Verdict

    # --- legacy BIOS must not be read as UEFI ---
    $legacy = New-SyntheticState
    $legacy.Firmware = [pscustomobject]@{
        Type = 'Legacy BIOS or unsupported UEFI'; Mode = 'Unknown'; IsUefiConfirmed = $false
        IsLegacyConfirmed = $false; DetectionSource = 'SelfTest'; SecureBootSupported = $false; SecureBootEnabled = $false
    }
    $legacyStatus = Get-ControlStatus -Id 'secure-launch' -State $legacy
    Assert-That 'Ambiguous firmware text is not treated as confirmed UEFI' ($legacyStatus.State -eq 'NotSupported') $legacyStatus.SupportReason

    # --- plan and apply ---
    Set-RegistryProvider (New-InMemoryRegistryProvider)
    $plan = @(Get-ChangePlan -Ids @('hvci') -State $clean)
    Assert-That 'Plan covers HVCI and its dependencies' (@($plan | Select-Object -ExpandProperty ControlId -Unique).Count -eq 3) (@($plan | Select-Object -ExpandProperty ControlId -Unique) -join ',')
    Assert-That 'Every value needs changing on a clean machine' (@($plan | Where-Object { -not $_.NeedsChange }).Count -eq 0)

    $journal = Join-Path ([IO.Path]::GetTempPath()) ('windsh-selftest-{0}.jsonl' -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $script:TestJournalPath = $journal
    try {
        $applied = Invoke-ControlApply -Ids @('hvci') -State $clean
        Assert-That 'Apply writes the planned values' ($applied.ChangeCount -eq @($plan).Count) ('changes={0}' -f $applied.ChangeCount)
        Assert-That 'VBS is on after apply' ((Get-RegValue -Path $script:RegDeviceGuard -Name 'EnableVirtualizationBasedSecurity') -eq 1)
        Assert-That 'HVCI is on after apply' ((Get-RegValue -Path $script:RegHvci -Name 'Enabled') -eq 1)
        Assert-That 'Locked stays 0 so changes can be undone' ((Get-RegValue -Path $script:RegHvci -Name 'Locked') -eq 0)

        $second = Invoke-ControlApply -Ids @('hvci') -State $clean
        Assert-That 'Applying twice is idempotent' ($second.ChangeCount -eq 0) ('changes={0}' -f $second.ChangeCount)

        $revert = Invoke-ControlRevert -RunId $applied.RunId
        Assert-That 'Revert restores every journalled value' ($revert.ChangeCount -eq $applied.ChangeCount) ('reverted={0}' -f $revert.ChangeCount)
        Assert-That 'Values that never existed are removed, not zeroed' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))

        $closedRejected = $false
        try { [void](Invoke-ControlRevert -RunId $applied.RunId) } catch { $closedRejected = $true }
        Assert-That 'A completed run cannot be reverted twice' $closedRejected
        Assert-That 'Completed runs are excluded from default rollback selection' (@(Get-JournalRuns).Count -eq 0)

        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegCiConfig + '|VulnerableDriverBlocklistEnable') = 0 })
        $conflictApply = Invoke-ControlApply -Ids @('driver-blocklist') -State $clean
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 2
        $conflictRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'Rollback preserves later administrator changes' ((Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 2 -and $conflictRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'String' '1'
        $typeRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'Rollback detects a registry type conflict' ($typeRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        $retryRevert = Invoke-ControlRevert -RunId $conflictApply.RunId
        Assert-That 'A conflicted entry can be retried when expected state is restored' ($retryRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 0)

        # An intent without a completion marker is ambiguous, even when the live
        # value happens to equal AfterValue. It must never erase a later change.
        $pendingId = 'selftest-pending'
        $pending = [pscustomobject]@{ RecordType = 'Change'; ChangeId = 'pending-write'; RunId = $pendingId; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $pending
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 2
        $pendingRevert = Invoke-ControlRevert -RunId $pendingId
        Assert-That 'Journal-before-write cannot overwrite an unrelated later value' ($pendingRevert.ChangeCount -eq 0 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 2)
        & $script:Registry.SetValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable' 'DWord' 1
        $ambiguousRevert = Invoke-ControlRevert -RunId $pendingId
        Assert-That 'Unconfirmed writes require manual review even if the value matches' ($ambiguousRevert.ChangeCount -eq 0 -and $ambiguousRevert.Conflicts.Count -eq 1)

        # Legacy v2 journals stay usable, but are subject to conflict and catalog checks.
        $legacyEntry = [pscustomobject]@{ RunId = 'selftest-legacy'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $legacyEntry
        $legacyRevert = Invoke-ControlRevert -RunId $legacyEntry.RunId
        Assert-That 'Legacy journal entries can be safely reverted' ($legacyRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable') -eq 0)

        # Partial revert recovery never repeats already-restored registry writes.
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $partialApply = Invoke-ControlApply -Ids @('vbs') -State $clean
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 2
        $partialRevert = Invoke-ControlRevert -RunId $partialApply.RunId
        Assert-That 'Partial rollback restores matching entries and reports conflicts' ($partialRevert.ChangeCount -eq 1 -and $partialRevert.Conflicts.Count -eq 1)
        & $script:Registry.SetValue $script:RegDeviceGuard 'EnableVirtualizationBasedSecurity' 'DWord' 2
        & $script:Registry.SetValue $script:RegDeviceGuard 'Locked' 'DWord' 0
        $finishRevert = Invoke-ControlRevert -RunId $partialApply.RunId
        Assert-That 'Retrying a partial revert never repeats completed entries' ($finishRevert.ChangeCount -eq 1 -and (Get-RegValue $script:RegDeviceGuard 'EnableVirtualizationBasedSecurity') -eq 2)

        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $crashApply = Invoke-ControlApply -Ids @('driver-blocklist') -State $clean
        $crashChange = @(Get-JournalChanges -Records @(Get-Journal -RunId $crashApply.RunId))[0]
        Write-JournalMarker -RunId $crashApply.RunId -RecordType 'RevertStarted' -ChangeId $crashChange.Id
        & $script:Registry.RemoveValue $script:RegCiConfig 'VulnerableDriverBlocklistEnable'
        $crashRevert = Invoke-ControlRevert -RunId $crashApply.RunId
        Assert-That 'An interrupted revert is finalized without rewriting registry state' ($crashRevert.ChangeCount -eq 0 -and $crashRevert.RecoveredCount -eq 1)

        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegCiConfig + '|VulnerableDriverBlocklistEnable') = 2 })
        foreach ($pair in @(@(0, 1), @(1, 2))) {
            Write-JournalEntry ([pscustomobject]@{ RunId = 'selftest-repeated-value'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = $pair[0]; AfterValue = $pair[1] })
        }
        # Catalog validation rejects arbitrary AfterValue, even for a known path.
        $badAfterRejected = $false
        try { [void](Invoke-ControlRevert -RunId 'selftest-repeated-value') } catch { $badAfterRejected = $true }
        Assert-That 'Rollback validates recorded target values against the catalog' $badAfterRejected

        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $baseSet = $script:Registry.SetValue
        $failureCounter = @{ Count = 0 }
        $script:Registry.SetValue = {
            param($Path, $Name, $Type, $Value)
            $failureCounter.Count++
            if ($failureCounter.Count -eq 2) { throw 'Synthetic write failure' }
            & $baseSet $Path $Name $Type $Value
        }.GetNewClosure()
        $partialRejected = $false
        try { [void](Invoke-ControlApply -Ids @('vbs') -State $clean -RunId 'selftest-partial-apply') } catch { $partialRejected = $true }
        $script:Registry.SetValue = $baseSet
        $partialWriteRevert = Invoke-ControlRevert -RunId 'selftest-partial-apply'
        Assert-That 'Partial apply records completed writes and leaves pending writes untouched' ($partialRejected -and $partialWriteRevert.ChangeCount -eq 1 -and $partialWriteRevert.Conflicts.Count -eq 1)

        # A process holding the lock excludes other apply/revert operations.
        $heldLock = Enter-JournalLock
        $lockedOut = $false
        try { [void](Invoke-ControlApply -Ids @('vbs') -State $clean) } catch { $lockedOut = $true }
        finally { $heldLock.Dispose() }
        Assert-That 'Concurrent change operations are rejected before writing' $lockedOut

        $validJournal = [IO.File]::ReadAllText($journal)
        try {
            [IO.File]::AppendAllText($journal, '{broken' + "`n")
            $corruptRejected = $false
            try { [void](Invoke-ControlRevert -RunId $pendingId) } catch { $corruptRejected = $true }
            Assert-That 'Malformed terminated journal records block rollback' $corruptRejected
            [IO.File]::WriteAllText($journal, $validJournal + '{torn')
            $repairLock = Enter-JournalLock
            $repairLock.Dispose()
            Assert-That 'A torn journal tail is repaired before subsequent appends' ([IO.File]::ReadAllText($journal) -eq $validJournal)
        }
        finally { [IO.File]::WriteAllText($journal, $validJournal) }
        $malicious = [pscustomobject]@{ RunId = 'selftest-invalid'; Time = (Get-Date).ToUniversalTime().ToString('o'); ControlId = 'driver-blocklist'; Path = $script:RegPolicyDG; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; BeforeExists = $true; BeforeValue = 0; AfterValue = 1 }
        Write-JournalEntry $malicious
        $invalidRejected = $false
        try { [void](Invoke-ControlRevert -RunId $malicious.RunId) } catch { $invalidRejected = $true }
        Assert-That 'Journal content cannot authorize writes outside the catalog' $invalidRejected

        $priorOverride = $env:WINDSH_JOURNAL_PATH
        try {
            $env:WINDSH_JOURNAL_PATH = 'untrusted-environment-path'
            Assert-That 'Inherited journal environment overrides are ignored' ((Get-JournalPath) -eq $journal)
        }
        finally { $env:WINDSH_JOURNAL_PATH = $priorOverride }

        # A stronger platform security level must survive.
        Set-RegistryProvider (New-InMemoryRegistryProvider -Seed @{ ($script:RegDeviceGuard + '|RequirePlatformSecurityFeatures') = 3 })
        $planStrong = @(Get-ChangePlan -Ids @('platform-security') -State $clean | Where-Object { $_.Name -eq 'RequirePlatformSecurityFeatures' -and $_.NeedsChange })
        Assert-That 'An existing stronger Secure Boot + DMA setting is preserved' (@($planStrong).Count -eq 0) 'value 3 must not be downgraded to 1'

        # Group policy is never overwritten.
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $policyState = New-SyntheticState
        $policyState.Policy = [pscustomobject]@{ Path = $script:RegPolicyDG; Values = @{ 'HypervisorEnforcedCodeIntegrity' = 0 }; AnyConfigured = $true }
        $applyPolicy = Invoke-ControlApply -Ids @('hvci') -State $policyState
        Assert-That 'Apply skips a policy-managed control' (@($applyPolicy.Skipped | Where-Object { $_.ControlId -eq 'hvci' }).Count -eq 1)
        Assert-That 'No HVCI value is written under policy' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        Assert-That 'The unmanaged dependency still applies' ((Get-RegValue -Path $script:RegDeviceGuard -Name 'EnableVirtualizationBasedSecurity') -eq 1)
    }
    finally {
        Remove-Item -LiteralPath $journal, ($journal + '.lock') -Force -ErrorAction SilentlyContinue
        $script:TestJournalPath = $null
        Set-RegistryProvider (New-InMemoryRegistryProvider)
    }

    # --- detection-only controls (restored from v1.6.0) ---
    $detOnly = @($script:ControlCatalog | Where-Object { Get-PropertySafe $_ 'DetectionOnly' $false })
    Assert-That 'Detection-only controls are present' (@($detOnly).Count -eq 3) (@($detOnly | Select-Object -ExpandProperty Id) -join ', ')
    Assert-That 'Detection-only controls are never remediable' (@($detOnly | Where-Object { $_.Remediable }).Count -eq 0)
    Assert-That 'Detection-only controls carry no scoring weight' (@($detOnly | Where-Object { $_.Weight -ne 0 }).Count -eq 0)

    $depState = New-SyntheticState
    $depStatus = Get-ControlStatus -Id 'dep' -State $depState
    Assert-That 'DEP is reported running when the policy is on' ($depStatus.State -eq 'Running') $depStatus.State
    $depOff = New-SyntheticState
    $depOff.Dep = [pscustomobject]@{ SupportPolicy = 0; Available = $true; Text = 'Always off'; Enabled = $false }
    Assert-That 'DEP off is not reported as configured' ((Get-ControlStatus -Id 'dep' -State $depOff).State -ne 'Running')

    $hvptState = New-SyntheticState
    $hvptState.DeviceGuard.Running = @(7)
    Assert-That 'HVPT is detected from security service 7' ((Get-ControlStatus -Id 'hvpt' -State $hvptState).State -eq 'Running')
    $smmState = New-SyntheticState
    $smmState.DeviceGuard.Running = @(4)
    Assert-That 'SMM firmware measurement is detected from service 4' ((Get-ControlStatus -Id 'smm-firmware-measurement' -State $smmState).State -eq 'Running')

    $detExplain = Get-ControlExplanation -Id 'hvpt' -State $depOff
    Assert-That 'Detection-only explainer does not offer to configure it' ($detExplain.Action -match 'does not configure') $detExplain.Action

    # --- pre-flight safety check declaration (restored from v1.6.0) ---
    $hvciControl = Get-Control -Id 'hvci'
    Assert-That 'Memory Integrity declares a driver pre-flight check' ($null -ne $hvciControl.Preflight)
    Assert-That 'Pre-flight watches Event ID 3087' (@($hvciControl.Preflight.EventIds) -contains 3087)
    Assert-That 'Pre-flight blocks the safe set when tripped' ([bool]$hvciControl.Preflight.BlocksSafeSet)

    $ciEvidence.EventCount = 1
    $riskPlan = @(Get-ChangePlan -Ids $script:SafeControlSet -State $clean)
    Assert-That 'Safe-set preview includes HVCI preflight blockers' (@($riskPlan | Where-Object { $_.ControlId -eq 'hvci' -and $_.SkipReason }).Count -eq 2)
    $riskJournal = Join-Path ([IO.Path]::GetTempPath()) ('windsh-preflight-{0}.jsonl' -f [Guid]::NewGuid())
    $script:TestJournalPath = $riskJournal
    try {
        Set-RegistryProvider (New-InMemoryRegistryProvider)
        $safeRisk = Invoke-ControlApply -Ids $script:SafeControlSet -State $clean
        Assert-That 'EnableAllSafe skips HVCI when 3087 evidence is present' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        Assert-That 'Safe-set apply reports the same preflight blocker as preview' (@($safeRisk.Skipped | Where-Object { $_.ControlId -eq 'hvci' }).Count -eq 1)
        $explicitRisk = Invoke-ControlApply -Ids @('hvci') -State $clean -ExplicitIds @('hvci')
        Assert-That 'Explicit unattended HVCI cannot bypass a typed override' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        $ciEvidence.EventCount = 0
        $ciEvidence.Queried = $false
        $unknownRisk = Invoke-ControlApply -Ids $script:SafeControlSet -State $clean
        Assert-That 'Unknown compatibility fails closed for the safe set' (-not (Test-RegValue -Path $script:RegHvci -Name 'Enabled'))
        $depRisk = @(Get-ChangePlan -Ids @('kernel-shadow-stacks') -State $clean)
        Assert-That 'A preflight-blocked dependency also blocks shadow stacks' (@($depRisk | Where-Object { $_.ControlId -eq 'kernel-shadow-stacks' -and $_.SkipReason }).Count -eq 1)
    }
    finally {
        $ciEvidence.Queried = $true
        $ciEvidence.EventCount = 0
        Remove-Item -LiteralPath $riskJournal, ($riskJournal + '.lock') -Force -ErrorAction SilentlyContinue
        $script:TestJournalPath = $null
        Set-RegistryProvider (New-InMemoryRegistryProvider)
    }

    # --- firmware guidance (restored from v1.6.0) ---
    $hintDell = Get-FirmwareVendorHints -Manufacturer 'Dell Inc.' -Model 'Latitude 7440'
    Assert-That 'Dell firmware hints are matched' (($hintDell.Vendor -eq 'Dell') -and ($hintDell.EnterKey -match 'F2')) $hintDell.Vendor
    $hintAcer = Get-FirmwareVendorHints -Manufacturer 'Acer' -Model 'Aspire A515'
    Assert-That 'Acer hint warns about the Supervisor Password' ($hintAcer.SecureBoot -match 'Supervisor Password')
    $hintSurface = Get-FirmwareVendorHints -Manufacturer 'Microsoft Corporation' -Model 'Surface Laptop 5'
    Assert-That 'Surface uses the volume-button entry method' ($hintSurface.EnterKey -match 'Volume Up')
    $hintUnknown = Get-FirmwareVendorHints -Manufacturer 'Acme Computers' -Model 'X1'
    Assert-That 'Unknown manufacturer gets no invented menu path' (($null -eq $hintUnknown.TPM) -and ($null -eq $hintUnknown.EnterKey))

    $fwState = New-SyntheticState
    $fwState.Tpm = [pscustomobject]@{ Present = $false; Ready = $false; SpecVersion = ''; IsTPM2 = $false }
    $fwState.Firmware.SecureBootEnabled = $false
    $guidance = Get-FirmwareGuidance -State $fwState
    Assert-That 'Firmware guidance lists only what is actually wrong' (@($guidance.Needed).Count -eq 2) (@($guidance.Needed | Select-Object -ExpandProperty What) -join '; ')
    Assert-That 'Firmware guidance is pure data, with no restart inside it' ($guidance.PSObject.Properties['CanOfferReboot'] -ne $null)

    $okState = New-SyntheticState
    Assert-That 'A correct machine needs no firmware changes' (@((Get-FirmwareGuidance -State $okState).Needed).Count -eq 0)

    # --- exit code meanings (restored from v1.6.0) ---
    Assert-That 'Exit code 3010 explains the restart' ((Get-ExitCodeMeaning -Code 3010) -match 'restart')
    Assert-That 'Exit code 4 explains the elevation failure' ((Get-ExitCodeMeaning -Code 4) -match 'Administrator')
    Assert-That 'Unknown exit codes do not throw' ((Get-ExitCodeMeaning -Code 99) -match 'Unrecognised')

    # --- confirmation must never prompt on an unattended run ---
    $previousUnattended = $script:Unattended
    $script:Unattended = $true
    Assert-That 'Unattended runs never block on a confirmation prompt' (Confirm-Action 'This must not prompt')
    Assert-That 'Unattended consent does not satisfy typed safety confirmation' (-not (Confirm-Action 'Risky' -RequireTyped 'hvci'))
    $script:Unattended = $previousUnattended

    # --- virtual machine assessment (restored from v1.6.0) ---
    $vm = Get-VirtualMachineAssessment -Computer ([pscustomobject]@{ IsVirtual = $true; Manufacturer = 'VMware, Inc.'; Model = 'VMware Virtual Platform' }) `
                                       -Virtualization ([pscustomobject]@{ FirmwareEnabled = $false })
    Assert-That 'VMware is identified' ($vm.Platform -eq 'VMware') $vm.Platform
    Assert-That 'VM guidance mentions nested virtualization' ((@($vm.Notes) -join ' ') -match 'Nested virtualization')
    $physical = Get-VirtualMachineAssessment -Computer ([pscustomobject]@{ IsVirtual = $false; Manufacturer = 'Dell Inc.'; Model = 'Latitude' }) `
                                             -Virtualization ([pscustomobject]@{ FirmwareEnabled = $true })
    Assert-That 'A physical machine gets no VM notes' (@($physical.Notes).Count -eq 0)

    # --- relaunch argument construction (privilege boundary) ---
    $quoted = Get-RelaunchArgumentList -Bound @{ ReportDirectory = 'C:\Temp\My Reports'; AuditOnly = [switch]$true }
    Assert-That 'Switch parameters relaunch without a value' (($quoted -contains '-AuditOnly') -and -not ($quoted -contains '"True"')) ($quoted -join ' ')
    Assert-That 'Paths with spaces are quoted as one argument' ($quoted -contains '"C:\Temp\My Reports"') ($quoted -join ' ')

    $hostile = Get-RelaunchArgumentList -Bound @{ ReportDirectory = 'C:\x" -Enable credential-guard "' }
    Assert-That 'Embedded quotes cannot inject a new argument' (-not ($hostile -contains '-Enable')) ($hostile -join ' ')
    Assert-That 'Embedded quotes are doubled, not passed through' (@($hostile | Where-Object { $_ -match '""' }).Count -eq 1) ($hostile -join ' ')

    $empty = Get-RelaunchArgumentList -Bound @{ AutoReboot = [switch]$false }
    Assert-That 'An unset switch is not relaunched' (@($empty).Count -eq 0) ('count={0}' -f @($empty).Count)

    # --- CIS comparison ---
    $cisState = New-SyntheticState
    $cisStatuses = Get-AllControlStatus -State $cisState
    $cis = Get-CisComplianceReport -State $cisState -Statuses $cisStatuses
    Assert-That 'CIS report covers all seven 18.9.5 controls' ($cis.TotalCount -eq 7) ('count={0}' -f $cis.TotalCount)
    Assert-That 'Nothing is CIS compliant with an empty policy hive' ($cis.CompliantCount -eq 0) ('compliant={0}' -f $cis.CompliantCount)

    $cisState.Policy = [pscustomobject]@{
        Path = $script:RegPolicyDG
        Values = @{ 'EnableVirtualizationBasedSecurity' = 1; 'RequirePlatformSecurityFeatures' = 3 }
        AnyConfigured = $true
    }
    $cis2 = Get-CisComplianceReport -State $cisState -Statuses $cisStatuses
    Assert-That 'A configured policy value is reported compliant' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.1' -and $_.Compliant }).Count -eq 1)
    Assert-That 'Platform security level 3 also passes CIS' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.2' -and $_.Compliant }).Count -eq 1)
    Assert-That 'HVCI divergence from CIS is documented' (@($cis2.Rows | Where-Object { $_.CisId -eq '18.9.5.3' -and $_.Divergence }).Count -eq 1)

    # --- HTML report ---
    $score2 = Get-SecurityScore -Statuses $cisStatuses
    $sc = Get-SecuredCoreVerdict -State $cisState -Statuses $cisStatuses
    $explanations = @(Get-ControlIds | ForEach-Object { Get-ControlExplanation -Id $_ -State $cisState })
    $html = New-HtmlReport -State $cisState -Statuses $cisStatuses -Score $score2 -SecuredCore $sc -Cis $cis2 -Explanations $explanations
    Assert-That 'HTML report is produced' ($html.Length -gt 3000) ('{0} bytes' -f $html.Length)
    Assert-That 'HTML report is self-contained' (($html -notmatch '<script') -and ($html -notmatch 'https?://[^"]*\.(css|js)')) 'no external css/js'
    Assert-That 'HTML report escapes markup in values' (-not ($html -match '<script>alert'))
    Assert-That 'HTML report states the CIS hive caveat' ($html -match 'Group Policy hive')

    $injected = New-SyntheticState
    $injected.Computer.Model = '<script>alert(1)</script>'
    $injStatuses = Get-AllControlStatus -State $injected
    $injHtml = New-HtmlReport -State $injected -Statuses $injStatuses -Score (Get-SecurityScore -Statuses $injStatuses) `
        -SecuredCore (Get-SecuredCoreVerdict -State $injected -Statuses $injStatuses) `
        -Cis (Get-CisComplianceReport -State $injected -Statuses $injStatuses) `
        -Explanations @(Get-ControlIds | ForEach-Object { Get-ControlExplanation -Id $_ -State $injected })
    Assert-That 'Hostile field content cannot inject markup' (-not ($injHtml -match '<script>alert\(1\)</script>')) 'model string is escaped'

    $textReport = New-TextReport -State $cisState -Statuses $cisStatuses -Score $score2 -SecuredCore $sc -Cis $cis2 -Explanations $explanations
    Assert-That 'Plain-text report is produced' ($textReport.Length -gt 1500) ('{0} bytes' -f $textReport.Length)
    Assert-That 'Text report states the CIS hive caveat' ($textReport -match 'Group Policy hive')
    Assert-That 'Text report includes the score' ($textReport -match 'SECURITY SCORE')
    Assert-That 'Text report includes DEP' ($textReport -match 'DEP')

    Set-RegistryProvider (New-RegistryProvider)
    $script:Unattended = $selfTestPriorUnattended

    Write-Line ''
    if ($script:stFail -eq 0) { Write-Line ('Self-test: {0} passed, 0 failed.' -f $script:stPass) 'Good'; return 0 }
    Write-Line ('Self-test: {0} passed, {1} FAILED.' -f $script:stPass, $script:stFail) 'Bad'
    return 1
}
