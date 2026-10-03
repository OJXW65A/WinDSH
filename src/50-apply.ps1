# ---------------------------------------------------------------------------
# Plan, apply and revert.
#
# The plan is a projection of the catalog, so -WhatIf cannot disagree with what apply
# actually writes. Every change is journalled BEFORE the registry is touched, which is
# what makes rollback possible even after an interrupted run. v1 had no rollback at all.
# ---------------------------------------------------------------------------

function Get-ControlDelta {
    param([Parameter(Mandatory = $true)][string]$Id)

    $control = Get-Control -Id $Id
    $rows = @()
    foreach ($value in (ConvertTo-Array $control.LocalValues)) {
        $exists = Test-RegValue -Path $value.Path -Name $value.Name
        $current = if ($exists) { Get-RegValue -Path $value.Path -Name $value.Name } else { $null }
        $comparison = if ($value.ContainsKey('Comparison')) { $value.Comparison } else { 'Exact' }

        $needs = if (-not $exists) { $true }
                 elseif ($comparison -eq 'AtLeast') { [int]$current -lt [int]$value.Value }
                 else { [int]$current -ne [int]$value.Value }

        $rows += [pscustomobject]@{
            ControlId = $control.Id
            ControlName = $control.Name
            Path = $value.Path
            Name = $value.Name
            Type = $value.Type
            Comparison = $comparison
            CurrentValue = $current
            CurrentExists = $exists
            DesiredValue = $value.Value
            NeedsChange = [bool]$needs
            Note = $value.Note
        }
    }
    return $rows
}

function Get-ChangePlan {
    param(
        [Parameter(Mandatory = $true)][string[]]$Ids,
        [Parameter(Mandatory = $true)]$State,
        [string[]]$ExplicitIds = @()
    )
    $plan = @()
    $seen = @{}
    foreach ($id in $Ids) {
        foreach ($control in (Resolve-ControlOrder -Id $id)) {
            if ($seen.ContainsKey($control.Id)) { continue }
            $seen[$control.Id] = $true

            $status = Get-ControlStatus -Id $control.Id -State $State
            $preflight = $null
            $deltas = @(Get-ControlDelta -Id $control.Id)
            if ($status.Supported -and -not $status.ManagedByPolicy -and @($deltas | Where-Object { $_.NeedsChange }).Count -gt 0) {
                $preflight = Get-ControlPreflight -Control $control
            }
            $requiresOverride = [bool]($preflight -and $preflight.Tripped -and $preflight.BlocksSafeSet)
            $explicit = [bool]($ExplicitIds -contains $control.Id)
            $skip = if ($status.ManagedByPolicy) { 'Managed by Group Policy' }
                    elseif (-not $status.Supported) { $status.SupportReason }
                    elseif ($requiresOverride) {
                        if ($explicit -and -not $script:Unattended) { $preflight.Message + ' A typed override is required.' }
                        else { $preflight.Message + ' Skipped for safety; use the interactive specific-control menu to confirm an override.' }
                    }
                    else { $null }
            foreach ($row in $deltas) {
                $plan += [pscustomobject]@{
                    ControlId = $row.ControlId
                    ControlName = $row.ControlName
                    Path = $row.Path
                    Name = $row.Name
                    Type = $row.Type
                    CurrentValue = $row.CurrentValue
                    CurrentExists = $row.CurrentExists
                    DesiredValue = $row.DesiredValue
                    NeedsChange = $row.NeedsChange
                    Note = $row.Note
                    ManagedByPolicy = $status.ManagedByPolicy
                    Supported = $status.Supported
                    ExplicitlyRequested = $explicit
                    Preflight = $preflight
                    RequiresOverride = $requiresOverride
                    SkipReason = $skip
                }
            }
        }
    }
    # A dependent cannot be enabled when its required protection is blocked.
    foreach ($row in $plan) {
        if ($row.SkipReason) { continue }
        foreach ($dep in (ConvertTo-Array (Get-Control -Id $row.ControlId).Requires)) {
            $blockedDep = @($plan | Where-Object { $_.ControlId -eq $dep -and $_.SkipReason })
            if ($blockedDep.Count -gt 0) {
                $row.SkipReason = ('Required control {0} is blocked: {1}' -f $dep, $blockedDep[0].SkipReason)
                break
            }
        }
    }
    return $plan
}

# ---------------------------------------------------------------------------
# Change journal
# ---------------------------------------------------------------------------

function Get-JournalPath {
    if ($env:WINDSH_JOURNAL_PATH) { return $env:WINDSH_JOURNAL_PATH }
    $root = if ($env:ProgramData) { Join-Path $env:ProgramData 'WinDSH' } else { Join-Path ([IO.Path]::GetTempPath()) 'WinDSH' }
    return (Join-Path $root 'changes.jsonl')
}

function Write-JournalEntry {
    param([Parameter(Mandatory = $true)]$Entry)
    $path = Get-JournalPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::AppendAllText($path, (($Entry | ConvertTo-Json -Compress -Depth 5) + "`n"), (New-Object Text.UTF8Encoding($false)))
}

function Get-Journal {
    param([string]$RunId)
    $path = Get-JournalPath
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    $entries = @()
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # A truncated tail must not make the whole journal unreadable.
        try { $entries += ($line | ConvertFrom-Json) } catch { continue }
    }
    if ($RunId) { $entries = @($entries | Where-Object { $_.RunId -eq $RunId }) }
    return $entries
}

function Get-JournalRuns {
    $runs = @()
    foreach ($group in (Get-Journal | Group-Object RunId)) {
        $first = @($group.Group | Sort-Object Time)[0]
        $runs += [pscustomobject]@{
            RunId = $group.Name
            Time = $first.Time
            ChangeCount = $group.Count
            Controls = (@($group.Group | Select-Object -ExpandProperty ControlId -Unique) -join ', ')
        }
    }
    return @($runs | Sort-Object Time -Descending)
}

# ---------------------------------------------------------------------------
# Apply / revert
# ---------------------------------------------------------------------------

function Invoke-ControlApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string[]]$Ids,
        [Parameter(Mandatory = $true)]$State,
        [string]$RunId,
        [string[]]$ExplicitIds = @()
    )

    if (-not $script:RemediationAllowed) { throw 'Remediation is disabled because the self-integrity check failed.' }
    if (-not $RunId) { $RunId = [Guid]::NewGuid().ToString('N').Substring(0, 12) }

    $applied = @(); $skipped = @()
    $plan = @(Get-ChangePlan -Ids $Ids -State $State -ExplicitIds $ExplicitIds)

    # Both preview and apply consume the same safety decision. Only a specifically
    # selected control in an interactive session can override a tripped check.
    foreach ($group in ($plan | Group-Object ControlId)) {
        $row = @($group.Group)[0]
        if (-not $row.RequiresOverride -or -not $row.ExplicitlyRequested -or $script:Unattended -or $WhatIfPreference) { continue }
        Write-Line $row.Preflight.Message 'Warn'
        if (Confirm-Action ('Enable {0} anyway?' -f $row.ControlName) -RequireTyped $row.ControlId) {
            foreach ($value in $group.Group) { $value.SkipReason = $null }
        }
    }
    # Rebuild dependency decisions after a genuine override without repeating queries.
    foreach ($row in $plan) {
        if ($row.SkipReason -notlike 'Required control *') { continue }
        $blockedDeps = @((Get-Control -Id $row.ControlId).Requires | Where-Object {
            $depId = $_
            @($plan | Where-Object { $_.ControlId -eq $depId -and $_.SkipReason }).Count -gt 0
        })
        if ($blockedDeps.Count -eq 0) { $row.SkipReason = $null }
    }

    # --- confirmation -----------------------------------------------------
    $pending = @($plan | Where-Object { $_.NeedsChange -and -not $_.SkipReason })
    if (@($pending).Count -gt 0 -and -not $script:Unattended -and -not $WhatIfPreference) {
        Write-Section 'About to change'
        foreach ($controlId in (@($pending | Select-Object -ExpandProperty ControlId -Unique))) {
            $control = Get-Control -Id $controlId
            Write-Line $control.Name 'Info' 2
            $caution = Get-PropertySafe $control 'Caution' $null
            if ($caution) { Write-Line $caution 'Warn' 5 }
        }
        Write-Line ''
        Write-Line ('{0} registry value(s) will change. A restart will be needed.' -f @($pending).Count) 'Plain'
        if (-not (Confirm-Action 'Continue?' -DefaultYes)) {
            Write-Line 'Cancelled. Nothing was changed.' 'Info'
            return [pscustomobject]@{ RunId = $RunId; Applied = @(); Skipped = @(); ChangeCount = 0; RestartRequired = $false; Cancelled = $true }
        }
    }

    foreach ($row in $plan) {
        if ($row.SkipReason) {
            if (-not @($skipped | Where-Object { $_.ControlId -eq $row.ControlId }).Count) {
                $skipped += [pscustomobject]@{ ControlId = $row.ControlId; ControlName = $row.ControlName; Reason = $row.SkipReason }
            }
            continue
        }
        if (-not $row.NeedsChange) { continue }

        $target = '{0}\{1}' -f $row.Path, $row.Name
        if (-not $PSCmdlet.ShouldProcess($target, ('Set {0} to {1}' -f $row.Type, $row.DesiredValue))) { continue }

        # Journal first. A crash before the write leaves a harmless no-op entry;
        # a crash after an unjournalled write leaves an unrevertible change.
        Write-JournalEntry ([pscustomobject]@{
            RunId = $RunId
            Time = (Get-Date).ToUniversalTime().ToString('o')
            ToolVersion = $script:ToolVersion
            ControlId = $row.ControlId
            Path = $row.Path
            Name = $row.Name
            Type = $row.Type
            BeforeExists = $row.CurrentExists
            BeforeValue = $row.CurrentValue
            AfterValue = $row.DesiredValue
        })

        & $script:Registry.SetValue $row.Path $row.Name $row.Type $row.DesiredValue

        $applied += [pscustomobject]@{
            ControlId = $row.ControlId
            ControlName = $row.ControlName
            Path = $row.Path
            Name = $row.Name
            Before = if ($row.CurrentExists) { $row.CurrentValue } else { '(not set)' }
            After = $row.DesiredValue
        }
    }

    if ($applied.Count -gt 0) { $script:RestartRequired = $true }
    $script:AppliedChanges += $applied

    return [pscustomobject]@{
        RunId = $RunId
        Applied = $applied
        Skipped = $skipped
        ChangeCount = $applied.Count
        RestartRequired = [bool]($applied.Count -gt 0)
        Cancelled = $false
    }
}

function Invoke-ControlRevert {
    <#
        Restores each journalled value in reverse order. A value that did not exist before
        the run is removed rather than set to zero, so the machine returns to its actual
        prior state instead of an approximation of it.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$RunId)

    if (-not $RunId) {
        $runs = Get-JournalRuns
        if (@($runs).Count -eq 0) { throw 'There is nothing to revert: no changes have been recorded on this computer.' }
        $RunId = @($runs)[0].RunId
    }

    $entries = @(Get-Journal -RunId $RunId)
    if ($entries.Count -eq 0) { throw ("No recorded changes found for run '{0}'." -f $RunId) }

    [array]::Reverse($entries)
    $reverted = @()

    foreach ($entry in $entries) {
        $target = '{0}\{1}' -f $entry.Path, $entry.Name
        if ($entry.BeforeExists) {
            if (-not $PSCmdlet.ShouldProcess($target, ('Restore to {0}' -f $entry.BeforeValue))) { continue }
            & $script:Registry.SetValue $entry.Path $entry.Name $entry.Type $entry.BeforeValue
            $restored = $entry.BeforeValue
        }
        else {
            if (-not $PSCmdlet.ShouldProcess($target, 'Remove value (did not exist before)')) { continue }
            & $script:Registry.RemoveValue $entry.Path $entry.Name
            $restored = '(removed)'
        }
        $reverted += [pscustomobject]@{ ControlId = $entry.ControlId; Path = $entry.Path; Name = $entry.Name; RestoredTo = $restored }
    }

    if ($reverted.Count -gt 0) { $script:RestartRequired = $true }

    return [pscustomobject]@{
        RunId = $RunId
        Reverted = $reverted
        ChangeCount = $reverted.Count
        RestartRequired = [bool]($reverted.Count -gt 0)
    }
}
