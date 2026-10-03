# ---------------------------------------------------------------------------
# Plan, apply and revert.
#
# The plan is a projection of the catalog, so -WhatIf cannot disagree with what apply
# actually writes. Intent is flushed before writing; completion/revert markers distinguish
# confirmed changes from ambiguous interrupted writes and prevent stale replay.
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
            CurrentType = if ($exists) { Get-RegKind -Path $value.Path -Name $value.Name } else { $null }
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
                    CurrentType = $row.CurrentType
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

# Tests inject a private path only with the in-memory registry provider. An inherited
# WINDSH_JOURNAL_PATH never controls an elevated production write.
$script:TestJournalPath = $null

function Get-JournalPath {
    if ($script:Registry.Kind -eq 'InMemory' -and $script:TestJournalPath) { return $script:TestJournalPath }
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programData) { throw 'ProgramData is unavailable; refusing to use a temporary production journal.' }
    return (Join-Path (Join-Path $programData 'WinDSH') 'changes.jsonl')
}

function Enter-JournalLock {
    $path = Get-JournalPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
    if ($script:Registry.Kind -eq 'Windows') {
        # The journal contains privileged rollback data. Reject links and restrict
        # writes to administrators/SYSTEM, including an existing pre-created folder.
        $item = Get-Item -LiteralPath $dir -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'The journal folder cannot be a reparse point.' }
        foreach ($file in @($path, ($path + '.lock'))) {
            if (Test-Path -LiteralPath $file) {
                if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Journal files cannot be reparse points.' }
            }
        }
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidText in @('S-1-5-32-544', 'S-1-5-18')) {
            $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        Set-Acl -LiteralPath $dir -AclObject $acl -ErrorAction Stop
        foreach ($file in @($path, ($path + '.lock'))) {
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $fileAcl = New-Object Security.AccessControl.FileSecurity
            $fileAcl.SetAccessRuleProtection($false, $false)
            $fileAcl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
            Set-Acl -LiteralPath $file -AclObject $fileAcl -ErrorAction Stop
        }
    }
    try { $handle = [IO.File]::Open(($path + '.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'Another WinDSH change operation is running, or the journal lock is inaccessible. No changes were made.' }
    try {
        # Validate the existing journal before any new change. Remove only an invalid
        # unterminated tail, otherwise the next append would turn it into middle damage.
        [void](Get-Journal)
        if (Test-Path -LiteralPath $path) {
            $raw = [IO.File]::ReadAllText($path)
            if ($raw.Length -gt 0 -and -not $raw.EndsWith("`n")) {
                $lastLf = $raw.LastIndexOf("`n")
                $tail = $raw.Substring($lastLf + 1)
                try {
                    $tailRecord = $tail | ConvertFrom-Json -ErrorAction Stop
                    if (-not (Get-PropertySafe $tailRecord 'RunId' $null)) { throw 'Missing RunId.' }
                    $repaired = $raw + "`n"
                }
                catch { $repaired = $raw.Substring(0, $lastLf + 1) }
                [IO.File]::WriteAllText($path, $repaired, (New-Object Text.UTF8Encoding($false)))
            }
        }
        return $handle
    }
    catch { $handle.Dispose(); throw }
}

function Write-JournalEntry {
    param([Parameter(Mandatory = $true)]$Entry)
    $path = Get-JournalPath
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Entry | ConvertTo-Json -Compress -Depth 5) + "`n")
    $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Get-Journal {
    param([string]$RunId)
    $path = Get-JournalPath
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $raw = [IO.File]::ReadAllText($path)
    $lines = @($raw -split "`n")
    $entries = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $record = $line | ConvertFrom-Json -ErrorAction Stop
            if (-not (Get-PropertySafe $record 'RunId' $null)) { throw 'Missing RunId.' }
            $entries += $record
        }
        catch {
            # Only a torn final append may be ignored; a corrupt middle/terminated
            # record could hide an applied/reverted marker, so do not guess.
            if ($i -eq $lines.Count - 1 -and -not $raw.EndsWith("`n")) { break }
            throw ('The change journal is malformed at line {0}. Revert is disabled until it is repaired.' -f ($i + 1))
        }
    }
    if ($RunId) { $entries = @($entries | Where-Object { $_.RunId -eq $RunId }) }
    return $entries
}

function Get-JournalChanges {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records)
    $changes = @(); $seen = @{}; $index = 0
    foreach ($record in $Records) {
        $index++
        $kind = Get-PropertySafe $record 'RecordType' 'LegacyChange'
        if ($kind -notin @('Change', 'LegacyChange')) { continue }
        $id = Get-PropertySafe $record 'ChangeId' ('legacy-{0}' -f $index)
        if ($seen.ContainsKey($id)) { throw 'The journal contains duplicate change identifiers.' }
        $seen[$id] = $true
        $markers = @($Records | Where-Object { (Get-PropertySafe $_ 'ChangeId' '') -eq $id })
        $changes += [pscustomobject]@{
            Id = $id
            Entry = $record
            Applied = [bool]($kind -eq 'LegacyChange' -or @($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'Applied' }).Count -gt 0)
            RevertStarted = [bool](@($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertStarted' }).Count -gt 0)
            Reverted = [bool](@($markers | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'Reverted' }).Count -gt 0)
        }
    }
    return $changes
}

function Get-JournalRuns {
    $runs = @()
    foreach ($group in (Get-Journal | Group-Object RunId)) {
        $changes = @(Get-JournalChanges -Records @($group.Group) | Where-Object { -not $_.Reverted })
        if ($changes.Count -eq 0) { continue }
        if (@($group.Group | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertCompleted' }).Count -gt 0) { continue }
        $first = @($group.Group)[0]
        $runs += [pscustomobject]@{
            RunId = $group.Name
            Time = $first.Time
            ChangeCount = $changes.Count
            Controls = (@($changes | ForEach-Object { $_.Entry.ControlId } | Select-Object -Unique) -join ', ')
        }
    }
    return @($runs | Sort-Object Time -Descending)
}

function Write-JournalMarker {
    param([string]$RunId, [string]$RecordType, [string]$ChangeId)
    Write-JournalEntry ([pscustomobject]@{ RunId = $RunId; Time = (Get-Date).ToUniversalTime().ToString('o'); RecordType = $RecordType; ChangeId = $ChangeId })
}

function Test-JournalChange {
    param($Entry)
    # A journal is data, not authority to write arbitrary registry paths or policies.
    $control = Get-Control -Id $Entry.ControlId
    $allowed = @($control.LocalValues | Where-Object { $_.Path -eq $Entry.Path -and $_.Name -eq $Entry.Name -and $_.Type -eq $Entry.Type -and $_.Value -eq $Entry.AfterValue })
    if ($allowed.Count -ne 1 -or $Entry.BeforeExists -isnot [bool]) { throw 'The journal contains a change outside the control catalog.' }
    $beforeType = Get-PropertySafe $Entry 'BeforeType' $Entry.Type
    if ($Entry.BeforeExists -and ($beforeType -ne 'DWord' -or $Entry.BeforeValue -isnot [ValueType] -or [long]$Entry.BeforeValue -lt [int]::MinValue -or [long]$Entry.BeforeValue -gt [uint32]::MaxValue)) {
        throw 'The journal contains an unsupported prior registry value. Restore it manually.'
    }
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

    $lock = $null
    if (-not $WhatIfPreference) { $lock = Enter-JournalLock }
    try {
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

            # Check again under the run lock: another administrator can change state
            # after planning even though other WinDSH processes are serialized.
            $existsNow = Test-RegValue -Path $row.Path -Name $row.Name
            $currentNow = if ($existsNow) { Get-RegValue -Path $row.Path -Name $row.Name } else { $null }
            $kindNow = if ($existsNow) { Get-RegKind -Path $row.Path -Name $row.Name } else { $null }
            if ($existsNow -ne $row.CurrentExists -or $currentNow -ne $row.CurrentValue -or $kindNow -ne $row.CurrentType) { throw 'Registry state changed since planning. Run the audit again.' }
            if ($existsNow -and $kindNow -ne 'DWord') { throw 'The existing registry value is not a DWORD. Review it manually before remediation.' }
            $changeId = [Guid]::NewGuid().ToString('N')
            Write-JournalEntry ([pscustomobject]@{
                RecordType = 'Change'
                ChangeId = $changeId
                RunId = $RunId
                Time = (Get-Date).ToUniversalTime().ToString('o')
                ToolVersion = $script:ToolVersion
                ControlId = $row.ControlId
                Path = $row.Path
                Name = $row.Name
                Type = $row.Type
                BeforeType = $row.CurrentType
                BeforeExists = $row.CurrentExists
                BeforeValue = $row.CurrentValue
                AfterValue = $row.DesiredValue
            })
            & $script:Registry.SetValue $row.Path $row.Name $row.Type $row.DesiredValue
            $script:RestartRequired = $true

            $applied += [pscustomobject]@{
                ControlId = $row.ControlId
                ControlName = $row.ControlName
                Path = $row.Path
                Name = $row.Name
                Before = if ($row.CurrentExists) { $row.CurrentValue } else { '(not set)' }
                After = $row.DesiredValue
            }
            $script:AppliedChanges += $applied[-1]
            Write-JournalMarker -RunId $RunId -RecordType 'Applied' -ChangeId $changeId
        }

        if ($applied.Count -gt 0) { $script:RestartRequired = $true }
        if ($applied.Count -gt 0) { Write-JournalMarker -RunId $RunId -RecordType 'RunCompleted' }

        return [pscustomobject]@{
            RunId = $RunId
            Applied = $applied
            Skipped = $skipped
            ChangeCount = $applied.Count
            RestartRequired = [bool]($applied.Count -gt 0)
            Cancelled = $false
        }
    }
    finally { if ($lock) { $lock.Dispose() } }
}


function Invoke-ControlRevert {
    <# Restore only values still matching completed writes, once per entry. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$RunId)

    if (-not $script:RemediationAllowed) { throw 'Revert is disabled because the self-integrity check failed.' }
    $lock = $null
    if (-not $WhatIfPreference) { $lock = Enter-JournalLock }
    try {
        if (-not $RunId) {
            $runs = @(Get-JournalRuns)
            if ($runs.Count -eq 0) { throw 'There is nothing to revert: no open change runs remain.' }
            $RunId = $runs[0].RunId
        }
        $records = @(Get-Journal -RunId $RunId)
        if (@($records | Where-Object { (Get-PropertySafe $_ 'RecordType' '') -eq 'RevertCompleted' }).Count -gt 0) { throw 'This run has already been reverted.' }
        $changes = @(Get-JournalChanges -Records $records | Where-Object { -not $_.Reverted })
        if ($changes.Count -eq 0) { throw ('No open changes found for run {0}.' -f $RunId) }
        # Validate every change before restoring anything, including legacy records.
        foreach ($change in $changes) { Test-JournalChange -Entry $change.Entry }
        [array]::Reverse($changes)
        $reverted = @(); $conflicts = @(); $recovered = 0
        foreach ($change in $changes) {
            $entry = $change.Entry
            $target = '{0}\{1}' -f $entry.Path, $entry.Name
            $exists = Test-RegValue -Path $entry.Path -Name $entry.Name
            $current = if ($exists) { Get-RegValue -Path $entry.Path -Name $entry.Name } else { $null }
            $kind = if ($exists) { Get-RegKind -Path $entry.Path -Name $entry.Name } else { $null }
            $beforeType = Get-PropertySafe $entry 'BeforeType' $entry.Type
            $matchesBefore = [bool]($exists -eq $entry.BeforeExists -and (-not $exists -or ($current -eq $entry.BeforeValue -and $kind -eq $beforeType)))
            if ($change.RevertStarted -and $matchesBefore) {
                if ($PSCmdlet.ShouldProcess($target, 'Record recovery of an interrupted revert')) {
                    Write-JournalMarker -RunId $RunId -RecordType 'Reverted' -ChangeId $change.Id
                    $recovered++
                }
                continue
            }
            $reason = if (-not $change.Applied) { 'The original registry write was not confirmed. Review this interrupted change manually.' }
                      elseif (-not $exists -or $current -ne $entry.AfterValue -or $kind -ne $entry.Type) { 'Current state differs from the value WinDSH wrote; leaving it unchanged.' }
                      else { $null }
            if ($reason) {
                $conflicts += [pscustomobject]@{ ControlId = $entry.ControlId; Path = $entry.Path; Name = $entry.Name; Reason = $reason }
                continue
            }
            $action = if ($entry.BeforeExists) { 'Restore to {0}' -f $entry.BeforeValue } else { 'Remove value (did not exist before)' }
            if (-not $PSCmdlet.ShouldProcess($target, $action)) { continue }
            Write-JournalMarker -RunId $RunId -RecordType 'RevertStarted' -ChangeId $change.Id
            if ($entry.BeforeExists) { & $script:Registry.SetValue $entry.Path $entry.Name $beforeType $entry.BeforeValue }
            else { & $script:Registry.RemoveValue $entry.Path $entry.Name }
            $script:RestartRequired = $true
            Write-JournalMarker -RunId $RunId -RecordType 'Reverted' -ChangeId $change.Id
            $restored = if ($entry.BeforeExists) { $entry.BeforeValue } else { '(removed)' }
            $reverted += [pscustomobject]@{ ControlId = $entry.ControlId; Path = $entry.Path; Name = $entry.Name; RestoredTo = $restored }
        }
        if (-not $WhatIfPreference -and $conflicts.Count -eq 0 -and $reverted.Count + $recovered -eq $changes.Count) {
            Write-JournalMarker -RunId $RunId -RecordType 'RevertCompleted'
        }
        return [pscustomobject]@{
            RunId = $RunId; Reverted = $reverted; Conflicts = $conflicts
            ChangeCount = $reverted.Count; RecoveredCount = $recovered
            RestartRequired = [bool]($reverted.Count -gt 0)
        }
    }
    finally { if ($lock) { $lock.Dispose() } }
}
