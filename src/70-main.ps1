# ---------------------------------------------------------------------------
# Console rendering. Two tiers: a plain-language summary by default, full technical
# detail behind -Advanced. v1 showed one uniform level of detail to everyone.
# ---------------------------------------------------------------------------

function Show-Summary {
    param($State, $Statuses, $Score, $SecuredCore)

    Write-Section 'Applicable protection score'
    $kind = if ($Score.UnknownCount -gt 0) { 'Warn' } elseif ($Score.Score -ge 75) { 'Good' } elseif ($Score.Score -ge 50) { 'Warn' } else { 'Bad' }
    Write-Line ('{0} / 100  ({1})' -f $Score.Score, $Score.Grade) $kind
    Write-Line ('{0} of {1} scored controls are applicable; unsupported controls are excluded.' -f $Score.ApplicableCount, $Score.TotalCount) 'Dim'
    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count
    Write-Line ('{0} of {1} applicable protections are active.' -f $running, $countable) 'Plain'
    if ($Score.UnknownCount -gt 0) { Write-Line ('{0} scored protection(s) could not be verified; they earn no points and remain in the total.' -f $Score.UnknownCount) 'Warn' }
    if ($Score.ExcludedCount -gt 0) {
        Write-Line ('{0} excluded: current platform requirements are not met, so they are not counted against you.' -f $Score.ExcludedCount) 'Dim'
    }

    if ($State.HypervisorLaunch.BlocksVbs) {
        Write-Line ''
        Write-Line 'The Windows hypervisor is switched off in the boot configuration.' 'Bad'
        Write-Line 'No virtualization-based protection can start until that is changed.' 'Bad' 2
    }

    Write-Section 'Protections'
    foreach ($s in $Statuses) {
        $kind = switch ($s.State) {
            'Running' { 'Good' }
            'ConfiguredNotRunning' { 'Warn' }
            'NotConfigured' { 'Bad' }
            default { 'Info' }
        }
        $label = (Get-StateLabel $s.State).Text
        $policy = if ($s.ManagedByPolicy) { ' (Group Policy)' } else { '' }
        Write-Line ('{0,-34} {1}{2}' -f $s.PlainName, $label, $policy) $kind
        if ($Advanced) {
            Write-Line ('{0}  [{1}]' -f $s.Name, $s.Id) 'Dim' 9
            if ($s.SupportReason) { Write-Line $s.SupportReason 'Dim' 9 }
        }
    }

    if ($Advanced) {
        Write-Section 'System'
        Write-Line ('Machine     : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) 'Dim'
        Write-Line ('Processor   : {0}' -f $State.Computer.ProcessorName) 'Dim'
        Write-Line ('Windows     : {0} build {1} ({2})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber, $State.Computer.EditionId) 'Dim'
        Write-Line ('Firmware    : {0} (mode {1}, via {2})' -f $State.Firmware.Type, $State.Firmware.Mode, $State.Firmware.DetectionSource) 'Dim'
        Write-Line ('Secure Boot : {0}' -f (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable')) 'Dim'
        Write-Line ('TPM         : {0} (spec {1})' -f (Format-Bool $State.Tpm.IsTPM2 'TPM 2.0' 'not confirmed'), $State.Tpm.SpecVersion) 'Dim'
        Write-Line ('Hypervisor  : launch type {0} via {1}' -f $State.HypervisorLaunch.LaunchType, $State.HypervisorLaunch.Source) 'Dim'
        Write-Line ('Secured-core: {0}' -f (Format-Bool $SecuredCore.Qualifies 'qualifies' ('does not qualify ({0} unmet)' -f $SecuredCore.UnmetCount))) 'Dim'
    }
}

function Show-NextSteps {
    param($Explanations)
    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    Write-Section 'What to do next'
    if (@($todo).Count -eq 0) { Write-Line 'Nothing. Every protection this computer supports is active.' 'Good'; return }

    $n = 0
    foreach ($e in $todo) {
        $n++
        Write-Line ''
        Write-Line ('{0}. {1}' -f $n, $e.PlainName) 'Head'
        Write-Line $e.Verdict $(if ($e.Severity -eq 'Warn') { 'Warn' } else { 'Info' }) 3
        if ($e.Action) {
            foreach ($line in ($e.Action -split "`n")) { Write-Line $line 'Plain' 6 }
        }
    }
}

function Show-CisSummary {
    param($Cis)
    Write-Section 'CIS Benchmark comparison'
    Write-Line ('{0}, section {1}' -f $Cis.Benchmark, $Cis.Section) 'Dim'
    Write-Line ('{0} of {1} checks pass.' -f $Cis.CompliantCount, $Cis.TotalCount) $(if ($Cis.CompliantCount -eq $Cis.TotalCount) { 'Good' } else { 'Warn' })
    if ($Cis.RunningButNotCompliantCount -gt 0) {
        Write-Line ('{0} protection(s) are running but still fail their CIS check.' -f $Cis.RunningButNotCompliantCount) 'Info'
    }
    Write-Line $Cis.Note 'Dim'
    foreach ($r in $Cis.Rows) {
        $kind = if (-not $r.PolicyKnown) { 'Warn' } elseif ($r.Compliant) { 'Good' } else { 'Bad' }
        $actual = if (-not $r.PolicyKnown) { 'unavailable' } elseif ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        Write-Line ('{0,-9} {1,-38} policy value = {2}' -f $r.CisId, $r.PolicyValueName, $actual) $kind 2
    }
}

function Show-Plan {
    param($Plan)
    Write-Section 'Planned changes'
    $changes = @($Plan | Where-Object { $_.NeedsChange -and -not $_.SkipReason })
    $skips = @($Plan | Where-Object { $_.SkipReason } | Group-Object ControlId)

    if (@($changes).Count -eq 0) { Write-Line 'No changes are needed.' 'Good' }
    foreach ($c in $changes) {
        $before = if ($c.CurrentExists) { [string]$c.CurrentValue } else { '(not set)' }
        Write-Line ('{0}\{1}: {2} -> {3}' -f $c.Path, $c.Name, $before, $c.DesiredValue) 'Info' 2
        if ($c.Note) { Write-Line $c.Note 'Dim' 6 }
    }
    foreach ($g in $skips) {
        Write-Line ('Skipping {0}: {1}' -f $g.Name, @($g.Group)[0].SkipReason) 'Warn' 2
    }
}

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

function Get-ReportFolder {
    if (-not [string]::IsNullOrWhiteSpace($ReportDirectory)) { return $ReportDirectory }
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = [IO.Path]::GetTempPath() }
    return (Join-Path $desktop 'WinDSH-Reports')
}

function Save-Reports {
    param($State, $Statuses, $Score, $SecuredCore, $Cis, $Explanations, [hashtable]$Formats)
    if ($NoReport) { return @() }

    # Interactive callers pass an explicit format selection; command-line runs fall back
    # to the switches, defaulting to HTML.
    $wantHtml = if ($Formats) { [bool]$Formats.Html } else { [bool]($HtmlReport -or -not ($JsonReport -or $TextReport)) }
    $wantText = if ($Formats) { [bool]$Formats.Text } else { [bool]$TextReport }
    $wantJson = if ($Formats) { [bool]$Formats.Json } else { [bool]$JsonReport }

    $folder = Get-ReportFolder
    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false | Out-Null
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $folder ('WinDSH-{0}-{1}' -f $State.Computer.Name, $stamp)
    $written = @()
    $encoding = New-Object Text.UTF8Encoding($false)

    if ($wantText) {
        $text = New-TextReport -State $State -Statuses $Statuses -Score $Score -SecuredCore $SecuredCore -Cis $Cis -Explanations $Explanations
        $path = $base + '.txt'
        [IO.File]::WriteAllText($path, $text, $encoding)
        $written += $path
    }
    if ($wantHtml) {
        $html = New-HtmlReport -State $State -Statuses $Statuses -Score $Score -SecuredCore $SecuredCore -Cis $Cis -Explanations $Explanations
        $path = $base + '.html'
        [IO.File]::WriteAllText($path, $html, $encoding)
        $written += $path
    }
    if ($wantJson) {
        $payload = [pscustomobject]@{
            SchemaVersion = $script:SchemaVersion
            Tool = [pscustomobject]@{ Name = $script:ToolName; Version = $script:ToolVersion; Integrity = (Get-SelfIntegrity).Status }
            Generated = $State.Generated
            Computer = $State.Computer
            Firmware = $State.Firmware
            Tpm = $State.Tpm
            HypervisorLaunch = $State.HypervisorLaunch
            Restart = $State.Restart
            Score = $Score
            SecuredCore = $SecuredCore
            Controls = $Statuses
            Cis = $Cis
            AppliedChanges = $script:AppliedChanges
            Warnings = $script:Warnings
        }
        $path = $base + '.json'
        [IO.File]::WriteAllText($path, ($payload | ConvertTo-Json -Depth 12), $encoding)
        $written += $path
    }
    return $written
}

function Write-RmmOutput {
    param($State, $Statuses, $Score, $Cis)
    $payload = [pscustomobject]@{
        schemaVersion = $script:SchemaVersion
        tool = $script:ToolName
        version = $script:ToolVersion
        computer = $State.Computer.Name
        generated = $State.Generated
        score = $Score.Score
        grade = $Score.Grade
        restartRequired = $script:RestartRequired
        hypervisorBlocksVbs = $State.HypervisorLaunch.BlocksVbs
        firmwareMode = $State.Firmware.Mode
        secureBoot = $State.Firmware.SecureBootEnabled
        tpm2 = $State.Tpm.IsTPM2
        cisCompliant = $Cis.CompliantCount
        cisTotal = $Cis.TotalCount
        controls = @($Statuses | ForEach-Object { [pscustomobject]@{ id = $_.Id; state = $_.State; policy = $_.ManagedByPolicy } })
        changes = @($script:AppliedChanges).Count
        warnings = @($script:Warnings).Count
        exitCode = $script:ExitCode
    }
    $script:RmmOutputWritten = $true
    Write-Output ($payload | ConvertTo-Json -Depth 8 -Compress)
}

# ---------------------------------------------------------------------------
# Interactive
# ---------------------------------------------------------------------------

function Wait-ForKey {
    param([string]$Message = 'Press any key to return to the menu...')
    Write-Line ''
    Write-Line $Message 'Info'
    try { [void][Console]::ReadKey($true) }
    catch { [void](Read-Host) }
}

function Show-Menu {
    param($Statuses, $Score)
    Write-Host ''
    Write-Line ('{0} {1}   applicable protection score {2}/100 ({3})' -f $script:ToolName, $script:ToolVersion, $Score.Score, $Score.Grade) 'Head'
    Write-Host ''
    Write-Line '  [1] Re-check this computer' 'Plain'
    Write-Line '  [2] Fix what can be fixed safely' 'Plain'
    Write-Line '  [3] Explain a protection' 'Plain'
    Write-Line '  [4] Save a report' 'Plain'
    Write-Line '  [5] More options' 'Plain'
    Write-Line '  [Q] Quit' 'Plain'
    Write-Host ''
}

function Show-MoreMenu {
    Write-Host ''
    Write-Line 'More options' 'Head'
    Write-Host ''
    Write-Line '  [A] Preview what "fix safely" would change' 'Plain'
    Write-Line '  [B] Turn on a specific protection' 'Plain'
    Write-Line '  [C] Undo a previous change' 'Plain'
    Write-Line '  [D] CIS Benchmark comparison' 'Plain'
    Write-Line '  [E] Open Windows Core isolation settings' 'Plain'
    Write-Line '  [F] How to change BIOS/UEFI settings on this PC' 'Plain'
    Write-Line '  [G] Why is Memory Integrity blocked? (driver diagnostics)' 'Plain'
    Write-Line '  [H] Open the Code Integrity event log' 'Plain'
    Write-Line '  [X] Back' 'Plain'
    Write-Host ''
}

function Read-Choice {
    param([string]$Valid)
    while ($true) {
        $raw = Read-Host 'Select'
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $c = $raw.Trim().ToUpperInvariant()
        if ($c.Length -eq 1 -and $Valid.Contains($c)) { return $c }
        Write-Line 'Not a valid choice.' 'Warn'
    }
}

function Select-ControlInteractive {
    Write-Line ''
    $ids = Get-ControlIds
    $n = 0
    foreach ($id in $ids) { $n++; Write-Line ('  {0}. {1}' -f $n, (Get-Control -Id $id).PlainName) 'Plain' }
    $raw = Read-Host 'Number (blank to cancel)'
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $index = 0
    if (-not [int]::TryParse($raw.Trim(), [ref]$index)) { return $null }
    if ($index -lt 1 -or $index -gt @($ids).Count) { return $null }
    return @($ids)[$index - 1]
}

function Show-Explanation {
    param($Explanation)
    Write-Section $Explanation.PlainName
    Write-Line $Explanation.Name 'Dim'
    Write-Line ''
    Write-Line $Explanation.Summary 'Plain'
    Write-Line ('Why it matters: {0}' -f $Explanation.Why) 'Dim'
    if ($Explanation.Caution) { Write-Line ('Caution: {0}' -f $Explanation.Caution) 'Warn' }
    Write-Line ''
    Write-Line $Explanation.Verdict $(switch ($Explanation.Severity) { 'Good' { 'Good' } 'Warn' { 'Warn' } default { 'Info' } })
    if ($Explanation.Action) {
        Write-Line ''
        Write-Line 'What to do:' 'Head'
        foreach ($line in ($Explanation.Action -split "`n")) { Write-Line $line 'Plain' 2 }
    }
    if ($Explanation.Cis) {
        Write-Line ''
        Write-Line ('CIS {0} ({1}): {2}' -f $Explanation.Cis.Id, $Explanation.Cis.Profile, $Explanation.Cis.Title) 'Dim'
    }
    Write-Line ('Reference: {0}' -f $Explanation.DocUrl) 'Dim'
}

function Invoke-Interactive {
    param($State)

    $assessment = Get-Assessment -State $State

    Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
    Show-NextSteps -Explanations $assessment.Explanations

    $changed = $false
    while ($true) {
        Show-Menu -Statuses $assessment.Statuses -Score $assessment.Score
        $choice = Read-Choice '12345Q'

        if ($choice -eq 'Q') {
            # No second full audit when nothing changed: the state we have is still true.
            if (-not $changed) {
                Write-Line ''
                Write-Line 'No changes were made to this computer.' 'Dim'
                if ($State.Restart.Pending) { Write-Line 'Note: Windows has its own restart pending, unrelated to this tool.' 'Dim' }
                return
            }
            $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations
            foreach ($p in $paths) { Write-Line ('Report saved: {0}' -f $p) 'Good' }
            if ($script:RestartRequired) {
                Write-Line ''
                Write-Line 'A restart is needed before the changes take effect.' 'Warn'
            }
            return
        }

        switch ($choice) {
            '1' {
                $State = Get-SystemState -Volatile
                $assessment = Get-Assessment -State $State
                Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
                Show-NextSteps -Explanations $assessment.Explanations
            }
            '2' {
                $result = Invoke-ControlApply -Ids $script:SafeControlSet -State $State
                if ($result.ChangeCount -gt 0) { $changed = $true }
                Write-Section 'Result'
                if ($result.ChangeCount -eq 0) { Write-Line 'Nothing needed changing.' 'Good' }
                foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                foreach ($s in $result.Skipped) { Write-Line ('Skipped {0}: {1}' -f $s.ControlName, $s.Reason) 'Warn' 2 }
                if ($result.RestartRequired) {
                    Write-Line ''
                    Write-Line ('Restart required. Undo with:  -Revert -RunId {0}' -f $result.RunId) 'Info'
                }
                $State = Get-SystemState -Volatile
                $assessment = Get-Assessment -State $State
            }
            '3' {
                $id = Select-ControlInteractive
                if ($id) { Show-Explanation (Get-ControlExplanation -Id $id -State $State) }
            }
            '4' {
                Write-Line ''
                Write-Line 'Report format:' 'Head'
                Write-Line '  [1] Web page (HTML) - easiest to read and share' 'Plain'
                Write-Line '  [2] Plain text' 'Plain'
                Write-Line '  [3] JSON - for other tools' 'Plain'
                Write-Line '  [4] All three' 'Plain'
                $fmt = Read-Choice '1234'
                $script:HtmlSelected = [bool]($fmt -eq '1' -or $fmt -eq '4')
                $script:TextSelected = [bool]($fmt -eq '2' -or $fmt -eq '4')
                $script:JsonSelected = [bool]($fmt -eq '3' -or $fmt -eq '4')
                $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations -Formats @{ Html = $script:HtmlSelected; Text = $script:TextSelected; Json = $script:JsonSelected }
                foreach ($p in $paths) { Write-Line ('Saved: {0}' -f $p) 'Good' }
            }
            '5' {
                Show-MoreMenu
                $sub = Read-Choice 'ABCDEFGHX'
                switch ($sub) {
                    'A' { Show-Plan (Get-ChangePlan -Ids $script:SafeControlSet -State $State) }
                    'B' {
                        $id = Select-ControlInteractive
                        if ($id) {
                            $result = Invoke-ControlApply -Ids @($id) -State $State -ExplicitIds @($id)
                            if ($result.ChangeCount -gt 0) { $changed = $true }
                            Write-Section 'Result'
                            if ($result.ChangeCount -eq 0) { Write-Line 'Nothing needed changing.' 'Good' }
                            foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                            foreach ($s in $result.Skipped) { Write-Line ('Skipped {0}: {1}' -f $s.ControlName, $s.Reason) 'Warn' 2 }
                            $State = Get-SystemState -Volatile
                            $assessment = Get-Assessment -State $State
                        }
                    }
                    'C' {
                        $runs = Get-JournalRuns
                        if (@($runs).Count -eq 0) { Write-Line 'No recorded changes to undo.' 'Info' }
                        else {
                            Write-Section 'Recorded change runs'
                            foreach ($r in $runs) { Write-Line ('{0}  {1}  {2} change(s)  [{3}]' -f $r.RunId, $r.Time, $r.ChangeCount, $r.Controls) 'Plain' 2 }
                            $rid = Read-Host 'Run id to undo (blank to cancel)'
                            if (-not [string]::IsNullOrWhiteSpace($rid)) {
                                $rev = Invoke-ControlRevert -RunId $rid.Trim()
                                if ($rev.ChangeCount -gt 0) { $changed = $true }
                                foreach ($conflict in $rev.Conflicts) { Write-Line $conflict.Reason 'Warn'; Add-Warning $conflict.Reason }
                                Write-Line ('Reverted {0} change(s).' -f $rev.ChangeCount) 'Good'
                                $State = Get-SystemState -Volatile
                                $assessment = Get-Assessment -State $State
                            }
                        }
                    }
                    'D' { Show-CisSummary -Cis $assessment.Cis }
                    'E' {
                        try { Start-Process 'windowsdefender://coreisolation' | Out-Null; Write-Line 'Opened Windows Security.' 'Good' }
                        catch { Write-Line 'Could not open Windows Security.' 'Warn' }
                    }
                    'F' {
                        $guidance = Get-FirmwareGuidance -State $State
                        Show-FirmwareGuidance -Guidance $guidance -State $State
                        # The restart is the caller's decision, never a side effect of rendering.
                        if ($guidance.CanOfferReboot) { [void](Invoke-RebootToFirmware -Guidance $guidance) }
                    }
                    'G' { Show-CodeIntegrityDiagnostics -State $State }
                    'H' { [void](Open-CodeIntegrityEventViewer) }
                }
            }
        }
        Wait-ForKey
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

function Invoke-Main {
    Initialize-Console -DisableColor:$NoColor

    if ($Version) { Write-Host ('{0} {1}' -f $script:ToolName, $script:ToolVersion); $script:ExitCode = 0; return }
    if ($SelfTest) { $script:ExitCode = (Invoke-SelfTest); return }

    if ($ListControls) {
        Write-Section 'Control catalog'
        foreach ($c in $script:ControlCatalog) {
            $cisText = if ($c.Cis) { $c.Cis.Id } else { '-' }
            Write-Line ('{0,-25} {1,-8} weight {2,-4} {3}' -f $c.Id, $cisText, $c.Weight, $c.Name) 'Plain'
            Write-Line $c.Summary 'Dim' 4
        }
        $script:ExitCode = 0; return
    }

    if ($AuditOnly -and ($EnableAllSafe -or $Enable -or $Revert)) {
        Write-Line '-AuditOnly cannot be combined with a change switch.' 'Bad'
        $script:ExitCode = 1; return
    }
    if ($AutoReboot -and -not ($EnableAllSafe -or $Enable -or $Revert)) {
        Write-Line '-AutoReboot only applies to an unattended change run.' 'Bad'
        $script:ExitCode = 1; return
    }

    if (($EnableAllSafe -and $Enable) -or ($Revert -and ($EnableAllSafe -or $Enable)) -or ($Explain -and ($EnableAllSafe -or $Enable -or $Revert)) -or ($RunId -and -not $Revert)) {
        Write-Line 'Use one change mode at a time; -RunId requires -Revert and -Explain cannot be combined with changes.' 'Bad'
        $script:ExitCode = 1; return
    }
    if ($Enable) {
        $Enable = @(ConvertTo-ControlIds -Ids $Enable)
        $script:InvocationParameters['Enable'] = $Enable
    }
    foreach ($controlId in (ConvertTo-Array $Enable)) {
        if (-not (Test-Contains (Get-ControlIds) $controlId)) { Write-Line ('Unknown control "{0}".' -f $controlId) 'Bad'; $script:ExitCode = 1; return }
        if (-not (Get-Control -Id $controlId).Remediable) { Write-Line ('Control "{0}" is report-only.' -f $controlId) 'Bad'; $script:ExitCode = 1; return }
    }
    if ($Explain -and -not (Test-Contains (Get-ControlIds) $Explain.Trim().ToLowerInvariant())) {
        Write-Line ('Unknown control "{0}". Use -ListControls to see valid ids.' -f $Explain) 'Bad'
        $script:ExitCode = 1; return
    }

    if (-not [string]::IsNullOrWhiteSpace($DebugLogPath)) {
        $script:DebugEnabled = $true
        $script:DebugPath = $DebugLogPath
        Write-Debug-Log ('{0} {1} starting' -f $script:ToolName, $script:ToolVersion)
    }

    if (-not (Test-IsElevated)) {
        # Try to elevate ourselves first. Telling a non-technical user to "run as
        # administrator" and exiting is not a workable instruction for this audience.
        if (Request-Elevation -Bound $script:InvocationParameters) { return }
        Write-Line 'WinDSH needs to run as Administrator to read platform security state.' 'Bad'
        Write-Line 'Right-click PowerShell, choose "Run as administrator", then run it again.' 'Info'
        Write-Line 'Or use Run-WinDSH-AsAdmin.bat, which requests elevation for you.' 'Info'
        $script:ExitCode = 4; return
    }

    $integrity = Get-SelfIntegrity
    if ($integrity.Status -ne 'OK') {
        Write-Line ('Self-integrity could not be verified ({0}).' -f $integrity.Status) 'Bad'
        Write-Line 'Auditing will continue, but making changes is disabled. Download a fresh copy.' 'Warn'
        $script:RemediationAllowed = $false
        $script:ExitCode = 3
    }

    $State = Get-SystemState
    if ($State.Computer.IsVirtual) {
        Add-Warning 'This is a virtual machine. Platform security features depend on what the host exposes.'
    }

    if (-not [string]::IsNullOrWhiteSpace($Explain)) {
        $id = $Explain.Trim().ToLowerInvariant()
        if (-not (Test-Contains (Get-ControlIds) $id)) {
            Write-Line ('Unknown control "{0}". Use -ListControls to see valid ids.' -f $Explain) 'Bad'
            $script:ExitCode = 1; return
        }
        Show-Explanation (Get-ControlExplanation -Id $id -State $State)
        return
    }

    $unattended = [bool]($AuditOnly -or $EnableAllSafe -or $Enable -or $Revert -or $Rmm)
    $script:Unattended = $unattended
    if ($Revert) {
        if (-not $script:RemediationAllowed) { Write-Line 'Revert is disabled because the integrity check failed.' 'Bad'; $script:ExitCode = 3; return }
        try {
            $result = Invoke-ControlRevert -RunId $RunId
            Write-Section 'Revert'
            foreach ($r in $result.Reverted) { Write-Line ('{0}\{1} restored to {2}' -f $r.Path, $r.Name, $r.RestoredTo) 'Good' 2 }
            foreach ($conflict in $result.Conflicts) {
                $message = '{0}\{1}: {2}' -f $conflict.Path, $conflict.Name, $conflict.Reason
                Write-Line $message 'Warn'; Add-Warning $message
            }
            if ($result.Conflicts.Count -gt 0) { $script:ExitCode = 5 }
            Write-Line ('Reverted {0} change(s) from run {1}.' -f $result.ChangeCount, $result.RunId) 'Info'
        }
        catch {
            Add-Warning ('Revert failed: {0}' -f $_.Exception.Message)
            $script:ExitCode = 5
        }
        $State = Get-SystemState -Volatile
    }
    elseif ($EnableAllSafe -or $Enable) {
        if (-not $script:RemediationAllowed) { Write-Line 'Changes are disabled because the integrity check failed.' 'Bad'; $script:ExitCode = 3; return }
        $ids = if ($Enable) { @($Enable) } else { $script:SafeControlSet }
        if ($WhatIfPreference) { Show-Plan (Get-ChangePlan -Ids $ids -State $State -ExplicitIds @($Enable)) }
        else {
            try {
                $result = Invoke-ControlApply -Ids $ids -State $State -ExplicitIds @($Enable)
                Write-Section 'Changes'
                if ($result.ChangeCount -eq 0 -and $result.Skipped.Count -eq 0) { Write-Line 'No changes were needed.' 'Good' }
                elseif ($result.ChangeCount -eq 0) { Write-Line 'No changes were made; see the skipped protections below.' 'Warn' }
                foreach ($a in $result.Applied) { Write-Line ('{0}: {1} -> {2}' -f $a.ControlName, $a.Before, $a.After) 'Good' 2 }
                foreach ($skip in $result.Skipped) {
                    $message = 'Skipped {0}: {1}' -f $skip.ControlName, $skip.Reason
                    Write-Line $message 'Warn'; Add-Warning $message
                }
                if ($result.ChangeCount -gt 0) { Write-Line ('Undo with:  -Revert -RunId {0}' -f $result.RunId) 'Info' }
            }
            catch {
                Add-Warning ('Remediation stopped: {0}' -f $_.Exception.Message)
                $script:ExitCode = 1
            }
            $State = Get-SystemState -Volatile
        }
    }

    $assessment = Get-Assessment -State $State
    if ($Rmm) {
        # Automation writes files only when a format was explicitly selected.
        if ($HtmlReport -or $JsonReport -or $TextReport) {
            [void](Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations)
        }
    }
    elseif ($unattended) {
        Show-Summary -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore
        Show-NextSteps -Explanations $assessment.Explanations
        if ($Advanced) { Show-CisSummary -Cis $assessment.Cis }
        $paths = Save-Reports -State $State -Statuses $assessment.Statuses -Score $assessment.Score -SecuredCore $assessment.SecuredCore -Cis $assessment.Cis -Explanations $assessment.Explanations
        foreach ($p in $paths) { Write-Line ('Report saved: {0}' -f $p) 'Good' }
    }
    else { Invoke-Interactive -State $State }

    $script:ExitCode = Get-FinalExitCode
    if ($AutoReboot -and $script:ExitCode -eq 3010 -and -not $WhatIfPreference) {
        try { Write-Line 'Restarting now.' 'Warn'; Restart-Computer -Force -ErrorAction Stop }
        catch { Add-Warning ('Automatic restart failed: {0}' -f $_.Exception.Message); $script:ExitCode = 1 }
    }
    if ($Rmm) {
        Write-RmmOutput -State $State -Statuses $assessment.Statuses -Score $assessment.Score -Cis $assessment.Cis
        return
    }
    foreach ($w in $script:Warnings) { Write-Line $w 'Warn' }
    if ($unattended) {
        Write-Line ''
        Write-Line ('Result: {0}' -f (Get-ExitCodeMeaning -Code $script:ExitCode)) 'Dim'
    }
}

function Get-FinalExitCode {
    # A partial failure must not be hidden behind a restart-required success code.
    if ($script:ExitCode -ne 0) { return $script:ExitCode }
    if ($script:RestartRequired) { return 3010 }
    if (@($script:Warnings).Count -gt 0) { return 2 }
    return 0
}

function Invoke-EntryPoint {
    $script:RmmOutputWritten = $false
    $failureMessage = $null
    try { Invoke-Main }
    catch {
        $script:ExitCode = 1
        $failureMessage = $_.Exception.Message
        if (-not $Rmm) { Write-Line ('WinDSH failed: {0}' -f $failureMessage) 'Bad' }
    }
    # Validation/elevation failures return before assessment. Automation still gets
    # one JSON result rather than a silent exit or mixed diagnostic output.
    if ($Rmm -and -not $script:RmmOutputWritten -and -not ($Version -or $ListControls -or $SelfTest)) {
        if (-not $failureMessage) { $failureMessage = Get-ExitCodeMeaning -Code $script:ExitCode }
        Write-Output (([pscustomobject]@{
            schemaVersion = $script:SchemaVersion; tool = $script:ToolName
            version = $script:ToolVersion; exitCode = $script:ExitCode
            restartRequired = $script:RestartRequired; error = $failureMessage
        }) | ConvertTo-Json -Compress)
    }
}

# Invoke-Main sets its exit code; do not capture stdout in the entry point.
Invoke-EntryPoint
exit $script:ExitCode
