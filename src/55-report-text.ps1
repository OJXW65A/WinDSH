# ---------------------------------------------------------------------------
# Plain-text report. Another projection over the same data as the HTML and JSON
# reports, so the three cannot describe the machine differently.
# ---------------------------------------------------------------------------

function New-TextReport {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Statuses,
        [Parameter(Mandatory = $true)]$Score,
        [Parameter(Mandatory = $true)]$SecuredCore,
        [Parameter(Mandatory = $true)]$Cis,
        [Parameter(Mandatory = $true)]$Explanations
    )

    $lines = @()
    $rule = '-' * 78
    $lines += $rule
    $lines += ('{0} {1} - Windows device security report' -f $script:ToolName, $script:ToolVersion)
    $lines += ('Computer  : {0}' -f $State.Computer.Name)
    $lines += ('Generated : {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    $lines += $rule
    $lines += ''

    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count
    $lines += 'SECURITY SCORE'
    $lines += ('  {0} / 100 ({1})' -f $Score.Score, $Score.Grade)
    $lines += ('  {0} of {1} applicable protections are active.' -f $running, $countable)
    if ($Score.ExcludedCount -gt 0) {
        $lines += ('  {0} excluded: this hardware cannot run them, so they are not counted against you.' -f $Score.ExcludedCount)
    }
    $lines += ('  Secured-core PC: {0}' -f $(if ($SecuredCore.Qualifies) { 'qualifies' } else { ('does not qualify, {0} requirement(s) unmet' -f $SecuredCore.UnmetCount) }))
    $lines += ''

    $lines += 'THIS COMPUTER'
    $lines += ('  Make and model  : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model)
    $lines += ('  Processor       : {0}' -f $State.Computer.ProcessorName)
    $lines += ('  Windows         : {0} build {1} ({2})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber, $State.Computer.EditionId)
    $lines += ('  Firmware mode   : {0} (detected via {1})' -f $State.Firmware.Mode, $State.Firmware.DetectionSource)
    $lines += ('  Secure Boot     : {0}' -f (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable'))
    $lines += ('  TPM             : {0} (spec {1})' -f (Format-Bool $State.Tpm.IsTPM2 'TPM 2.0 present' 'not confirmed'), $State.Tpm.SpecVersion)
    $lines += ('  Hypervisor      : launch type {0}' -f $State.HypervisorLaunch.LaunchType)
    $lines += ('  DEP             : {0}' -f $State.Dep.Text)
    $lines += ('  Restart pending : {0}' -f (Format-Bool $State.Restart.Pending))
    if ($State.VirtualMachine.IsVirtual) {
        $lines += ('  Virtual machine : yes ({0})' -f $State.VirtualMachine.Platform)
        foreach ($note in (ConvertTo-Array $State.VirtualMachine.Notes)) { $lines += ('      - {0}' -f $note) }
    }
    $lines += ''

    if ($State.HypervisorLaunch.BlocksVbs) {
        $lines += 'BLOCKING ISSUE'
        $lines += '  The Windows hypervisor is switched off in the boot configuration, so none of the'
        $lines += '  virtualization-based protections can start, whatever else is configured.'
        $lines += '  Fix: run  bcdedit /set hypervisorlaunchtype Auto  elevated, then restart.'
        $lines += ''
    }

    $lines += 'PROTECTIONS'
    foreach ($s in $Statuses) {
        $marker = switch ($s.State) {
            'Running' { '[ OK ]' }
            'ConfiguredNotRunning' { '[ !  ]' }
            'NotConfigured' { '[ X  ]' }
            default { '[ -  ]' }
        }
        $label = (Get-StateLabel $s.State).Text
        $policy = if ($s.ManagedByPolicy) { ' (Group Policy)' } else { '' }
        $lines += ('  {0} {1,-34} {2}{3}' -f $marker, $s.PlainName, $label, $policy)
        $lines += ('         {0}' -f $s.Name)
    }
    $lines += ''

    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    $lines += 'WHAT TO DO NEXT'
    if (@($todo).Count -eq 0) { $lines += '  Nothing. Every protection this computer supports is already active.' }
    else {
        $n = 0
        foreach ($e in $todo) {
            $n++
            $lines += ''
            $lines += ('  {0}. {1}' -f $n, $e.PlainName)
            $lines += ('     {0}' -f $e.Verdict)
            if ($e.Action) { foreach ($l in ($e.Action -split "`n")) { $lines += ('     {0}' -f $l) } }
        }
    }
    $lines += ''

    $lines += 'CIS BENCHMARK COMPARISON'
    $lines += ('  {0}, section {1}' -f $Cis.Benchmark, $Cis.Section)
    $lines += ('  {0} of {1} checks pass.' -f $Cis.CompliantCount, $Cis.TotalCount)
    $lines += ''
    $lines += '  IMPORTANT: CIS audits the Group Policy hive. WinDSH configures local machine'
    $lines += '  values and never writes Group Policy, so a protection can be active on this'
    $lines += '  computer while its CIS check still reports non-compliant.'
    $lines += ''
    foreach ($r in $Cis.Rows) {
        $verdict = if ($r.Compliant) { 'PASS' } else { 'FAIL' }
        $actual = if ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        $lines += ('  {0} {1,-9} {2,-38} policy = {3}, running = {4}' -f `
            $verdict, $r.CisId, $r.PolicyValueName, $actual, (Format-Bool $r.FeatureRunning))
        if ($r.Divergence) { $lines += ('           Deliberate difference: {0}' -f $r.Divergence) }
    }
    $lines += ''

    $lines += 'SECURED-CORE PC CRITERIA'
    foreach ($c in $SecuredCore.Checks) {
        $lines += ('  {0} {1}' -f $(if ($c.Met) { '[ OK ]' } else { '[ X  ]' }), $c.Name)
    }
    $lines += ''

    if (@($script:AppliedChanges).Count -gt 0) {
        $lines += 'CHANGES MADE IN THIS SESSION'
        foreach ($c in $script:AppliedChanges) {
            $lines += ('  {0}\{1}: {2} -> {3}' -f $c.Path, $c.Name, $c.Before, $c.After)
        }
        $lines += ''
    }

    $lines += $rule
    $lines += 'This report describes configuration state only. It is not a vulnerability assessment.'
    $lines += 'WinDSH writes local machine settings and never modifies Group Policy.'
    $lines += $rule

    return ($lines -join "`r`n")
}
