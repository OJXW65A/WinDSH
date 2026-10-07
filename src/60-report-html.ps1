# ---------------------------------------------------------------------------
# HTML report. Self-contained single file: no external CSS, fonts, scripts or images,
# so it renders identically on a machine with no internet access and can be attached to
# a ticket or emailed without anything breaking.
# ---------------------------------------------------------------------------

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).
        Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').
        Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-StateLabel {
    param([string]$State)
    switch ($State) {
        'Running' { return @{ Text = 'Active'; Class = 'ok' } }
        'ConfiguredNotRunning' { return @{ Text = 'Configured; not active'; Class = 'warn' } }
        'NotConfigured' { return @{ Text = 'Off'; Class = 'bad' } }
        'NotSupported' { return @{ Text = 'Not available on this PC'; Class = 'na' } }
        'Unknown' { return @{ Text = 'Unable to verify'; Class = 'warn' } }
        'AuditMode' { return @{ Text = 'Audit only; not enforcing'; Class = 'warn' } }
        default { return @{ Text = $State; Class = 'na' } }
    }
}

function New-HtmlReport {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Returns report markup only; file writes are handled separately.')]
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Statuses,
        [Parameter(Mandatory = $true)]$Score,
        [Parameter(Mandatory = $true)]$SecuredCore,
        [Parameter(Mandatory = $true)]$Cis,
        [Parameter(Mandatory = $true)]$Explanations
    )

    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $scoreColour = if ($Score.UnknownCount -gt 0) { '#b7791f' } elseif ($Score.Score -ge 90) { '#1a7f43' } elseif ($Score.Score -ge 75) { '#2f855a' } elseif ($Score.Score -ge 50) { '#b7791f' } else { '#c53030' }

    # Donut geometry: circumference of r=70 is 2*pi*70.
    $circumference = [math]::Round(2 * [math]::PI * 70, 2)
    $filled = [math]::Round($circumference * ($Score.Score / 100.0), 2)
    $gap = [math]::Round($circumference - $filled, 2)

    $sb = New-Object Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine(('<title>WinDSH security report - {0}</title>' -f (ConvertTo-HtmlText $State.Computer.Name)))
    $null = $sb.AppendLine(@'
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1a202c;--muted:#5a6472;--line:#e2e6ec;
--ok:#1a7f43;--warn:#b7791f;--bad:#c53030;--na:#718096;}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--ink:#e8eaed;
--muted:#9aa4b2;--line:#2d333d;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--na:#94a3b8;}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--ink);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;
padding-bottom:6px;border-bottom:2px solid var(--line)}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:16px}
.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.gauge{flex:0 0 180px;text-align:center}
.gv{font-size:40px;font-weight:700;line-height:1}
.gl{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.hero-txt{flex:1;min-width:260px}
.verdict{font-size:17px;margin:0 0 8px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{background:rgba(26,127,67,.13);color:var(--ok)}
.warn{background:rgba(183,121,31,.15);color:var(--warn)}
.bad{background:rgba(197,48,48,.13);color:var(--bad)}
.na{background:rgba(113,128,150,.15);color:var(--na)}
.kv{display:grid;grid-template-columns:200px 1fr;gap:6px 16px;font-size:14px}
.kv dt{color:var(--muted)}.kv dd{margin:0}
.note{background:rgba(183,121,31,.1);border-left:3px solid var(--warn);padding:12px 14px;
border-radius:0 6px 6px 0;font-size:14px;margin:12px 0}
.item{border-top:1px solid var(--line);padding:14px 0}
.item:first-child{border-top:0}
.item h3{margin:0 0 4px;font-size:15px}
.why{color:var(--muted);font-size:13.5px;margin:4px 0}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;
font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:8px 0 0}
.tiny{font-size:12px;color:var(--muted)}
a{color:inherit}
@media print{body{background:#fff;padding:0}.card{break-inside:avoid;border-color:#ccc}}
</style></head><body><div class="wrap">
'@)

    # ---- header + score ----
    $null = $sb.AppendLine(('<h1>Windows device security report</h1>'))
    $null = $sb.AppendLine(('<div class="sub">{0} &middot; generated {1} &middot; {2} {3}</div>' -f `
        (ConvertTo-HtmlText $State.Computer.Name), (ConvertTo-HtmlText $generated),
        (ConvertTo-HtmlText $script:ToolName), (ConvertTo-HtmlText $script:ToolVersion)))

    $running = @($Statuses | Where-Object { $_.State -eq 'Running' }).Count
    $countable = @($Statuses | Where-Object { $_.State -ne 'NotSupported' }).Count

    $null = $sb.AppendLine('<div class="card hero">')
    $null = $sb.AppendLine('<div class="gauge"><svg viewBox="0 0 180 180" width="160" height="160" role="img" aria-label="Applicable protection score">')
    $null = $sb.AppendLine('<circle cx="90" cy="90" r="70" fill="none" stroke="var(--line)" stroke-width="16"/>')
    $filledText = $filled.ToString('0.##', [Globalization.CultureInfo]::InvariantCulture)
    $gapText = $gap.ToString('0.##', [Globalization.CultureInfo]::InvariantCulture)
    $null = $sb.AppendLine(('<circle cx="90" cy="90" r="70" fill="none" stroke="{0}" stroke-width="16" stroke-linecap="round" stroke-dasharray="{1} {2}" transform="rotate(-90 90 90)"/>' -f $scoreColour, $filledText, $gapText))
    $null = $sb.AppendLine(('<text x="90" y="86" text-anchor="middle" font-size="40" font-weight="700" fill="currentColor">{0}</text>' -f $Score.Score))
    $null = $sb.AppendLine('<text x="90" y="108" text-anchor="middle" font-size="13" fill="currentColor" opacity="0.65">out of 100</text>')
    $null = $sb.AppendLine('</svg>')
    $null = $sb.AppendLine(('<div class="gl">{0}</div></div>' -f (ConvertTo-HtmlText $Score.Grade)))

    $null = $sb.AppendLine('<div class="hero-txt">')
    $null = $sb.AppendLine('<h2>Applicable protection score</h2>')
    $null = $sb.AppendLine(('<p class="tiny">{0} of {1} controls are included in scoring; confirmed unsupported controls are excluded.</p>' -f $Score.ApplicableCount, $Score.TotalCount))
    $null = $sb.AppendLine(('<p class="verdict">{0} of {1} applicable protections are active on this computer.</p>' -f $running, $countable))
    if ($Score.UnknownCount -gt 0) { $null = $sb.AppendLine(('<p class="note">{0} scored protection(s) could not be verified. No points are credited for them, and they remain in the total.</p>' -f $Score.UnknownCount)) }
    if ($Score.ExcludedCount -gt 0) {
        $null = $sb.AppendLine(('<p class="tiny">{0} protection(s) are excluded from the score because current platform requirements are not met. They are not counted against you.</p>' -f $Score.ExcludedCount))
    }
    $scVerdict = if ($SecuredCore.Qualifies) { 'This computer meets the Secured-core PC criteria.' } else { ('Secured-core PC qualification is not confirmed ({0} requirement(s) unmet or unverified).' -f $SecuredCore.UnmetCount) }
    $null = $sb.AppendLine(('<p class="tiny">{0}</p>' -f (ConvertTo-HtmlText $scVerdict)))
    $null = $sb.AppendLine('</div></div>')

    # ---- system ----
    $null = $sb.AppendLine('<h2>This computer</h2><div class="card"><dl class="kv">')
    $rows = @(
        @{ K = 'Computer name'; V = $State.Computer.Name }
        @{ K = 'Make and model'; V = ('{0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) }
        @{ K = 'Processor'; V = $State.Computer.ProcessorName }
        @{ K = 'Windows'; V = ('{0} (build {1})' -f $State.Computer.OsCaption, $State.Computer.BuildNumber) }
        @{ K = 'Edition'; V = $State.Computer.EditionId }
        @{ K = 'Firmware mode'; V = $State.Firmware.Mode }
        @{ K = 'Secure Boot'; V = (Format-Bool $State.Firmware.SecureBootEnabled 'Enabled' 'Disabled' 'Unavailable') }
        @{ K = 'TPM 2.0'; V = (Format-Bool $State.Tpm.IsTPM2 'Present' 'Not confirmed') }
        @{ K = 'Hypervisor launch type'; V = $(if ($State.HypervisorLaunch.LaunchType) { $State.HypervisorLaunch.LaunchType } else { 'Unknown' }) }
        @{ K = 'Virtual machine'; V = (Format-Bool $State.Computer.IsVirtual) }
        @{ K = 'Restart pending'; V = (Format-Bool $State.Restart.Pending) }
    )
    foreach ($r in $rows) {
        $null = $sb.AppendLine(('<dt>{0}</dt><dd>{1}</dd>' -f (ConvertTo-HtmlText $r.K), (ConvertTo-HtmlText ([string]$r.V))))
    }
    $null = $sb.AppendLine('</dl></div>')

    if ($State.HypervisorLaunch.BlocksVbs) {
        $null = $sb.AppendLine('<div class="note"><strong>Blocking issue.</strong> The Windows hypervisor is switched off in this computer&#39;s boot configuration, so none of the virtualization-based protections can start, whatever else is configured. In an elevated Command Prompt run <code>bcdedit /set hypervisorlaunchtype Auto</code> and restart.</div>')
    }

    # ---- protections ----
    $null = $sb.AppendLine('<h2>Protections</h2><div class="card"><table><thead><tr>')
    $null = $sb.AppendLine('<th>Protection</th><th>What it does</th><th>Status</th><th>Points</th></tr></thead><tbody>')
    foreach ($s in $Statuses) {
        $label = Get-StateLabel $s.State
        $control = Get-Control -Id $s.Id
        $pts = @($Score.Breakdown | Where-Object { $_.Id -eq $s.Id })
        $ptsText = if (@($pts).Count -gt 0 -and $pts[0].Counted) { '{0} / {1}' -f $pts[0].Points, $s.Weight } else { 'n/a' }
        $policy = if ($s.ManagedByPolicy) { ' <span class="badge na">Group Policy</span>' } else { '' }
        $null = $sb.AppendLine(('<tr><td><strong>{0}</strong><br><span class="tiny">{1}</span></td><td>{2}</td><td><span class="badge {3}">{4}</span>{5}</td><td>{6}</td></tr>' -f `
            (ConvertTo-HtmlText $s.PlainName), (ConvertTo-HtmlText $s.Name), (ConvertTo-HtmlText $control.Summary),
            $label.Class, (ConvertTo-HtmlText $label.Text), $policy, $ptsText))
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    # ---- what to do ----
    $todo = @($Explanations | Where-Object { $_.Severity -ne 'Good' })
    $null = $sb.AppendLine('<h2>What to do next</h2><div class="card">')
    if (@($todo).Count -eq 0) {
        $null = $sb.AppendLine('<p>Nothing. Every protection this computer supports is already active.</p>')
    }
    else {
        foreach ($e in $todo) {
            $null = $sb.AppendLine('<div class="item">')
            $null = $sb.AppendLine(('<h3>{0}</h3>' -f (ConvertTo-HtmlText $e.PlainName)))
            $null = $sb.AppendLine(('<p class="why">{0}</p>' -f (ConvertTo-HtmlText $e.Verdict)))
            if ($e.Action) { $null = $sb.AppendLine(('<pre>{0}</pre>' -f (ConvertTo-HtmlText $e.Action))) }
            if ($e.Caution) { $null = $sb.AppendLine(('<p class="tiny"><strong>Note:</strong> {0}</p>' -f (ConvertTo-HtmlText $e.Caution))) }
            $null = $sb.AppendLine('</div>')
        }
    }
    $null = $sb.AppendLine('</div>')

    if (@($script:RevertedChanges).Count -gt 0) {
        $null = $sb.AppendLine('<h2>Changes reverted in this session</h2><div class="card"><ul>')
        foreach ($change in $script:RevertedChanges) {
            $description = '{0}\{1}: {2} -> {3}' -f $change.Path, $change.Name, $change.Before, $change.RestoredTo
            $null = $sb.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlText $description)))
        }
        $null = $sb.AppendLine('</ul></div>')
    }

    # ---- CIS ----
    $null = $sb.AppendLine(('<h2>CIS Benchmark comparison</h2>'))
    $null = $sb.AppendLine('<div class="card">')
    $null = $sb.AppendLine(('<p class="tiny">{0} &middot; section {1}</p>' -f (ConvertTo-HtmlText $Cis.Benchmark), (ConvertTo-HtmlText $Cis.Section)))
    $null = $sb.AppendLine(('<div class="note"><strong>Read this before using these results.</strong> {0}</div>' -f (ConvertTo-HtmlText $Cis.Note)))
    $null = $sb.AppendLine(('<p>{0} of {1} checks pass. {2} protection(s) are actually running on this computer but still fail their CIS check for the reason above.</p>' -f $Cis.CompliantCount, $Cis.TotalCount, $Cis.RunningButNotCompliantCount))
    $null = $sb.AppendLine('<table><thead><tr><th>CIS</th><th>Requirement</th><th>Policy value</th><th>CIS result</th><th>Actually running</th></tr></thead><tbody>')
    foreach ($r in $Cis.Rows) {
        $cls = if (-not $r.PolicyKnown) { 'warn' } elseif ($r.Compliant) { 'ok' } else { 'bad' }
        $txt = if (-not $r.PolicyKnown) { 'Unknown' } elseif ($r.Compliant) { 'Pass' } else { 'Fail' }
        $actual = if (-not $r.PolicyKnown) { 'unavailable' } elseif ($null -ne $r.Actual) { [string]$r.Actual } else { 'not set' }
        $runCls = if (-not $r.FeatureRunningKnown) { 'warn' } elseif ($r.FeatureRunning) { 'ok' } else { 'na' }
        $runTxt = if (-not $r.FeatureRunningKnown) { 'Unknown' } elseif ($r.FeatureRunning) { 'Yes' } else { 'No' }
        $null = $sb.AppendLine(('<tr><td>{0}<br><span class="tiny">{1}</span></td><td>{2}</td><td><code>{3}</code> = {4}</td><td><span class="badge {5}">{6}</span></td><td><span class="badge {7}">{8}</span></td></tr>' -f `
            (ConvertTo-HtmlText $r.CisId), (ConvertTo-HtmlText $r.Profile), (ConvertTo-HtmlText $r.Title),
            (ConvertTo-HtmlText $r.PolicyValueName), (ConvertTo-HtmlText $actual), $cls, $txt, $runCls, $runTxt))
        if ($r.Divergence) {
            $null = $sb.AppendLine(('<tr><td></td><td colspan="4" class="tiny"><strong>Deliberate difference:</strong> {0}</td></tr>' -f (ConvertTo-HtmlText $r.Divergence)))
        }
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    # ---- secured core ----
    $null = $sb.AppendLine('<h2>Secured-core PC criteria</h2><div class="card"><table><thead><tr><th>Requirement</th><th>Status</th></tr></thead><tbody>')
    foreach ($c in $SecuredCore.Checks) {
        $cls = if ($c.Met) { 'ok' } else { 'bad' }
        $txt = if ($c.Met) { 'Met' } else { 'Not met' }
        $null = $sb.AppendLine(('<tr><td>{0}</td><td><span class="badge {1}">{2}</span></td></tr>' -f (ConvertTo-HtmlText $c.Name), $cls, $txt))
    }
    $null = $sb.AppendLine('</tbody></table></div>')

    $null = $sb.AppendLine(('<p class="tiny">Generated by {0} {1}. This report describes configuration state only and is not a vulnerability assessment. WinDSH writes local machine settings and never modifies Group Policy.</p>' -f `
        (ConvertTo-HtmlText $script:ToolName), (ConvertTo-HtmlText $script:ToolVersion)))
    $null = $sb.AppendLine('</div></body></html>')

    return $sb.ToString()
}
