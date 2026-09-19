# ---------------------------------------------------------------------------
# Firmware (BIOS/UEFI) guidance.
#
# "Enable it in BIOS" is not usable guidance for a non-technical user. This answers
# how to get in, where the setting lives on their machine, what it is called there,
# and what could go wrong.
#
# Ported from v1.6.0 with one design fault corrected: there, Show-FirmwareGuidance
# could reboot the computer, so a Show-* function had side effects and the restart
# bypassed -WhatIf entirely. Here Get-FirmwareGuidance returns data, Show- renders it,
# and only the caller may act on it.
# ---------------------------------------------------------------------------

function Get-DriveEncryptionSummary {
    <#
        READ ONLY. WinDSH never manages BitLocker, but it must warn before sending
        someone into firmware: changing or clearing a TPM with BitLocker active can make
        Windows demand a 48-digit recovery key at next boot, and someone without that key
        is locked out of their own data.
    #>
    $protected = @()
    try {
        $volumes = @(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
                        -ClassName 'Win32_EncryptableVolume' -ErrorAction Stop)
        foreach ($v in $volumes) {
            if ([int](Get-PropertySafe $v 'ProtectionStatus' 0) -eq 1) {
                $protected += [string](Get-PropertySafe $v 'DriveLetter' '?')
            }
        }
        return [pscustomobject]@{ Queried = $true; AnyProtected = [bool](@($protected).Count -gt 0); ProtectedDrives = $protected }
    }
    catch {
        Write-DebugError 'Query BitLocker protection status' $_
        # Unknown is treated as "warn anyway": being over-cautious about a recovery-key
        # lockout costs nothing, being wrong the other way can cost the user their data.
        return [pscustomobject]@{ Queried = $false; AnyProtected = $null; ProtectedDrives = @() }
    }
}

function Get-FirmwareVendorHints {
    <#
        Maps a manufacturer to the menu locations its firmware normally uses. Layouts
        differ by model and firmware revision, so every hint is phrased as typical, and an
        unrecognised manufacturer returns nulls rather than an invented path.
    #>
    param([string]$Manufacturer, [string]$Model)

    $m = ('{0} {1}' -f $Manufacturer, $Model)

    if ($m -match 'Microsoft' -and $m -match 'Surface') {
        return [pscustomobject]@{
            Vendor = 'Microsoft Surface'
            EnterKey = 'Shut down fully, then hold Volume Up and press Power. Keep holding Volume Up until the Surface UEFI screen appears.'
            TPM = 'Security section. Surface devices have TPM 2.0 enabled by default.'
            Virtualization = 'Usually always on and not exposed as a setting.'
            SecureBoot = 'Security section, Secure Boot.'
        }
    }
    if ($m -match '\bDell\b|Alienware') {
        return [pscustomobject]@{
            Vendor = 'Dell'
            EnterKey = 'Tap F2 repeatedly as the Dell logo appears.'
            TPM = 'Security > TPM 2.0 Security (older models call it PTT Security). Set it to On.'
            Virtualization = 'Virtualization Support > Virtualization. Also enable VT for Direct I/O.'
            SecureBoot = 'Boot Configuration or Secure Boot > Secure Boot Enable.'
        }
    }
    if ($m -match '\bHP\b|Hewlett') {
        return [pscustomobject]@{
            Vendor = 'HP'
            EnterKey = 'Tap F10 repeatedly at power on. On some models press Esc first, then F10.'
            TPM = 'Security > TPM Device and TPM State, or Embedded Security Device.'
            Virtualization = 'Advanced > System Options > Virtualization Technology (VTx). Also enable VTd.'
            SecureBoot = 'Advanced > Secure Boot Configuration. Some HP models require a BIOS administrator password to be set before this can change.'
        }
    }
    if ($m -match 'Lenovo|ThinkPad|IdeaPad') {
        return [pscustomobject]@{
            Vendor = 'Lenovo'
            EnterKey = 'ThinkPad: tap F1 at the logo. IdeaPad: tap F2, or use the small Novo button next to the power socket.'
            TPM = 'Security > Security Chip. Set Security Chip Selection to Intel PTT or Discrete TPM, then set Security Chip to Enabled.'
            Virtualization = 'Security > Virtualization > Intel Virtualization Technology. Also enable Intel VT-d.'
            SecureBoot = 'Security > Secure Boot.'
        }
    }
    if ($m -match 'ASUS|ASUSTeK') {
        return [pscustomobject]@{
            Vendor = 'ASUS'
            EnterKey = 'Tap F2 or Delete at power on. Press F7 for Advanced Mode if you land on the simple EZ screen.'
            TPM = 'Intel: Advanced > PCH-FW Configuration > PTT. AMD: Advanced > AMD fTPM configuration.'
            Virtualization = 'Intel: Advanced > CPU Configuration > Intel (VMX) Virtualization Technology. AMD: Advanced > CPU Configuration > SVM Mode.'
            SecureBoot = 'Boot > Secure Boot. Set OS Type to Windows UEFI mode.'
        }
    }
    if ($m -match '\bAcer\b|Predator') {
        return [pscustomobject]@{
            Vendor = 'Acer'
            EnterKey = 'Tap F2 at the Acer logo.'
            TPM = 'Security > TPM State, or Main > TPM.'
            Virtualization = 'Main or Advanced > VT-x / Virtualization Technology.'
            SecureBoot = 'Boot > Secure Boot. IMPORTANT: on most Acer models Secure Boot stays greyed out until you set a Supervisor Password under Security. Set one, enable Secure Boot, then you may remove the password.'
        }
    }
    if ($m -match '\bMSI\b|Micro-Star') {
        return [pscustomobject]@{
            Vendor = 'MSI'
            EnterKey = 'Tap Delete at power on.'
            TPM = 'Settings > Security > Trusted Computing > Security Device Support. Intel: PTT. AMD: AMD fTPM switch.'
            Virtualization = 'OC > CPU Features > Intel Virtualization Tech, or SVM Mode on AMD.'
            SecureBoot = 'Settings > Advanced > Windows OS Configuration > Secure Boot.'
        }
    }
    if ($m -match 'Gigabyte|ASRock') {
        return [pscustomobject]@{
            Vendor = 'Gigabyte / ASRock'
            EnterKey = 'Tap Delete or F2 at power on.'
            TPM = 'Settings > Miscellaneous > Intel Platform Trust Technology (PTT), or AMD CPU fTPM. On ASRock look under Security or Advanced > CPU Configuration.'
            Virtualization = 'Tweaker or Advanced > CPU Configuration > SVM Mode (AMD) or Intel Virtualization Technology.'
            SecureBoot = 'Boot > Secure Boot. Set to Windows UEFI mode / Standard.'
        }
    }

    return [pscustomobject]@{
        Vendor = $(if ([string]::IsNullOrWhiteSpace($Manufacturer)) { 'Unknown' } else { $Manufacturer })
        EnterKey = $null; TPM = $null; Virtualization = $null; SecureBoot = $null
    }
}

function Get-FirmwareGuidance {
    <# Pure: returns what needs changing and where. Takes no action. #>
    param([Parameter(Mandatory = $true)]$State)

    $hints = Get-FirmwareVendorHints -Manufacturer $State.Computer.Manufacturer -Model $State.Computer.Model
    $encryption = Get-DriveEncryptionSummary
    $needed = @()

    if (-not $State.Tpm.Present -or -not $State.Tpm.IsTPM2) {
        $needed += [pscustomobject]@{
            What = 'Security processor (TPM 2.0)'
            Why = 'Stores boot measurements. Needed for Secure Launch, and used by BitLocker and Windows Hello.'
            AlsoCalled = 'Intel PTT, Platform Trust Technology, AMD fTPM, Security Device, Security Chip, Trusted Computing'
            Where = $hints.TPM
        }
    }
    if (-not $State.Virtualization.FirmwareEnabled) {
        $needed += [pscustomobject]@{
            What = 'CPU virtualization'
            Why = 'Required for Virtualization-based Security. Nothing VBS-related can run without it.'
            AlsoCalled = 'Intel VT-x, Intel Virtualization Technology, VMX, AMD SVM, SVM Mode, AMD-V'
            Where = $hints.Virtualization
        }
    }
    if ($State.Firmware.SecureBootSupported -and -not $State.Firmware.SecureBootEnabled) {
        $needed += [pscustomobject]@{
            What = 'Secure Boot'
            Why = 'Verifies the boot chain. WinDSH requires it for VBS, so VBS will not start while it is off.'
            AlsoCalled = 'Secure Boot Enable, Windows UEFI mode, OS Type'
            Where = $hints.SecureBoot
        }
    }
    if ($State.HypervisorLaunch.BlocksVbs) {
        $needed += [pscustomobject]@{
            What = 'Windows hypervisor (not a firmware setting)'
            Why = 'The boot configuration currently switches the hypervisor off, which blocks every VBS feature.'
            AlsoCalled = 'hypervisorlaunchtype'
            Where = 'Fix this in Windows, not firmware. In an elevated Command Prompt run:  bcdedit /set hypervisorlaunchtype Auto   then restart.'
        }
    }

    return [pscustomobject]@{
        Vendor = $hints.Vendor
        EnterKey = $hints.EnterKey
        Encryption = $encryption
        Needed = $needed
        LegacyWarning = [bool]$State.Firmware.IsLegacyConfirmed
        CanOfferReboot = [bool](@($needed).Count -gt 0)
    }
}

function Show-FirmwareGuidance {
    <# Renders only. The caller decides whether to offer a restart. #>
    param([Parameter(Mandatory = $true)]$Guidance, [Parameter(Mandatory = $true)]$State)

    Write-Section 'Changing firmware (BIOS/UEFI) settings'
    Write-Line ('Detected system : {0} {1}' -f $State.Computer.Manufacturer, $State.Computer.Model) 'Dim'
    Write-Line ('Processor       : {0}' -f $State.Computer.ProcessorName) 'Dim'
    Write-Line ('Firmware mode   : {0}' -f $State.Firmware.Mode) 'Dim'

    Write-Line ''
    if ($Guidance.Encryption.AnyProtected) {
        Write-Line 'BEFORE YOU CHANGE ANYTHING' 'Bad'
        Write-Line ('BitLocker is protecting: {0}' -f (@($Guidance.Encryption.ProtectedDrives) -join ', ')) 'Bad' 2
        Write-Line 'Changing or clearing the TPM can make Windows ask for a 48-digit recovery key at the' 'Warn' 2
        Write-Line 'next start. Without that key the drive cannot be opened.' 'Warn' 2
        Write-Line 'Find your key first at https://aka.ms/myrecoverykey, or suspend BitLocker before' 'Warn' 2
        Write-Line 'entering firmware.' 'Warn' 2
    }
    elseif (-not $Guidance.Encryption.Queried) {
        Write-Line 'BEFORE YOU CHANGE ANYTHING' 'Warn'
        Write-Line 'Drive encryption status could not be read. If this PC uses BitLocker or Device' 'Warn' 2
        Write-Line 'Encryption, locate your recovery key first: https://aka.ms/myrecoverykey' 'Warn' 2
    }
    else {
        Write-Line 'Drive encryption is not active, so TPM changes will not trigger a recovery prompt.' 'Dim'
    }

    Write-Line ''
    Write-Line 'How to open firmware setup' 'Head'
    Write-Line 'Easiest, works on every PC:' 'Plain' 2
    Write-Line 'Settings > System > Recovery > Advanced startup > Restart now' 'Info' 4
    Write-Line 'then Troubleshoot > Advanced options > UEFI Firmware Settings > Restart' 'Info' 4
    if ($Guidance.EnterKey) { Write-Line ('On your {0}: {1}' -f $Guidance.Vendor, $Guidance.EnterKey) 'Info' 2 }
    else { Write-Line 'Key at power on varies by manufacturer: F2, F10, F12 or Delete are the usual ones.' 'Info' 2 }

    Write-Line ''
    if (@($Guidance.Needed).Count -eq 0) {
        Write-Line 'Nothing needs changing in firmware. Every setting WinDSH can see is already correct.' 'Good'
    }
    else {
        Write-Line 'What to change on this PC' 'Head'
        $n = 0
        foreach ($item in $Guidance.Needed) {
            $n++
            Write-Line ''
            Write-Line ('{0}. {1}' -f $n, $item.What) 'Warn' 2
            Write-Line ('Why        : {0}' -f $item.Why) 'Dim' 5
            Write-Line ('Also called: {0}' -f $item.AlsoCalled) 'Dim' 5
            if ($item.Where) { Write-Line ('Where      : {0}' -f $item.Where) 'Info' 5 }
            else {
                Write-Line 'Where      : Menu layout unknown for this manufacturer. Search your model' 'Info' 5
                Write-Line '             number plus the setting name on the support site.' 'Info' 5
            }
        }
    }

    if ($Guidance.LegacyWarning) {
        Write-Line ''
        Write-Line 'This PC is running in Legacy/CSM mode, not UEFI.' 'Warn'
        Write-Line 'Secure Boot cannot be enabled until that changes, but switching the firmware to UEFI' 'Warn' 2
        Write-Line 'will stop Windows starting unless the disk is converted from MBR to GPT first' 'Warn' 2
        Write-Line '(mbr2gpt). Back up before attempting this, or ask a technician.' 'Warn' 2
    }

    Write-Line ''
    Write-Line 'General notes' 'Head'
    Write-Line 'Change one setting at a time, save and exit (usually F10), then restart into Windows.' 'Dim' 2
    Write-Line 'Run the audit again after each change so you can see what it actually did.' 'Dim' 2
    Write-Line 'If a setting you need is missing entirely, update to the newest BIOS from your maker.' 'Dim' 2
    Write-Line 'Some settings stay hidden until related ones are on. Intel TXT commonly does not appear' 'Dim' 2
    Write-Line 'until both TPM and VT-x are enabled.' 'Dim' 2
    Write-Line 'WinDSH never changes firmware, Secure Boot keys or the TPM. All of this is manual.' 'Dim' 2
}

function Invoke-RebootToFirmware {
    <# The side effect, kept out of the Show- function and behind explicit confirmation. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)]$Guidance)

    if ($Guidance.Encryption.AnyProtected) {
        Write-Line 'Reminder: have your BitLocker recovery key available before continuing.' 'Bad'
    }
    Write-Line 'Restarting will close all applications. Save your work first.' 'Warn'
    if (-not (Confirm-Action 'Restart now directly into firmware setup?')) { return $false }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart into firmware setup')) { return $false }

    Write-Line 'Restarting into firmware setup...' 'Info'
    & (Join-Path $env:SystemRoot 'System32\shutdown.exe') '/r' '/fw' '/t' '5'
    if ($LASTEXITCODE -ne 0) {
        Write-Line 'Windows refused the request to boot into firmware setup.' 'Warn'
        Write-Line 'Use the Settings > Recovery > Advanced startup route described above instead.' 'Warn'
        return $false
    }
    return $true
}

function Open-CodeIntegrityEventViewer {
    try {
        Start-Process -FilePath 'eventvwr.msc' -ArgumentList '/c:Microsoft-Windows-CodeIntegrity/Operational' -ErrorAction Stop | Out-Null
        Write-Line 'Opened Event Viewer at the Code Integrity log.' 'Good'
        return $true
    }
    catch {
        Write-DebugError 'Open Event Viewer' $_
        Write-Line 'Could not open Event Viewer automatically.' 'Warn'
        Write-Line 'Open it manually: Applications and Services Logs > Microsoft > Windows >' 'Info' 2
        Write-Line 'CodeIntegrity > Operational, and look for event ID 3087.' 'Info' 2
        return $false
    }
}

function Show-CodeIntegrityDiagnostics {
    param([Parameter(Mandatory = $true)]$State)

    Write-Section 'Memory Integrity driver diagnostics'
    $events = Get-CodeIntegrityEvents -EventIds @(3087) -LookbackDays 14

    if (-not $events.Queried) {
        Write-Line 'The Code Integrity log could not be read.' 'Warn'
        if ($events.Error) { Write-Line $events.Error 'Dim' 2 }
        return
    }
    if ($events.EventCount -eq 0) {
        Write-Line 'No driver-compatibility warnings in the last 14 days.' 'Good'
        Write-Line 'Nothing is recorded as blocking Memory Integrity on this computer.' 'Dim'
        return
    }

    Write-Line ('{0} compatibility event(s) in the last 14 days.' -f $events.EventCount) 'Warn'
    if ($events.Newest) { Write-Line ('Most recent: {0}' -f $events.Newest) 'Dim' }
    Write-Line ''
    Write-Line 'Drivers named in those events:' 'Head'
    foreach ($d in (ConvertTo-Array $events.Drivers)) {
        Write-Line $d.FileName 'Warn' 2
        if ($d.Publisher) { Write-Line ('Publisher: {0}' -f $d.Publisher) 'Dim' 5 }
        if ($d.Version) { Write-Line ('Version  : {0}' -f $d.Version) 'Dim' 5 }
        if ($d.Service) { Write-Line ('Used by  : {0}' -f $d.Service) 'Dim' 5 }
        if ($d.Path) { Write-Line ('Path     : {0}' -f $d.Path) 'Dim' 5 }
        if (-not $d.Found) { Write-Line 'This file is no longer present, so the problem may already be resolved.' 'Dim' 5 }
    }
    Write-Line ''
    Write-Line 'Update or remove the driver above, restart, then run the audit again.' 'Info'
}
