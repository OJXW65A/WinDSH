# ---------------------------------------------------------------------------
# State collection.
#
# Split into static and volatile. Hardware, firmware, TPM and OS identity cannot change
# while WinDSH is running, so they are collected once. Only the DeviceGuard state,
# registry values and restart status are re-read after a change. In v1 every menu action
# re-ran the whole collection, including Get-ComputerInfo and a bcdedit process spawn,
# to learn a handful of registry DWORDs.
# ---------------------------------------------------------------------------

$script:StaticState = $null

function Get-OsAndHardwareState {
    $os = $null; $cs = $null; $cpus = @()
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    catch { Write-DebugError 'Query Win32_OperatingSystem' $_ }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    catch { Write-DebugError 'Query Win32_ComputerSystem' $_ }
    try { $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) }
    catch { Write-DebugError 'Query Win32_Processor' $_ }

    $build = 0
    $buildText = [string](Get-PropertySafe $os 'BuildNumber' '0')
    [void][int]::TryParse($buildText, [ref]$build)

    $ubr = $null
    $editionId = $null
    $productName = $null
    try {
        $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ubr = Get-RegValue -Path $cv -Name 'UBR'
        $editionId = Get-RegValue -Path $cv -Name 'EditionID'
        $productName = Get-RegValue -Path $cv -Name 'ProductName'
    }
    catch { Write-DebugError 'Read CurrentVersion' $_ }

    $manufacturer = [string](Get-PropertySafe $cs 'Manufacturer' '')
    $model = [string](Get-PropertySafe $cs 'Model' '')
    $domainRole = Get-PropertySafe $cs 'DomainRole' $null
    $partOfDomain = [bool](Get-PropertySafe $cs 'PartOfDomain' $false)

    $cpuName = 'Unknown'
    if (@($cpus).Count -gt 0) { $cpuName = [string](Get-PropertySafe @($cpus)[0] 'Name' 'Unknown') }

    # Virtual machines cannot always expose the hardware these features need.
    $vmMarkers = 'VMware|VirtualBox|Virtual Machine|KVM|QEMU|Xen|Parallels|Hyper-V|Bochs|Google Compute|Amazon EC2'
    $isVm = [bool](("$manufacturer $model") -match $vmMarkers)

    return [pscustomobject]@{
        Name           = $env:COMPUTERNAME
        Manufacturer   = $manufacturer
        Model          = $model
        ProcessorName  = $cpuName
        ProcessorCount = @($cpus).Count
        OsCaption      = [string](Get-PropertySafe $os 'Caption' 'Unknown')
        ProductName    = [string]$productName
        EditionId      = [string]$editionId
        BuildNumber    = $build
        Ubr            = $ubr
        Is64Bit        = [Environment]::Is64BitOperatingSystem
        PartOfDomain   = $partOfDomain
        DomainRole     = $domainRole
        IsVirtual      = $isVm
    }
}

function Get-FirmwareState {
    # Type is a display string and must never drive logic: it can legitimately read
    # 'Legacy BIOS or unsupported UEFI', which contains the substring 'UEFI'.
    $type = 'Unknown'; $mode = 'Unknown'; $source = 'None'

    $envFirmware = [string]$env:firmware_type
    if ($envFirmware -eq 'UEFI') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Environment' }
    elseif ($envFirmware -eq 'Legacy') { $mode = 'Legacy'; $type = 'Legacy BIOS'; $source = 'Environment' }

    if ($mode -eq 'Unknown') {
        try {
            $ci = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
            $bios = [string](Get-PropertySafe $ci 'BiosFirmwareType' '')
            if ($bios -eq 'Uefi') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Get-ComputerInfo' }
            elseif ($bios -eq 'Bios') { $mode = 'Legacy'; $type = 'Legacy BIOS'; $source = 'Get-ComputerInfo' }
        }
        catch { Write-DebugError 'Determine firmware type' $_ }
    }

    $secureBootSupported = $false
    $secureBootEnabled = $null
    try {
        $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $secureBootSupported = $true
        if ($mode -eq 'Unknown') { $mode = 'UEFI'; $type = 'UEFI'; $source = 'Confirm-SecureBootUEFI' }
    }
    catch {
        Write-DebugError 'Query Secure Boot' $_
        if ($mode -eq 'Unknown') { $type = 'Legacy BIOS or unsupported UEFI' }
    }

    return [pscustomobject]@{
        Type = $type
        Mode = $mode
        IsUefiConfirmed = [bool]($mode -eq 'UEFI')
        IsLegacyConfirmed = [bool]($mode -eq 'Legacy')
        DetectionSource = $source
        SecureBootSupported = $secureBootSupported
        SecureBootEnabled = $secureBootEnabled
    }
}

function Get-TpmState {
    $present = $false; $ready = $null; $spec = $null; $isTpm2 = $false
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $present = [bool](Get-PropertySafe $tpm 'TpmPresent' $false)
        $ready = Get-PropertySafe $tpm 'TpmReady' $null
    }
    catch { Write-DebugError 'Get-Tpm' $_ }

    try {
        $wmi = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -ErrorAction Stop
        $spec = [string](Get-PropertySafe $wmi 'SpecVersion' '')
        if ($spec -match '^\s*2\.0') { $isTpm2 = $true; $present = $true }
    }
    catch { Write-DebugError 'Query Win32_Tpm' $_ }

    return [pscustomobject]@{
        Present = $present
        Ready = $ready
        SpecVersion = $spec
        IsTPM2 = $isTpm2
    }
}

function Get-VirtualizationState {
    $hypervisorPresent = $false; $vmx = $null; $slat = $null
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hypervisorPresent = [bool](Get-PropertySafe $cs 'HypervisorPresent' $false)
    }
    catch { Write-DebugError 'Query HypervisorPresent' $_ }

    try {
        $cpu = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)[0]
        $vmx = Get-PropertySafe $cpu 'VirtualizationFirmwareEnabled' $null
        $slat = Get-PropertySafe $cpu 'SecondLevelAddressTranslationExtensions' $null
    }
    catch { Write-DebugError 'Query processor virtualization' $_ }

    # When Hyper-V owns the CPU, VirtualizationFirmwareEnabled often reports false even
    # though virtualization is plainly working. Treat a running hypervisor as proof.
    $enabled = [bool]($vmx -or $hypervisorPresent)

    return [pscustomobject]@{
        HypervisorPresent = $hypervisorPresent
        FirmwareEnabled = $enabled
        FirmwareRaw = $vmx
        Slat = $slat
    }
}

function Get-HypervisorLaunchState {
    # hypervisorlaunchtype=Off blocks every VBS feature regardless of the registry, and is
    # invisible in the registry. This is one of the most common causes of a feature that
    # is configured but never runs.
    $launchType = $null; $source = 'Unavailable'; $errorText = $null
    $previousEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $bcdedit = Join-Path $env:SystemRoot 'System32\bcdedit.exe'
        if (Test-Path -LiteralPath $bcdedit) {
            $raw = @(& $bcdedit '/enum' '{current}' 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -eq 0) {
                $source = 'bcdedit'
                $line = @($raw | Where-Object { $_ -match '^\s*hypervisorlaunchtype\s+' }) | Select-Object -First 1
                if ($line) { $launchType = ($line -replace '^\s*hypervisorlaunchtype\s+', '').Trim() }
                else { $launchType = 'NotSet' }
            }
            else { $errorText = 'bcdedit exit code {0}' -f $LASTEXITCODE }
        }
        else { $errorText = 'bcdedit.exe not found' }
    }
    catch { $errorText = $_.Exception.Message; Write-DebugError 'Query hypervisorlaunchtype' $_ }
    finally { $ErrorActionPreference = $previousEap }

    $blocks = [bool]($launchType -and ($launchType -match '^(?i)off$'))
    return [pscustomobject]@{
        LaunchType = $launchType
        Source = $source
        BlocksVbs = $blocks
        Error = $errorText
    }
}

function Get-DeviceGuardState {
    $dg = $null
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
                -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
    }
    catch { Write-DebugError 'Query Win32_DeviceGuard' $_ }

    $configured = ConvertTo-Array (Get-PropertySafe $dg 'SecurityServicesConfigured' @())
    $running    = ConvertTo-Array (Get-PropertySafe $dg 'SecurityServicesRunning' @())
    $available  = ConvertTo-Array (Get-PropertySafe $dg 'AvailableSecurityProperties' @())
    $required   = ConvertTo-Array (Get-PropertySafe $dg 'RequiredSecurityProperties' @())
    $vbsStatus  = Get-PropertySafe $dg 'VirtualizationBasedSecurityStatus' $null
    $ciPolicy   = Get-PropertySafe $dg 'CodeIntegrityPolicyEnforcementStatus' $null

    return [pscustomobject]@{
        Available = $dg -ne $null
        Configured = $configured
        Running = $running
        AvailableProperties = $available
        RequiredProperties = $required
        VbsStatusCode = $vbsStatus
        VbsStatusText = (ConvertTo-VbsStatusText $vbsStatus)
        CodeIntegrityPolicyEnforcement = $ciPolicy
        # AvailableSecurityProperties: 1 hypervisor, 2 Secure Boot, 3 DMA protection,
        # 4 secure memory overwrite, 5 NX, 6 SMM mitigations, 7 MBEC, 8 APIC virtualization
        HasHypervisorSupport = (Test-Contains $available 1)
        HasSecureBootProperty = (Test-Contains $available 2)
        HasDmaProtection = (Test-Contains $available 3)
        HasSmmMitigations = (Test-Contains $available 6)
        HasMbec = (Test-Contains $available 7)
    }
}

function ConvertTo-VbsStatusText {
    param($Value)
    if ($null -eq $Value) { return 'Unknown' }
    switch ([int]$Value) {
        0 { 'Not enabled' }
        1 { 'Configured, not running' }
        2 { 'Running' }
        default { 'Unknown ({0})' -f $Value }
    }
}

function Get-DepState {
    $policy = $null; $supported = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $policy = Get-PropertySafe $os 'DataExecutionPrevention_SupportPolicy' $null
        $supported = Get-PropertySafe $os 'DataExecutionPrevention_Available' $null
    }
    catch { Write-DebugError 'Query DEP state' $_ }

    # 0 AlwaysOff, 1 AlwaysOn, 2 OptIn (Windows components only), 3 OptOut (all programs)
    $text = switch ($policy) {
        0 { 'Always off' }
        1 { 'Always on' }
        2 { 'On for Windows programs only' }
        3 { 'On for all programs' }
        default { 'Unknown' }
    }
    return [pscustomobject]@{
        SupportPolicy = $policy
        Available = $supported
        Text = $text
        Enabled = [bool]($null -ne $policy -and [int]$policy -ne 0)
    }
}

function Get-VirtualMachineAssessment {
    param([Parameter(Mandatory = $true)]$Computer, [Parameter(Mandatory = $true)]$Virtualization)

    if (-not $Computer.IsVirtual) {
        return [pscustomobject]@{ IsVirtual = $false; Platform = $null; Notes = @() }
    }

    $platform = 'Unknown virtualization platform'
    $text = '{0} {1}' -f $Computer.Manufacturer, $Computer.Model
    if ($text -match 'VMware') { $platform = 'VMware' }
    elseif ($text -match 'VirtualBox') { $platform = 'VirtualBox' }
    elseif ($text -match 'Hyper-V|Virtual Machine') { $platform = 'Hyper-V' }
    elseif ($text -match 'KVM|QEMU') { $platform = 'KVM/QEMU' }
    elseif ($text -match 'Xen') { $platform = 'Xen' }
    elseif ($text -match 'Parallels') { $platform = 'Parallels' }
    elseif ($text -match 'Amazon EC2') { $platform = 'Amazon EC2' }
    elseif ($text -match 'Google Compute') { $platform = 'Google Compute Engine' }

    $notes = @(
        'This is a virtual machine, so these protections depend on what the host exposes to it.'
        'Nested virtualization must be enabled on the host for VBS to run inside the guest.'
    )
    if ($platform -eq 'Amazon EC2' -or $platform -eq 'Google Compute Engine') {
        $notes += 'Cloud instances frequently do not expose the hardware these features need.'
    }
    if (-not $Virtualization.FirmwareEnabled) {
        $notes += 'The host is not exposing hardware-assisted virtualization (Intel VT-x / AMD-V) to this guest.'
    }
    return [pscustomobject]@{ IsVirtual = $true; Platform = $platform; Notes = $notes }
}

function Get-CodeIntegrityEvents {
    <#
        Reads driver-compatibility evidence from the Code Integrity log. Feeds BOTH the
        Memory Integrity diagnostic and the pre-flight safety check, so the log is parsed
        once and the two can never disagree.

        Driver names are resolved to a publisher and version where possible: telling
        someone "vendor X driver 2.1.0 is blocking this" is far more actionable than
        showing them a bare .sys filename.
    #>
    param([int[]]$EventIds = @(3087), [int]$LookbackDays = 14, [int]$MaxEvents = 80)

    $result = [pscustomobject]@{
        Queried = $false
        LogAvailable = $false
        EventCount = 0
        Drivers = @()
        Newest = $null
        Error = $null
    }

    $start = (Get-Date).AddDays(-[math]::Abs($LookbackDays))
    $logs = @('Microsoft-Windows-CodeIntegrity/Operational')
    $messages = @()

    foreach ($log in $logs) {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start; Id = $EventIds } `
                        -MaxEvents $MaxEvents -ErrorAction Stop)
            $result.LogAvailable = $true
            $result.Queried = $true
            foreach ($e in $events) {
                $result.EventCount++
                if ($null -eq $result.Newest -or $e.TimeCreated -gt $result.Newest) { $result.Newest = $e.TimeCreated }
                $messages += [string](Get-PropertySafe $e 'Message' '')
            }
        }
        catch {
            # "No events were found" is a normal, healthy outcome, not an error.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $result.Queried = $true; $result.LogAvailable = $true }
            else { $result.Error = $_.Exception.Message; Write-DebugError ('Read {0}' -f $log) $_ }
        }
    }

    $names = @()
    foreach ($message in $messages) {
        foreach ($m in [regex]::Matches($message, '[A-Za-z0-9_\-\.]+\.sys')) {
            $name = $m.Value
            if ($names -notcontains $name) { $names += $name }
        }
    }

    $drivers = @()
    foreach ($name in $names) {
        $drivers += (Resolve-DriverDetail -FileName $name)
    }
    $result.Drivers = $drivers
    return $result
}

function Resolve-DriverDetail {
    <# Turns a bare .sys filename into something a person can act on. #>
    param([Parameter(Mandatory = $true)][string]$FileName)

    $detail = [pscustomobject]@{
        FileName = $FileName
        Path = $null
        Publisher = $null
        Version = $null
        Service = $null
        Found = $false
    }

    $candidates = @(
        (Join-Path $env:SystemRoot ('System32\drivers\' + $FileName))
        (Join-Path $env:SystemRoot ('System32\' + $FileName))
        (Join-Path $env:SystemRoot ('SysWOW64\drivers\' + $FileName))
    )
    foreach ($candidate in $candidates) {
        try {
            if (Test-Path -LiteralPath $candidate) {
                $detail.Path = $candidate
                $detail.Found = $true
                $item = Get-Item -LiteralPath $candidate -ErrorAction Stop
                $detail.Version = [string](Get-PropertySafe $item.VersionInfo 'FileVersion' $null)
                $product = [string](Get-PropertySafe $item.VersionInfo 'CompanyName' $null)
                if ($product) { $detail.Publisher = $product }
                break
            }
        }
        catch { Write-DebugError ('Inspect driver {0}' -f $candidate) $_ }
    }

    if ($detail.Found -and -not $detail.Publisher) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $detail.Path -ErrorAction Stop
            if ($sig -and $sig.SignerCertificate) { $detail.Publisher = $sig.SignerCertificate.Subject }
        }
        catch { Write-DebugError 'Read driver signature' $_ }
    }

    try {
        $base = [IO.Path]::GetFileNameWithoutExtension($FileName)
        $svc = Get-CimInstance -ClassName Win32_SystemDriver -Filter ("Name='{0}'" -f $base) -ErrorAction Stop
        if ($svc) { $detail.Service = [string](Get-PropertySafe $svc 'DisplayName' $base) }
    }
    catch { Write-DebugError 'Resolve driver service' $_ }

    return $detail
}

function Get-PendingRestartState {
    # Component Based Servicing and Windows Update are authoritative.
    # PendingFileRenameOperations is NOT: Windows, installers and antivirus queue file
    # renames constantly, so keying off its existence reported a pending restart on
    # essentially every healthy machine. Collected for diagnostics only.
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

    $queued = 0
    try {
        $value = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        if ($null -ne $value) {
            $queued = @(ConvertTo-Array $value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
        }
    }
    catch { Write-DebugError 'Read PendingFileRenameOperations' $_ }

    $reasons = @()
    if ($cbs) { $reasons += 'Windows servicing has a restart pending.' }
    if ($wu) { $reasons += 'Windows Update has a restart pending.' }

    return [pscustomobject]@{
        Pending = [bool]($cbs -or $wu)
        Reasons = $reasons
        ComponentBasedServicing = [bool]$cbs
        WindowsUpdate = [bool]$wu
        QueuedFileRenameCount = $queued
    }
}

function Get-PolicyState {
    <#
        Reads the Group Policy hive. READ ONLY - WinDSH never writes here.
        Used both to back off from GPO-managed values and to evaluate CIS compliance,
        because CIS section 18.9.5 audits this hive rather than the local one.
    #>
    $values = @{}
    foreach ($control in $script:ControlCatalog) {
        foreach ($pv in (ConvertTo-Array $control.PolicyValues)) {
            if (-not $values.ContainsKey($pv.Name)) {
                $values[$pv.Name] = Get-RegValue -Path $script:RegPolicyDG -Name $pv.Name
            }
        }
    }
    return [pscustomobject]@{
        Path = $script:RegPolicyDG
        Values = $values
        AnyConfigured = [bool](@($values.Values | Where-Object { $null -ne $_ }).Count -gt 0)
    }
}

function Get-StaticState {
    <# Collected once. Nothing here can change while WinDSH is running. #>
    if ($null -ne $script:StaticState) { return $script:StaticState }
    Write-Debug-Log 'Collecting static state'
    $computer = Get-OsAndHardwareState
    $virtualization = Get-VirtualizationState
    $script:StaticState = [pscustomobject]@{
        Computer = $computer
        Firmware = Get-FirmwareState
        Tpm = Get-TpmState
        Virtualization = $virtualization
        HypervisorLaunch = Get-HypervisorLaunchState
        Dep = Get-DepState
        VirtualMachine = Get-VirtualMachineAssessment -Computer $computer -Virtualization $virtualization
    }
    return $script:StaticState
}

function Get-SystemState {
    <#
        Full state. Pass -Volatile to re-read only what a configuration change can affect,
        reusing the cached static facts.
    #>
    param([switch]$Volatile)

    if (-not $Volatile) { $script:StaticState = $null }
    $static = Get-StaticState
    Write-Debug-Log ('Collecting volatile state (volatile-only={0})' -f [bool]$Volatile)

    return [pscustomobject]@{
        Generated = (Get-Date).ToUniversalTime().ToString('o')
        Computer = $static.Computer
        Firmware = $static.Firmware
        Tpm = $static.Tpm
        Virtualization = $static.Virtualization
        HypervisorLaunch = $static.HypervisorLaunch
        Dep = $static.Dep
        VirtualMachine = $static.VirtualMachine
        DeviceGuard = Get-DeviceGuardState
        Policy = Get-PolicyState
        Restart = Get-PendingRestartState
    }
}
