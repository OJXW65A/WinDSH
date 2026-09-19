# ---------------------------------------------------------------------------
# Control catalog: the single source of truth.
#
# Audit, explain, preview, apply, revert, scoring, CIS comparison and every report
# format are projections over this table. Adding a control means adding one entry.
#
# LocalValues  - what WinDSH writes, under HKLM\SYSTEM\CurrentControlSet\Control
# PolicyValues - what CIS audits, under HKLM\SOFTWARE\Policies (READ ONLY, never written)
#
# Comparison semantics for a value:
#   Exact   - rewrite anything that differs (default)
#   AtLeast - the declared value is a floor; a stronger existing value is preserved
# ---------------------------------------------------------------------------

$script:RegDeviceGuard   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$script:RegHvci          = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$script:RegSystemGuard   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard'
$script:RegShadowStacks  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks'
$script:RegLsa           = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$script:RegCiConfig      = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
$script:RegPolicyDG      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'

$script:ControlCatalog = @(

    [pscustomobject]@{
        Id          = 'vbs'
        Name        = 'Virtualization-based Security'
        PlainName   = 'Core security container'
        Category    = 'Platform'
        Weight      = 25
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @()
        Summary     = 'Uses the Windows hypervisor to create a protected area of memory that the rest of Windows cannot reach.'
        Why         = 'Everything else on this list runs inside it. Without it, none of the other protections can start.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Vbs'
        LocalValues = @(
            @{ Path = $script:RegDeviceGuard; Name = 'EnableVirtualizationBasedSecurity'; Type = 'DWord'; Value = 1
               Note = 'Turns VBS on.' }
            @{ Path = $script:RegDeviceGuard; Name = 'Locked'; Type = 'DWord'; Value = 0
               Note = 'No UEFI lock, so the change can be undone from Windows.' }
        )
        PolicyValues = @(
            @{ Name = 'EnableVirtualizationBasedSecurity'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.1'; Profile = 'L1'
            Title = "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'"
            Expected = 'EnableVirtualizationBasedSecurity = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'platform-security'
        Name        = 'Platform Security Level'
        PlainName   = 'Secure Boot requirement'
        Category    = 'Platform'
        Weight      = 10
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Requires Secure Boot before the security container is allowed to start.'
        Why         = 'Stops the protection being started on a machine whose boot chain has not been verified.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'PlatformSecurity'
        LocalValues = @(
            # 1 = Secure Boot only, 3 = Secure Boot and DMA protection. CIS accepts either,
            # so 1 is a floor rather than a target: an administrator who chose 3 keeps it.
            # Note 3 is stricter, not simply better - on hardware without an IOMMU it
            # prevents VBS from starting at all.
            @{ Path = $script:RegDeviceGuard; Name = 'RequirePlatformSecurityFeatures'; Type = 'DWord'; Value = 1
               Comparison = 'AtLeast'
               Note = 'Secure Boot required. An existing value of 3 (Secure Boot + DMA) is preserved.' }
        )
        PolicyValues = @(
            @{ Name = 'RequirePlatformSecurityFeatures'; Expected = 1; AlsoAccepted = @(3) }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.2'; Profile = 'L1'
            Title = "Ensure 'Select Platform Security Level' is set to 'Secure Boot' or higher"
            Expected = 'RequirePlatformSecurityFeatures = 1 or 3 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'hvci'
        Name        = 'Memory Integrity (HVCI)'
        PlainName   = 'Driver protection'
        Category    = 'Kernel'
        Weight      = 25
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'platform-security')
        Summary     = 'Checks every driver inside the protected container before Windows will load it.'
        Why         = 'Blocks malicious or tampered drivers from running with kernel privileges.'
        Caution     = 'An incompatible driver can stop the computer from starting normally. WinDSH checks recent compatibility warnings before offering this.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Hvci'
        # Windows logs Event ID 3087 in CodeIntegrity/Operational when a driver is not
        # compatible with Memory Integrity. Enabling HVCI anyway can stop the machine
        # booting cleanly, so recent evidence blocks the safe set. Declared here rather
        # than special-cased inside the apply path, so any control can have one.
        Preflight   = @{
            Kind = 'CodeIntegrityEvents'
            EventIds = @(3087)
            LookbackDays = 14
            BlocksSafeSet = $true
            Message = 'Windows has recently reported a driver that is not compatible with Memory Integrity. Enabling it now could stop this computer starting normally.'
        }
        LocalValues = @(
            @{ Path = $script:RegHvci; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Turns Memory Integrity on.' }
            @{ Path = $script:RegHvci; Name = 'Locked'; Type = 'DWord'; Value = 0; Note = 'No UEFI lock, so it stays revertible.' }
        )
        PolicyValues = @(
            # CIS wants 1 = Enabled with UEFI lock. WinDSH deliberately configures the
            # unlocked form locally so a machine that will not boot can be recovered.
            @{ Name = 'HypervisorEnforcedCodeIntegrity'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.3'; Profile = 'L1'
            Title = "Ensure 'Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'"
            Expected = 'HypervisorEnforcedCodeIntegrity = 1, with UEFI lock (Group Policy hive)'
            Divergence = 'WinDSH configures Memory Integrity WITHOUT a UEFI lock so it can be reverted from Windows. CIS requires the locked form, which can only be removed with a physically present user.'
        }
    }

    [pscustomobject]@{
        Id          = 'hvci-mat'
        Name        = 'Require UEFI Memory Attributes Table'
        PlainName   = 'Firmware compatibility check'
        Category    = 'Kernel'
        Weight      = 5
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Only allows driver protection to start on firmware that reports a UEFI Memory Attributes Table.'
        Why         = 'A safety setting. Firmware without this table can be incompatible with Memory Integrity, which CIS notes may lead to crashes, data loss, or plug-in card incompatibility.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'HvciMat'
        LocalValues = @(
            @{ Path = $script:RegDeviceGuard; Name = 'HVCIMATRequired'; Type = 'DWord'; Value = 1
               Note = 'Refuses to start Memory Integrity on firmware that cannot support it safely.' }
        )
        PolicyValues = @(
            @{ Name = 'HVCIMATRequired'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.4'; Profile = 'L1'
            Title = "Ensure 'Require UEFI Memory Attributes Table' is set to 'True (checked)'"
            Expected = 'HVCIMATRequired = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'credential-guard'
        Name        = 'Credential Guard'
        PlainName   = 'Password and sign-in protection'
        Category    = 'Credentials'
        Weight      = 20
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'platform-security')
        Summary     = 'Moves your saved sign-in secrets into the protected container so malware on the computer cannot read them.'
        Why         = 'Defeats credential-theft tools that scrape passwords and Kerberos tickets from memory.'
        Caution     = 'Can break older network sign-in methods, some VPN clients, and legacy NTLM delegation.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/'
        DetectKey   = 'CredentialGuard'
        LocalValues = @(
            # 1 = enabled with UEFI lock, 2 = enabled without lock. WinDSH uses 2.
            @{ Path = $script:RegLsa; Name = 'LsaCfgFlags'; Type = 'DWord'; Value = 2
               Note = 'Enabled without a UEFI lock, so it can be switched off again from Windows.' }
        )
        PolicyValues = @(
            @{ Name = 'LsaCfgFlags'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.5'; Profile = 'L1'
            Title = "Ensure 'Credential Guard Configuration' is set to 'Enabled with UEFI lock'"
            Expected = 'LsaCfgFlags = 1 (Group Policy hive, UEFI lock)'
            Divergence = 'WinDSH sets LsaCfgFlags = 2 (enabled without UEFI lock) locally. CIS requires 1. The locked form cannot be removed remotely and needs a physically present user at the machine.'
        }
    }

    [pscustomobject]@{
        Id          = 'secure-launch'
        Name        = 'System Guard Secure Launch'
        PlainName   = 'Firmware attack protection'
        Category    = 'Firmware'
        Weight      = 10
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs')
        Summary     = 'Re-establishes trust in the computer after start-up, so a compromised firmware cannot undermine the other protections.'
        Why         = 'Protects the security container from exploited vulnerabilities in device firmware.'
        Caution     = 'Needs DRTM-capable firmware (Intel TXT or AMD SKINIT). Most consumer laptops do not have it, and Windows silently ignores the setting when it is absent.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection'
        DetectKey   = 'SecureLaunch'
        LocalValues = @(
            @{ Path = $script:RegSystemGuard; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Turns Secure Launch on.' }
        )
        PolicyValues = @(
            @{ Name = 'ConfigureSystemGuardLaunch'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.6'; Profile = 'L1'
            Title = "Ensure 'Secure Launch Configuration' is set to 'Enabled'"
            Expected = 'ConfigureSystemGuardLaunch = 1 (Group Policy hive)'
        }
    }

    [pscustomobject]@{
        Id          = 'kernel-shadow-stacks'
        Name        = 'Kernel-mode Hardware-enforced Stack Protection'
        PlainName   = 'Code hijacking protection'
        Category    = 'Kernel'
        Weight      = 10
        RiskLevel   = 'Medium'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @('vbs', 'hvci')
        Summary     = 'Keeps a hardware-protected copy of where kernel code is meant to return to, so an exploit cannot redirect it.'
        Why         = 'Stops memory-corruption exploits such as stack buffer overflows from hijacking kernel execution.'
        Caution     = 'Requires Windows 11 22H2 or newer and an Intel Tiger Lake or AMD Zen 3 processor or newer. Once enforcing, a shadow stack violation is fatal to the offending code.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection'
        DetectKey   = 'KernelShadowStacks'
        MinimumBuild = 22621
        LocalValues = @(
            @{ Path = $script:RegShadowStacks; Name = 'Enabled'; Type = 'DWord'; Value = 1; Note = 'Enables kernel shadow stacks in enforcement mode.' }
        )
        PolicyValues = @(
            @{ Name = 'ConfigureKernelShadowStacksLaunch'; Expected = 1 }
        )
        Cis = [pscustomobject]@{
            Id = '18.9.5.7'; Profile = 'L1'
            Title = "Ensure 'Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode'"
            Expected = 'ConfigureKernelShadowStacksLaunch = 1 (Group Policy hive)'
        }
    }

    # ---- Detection only. WinDSH reports these but never configures them. -------
    # Weight 0 deliberately: they are informational and mostly not user-actionable, so
    # counting them would move the score without the user being able to do anything.

    [pscustomobject]@{
        Id          = 'hvpt'
        Name        = 'Hypervisor-enforced Paging Translation'
        PlainName   = 'Memory address protection'
        Category    = 'Kernel'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Moves control of memory address translation into the protected container.'
        Why         = 'Stops an attacker with kernel access from remapping memory to bypass other protections.'
        Caution     = 'Reported only. Windows enables this on supported hardware; WinDSH does not configure it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity'
        DetectKey   = 'Hvpt'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'smm-firmware-measurement'
        Name        = 'SMM Firmware Measurement'
        PlainName   = 'Firmware self-check'
        Category    = 'Firmware'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Measures System Management Mode firmware so tampering with it can be detected.'
        Why         = 'System Management Mode runs beneath the operating system, so compromise there is invisible to Windows.'
        Caution     = 'Reported only. Provided by the platform firmware; WinDSH does not configure it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/hardware-security/system-guard-secure-launch-and-smm-protection'
        DetectKey   = 'SmmFirmware'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'dep'
        Name        = 'Data Execution Prevention'
        PlainName   = 'Executable memory protection'
        Category    = 'Kernel'
        Weight      = 0
        RiskLevel   = 'Low'
        Remediable  = $false
        DetectionOnly = $true
        Requires    = @()
        Summary     = 'Stops code running from memory that is only meant to hold data.'
        Why         = 'A long-standing defence against buffer-overflow exploits.'
        Caution     = 'Reported only. Configured in the boot configuration, not the registry; WinDSH does not change it.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention'
        DetectKey   = 'Dep'
        LocalValues = @()
        PolicyValues = @()
        Cis = $null
    }

    [pscustomobject]@{
        Id          = 'driver-blocklist'
        Name        = 'Microsoft vulnerable driver blocklist'
        PlainName   = 'Known-bad driver blocking'
        Category    = 'Kernel'
        Weight      = 15
        RiskLevel   = 'Low'
        Remediable  = $true
        DetectionOnly = $false
        Requires    = @()
        Summary     = 'Blocks drivers Microsoft has identified as dangerous, even when they are correctly signed.'
        Why         = 'Attackers bring their own vulnerable signed driver to gain kernel access. This blocks the known ones.'
        DocUrl      = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/design/microsoft-recommended-driver-block-rules'
        DetectKey   = 'DriverBlocklist'
        LocalValues = @(
            @{ Path = $script:RegCiConfig; Name = 'VulnerableDriverBlocklistEnable'; Type = 'DWord'; Value = 1; Note = 'Turns the blocklist on.' }
        )
        PolicyValues = @()
        Cis = $null   # Not covered by CIS 18.9.5. WinDSH does more than the benchmark here.
    }
)

function Get-Control {
    param([Parameter(Mandatory = $true)][string]$Id)
    $match = @($script:ControlCatalog | Where-Object { $_.Id -eq $Id })
    if ($match.Count -ne 1) { throw "Unknown control id: $Id" }
    return $match[0]
}

function Get-ControlIds { return @($script:ControlCatalog | Select-Object -ExpandProperty Id) }

function Resolve-ControlOrder {
    <# Dependencies first, deduplicated, with cycle detection. #>
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [System.Collections.Generic.HashSet[string]]$Visiting
    )
    if (-not $Visiting) { $Visiting = New-Object 'System.Collections.Generic.HashSet[string]' }
    if (-not $Visiting.Add($Id)) { throw "Dependency cycle detected at control '$Id'." }

    $control = Get-Control -Id $Id
    $ordered = @()
    foreach ($dep in (ConvertTo-Array $control.Requires)) {
        $ordered += Resolve-ControlOrder -Id $dep -Visiting $Visiting
    }
    $ordered += $control
    $Visiting.Remove($Id) | Out-Null

    $seen = @{}
    $unique = @()
    foreach ($c in $ordered) {
        if (-not $seen.ContainsKey($c.Id)) { $seen[$c.Id] = $true; $unique += $c }
    }
    return $unique
}

# Applied by -EnableAllSafe. Deliberately excludes Credential Guard (compatibility risk)
# and kernel shadow stacks (fatal violations), which stay opt-in.
$script:SafeControlSet = @('vbs', 'platform-security', 'hvci-mat', 'hvci', 'driver-blocklist')
