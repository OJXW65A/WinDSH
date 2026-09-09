@echo off
setlocal EnableExtensions
set "WINDSH_SCRIPT=%~dp0WinDSH.ps1"
set "WINDSH_FORWARD=%*"
title WinDSH Launcher

rem WinDSH bootstrap launcher.
rem - Checks Group Policy before launch.
rem - Automatically removes Mark of the Web from WinDSH.ps1 only when detected.
rem - Uses RemoteSigned only for the new PowerShell PROCESS.
rem - Does not set CurrentUser or LocalMachine execution policy.
rem - Starts an elevated PowerShell console and exits.

if not exist "%WINDSH_SCRIPT%" (
    echo.
    echo ================================================================================
    echo  WinDSH cannot start
    echo ================================================================================
    echo WinDSH.ps1 was not found next to this launcher.
    echo.
    echo Expected file:
    echo   %WINDSH_SCRIPT%
    echo.
    echo Keep Run-WinDSH-AsAdmin.bat and WinDSH.ps1 in the same folder.
    echo If WinDSH.ps1 was present earlier, check whether endpoint security quarantined it.
    echo.
    pause
    exit /b 2
)

rem Group Policy has higher priority than Process-scope -ExecutionPolicy.
powershell.exe -NoProfile -Command ^
 "$mp=[string](Get-ExecutionPolicy -Scope MachinePolicy); $up=[string](Get-ExecutionPolicy -Scope UserPolicy); if([string]::IsNullOrWhiteSpace($mp)){$mp='Undefined'}; if([string]::IsNullOrWhiteSpace($up)){$up='Undefined'}; $effectiveGp=if($mp -ne 'Undefined'){$mp}elseif($up -ne 'Undefined'){$up}else{'Undefined'}; if($effectiveGp -eq 'Restricted' -or $effectiveGp -eq 'AllSigned'){ Write-Host ''; Write-Host ('='*80) -ForegroundColor DarkGray; Write-Host ' WinDSH is blocked by organization PowerShell policy' -ForegroundColor Red; Write-Host ('='*80) -ForegroundColor DarkGray; Write-Host ('MachinePolicy : ' + $mp) -ForegroundColor Yellow; Write-Host ('UserPolicy    : ' + $up) -ForegroundColor Yellow; Write-Host ''; if($effectiveGp -eq 'Restricted'){Write-Host 'This policy does not allow PowerShell scripts to run.' -ForegroundColor White}else{Write-Host 'This policy allows only trusted signed PowerShell scripts.' -ForegroundColor White; Write-Host 'This WinDSH build is not Authenticode-signed yet.' -ForegroundColor White}; Write-Host ''; Write-Host 'WinDSH will NOT bypass or change an organization Group Policy.' -ForegroundColor Cyan; Write-Host 'Ask your IT/domain administrator to allow RemoteSigned scripts or a signed WinDSH release.' -ForegroundColor Cyan; Write-Host 'No Windows security or execution-policy setting was changed.' -ForegroundColor Gray; exit 20 }; exit 0"
set "WINDSH_POLICY_RC=%errorlevel%"
if "%WINDSH_POLICY_RC%"=="20" (
    echo.
    pause
    exit /b 20
)
if not "%WINDSH_POLICY_RC%"=="0" (
    echo.
    echo WinDSH could not read the PowerShell execution-policy status.
    echo No settings were changed.
    echo.
    pause
    exit /b 21
)

rem Under RemoteSigned, an unsigned file carrying Mark of the Web cannot run.
powershell.exe -NoProfile -Command "if(Get-Item -LiteralPath $env:WINDSH_SCRIPT -Stream Zone.Identifier -ErrorAction SilentlyContinue){exit 10}else{exit 0}"
set "WINDSH_ZONE_RC=%errorlevel%"
if "%WINDSH_ZONE_RC%"=="10" (
    powershell.exe -NoProfile -Command "try{Unblock-File -LiteralPath $env:WINDSH_SCRIPT -ErrorAction Stop; exit 0}catch{Write-Host $_.Exception.Message -ForegroundColor Red; exit 1}"
    if errorlevel 1 (
        echo.
        echo Windows download mark detected on WinDSH.ps1.
        echo The mark could not be removed from this file.
        echo WinDSH was not started and no execution-policy setting was changed.
        echo.
        pause
        exit /b 23
    )
    echo.
    echo Windows download mark detected on WinDSH.ps1. Removing the mark from this file only... Done.
)

echo.
echo Starting WinDSH with temporary Process-scope RemoteSigned.
echo This setting exists only in the new PowerShell process and disappears when it closes.
echo CurrentUser and LocalMachine execution-policy settings are not changed.
echo.

rem Request UAC for PowerShell itself. -PauseOnExit is hidden and is used only
rem for interactive launcher runs so users can read the final result/error.
powershell.exe -NoProfile -Command ^
 "$p=$env:WINDSH_SCRIPT; $forward=$env:WINDSH_FORWARD; $q=[char]34; $argsText='-NoProfile -ExecutionPolicy RemoteSigned -File ' + $q + $p + $q + ' -PauseOnExit'; if(-not [string]::IsNullOrWhiteSpace($forward)){$argsText += ' ' + $forward}; try{Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argsText -ErrorAction Stop; exit 0}catch{Write-Host ''; Write-Host ('UAC elevation was cancelled or failed: ' + $_.Exception.Message) -ForegroundColor Red; exit 5}"
set "WINDSH_EXIT=%errorlevel%"
if not "%WINDSH_EXIT%"=="0" (
    echo.
    echo WinDSH did not start. No Windows security setting was changed by the launcher.
    echo.
    pause
)
endlocal & exit /b %WINDSH_EXIT%
