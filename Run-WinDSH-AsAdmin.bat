@echo off
setlocal EnableExtensions
title WinDSH - Windows Device Security Helper

REM ===========================================================================
REM  WinDSH launcher
REM
REM  Double-click this file to run WinDSH. Windows opens a .ps1 in Notepad rather
REM  than running it, so this launcher is how a non-technical user starts the tool.
REM
REM  It does three things and nothing else:
REM    1. Finds WinDSH.ps1 in this folder.
REM    2. Asks Windows for Administrator rights (you will see a UAC prompt).
REM    3. Runs the script and shows you the result.
REM
REM  It deliberately does NOT remove the Mark of the Web from WinDSH.ps1.
REM  Earlier versions did. Stripping that mark permanently edits the file and
REM  removes the "this came from the internet" signal for every other program on
REM  the computer, forever. Instead this launcher uses -ExecutionPolicy Bypass,
REM  which applies to this one PowerShell process, ends when it ends, and leaves
REM  the file untouched. No persistent execution policy is changed.
REM
REM  It also does not forward command-line arguments into the elevated process.
REM  For automation, call WinDSH.ps1 directly instead of using this launcher.
REM ===========================================================================

set "HERE=%~dp0"
set "WINDSH_PS1=%HERE%WinDSH.ps1"
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "WINDSH_SELF=%~f0"

echo.
echo   WinDSH - Windows Device Security Helper
echo   ---------------------------------------
echo.

if not exist "%WINDSH_PS1%" (
    echo   PROBLEM: WinDSH.ps1 was not found next to this launcher.
    echo.
    echo   Both files must sit in the same folder:
    echo     %HERE%
    echo.
    echo   If you extracted a zip, make sure you extracted all of it.
    echo.
    pause
    exit /b 1
)

if not exist "%PSEXE%" (
    echo   PROBLEM: Windows PowerShell was not found at the expected location.
    echo     %PSEXE%
    echo.
    pause
    exit /b 1
)

REM --- Are we already running with Administrator rights? ---------------------
net session >nul 2>&1
if not errorlevel 1 goto RUN

REM --- Not elevated: relaunch this launcher through UAC ----------------------
echo   WinDSH needs Administrator rights to read device security settings.
echo   A User Account Control prompt will appear. Choose Yes to continue.
echo.

"%PSEXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:WINDSH_SELF -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"

if errorlevel 1 (
    echo.
    echo   Elevation was cancelled, so WinDSH did not run.
    echo.
    echo   If you cannot approve the prompt, ask whoever administers this
    echo   computer to run it for you.
    echo.
    pause
    exit /b 4
)
exit /b 0

REM --- Elevated: run the script ---------------------------------------------
:RUN
echo   Running as Administrator. Starting the security check...
echo.

"%PSEXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%WINDSH_PS1%"
set "RC=%errorlevel%"

echo.
echo   ---------------------------------------
if "%RC%"=="0"    echo   Finished successfully.
if "%RC%"=="2"    echo   Finished, with warnings shown above.
if "%RC%"=="3"    echo   The file's integrity check failed. Changes were disabled.
if "%RC%"=="3010" echo   Finished. RESTART WINDOWS for the changes to take effect.
if "%RC%"=="4"    echo   Administrator rights were required but not available.
if "%RC%"=="5"    echo   The undo operation failed. See the messages above.
if "%RC%"=="1"    echo   WinDSH could not start. See the messages above.
echo   Exit code: %RC%
echo.
pause
exit /b %RC%
