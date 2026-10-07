@echo off
REM Builds dist\USBThreatAnalyzer.exe (single file, no console, no browser needed).
REM Run this on Windows 10/11 with Python 3.12+ on PATH.
setlocal
cd /d "%~dp0"

if not exist venv\Scripts\activate.bat (
    echo Creating virtual environment...
    python -m venv venv || goto :fail
)
call venv\Scripts\activate.bat

echo Installing build requirements...
python -m pip install --upgrade pip >nul
pip install -r requirements-desktop.txt || goto :fail

echo Building executable...
pyinstaller --noconfirm --clean USB_Threat_Analyzer.spec || goto :fail

echo Running post-build self-test on the packaged EXE...
start /wait "" "dist\USBThreatAnalyzer.exe" --selftest
if errorlevel 1 (
    echo.
    echo SELF-TEST FAILED. Details: %LOCALAPPDATA%\USBThreatAnalyzer\history\selftest.log
    goto :fail
)

echo.
echo Build OK: %CD%\dist\USBThreatAnalyzer.exe

REM Optional: build the installer (gives a Desktop icon + Start Menu entry) if Inno Setup is installed.
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if exist "%ISCC%" (
    echo Building installer...
    "%ISCC%" installer\USBThreatAnalyzer.iss || goto :fail
    echo Installer OK: %CD%\installer\USBThreatAnalyzer_Setup.exe
) else (
    echo.
    echo Inno Setup not found - skipping the installer.
    echo Install it from https://jrsoftware.org/isdl.php and run build_exe.bat again
    echo to get installer\USBThreatAnalyzer_Setup.exe ^(desktop icon + Start Menu^).
)
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
