@echo off
setlocal enabledelayedexpansion

set "SCRIPT=triager.py"
set "NAME=Triager"
set "BUILD_DIR=build"
set "DIST_DIR=%BUILD_DIR%\windows"
set "REQ=requirements.txt"
set "VENV_DIR=%BUILD_DIR%\venv"

if not exist "%SCRIPT%" (
    echo [!] %SCRIPT% not found in %cd%
    exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
    echo [!] python not found on PATH. Install Python 3.10+ first.
    exit /b 1
)

echo [*] Cleaning previous build...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%DIST_DIR%"

echo [*] Creating build venv...
python -m venv "%VENV_DIR%"
call "%VENV_DIR%\Scripts\activate.bat"

echo [*] Installing Python dependencies...
python -m pip install --upgrade pip
if exist "%REQ%" (
    python -m pip install --upgrade -r "%REQ%"
) else (
    echo [!] %REQ% not found -- installing known runtime deps directly.
    python -m pip install --upgrade pyyaml python-registry
)
python -m pip install --upgrade pyinstaller

echo [*] Running PyInstaller (onefile)...
set "ADD_DATA=--add-data tools;tools"
if not exist "tools" (
    echo [!] NOTE: tools\ directory not found -- building without --add-data for it.
    echo [!] Triager's external forensic utilities - PECmd, MFTECmd, etc. - must
    echo [!] be placed in a tools\ folder next to the built .exe at runtime.
    set "ADD_DATA="
)

pyinstaller --clean --onefile ^
            --name "%NAME%" ^
            --distpath "%DIST_DIR%" ^
            --hidden-import=Registry ^
            --collect-all=pyyaml ^
            %ADD_DATA% ^
            "%SCRIPT%"

if errorlevel 1 (
    echo [!] Build failed.
    call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul
    exit /b 1
)

call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul

echo [*] Copying executable to web backend...
copy /Y "%DIST_DIR%\%NAME%.exe" "%~dp0..\web\backend\tools\%NAME%.exe" >nul

echo.
echo [*] Build complete!
echo  - Windows EXE (onefile): %DIST_DIR%\%NAME%.exe
