@echo off
setlocal enabledelayedexpansion

set "BUILD_DIR=build"
set "VENV_DIR=%BUILD_DIR%\venv"
set "BACKEND_REQ=..\backend\requirements.txt"

where python >nul 2>nul
if errorlevel 1 (
    echo [!] python not found on PATH. Install Python 3.10+ first, or run build_all.bat from the repo root.
    exit /b 1
)

echo [*] Cleaning previous build...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "dist" rmdir /s /q "dist"
mkdir "%BUILD_DIR%"

echo [*] Creating build venv...
python -m venv "%VENV_DIR%"
call "%VENV_DIR%\Scripts\activate.bat"

echo [*] Installing Python dependencies...
python -m pip install --upgrade pip
if exist "%BACKEND_REQ%" (
    python -m pip install --upgrade -r "%BACKEND_REQ%"
) else (
    echo [!] %BACKEND_REQ% not found -- the packaged app may be missing dependencies at runtime.
)
python -m pip install --upgrade pyinstaller

echo [*] Running PyInstaller...
pyinstaller triager_web.spec
if errorlevel 1 (
    echo [!] Build failed.
    call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul
    exit /b 1
)

call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul

echo.
echo [*] Done. Distributable is at: desktop\dist\TriagerWeb\
echo [*] Double-click TriagerWeb.exe inside that folder to run it.
