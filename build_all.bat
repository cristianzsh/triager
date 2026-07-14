@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "PYTHON_VERSION=3.13.14"
set "PYTHON_INSTALLER_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-amd64.exe"
set "OUT_DIR=%ROOT%compiled_binaries"

echo ============================================================
echo   Triager Builder
echo ============================================================
echo.

call :ensure_python
if errorlevel 1 (
    echo [-] Could not find or install Python. Install Python 3.10+ from
    echo     https://www.python.org/downloads/ and re-run this script.
    exit /b 1
)

echo.
echo [*] Using:
python --version

echo.
echo ============================================================
echo   Step 1/2 - Building Triager CLI
echo ============================================================
pushd "%ROOT%cli"
call build.bat
set "CLI_RESULT=%errorlevel%"
popd
if not "%CLI_RESULT%"=="0" (
    echo [-] Triager CLI build failed. Stopping.
    exit /b 1
)

echo.
echo ============================================================
echo   Step 2/2 - Building Triager Web Console desktop app
echo ============================================================
pushd "%ROOT%web\desktop"
call build_web.bat
set "WEB_RESULT=%errorlevel%"
popd
if not "%WEB_RESULT%"=="0" (
    echo [-] Triager Web build failed. Stopping.
    exit /b 1
)

echo.
echo ============================================================
echo   Collecting output into compiled_binaries\
echo ============================================================
if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%\cli"
mkdir "%OUT_DIR%\web"

copy /Y "%ROOT%cli\build\windows\Triager.exe" "%OUT_DIR%\cli\" >nul
xcopy /E /I /Y "%ROOT%web\desktop\dist\TriagerWeb\*" "%OUT_DIR%\web\" >nul

echo.
echo ============================================================
echo   Done
echo ============================================================
echo  - Triager CLI:  compiled_binaries\cli\Triager.exe
echo  - Triager Web:  compiled_binaries\web\TriagerWeb.exe
echo.

echo [*] Starting Triager Web from compiled_binaries\web ...
pushd "%OUT_DIR%\web"
start "Triager Web" "%OUT_DIR%\web\TriagerWeb.exe"
popd
exit /b 0


:ensure_python
where python >nul 2>nul
if not errorlevel 1 (
    call :python_version_ok
    if not errorlevel 1 exit /b 0
    echo [-] A python was found on PATH but is older than 3.10.
)

echo [*] Python not found ^(or too old^). Downloading the official installer...
set "PY_INSTALLER=%TEMP%\python-installer.exe"
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%PYTHON_INSTALLER_URL%' -OutFile '%PY_INSTALLER%' } catch { exit 1 }"
if not exist "%PY_INSTALLER%" (
    echo [-] Download failed. Check your internet connection.
    exit /b 1
)

echo [*] Running the Python installer ^(silent, current user^)...
"%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1
del "%PY_INSTALLER%" >nul 2>nul

for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do set "PY_SHORT=%%a%%b"
set "PATH=%LocalAppData%\Programs\Python\Python%PY_SHORT%;%LocalAppData%\Programs\Python\Python%PY_SHORT%\Scripts;%PATH%"

where python >nul 2>nul
if errorlevel 1 (
    echo [-] Still could not find python after installing it.
    echo [-] Close this window, open a new terminal ^(so PATH refreshes^), and re-run build_all.bat.
    exit /b 1
)
call :python_version_ok
if errorlevel 1 exit /b 1
exit /b 0


:python_version_ok
python -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)" 2>nul
exit /b %errorlevel%
