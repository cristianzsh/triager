@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "PYTHON_VERSION=3.13.14"
set "PYTHON_INSTALLER_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-amd64.exe"
set "OUT_DIR=%ROOT%bin"
set "SCRIPT=%ROOT%triager.py"
set "NAME=Triager"
set "BUILD_DIR=%ROOT%build"
set "DIST_DIR=%BUILD_DIR%\windows"
set "REQ=%ROOT%requirements.txt"
set "WEB_BACKEND=%ROOT%web\backend"
set "WEB_FRONTEND=%ROOT%web\frontend"
set "VENV_DIR=%BUILD_DIR%\venv"
set "TOOLS_DIR=%ROOT%tools"

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

if not exist "%SCRIPT%" (
    echo [!] triager.py not found at %SCRIPT%
    exit /b 1
)

echo.
echo ============================================================
echo   Building Triager
echo ============================================================

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
    echo [!] requirements.txt not found -- installing known runtime deps directly.
    python -m pip install --upgrade pyyaml python-registry
    if exist "%WEB_BACKEND%\requirements.txt" python -m pip install --upgrade -r "%WEB_BACKEND%\requirements.txt"
)
python -m pip install --upgrade pyinstaller

echo [*] Running PyInstaller (onefile, CLI + web console in one binary)...

set "WEB_ARGS="
set "PATHS_ARG="
set "ADD_DATA="
if exist "%WEB_BACKEND%\app\main.py" (
    set "PATHS_ARG=--paths %WEB_BACKEND%"
    set "ADD_DATA=--add-data %WEB_FRONTEND%;frontend"
    set "WEB_ARGS=--hidden-import=uvicorn.logging --hidden-import=uvicorn.loops --hidden-import=uvicorn.loops.auto --hidden-import=uvicorn.protocols --hidden-import=uvicorn.protocols.http --hidden-import=uvicorn.protocols.http.auto --hidden-import=uvicorn.protocols.websockets --hidden-import=uvicorn.protocols.websockets.auto --hidden-import=uvicorn.lifespan --hidden-import=uvicorn.lifespan.on --hidden-import=app.main"
) else (
    echo [!] NOTE: web backend not found at %WEB_BACKEND% -- building CLI-only, --web won't work.
)

pyinstaller --clean --onefile ^
            --name "%NAME%" ^
            --distpath "%DIST_DIR%" ^
            --workpath "%BUILD_DIR%\pyinstaller" ^
            --specpath "%BUILD_DIR%" ^
            --noupx ^
            --hidden-import=Registry ^
            --collect-all=pyyaml ^
            --icon="%ROOT%triager.ico" ^
            %PATHS_ARG% ^
            %ADD_DATA% ^
            %WEB_ARGS% ^
            "%SCRIPT%"
set "BUILD_RESULT=%errorlevel%"

if not "%BUILD_RESULT%"=="0" (
    echo [!] Build failed.
    call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul
    exit /b 1
)

set "PACK_SCRIPT=%BUILD_DIR%\_pack_tools.py"
set "TOOLS_ZIP=%BUILD_DIR%\tools_bundle.zip"
(
    echo import zipfile, os, sys
    echo src = sys.argv[1]
    echo dest = sys.argv[2]
    echo zf = zipfile.ZipFile^(dest, "w", zipfile.ZIP_DEFLATED^)
    echo for root, dirs, files in os.walk^(src^):
    echo     for name in files:
    echo         full = os.path.join^(root, name^)
    echo         rel = os.path.relpath^(full, src^)
    echo         zf.write^(full, rel^)
    echo zf.close^(^)
) > "%PACK_SCRIPT%"

if not exist "%TOOLS_DIR%" goto :no_tools

echo [*] Packing tools\ and appending it to the exe for one-time first-run extraction...
python "%PACK_SCRIPT%" "%TOOLS_DIR%" "%TOOLS_ZIP%"
if not exist "%TOOLS_ZIP%" goto :pack_failed

copy /b "%DIST_DIR%\%NAME%.exe"+"%TOOLS_ZIP%" "%DIST_DIR%\%NAME%_with_tools.exe" >nul
if errorlevel 1 goto :append_failed

move /Y "%DIST_DIR%\%NAME%_with_tools.exe" "%DIST_DIR%\%NAME%.exe" >nul
del "%TOOLS_ZIP%" >nul 2>nul
goto :pack_done

:pack_failed
echo [!] Failed to pack tools\ -- shipping the exe without it.
goto :pack_done

:append_failed
echo [!] Failed to append tools\ to the exe -- shipping it without.
goto :pack_done

:no_tools
echo [!] NOTE: tools\ directory not found -- Triager.exe will have no
echo [!] forensic utilities available until rebuilt with a tools\ folder present.

:pack_done
del "%PACK_SCRIPT%" >nul 2>nul

call "%VENV_DIR%\Scripts\deactivate.bat" 2>nul

echo.
echo ============================================================
echo   Collecting output into bin\
echo ============================================================
if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

copy /Y "%DIST_DIR%\%NAME%.exe" "%OUT_DIR%\" >nul

echo.
echo ============================================================
echo   Done
echo ============================================================
echo  - Triager:  bin\Triager.exe
echo  - Forensic parsing:  Triager.exe --root ^<dir^> -o ^<output^>
echo  - Web console:       Triager.exe --web
echo.

echo [*] Starting Triager Web Console from bin ...
pushd "%OUT_DIR%"
start "Triager Web Console" "%OUT_DIR%\Triager.exe" --web
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
    echo [-] Close this window, open a new terminal ^(so PATH refreshes^), and re-run build.bat.
    exit /b 1
)
call :python_version_ok
if errorlevel 1 exit /b 1
exit /b 0


:python_version_ok
python -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)" 2>nul
exit /b %errorlevel%
