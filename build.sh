#!/usr/bin/env bash

set -euo pipefail

# Configuration
SCRIPT="triager.py"
NAME="${SCRIPT%.*}"
BUILD_DIR="build"
LINUX_DIR="$BUILD_DIR/linux"
WIN_DIR="$BUILD_DIR/windows"
REQ="requirements.txt"

WINEPREFIX="$(pwd)/$BUILD_DIR/wine_prefix"
export WINEPREFIX
export WINEARCH=win64

# Windows Python installer version
PYTHON_VERSION="3.11.5"
PYTHON_INSTALLER_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-amd64.exe"

# Detect host package manager
if command -v apt-get &>/dev/null; then PKG_MANAGER="apt-get"
elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf"
else
  echo "Error: only tested on Debian/Ubuntu or Fedora." >&2
  exit 1
fi

# Sanity check
if [ ! -f "$REQ" ]; then
  echo "Error: $REQ not found in $(pwd)" >&2
  exit 1
fi

# Install host deps
if [ "$PKG_MANAGER" = "apt-get" ]; then
  sudo apt-get update
  sudo apt-get install -y \
    python3 python3-dev python3-pip wget \
    wine64 winetricks unzip zip
elif [ "$PKG_MANAGER" = "dnf" ]; then
  sudo dnf install -y \
    python3 python3-devel python3-pip wget \
    wine winetricks unzip zip
fi

# Prepare build dirs
rm -rf "$BUILD_DIR"
mkdir -p "$LINUX_DIR" "$WIN_DIR"

# Linux build
echo "[*] Installing Python deps for Linux build from $REQ…"
pip3 install --upgrade -r "$REQ" pyinstaller staticx

echo "[*] Running PyInstaller (onefile)…"
pyinstaller --clean --onefile \
            --name "$NAME" \
            --distpath "$LINUX_DIR" \
            --hidden-import=Registry \
            --collect-all=pyyaml \
            --collect-all=requests \
            --add-data "tools:tools" \
            --add-data "config.yml:." \
            "$SCRIPT"

staticx "$LINUX_DIR/$NAME" \
        "$LINUX_DIR/${NAME}-static"
chmod +x "$LINUX_DIR/${NAME}-static"

# Windows build under Wine
echo "[*] Initializing 64-bit Wine prefix…"
rm -rf "$WINEPREFIX"
wineboot --init

echo "[*] Downloading Windows Python ${PYTHON_VERSION} installer…"
wget -q --show-progress \
     "$PYTHON_INSTALLER_URL" \
     -O "$BUILD_DIR/python-installer.exe"

echo "[*] Installing Python into Wine…"
wine "$BUILD_DIR/python-installer.exe" \
     /quiet InstallAllUsers=1 PrependPath=1 TargetDir=C:\\Python /NoRestart

echo "[*] Installing Python deps inside Wine from $REQ…"
wine C:\\Python\\python.exe -m pip install --upgrade pip pyinstaller
wine C:\\Python\\python.exe -m pip install --upgrade -r "$(winepath -w "$PWD/$REQ")"

echo "[*] Building Windows EXE via PyInstaller…"
wine C:\\Python\\python.exe -m PyInstaller --clean --onefile \
     --name "${NAME}.exe" \
     --distpath "$WIN_DIR" \
     --hidden-import=Registry \
     --collect-all=pyyaml \
     --collect-all=requests \
     --add-data "tools;tools" \
     --add-data "config.yml;." \
     "$SCRIPT"

echo
echo "[*] Build complete!"
echo " - Statically-linked Linux ELF:   $LINUX_DIR/${NAME}-static"
echo " - Native Windows EXE via Wine:  $WIN_DIR/${NAME}.exe"
