import sys
from pathlib import Path

block_cipher = None

_SPEC_DIR = Path(SPECPATH).resolve()
_REPO_ROOT = _SPEC_DIR.parent
_BACKEND_DIR = _REPO_ROOT / "backend"
_FRONTEND_DIR = _REPO_ROOT / "frontend"
_TOOLS_DIR = _BACKEND_DIR / "tools"

datas = [
    (str(_FRONTEND_DIR), "frontend"),
]

_triager_exe = _TOOLS_DIR / "Triager.exe"
if _triager_exe.exists():
    datas.append((str(_triager_exe), "tools"))
    print(f"[spec] Bundling Triager.exe ({_triager_exe.stat().st_size / 1_048_576:.1f} MB)")
else:
    print("[spec] NOTE: no Triager.exe found in backend/tools/ --")
    print("[spec] building a web-app-only package. See desktop/README.md.")

a = Analysis(
    [str(_SPEC_DIR / "launcher.py")],
    pathex=[str(_BACKEND_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TriagerWeb",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,  # keep the console window
    icon="triager.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="TriagerWeb",
)
