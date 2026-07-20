"""
Path resolution that works identically whether this app runs from source
(uvicorn app.main:app) or frozen into a single PyInstaller executable.

bundle_dir(): read-only packaged resources (frontend's index.html/app.js/
styles.css). PyInstaller --onefile extracts these fresh to sys._MEIPASS
on every launch -- fine for files only ever read.

writable_data_dir(): persistent data (case databases, uploads, the app's
own db). Must NOT be sys._MEIPASS, which is wiped on every launch.
Resolves to %APPDATA%\\triager\\data instead (or the source tree when not
frozen) -- the same per-user location tools/ extracts to, so cases persist
across restarts and are easy to find/back up.
"""
import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path:
    """Root for bundled read-only resources (e.g. the frontend/ folder)."""
    if is_frozen():
        # PyInstaller sets sys._MEIPASS to the temp extraction root for
        # --onefile builds (and to the app folder itself for --onedir).
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    # Running from source: backend/app/runtime_paths.py -> repo root
    return Path(__file__).resolve().parents[2]


def appdata_root() -> Path:
    """%APPDATA%\\triager (or its equivalent) -- the shared per-user home
    for everything Triager persists outside the exe itself: this app's
    data (see writable_data_dir()) and Triager's own extracted tools/."""
    appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    return Path(appdata) / "triager"


def writable_data_dir() -> Path:
    """Root for persistent data (storage/, the app's sqlite database)."""
    if is_frozen():
        data_dir = appdata_root() / "data"
    else:
        data_dir = Path(__file__).resolve().parents[2]
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def tools_dir() -> Path:
    """
    Where Triager.exe's own forensic utilities live. Only a fallback for a
    standalone web-only deployment (see triager_runner.resolve_triager_command);
    a normal merged binary extracts tools/ itself via triager.py's
    _ensure_tools_dir() and never touches this.
    """
    if is_frozen():
        return bundle_dir() / "tools"
    # backend/app/runtime_paths.py -> repo root/tools
    return Path(__file__).resolve().parents[3] / "tools"
