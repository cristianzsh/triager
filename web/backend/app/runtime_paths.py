"""
Path resolution that works identically whether this app is run from source
(uvicorn app.main:app) or frozen into a single executable with PyInstaller. bundle_dir(): where read-only packaged resources live (the frontend's
    index.html/app.js/styles.css). PyInstaller --onefile extracts these into
    a temp directory (sys._MEIPASS) fresh on every launch, fine for files
    you only ever read. writable_data_dir(): where the app's persistent data lives (case
    databases, uploads, the app's own users/cases/jobs database). This must
    NOT be sys._MEIPASS, that directory is wiped and recreated every time
    a --onefile exe runs, so anything written there disappears when the app
    closes. Instead this resolves to %APPDATA%\\triager\\data (or the source
    tree, when not frozen) -- the same per-user location Triager's own
    tools/ gets extracted to on first run, so an investigator's cases
    persist across restarts, survive the exe being moved or rebuilt, and
    are easy to find/back up.
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
    Where Triager.exe's own forensic utilities live. Only used as a
    fallback path for a standalone web-only deployment (no merged
    Triager binary, no sibling triager.py checkout) -- see
    triager_runner.resolve_triager_command(). A normal merged-binary
    deployment extracts tools/ to appdata_root() / "tools" itself (see
    triager.py's _ensure_tools_dir()) and never touches this function.
    """
    if is_frozen():
        return bundle_dir() / "tools"
    # backend/app/runtime_paths.py -> repo root/tools
    return Path(__file__).resolve().parents[3] / "tools"
