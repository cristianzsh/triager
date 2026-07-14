"""
Path resolution that works identically whether this app is run from source
(uvicorn app.main:app) or frozen into a single executable with PyInstaller. bundle_dir(): where read-only packaged resources live (the frontend's
    index.html/app.js/styles.css). PyInstaller --onefile extracts these into
    a temp directory (sys._MEIPASS) fresh on every launch, fine for files
    you only ever read. writable_data_dir(): where the app's persistent data lives (case
    databases, uploads, the app's own users/cases/jobs database). This must
    NOT be sys._MEIPASS, that directory is wiped and recreated every time
    a --onefile exe runs, so anything written there disappears when the app
    closes. Instead this resolves to a stable folder next to the executable
    (or the source tree, when not frozen), so an investigator's cases
    persist across restarts and are easy to find/back up.
"""
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


def writable_data_dir() -> Path:
    """Root for persistent data (storage/, the app's sqlite database)."""
    if is_frozen():
        data_dir = Path(sys.executable).resolve().parent / "data"
    else:
        data_dir = Path(__file__).resolve().parents[2]
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def tools_dir() -> Path:
    """
    Where Triager.exe (Windows-only) lives. This is a read-only bundled
    resource, not writable data, resolved via bundle_dir(), not
    writable_data_dir(), so a packaged build finds it next to the
    frozen app (--onedir) or in the temp extraction (--onefile), and a
    source checkout finds it at backend/tools/, matching the existing
    convention.
    """
    if is_frozen():
        return bundle_dir() / "tools"
    # backend/app/runtime_paths.py -> backend/tools
    return Path(__file__).resolve().parents[1] / "tools"
