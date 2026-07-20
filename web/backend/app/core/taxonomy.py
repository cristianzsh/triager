"""
Mirrors Triager's OUTPUT_SUBDIRS layout so the web UI's sidebar groups
artifacts the way the CLI tool's output folder already does.

Triager's top-level folders: Event logs, Evidence of execution, File
system artifacts, Meta, Persistence, Registry, User artifacts.

Each category maps to sub-folders of CSV output. The importer creates a
table "<subfolder>__<csv_stem>" per CSV and records its category here.
"""

CATEGORIES: dict[str, dict] = {
    "event_logs": {
        "label": "Event Logs",
        "folder": "Event logs",
        "subfolders": ["APT-Hunter", "Chainsaw", "EvtxECmd", "Hayabusa"],
    },
    "execution_evidence": {
        "label": "Evidence of Execution",
        "folder": "Evidence of execution",
        "subfolders": [
            "AmCache", "Prefetch", "SRUM", "WER", "WindowsDefenderDetection", "PCA",
        ],
    },
    "filesystem": {
        "label": "File System Artifacts",
        "folder": "File system artifacts",
        "subfolders": ["LogFile", "MFT", "RecycleBin", "USNJournal"],
    },
    "persistence": {
        "label": "Persistence",
        "folder": "Persistence",
        "subfolders": ["ScheduledTasks", "WMI"],
    },
    "registry": {
        "label": "Registry",
        "folder": "Registry",
        "subfolders": ["BamDam", "Shimcache", "USB"],
    },
    "user_artifacts": {
        "label": "User Artifacts",
        "folder": "User artifacts",
        "subfolders": [
            "BrowserHistory", "Certutil", "JumpLists", "MUICache", "NotepadFiles",
            "NTUSER_Artifacts", "PSReadLine", "RDPCache", "RecentLnk", "Shellbags",
            "Thumbnails", "UserAssist", "Win10Timelines",
        ],
    },
    "meta": {
        "label": "Case Meta / Host Profile",
        "folder": "Meta",
        "subfolders": [],
    },
}

# File extensions the importer will pull into SQLite tables.
IMPORTABLE_EXTENSIONS = {".csv"}

# Files/patterns to skip everywhere (logs, cmdlines, non-tabular noise).
SKIP_SUFFIXES = {".log", ".txt"}
SKIP_NAME_HINTS = ("stdout", "stderr", "cmdline")


def category_for_relpath(rel_path: str) -> str | None:
    """Given a path like 'Registry/Shimcache/Shimcache.csv', return category key."""
    parts = rel_path.replace("\\", "/").split("/")
    if not parts:
        return None
    top = parts[0]
    for key, meta in CATEGORIES.items():
        if meta["folder"].lower() == top.lower():
            return key
    return None
