#!/usr/bin/env python3

"""
Triager: A script to automate forensic evidence processing and analysis.
by Cristian Souza (cristianmsbr@gmail.com / cristian.souza@kaspersky.com)
"""

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import traceback
import zipfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import xml.etree.ElementTree as ET
import hashlib

import yaml
from Registry import Registry

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

# Some types and constants
JSONDict = dict[str, Any]
PathMap = dict[str, Path]

PRINT_LOCK = threading.Lock()

def _enable_windows_vt_mode() -> bool:
    """
    Enable ANSI escape processing on Windows terminals (cmd.exe/PowerShell).
    Returns True if enabled (or already enabled), False otherwise.
    """
    if os.name != "nt":
        return True

    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        for handle_id in (-11, -12):
            h = kernel32.GetStdHandle(handle_id)
            if h in (None, 0, ctypes.c_void_p(-1).value):
                continue

            mode = wintypes.DWORD()
            if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                continue

            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            new_mode = mode.value | 0x0004
            if not kernel32.SetConsoleMode(h, new_mode):
                continue

        return True
    except Exception:
        return False


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False

    # If output is redirected to a file/pipe, avoid escape sequences
    if not sys.stdout.isatty():
        return False

    if os.name == "nt":
        return _enable_windows_vt_mode()

    return True


class C:
    RESET  = "\033[0m"
    INFO   = "\033[94m"  # blue
    SUCCESS= "\033[92m"  # green
    WARN   = "\033[93m"  # yellow
    ERROR  = "\033[91m"  # red
    STEP   = "\033[96m"  # cyan
    HEADER = "\033[95m"  # magenta
    DIM    = "\033[90m"  # gray

def _c(color: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{C.RESET}"

def log_info(msg: str):
    with PRINT_LOCK:
        print(_c(C.INFO, f"[INFO] {msg}"))

def log_step(msg: str):
    with PRINT_LOCK:
        print(_c(C.STEP, f"[+] {msg}"))

def log_success(msg: str):
    with PRINT_LOCK:
        print(_c(C.SUCCESS, f"[OK] {msg}"))

def log_warn(msg: str):
    with PRINT_LOCK:
        print(_c(C.WARN, f"[!] {msg}"), file=sys.stderr)

def log_error(msg: str):
    with PRINT_LOCK:
        print(_c(C.ERROR, f"[ERROR] {msg}"), file=sys.stderr)

def log_header(msg: str):
    with PRINT_LOCK:
        print(_c(C.HEADER, f"\n=== {msg} ==="))

def log_dim(msg: str):
    with PRINT_LOCK:
        print(_c(C.DIM, msg))


def get_runtime_base_dir() -> Path:
    """
    Returns the base directory where resources are located.
    """
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def resolve_default_config_path(default_name: str) -> Path:
    """
    Resolve default config.yml path.
    """
    # 1) PyInstaller bundled data
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = Path(meipass) / default_name
        if p.exists():
            return p.resolve()

    # 2) Current working directory
    p = Path.cwd() / default_name
    if p.exists():
        return p.resolve()

    return Path(default_name).resolve()

VERSION = "0.0.2"
USE_COLOR = _supports_color()

# Config file (contains paths for the forensic evidence files).
# You should adjust the contents of this file according to your needs.
DEFAULT_CONFIG_NAME = "config.yml"


VELOCIRAPTOR_CONFIG_YAML = r"""
root: "D:\\cases\\sample_001\\cape_triage"

# Core Windows paths (relative to triage root)
System32: "uploads\\auto\\C%3A\\Windows\\System32"
EventLogs: "uploads\\auto\\C%3A\\Windows\\System32\\winevt\\Logs"
ScheduledTasks: "uploads\\auto\\C%3A\\Windows\\System32\\Tasks"
Prefetch: "uploads\\auto\\C%3A\\Windows\\Prefetch"
AmCache: "uploads\\auto\\C%3A\\Windows\\AppCompat\\Programs\\Amcache.hve"
PCA: "uploads\\auto\\C%3A\\Windows\\AppCompat\\pca"
WER: "uploads\\auto\\C%3A\\ProgramData\\Microsoft\\Windows\\WER"
WindowsDefenderLogs: "uploads\\auto\\C%3A\\ProgramData\\Microsoft\\Windows Defender\\Support"
SRUM: "uploads\\auto\\C%3A\\Windows\\System32\\sru\\SRUDB.dat"
WMI: "uploads\\auto\\C%3A\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"

# If present in the triage (depends on how it was collected)
RecycleBin: "uploads\\auto\\C%3A\\$Recycle.Bin"
USNJournal: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$Extend\\$UsnJrnl%3A$J"
MFT: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$MFT"
LogFile: "uploads\\ntfs\\%5C%5C.%5CC%3A\\$LogFile"

# Users root in triage
Users: "uploads\\auto\\C%3A\\Users"

# Registry hives
RegistryHives:
  SYSTEM: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SYSTEM"
  SOFTWARE: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SOFTWARE"
  SAM: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SAM"
  SECURITY: "uploads\\auto\\C%3A\\Windows\\System32\\config\\SECURITY"
  DEFAULT: "uploads\\auto\\C%3A\\Windows\\System32\\config\\DEFAULT"

# Per-user hives patterns
UserHives:
  NTUSERGlob: "Users\\*\\NTUSER.DAT"
  USRCLASSGlob: "Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
"""

ARALEZ_CONFIG_YAML = r"""
root: "D:\\cases\\sample_001\\cape_triage"

# Core Windows paths (relative to triage root)
System32: "C\\Windows\\System32"
EventLogs: "C\\Windows\\System32\\winevt\\Logs"
ScheduledTasks: "C\\Windows\\System32\\Tasks"
Prefetch: "C\\Windows\\Prefetch"
AmCache: "C\\Windows\\AppCompat\\Programs\\Amcache.hve"
PCA: "C\\Windows\\AppCompat\\pca"
WER: "C\\ProgramData\\Microsoft\\Windows\\WER"
WindowsDefenderLogs: "C\\ProgramData\\Microsoft\\Windows Defender\\Support"
SRUM: "C\\Windows\\System32\\sru\\SRUDB.dat"
WMI: "C\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"

# If present in the triage (depends on how it was collected)
RecycleBin: "C\\$Recycle.Bin"
USNJournal: "C\\$Extend\\$UsnJrnl_$J"
MFT: "C\\$MFT"
LogFile: "C\\$LogFile"

# Users root in triage
Users: "C\\Users"

# Registry hives
RegistryHives:
  SYSTEM: "C\\Windows\\System32\\config\\SYSTEM"
  SOFTWARE: "C\\Windows\\System32\\config\\SOFTWARE"
  SAM: "C\\Windows\\System32\\config\\SAM"
  SECURITY: "C\\Windows\\System32\\config\\SECURITY"
  DEFAULT: "C\\Windows\\System32\\config\\DEFAULT"

# Per-user hives patterns
UserHives:
  NTUSERGlob: "Users\\*\\NTUSER.DAT"
  USRCLASSGlob: "Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
"""

# Maps --profile name -> embedded config YAML text. Used as the default
# config source when -c/--config isn't given.
CONFIG_PROFILES: dict[str, str] = {
    "velociraptor": VELOCIRAPTOR_CONFIG_YAML,
    "aralez": ARALEZ_CONFIG_YAML,
}
DEFAULT_CONFIG_PROFILE = "velociraptor"

# Contains tools used for processing some of the artifacts.
TOOLS_DIR = get_runtime_base_dir() / "tools"

# Keys from config.yml
ARTIFACT_KEYS = [
    "EventLogs",
    "ScheduledTasks",
    "Users",
    "Prefetch",
    "AmCache",
    "PCA",
    "RecycleBin",
    "USNJournal",
    "MFT",
    "LogFile",
    "WMI",
    "WER",
    "WindowsDefenderLogs",
    "SRUM",
    "System32",
]

# Output structure
OUTPUT_SUBDIRS: dict[str, str] = {
    "Prefetch": "Evidence of execution",
    "SRUM": "Evidence of execution",
    "AmCache": "Evidence of execution",
    "WER": "Evidence of execution",
    "WindowsDefenderLogs": "Evidence of execution",
    "PCA": "Evidence of execution",
    "ScheduledTasks": "Persistence",
    "WMI": "Persistence",
    "RecycleBin": "File system artifacts",
    "USNJournal": "File system artifacts",
    "MFT": "File system artifacts",
    "LogFile": "File system artifacts",
    "Users": "User artifacts",
    "Registry": "Registry",
    "EventLogs": "Event logs",
    "Meta": "Meta",
}

def get_tool(*parts: str) -> Path:
    """Build an absolute path under ./tools relative to this script file."""
    return TOOLS_DIR.joinpath(*parts)


@dataclass
class HostProfile:
    computer_name: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    operating_system: str = ""
    timezone: str = ""
    os_install_date: str = ""
    installed_software: list[dict[str, Any]] = field(default_factory=list)
    autorun: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


# General helpers
def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def ensure_exists(path: Path, what: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{what} not found: {path}")


def read_text_best_effort(
    path: Path,
    encodings: tuple[str, ...] = ("utf-16", "utf-8", "utf-16-le", "utf-16-be", "latin-1"),
) -> str | None:
    for enc in encodings:
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def run_cmd(
    cmd: list[str],
    stdout_path: Path,
    stderr_path: Path,
    check: bool = False,
    cwd: Path | None = None,
) -> int:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    # Persist exact command line for reproducibility
    try:
        cmdline_path = stdout_path.parent / f"{stdout_path.stem}_cmdline.txt"
        cmdline_path.write_text(" ".join(cmd), encoding="utf-8")
    except Exception:
        pass

    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        try:
            p = subprocess.run(cmd, stdout=out, stderr=err, check=False, cwd=str(cwd) if cwd else None)
        except FileNotFoundError as ex:
            raise FileNotFoundError(f"Tool executable not found: {cmd[0]}") from ex
        if check and p.returncode != 0:
            raise subprocess.CalledProcessError(p.returncode, cmd)
        return p.returncode


# Config
def load_yaml_config(path: Path) -> JSONDict:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if yaml is None:
        raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config.yml must be a mapping (dict).")
    return data


def load_yaml_config_from_text(text: str) -> JSONDict:
    """Same as load_yaml_config, but for an embedded config profile's YAML
    text rather than a file on disk."""
    if yaml is None:
        raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")

    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Config profile must be a mapping (dict).")
    return data


def _set_nested(cfg: JSONDict, dotted_key: str, value: str) -> None:
    """
    Backward compatible: supports: a=b a.b=c a.b.c=d
    """
    parts = [p.strip() for p in dotted_key.split(".") if p.strip()]
    if not parts:
        return

    cur: Any = cfg
    for i, key in enumerate(parts):
        if i == len(parts) - 1:
            if isinstance(cur, dict):
                cur[key] = value
            return

        if not isinstance(cur, dict):
            return

        if key not in cur or not isinstance(cur[key], dict):
            cur[key] = {}
        cur = cur[key]


def apply_overrides(cfg: JSONDict, args: argparse.Namespace) -> JSONDict:
    new_cfg = dict(cfg)
    if args.root:
        new_cfg["root"] = args.root

    #if args.set:
    #    for kv in args.set:
    #        if "=" not in kv:
    #            raise ValueError(f"Invalid --set value (expected key=value): {kv}")
    #        k, v = kv.split("=", 1)
    #        _set_nested(new_cfg, k.strip(), v.strip())

    return new_cfg


def build_paths(cfg: JSONDict) -> JSONDict:
    """
    Resolve triage-root-relative paths into absolute Paths.
    """
    root = Path(str(cfg.get("root", ""))).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Triage root does not exist: {root}")

    artifact_paths: PathMap = {}
    for key in ARTIFACT_KEYS:
        rel = cfg.get(key)
        if rel:
            artifact_paths[key] = (root / str(rel)).resolve()

    reg = cfg.get("RegistryHives", {}) or {}
    if not isinstance(reg, dict):
        raise ValueError("RegistryHives must be a mapping/dict in config.yml")

    hive_paths: PathMap = {}
    for hive_name, rel in reg.items():
        hive_paths[hive_name] = (root / str(rel)).resolve()

    user_hive_globs = cfg.get("user_hives", {}) or {}
    if not isinstance(user_hive_globs, dict):
        raise ValueError("user_hives must be a mapping/dict in config.yml")

    return {
        "root": root,
        "artifact_paths": artifact_paths,
        "hive_paths": hive_paths,
        "user_hive_globs": user_hive_globs,
    }


def create_main_dir(output_dir: Path) -> dict[str, Path]:
    if output_dir.exists():
        log_error(f"Output directory already exists: {output_dir}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=False)

    # Create unique folders once (multiple keys map to same folder)
    for folder in set(OUTPUT_SUBDIRS.values()):
        (output_dir / folder).mkdir(parents=True, exist_ok=True)

    outdirs: dict[str, Path] = {}
    for k, folder in OUTPUT_SUBDIRS.items():
        outdirs[k] = (output_dir / folder).resolve()

    return outdirs


def _win_long_path(p: Path) -> str:
    """
    On Windows, prefix with \\\\?\\ to opt into the extended-length path
    convention (bypasses the classic 260-character MAX_PATH limit). This
    matters here because Triager's own output tree is often deeply nested
    (user profile artifacts, JumpLists, EvtxECmd filenames, merged .lnk
    CSVs, ...) and can easily exceed 260 characters once combined with a
    long case/output directory name. No-op on other platforms.
    """
    if os.name != "nt":
        return str(p)
    s = str(p)
    if s.startswith("\\\\?\\"):
        return s
    return "\\\\?\\" + s


def compress_output_directory(output_dir: Path) -> Path | None:
    """
    Zips the whole processing results folder into a sibling
    "<output_dir_name>.zip".
    """
    HEARTBEAT_SECONDS = 15
    LARGE_FILE_NOTICE_BYTES = 100 * 1024 * 1024  # 100 MB

    try:
        output_dir = output_dir.resolve()
        if not output_dir.exists():
            log_error(f"Compress: directory does not exist: {output_dir}")
            return None

        zip_path = output_dir.parent / f"{output_dir.name}.zip"

        if zip_path.exists():
            log_warn(f"Compress: target already exists, overwriting: {zip_path}")
            try:
                zip_path.unlink()
            except Exception as ex:
                log_error(f"Compress: could not remove existing archive {zip_path}: {ex}")
                return None

        log_info("Compress: scanning files to archive...")
        all_files = [p for p in sorted(output_dir.rglob("*")) if p.is_file()]
        total_bytes = 0
        for p in all_files:
            try:
                total_bytes += p.stat().st_size
            except Exception:
                pass
        log_info(
            f"Compress: {len(all_files)} file(s), {total_bytes / (1024 * 1024):.1f} MB total -- "
            f"this can take a while for large evidence sets, progress below."
        )

        file_count = 0
        skipped = 0
        bytes_done = 0
        last_heartbeat = time.time()

        with zipfile.ZipFile(_win_long_path(zip_path), "w", zipfile.ZIP_DEFLATED, allowZip64=True, compresslevel=1) as zf:
            for path in all_files:
                try:
                    arcname = Path(output_dir.name) / path.relative_to(output_dir)
                    size = 0
                    try:
                        size = path.stat().st_size
                    except Exception:
                        pass

                    if size >= LARGE_FILE_NOTICE_BYTES:
                        log_info(f"Compress: compressing large file ({size / (1024 * 1024):.1f} MB): {arcname}")

                    zf.write(_win_long_path(path), arcname)
                    file_count += 1
                    bytes_done += size

                    now = time.time()
                    if now - last_heartbeat >= HEARTBEAT_SECONDS:
                        pct = (bytes_done / total_bytes * 100) if total_bytes else 0
                        log_info(
                            f"Compress: still working... {file_count}/{len(all_files)} file(s), "
                            f"~{pct:.0f}% by size"
                        )
                        last_heartbeat = now
                except Exception as ex:
                    skipped += 1
                    log_warn(f"Compress: skipped '{path}': {ex}")
                    continue

        if skipped:
            log_warn(f"Compress: {skipped} file(s) skipped -- see warnings above.")
        log_success(f"Compressed output directory ({file_count} file(s)) -> {zip_path}")
        return zip_path
    except Exception as ex:
        log_error(f"Compress: failed to create archive: {ex}")
        return None


def _xml_find_text(root: ET.Element, xpath: str, ns: dict[str, str]) -> str:
    el = root.find(xpath, ns)
    return (el.text or "").strip() if el is not None and el.text else ""


def _safe_read_task_xml(path: Path) -> ET.Element | None:
    data = read_text_best_effort(path, ("utf-16", "utf-8", "utf-16-le", "utf-16-be"))

    if data is None:
        return None

    try:
        return ET.fromstring(data)
    except Exception:
        return None


def get_available_users(users_dir: Path) -> list[str]:
    try:
        return sorted(p.name for p in users_dir.iterdir() if p.is_dir())
    except FileNotFoundError:
        return []


def _ntuser_path_for_user(users_dir: Path, user: str) -> Path:
    return users_dir / user / "NTUSER.DAT"


def _bytes_to_text_or_hex(b: Any) -> str:
    if b is None:
        return ""

    if isinstance(b, list):
        return "; ".join(_bytes_to_text_or_hex(x) for x in b)

    if isinstance(b, (bytes, bytearray)):
        bb = bytes(b)
        for enc in ("utf-16-le", "utf-8", "latin-1"):
            try:
                s = bb.decode(enc, errors="strict").rstrip("\x00")
                if s:
                    return s
            except Exception:
                pass
        return bb.hex()

    return str(b)


def _decode_mru_listex(raw: Any) -> list[int]:
    if not isinstance(raw, (bytes, bytearray)):
        return []

    b = bytes(raw)
    out: list[int] = []

    for i in range(0, len(b), 4):
        if i + 4 > len(b):
            break

        n = int.from_bytes(b[i : i + 4], "little", signed=False)
        if n == 0xFFFFFFFF:
            break

        out.append(n)

    return out


def _get_key_values_map(hive, key_path: str) -> dict[str, Any]:
    vals = reg_list_values(hive, key_path)
    return {name: val for name, val in vals if name is not None}


def _safe_open_ntuser(ntuser_path: Path):
    try:
        return hive_open(ntuser_path)
    except Exception:
        return None


def _write_rows_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def _wer_filetime_to_iso(event_time_str: str) -> str:
    try:
        unix = (int(event_time_str) - 116444736000000000) / 10_000_000
        return dt.datetime.fromtimestamp(unix, tz=dt.timezone.utc).isoformat()
    except Exception:
        return ""


def _parse_wer_kv(path: Path) -> dict[str, str]:
    txt = read_text_best_effort(path, ("utf-16", "utf-8", "utf-16-le", "latin-1"))
    if txt is None:
        return {}

    out: dict[str, str] = {}
    for line in txt.splitlines():
        line = line.strip()

        if not line or "=" not in line:
            continue

        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


# Registry helpers
def require_python_registry():
    if Registry is None:
        raise RuntimeError("python-registry not installed. Install with: pip install python-registry")


def hive_open(path: Path):
    require_python_registry()
    if not path.exists():
        raise FileNotFoundError(f"Registry hive not found: {path}")

    return Registry.Registry(str(path))


def _norm_reg_value(v: Any) -> Any:
    """
    Normalize python-registry value data.
    """
    if v is None:
        return None

    if isinstance(v, (bytes, bytearray)):
        b = bytes(v)
        for enc in ("utf-16-le", "utf-8", "latin-1"):
            try:
                s = b.decode(enc, errors="strict")
                return s.rstrip("\x00")
            except Exception:
                pass
        return repr(b)

    if isinstance(v, (list, tuple)):
        return [_norm_reg_value(x) for x in v]

    return v


def _open_key(hive, key_path: str):
    return hive.open(key_path.strip("\\"))


def reg_get_value(hive, key_path: str, value_name: str) -> Any | None:
    try:
        k = _open_key(hive, key_path)
        v = k.value(value_name)
        return _norm_reg_value(v.value())
    except Exception:
        return None


def reg_list_values(hive, key_path: str) -> list[tuple[str, Any]]:
    try:
        k = _open_key(hive, key_path)
        out: list[tuple[str, Any]] = []
        for v in k.values():
            out.append((v.name(), _norm_reg_value(v.value())))
        return out
    except Exception:
        return []


def reg_list_subkeys(hive, key_path: str) -> list[str]:
    try:
        k = _open_key(hive, key_path)
        return [sk.name() for sk in k.subkeys()]
    except Exception:
        return []


def system_current_control_set(system_hive) -> str:
    cur = reg_get_value(system_hive, r"Select", "Current")
    if cur is None:
        return "ControlSet001"

    try:
        return f"ControlSet{int(cur):03d}"
    except Exception:
        return "ControlSet001"


def filetime_unix_to_iso(ts: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ts), dt.UTC).isoformat()
    except Exception:
        return ""


# Host info collection from triage registry
def _resolve_user_hive_matches(
    triage_root: Path,
    users_dir: Path | None,
    pattern: str,
) -> list[Path]:
    """
    Backward-compatible resolver for user hive globs.
    """
    matches = sorted(triage_root.glob(pattern))
    if matches:
        return matches

    if users_dir is None:
        return []

    # Try pattern under users_dir directly
    matches2 = sorted(users_dir.glob(pattern))
    if matches2:
        return matches2

    p = pattern.replace("/", "\\")
    if p.lower().startswith("users\\"):
        stripped = p[6:]
        matches3 = sorted(users_dir.glob(stripped))
        return matches3

    return []


def collect_host_info_from_triage(
    hive_paths: PathMap,
    triage_root: Path,
    out_meta: Path,
    user_hive_globs: dict[str, str],
    artifact_paths: PathMap,
) -> HostProfile:
    system_path = hive_paths.get("SYSTEM")
    software_path = hive_paths.get("SOFTWARE")

    if not system_path or not software_path:
        raise ValueError("RegistryHives.SYSTEM and RegistryHives.SOFTWARE are required in config.yml")

    system = hive_open(system_path)
    software = hive_open(software_path)

    ccs = system_current_control_set(system)

    hp = HostProfile()

    # COMPUTER_NAME
    hp.computer_name = (
        reg_get_value(system, rf"{ccs}\Control\ComputerName\ComputerName", "ComputerName") or ""
    )
    log_info(f"===> COMPUTER_NAME={hp.computer_name}")

    # TIMEZONE
    hp.timezone = (
        reg_get_value(system, rf"{ccs}\Control\TimeZoneInformation", "TimeZoneKeyName")
        or reg_get_value(system, rf"{ccs}\Control\TimeZoneInformation", "StandardName")
        or ""
    )

    # OS info + install date
    product = reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "ProductName") or ""
    build = reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "CurrentBuild") or ""
    dispver = (
        reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "DisplayVersion")
        or reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "ReleaseId")
        or ""
    )
    edition = reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "EditionID") or ""
    hp.operating_system = " ".join([x for x in [product, edition, dispver, f"Build {build}".strip()] if x]).strip()

    install_date = reg_get_value(software, r"Microsoft\Windows NT\CurrentVersion", "InstallDate")
    hp.os_install_date = filetime_unix_to_iso(install_date)

    # IP addresses (best-effort)
    iface_root = rf"{ccs}\Services\Tcpip\Parameters\Interfaces"
    ips: list[str] = []
    for guid in reg_list_subkeys(system, iface_root):
        key = rf"{iface_root}\{guid}"

        dhcp_ip = reg_get_value(system, key, "DhcpIPAddress")
        static_ip = reg_get_value(system, key, "IPAddress")

        if dhcp_ip and str(dhcp_ip) not in ("0.0.0.0", ""):
            ips.append(str(dhcp_ip))

        if isinstance(static_ip, list):
            for ip in static_ip:
                if ip and str(ip) not in ("0.0.0.0", ""):
                    ips.append(str(ip))
        elif static_ip:
            if str(static_ip) not in ("0.0.0.0", ""):
                ips.append(str(static_ip))

    hp.ip_addresses = sorted(set(ips))

    # Installed software (HKLM)
    uninstall_paths = [
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    installed: list[dict[str, Any]] = []
    for up in uninstall_paths:
        base = rf"{up}"
        for sub in reg_list_subkeys(software, base):
            kp = rf"{base}\{sub}"
            name = reg_get_value(software, kp, "DisplayName")
            if not name:
                continue
            installed.append(
                {
                    "name": str(name),
                    "version": reg_get_value(software, kp, "DisplayVersion"),
                    "publisher": reg_get_value(software, kp, "Publisher"),
                    "install_date": reg_get_value(software, kp, "InstallDate"),
                }
            )
    hp.installed_software = installed

    # Autoruns (HKLM)
    autoruns: list[dict[str, Any]] = []
    run_keys = [
        (software, r"Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
        (software, r"Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
        (software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run (Wow6432Node)"),
        (software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce (Wow6432Node)"),
    ]
    for hive, key_path, location in run_keys:
        for name, value in reg_list_values(hive, key_path):
            if name:
                autoruns.append({"location": location, "name": name, "command": value})

    # Autoruns (HKCU)
    ntuser_glob = user_hive_globs.get("NTUSERGlob")
    users_dir = artifact_paths.get("Users")
    if ntuser_glob:
        for ntuser_path in _resolve_user_hive_matches(triage_root, users_dir, ntuser_glob):
            user = ntuser_path.parent.name
            try:
                nt = hive_open(ntuser_path)
                for key_path, location in [
                    (r"Software\Microsoft\Windows\CurrentVersion\Run", f"HKCU({user})\\...\\Run"),
                    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", f"HKCU({user})\\...\\RunOnce"),
                ]:
                    for name, value in reg_list_values(nt, key_path):
                        if name:
                            autoruns.append({"location": location, "name": name, "command": value})
            except Exception as ex:
                log_error(f"HKCU autoruns failed for {user}: {ex}")

    hp.autorun = autoruns

    # Summary
    if hp.computer_name and hp.ip_addresses:
        hp.summary = f"{hp.computer_name} ({', '.join(hp.ip_addresses)})"
    elif hp.computer_name:
        hp.summary = hp.computer_name

    # Save host profile to meta
    host_profile = {
        "COMPUTER_NAME": hp.computer_name,
        "IP_ADDRESSES": hp.ip_addresses,
        "OPERATING_SYSTEM": hp.operating_system,
        "TIMEZONE": hp.timezone,
        "OS_INSTALL_DATE": hp.os_install_date,
        "INSTALLED_SOFTWARE_COUNT": len(hp.installed_software),
        "AUTORUN_COUNT": len(hp.autorun),
    }
    write_json(out_meta / "host_profile.json", host_profile)
    write_json(out_meta / "installed_software.json", hp.installed_software)
    write_json(out_meta / "autoruns.json", hp.autorun)

    return hp


# Evidence of execution parsers
def parse_amcache(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    src = artifact_paths.get("AmCache")
    if not src:
        log_warn("AmCache missing in config; skipping.")
        return
    ensure_exists(src, "Amcache hive")

    base_out = outdirs["AmCache"] / "AmCache"
    base_out.mkdir(exist_ok=True)

    out1 = base_out / "AmcacheParser"
    out1.mkdir(exist_ok=True)
    cmd1 = [str(get_tool("AmcacheParser.exe")), "-f", str(src), "--csv", str(out1)]
    run_cmd(cmd1, out1 / "stdout.log", out1 / "stderr.log", check=False)

    out2 = base_out / "AmCache-EvilHunter"
    out2.mkdir(exist_ok=True)
    cmd2 = [str(get_tool("amcache-evilhunter.exe")), "-i", str(src), "--csv", "{}/amcache_entries.csv".format(str(out2))]
    run_cmd(cmd2, out2 / "stdout.log", out2 / "stderr.log", check=False)

    log_success(f"Amcache parsed -> {base_out}")


def parse_defender_logs(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    logs_dir = artifact_paths.get("WindowsDefenderLogs")
    if logs_dir is None or not Path(logs_dir).exists():
        log_warn("WindowsDefenderLogs: WindowsDefenderLogs path not resolved; skipping.")
        return

    logs_dir = Path(logs_dir)
    mp_logs = sorted(logs_dir.glob("MPDetection-*.log"))
    if not mp_logs:
        log_warn("WindowsDefenderLogs: no MPDetection-*.log files found.")
        return

    out_dir = outdirs["WindowsDefenderLogs"] / "WindowsDefenderDetection"
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / "MP_Detection.csv"

    total = 0
    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=["Timestamp", "Verdict", "Message", "SourceLog"])
        writer.writeheader()

        for log_file in mp_logs:
            try:
                with log_file.open("r", encoding="utf-16le", errors="ignore") as f:
                    for raw_line in f:
                        if "DETECTION" not in raw_line:
                            continue
                        line = raw_line.rstrip("\r\n")
                        parts = line.split(maxsplit=3)
                        if len(parts) < 3:
                            continue
                        timestamp, keyword, verdict = parts[0], parts[1], parts[2]
                        message = parts[3].strip() if len(parts) == 4 else ""
                        if keyword != "DETECTION":
                            continue
                        writer.writerow(
                            {"Timestamp": timestamp, "Verdict": verdict, "Message": message, "SourceLog": log_file.name}
                        )
                        total += 1
            except UnicodeError:
                try:
                    with log_file.open("r", encoding="latin-1", errors="ignore") as f:
                        for raw_line in f:
                            if "DETECTION" not in raw_line:
                                continue
                            line = raw_line.rstrip("\r\n")
                            parts = line.split(maxsplit=3)
                            if len(parts) < 3:
                                continue
                            timestamp, keyword, verdict = parts[0], parts[1], parts[2]
                            message = parts[3].strip() if len(parts) == 4 else ""
                            if keyword != "DETECTION":
                                continue
                            writer.writerow(
                                {"Timestamp": timestamp, "Verdict": verdict, "Message": message, "SourceLog": log_file.name}
                            )
                            total += 1
                except Exception as ex:
                    log_error(f"WindowsDefenderLogs: fallback read error {log_file.name}: {ex}")
            except Exception as ex:
                log_error(f"WindowsDefenderLogs: error parsing {log_file.name}: {ex}")

    if total == 0:
        log_warn("WindowsDefenderLogs: no DETECTION entries parsed.")
    else:
        log_success(f"Defender MPDetection parsed ({total} detections) -> {out_csv}")


def parse_pca(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    pca_dir = artifact_paths.get("PCA")
    if not pca_dir or not pca_dir.exists():
        log_warn("PCA: directory not found; skipping.")
        return

    out_dir = outdirs["PCA"] / "PCA"
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / "PCA.csv"

    rows: list[dict[str, str]] = []

    def open_lines(path: Path, encoding: str) -> list[str]:
        return path.read_text(encoding=encoding, errors="replace").splitlines()

    def resolve_file(name: str) -> Path | None:
        p = pca_dir / name
        if p.exists():
            return p
        lname = name.lower()
        for f in pca_dir.iterdir():
            if f.is_file() and f.name.lower() == lname:
                return f
        return None

    launch_file = resolve_file("PcaAppLaunchDic.txt")
    if launch_file:
        for line in open_lines(launch_file, "cp1252"):
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) != 2:
                continue
            exe, date = parts
            rows.append(
                {
                    "Date": date.strip(),
                    "RecordType": "AppLaunch",
                    "ExecutableFile": exe.strip(),
                    "ProductName": "",
                    "CompanyName": "",
                    "ProductVersion": "",
                    "WindowsApplicationID": "",
                    "Message": "",
                }
            )

    for fname in ("PcaGeneralDb0.txt", "PcaGeneralDb1.txt"):
        fpath = resolve_file(fname)
        if not fpath:
            continue
        for line in open_lines(fpath, "utf-16-le"):
            if not line.strip():
                continue
            parts = line.split("|", 7)
            if len(parts) < 3:
                continue
            rows.append(
                {
                    "Date": parts[0].strip(),
                    "RecordType": parts[1].strip(),
                    "ExecutableFile": parts[2].strip(),
                    "ProductName": parts[3].strip() if len(parts) > 3 else "",
                    "CompanyName": parts[4].strip() if len(parts) > 4 else "",
                    "ProductVersion": parts[5].strip() if len(parts) > 5 else "",
                    "WindowsApplicationID": parts[6].strip() if len(parts) > 6 else "",
                    "Message": parts[7].strip() if len(parts) > 7 else "",
                }
            )

    fieldnames = [
        "Date",
        "RecordType",
        "ExecutableFile",
        "ProductName",
        "CompanyName",
        "ProductVersion",
        "WindowsApplicationID",
        "Message",
    ]

    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    log_success(f"PCA parsed: {len(rows)} rows -> {out_csv}")


def parse_prefetch(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    src_dir = artifact_paths.get("Prefetch")
    if not src_dir:
        log_warn("Prefetch missing in config; skipping.")
        return
    ensure_exists(src_dir, "Prefetch directory")

    tool_out = outdirs["Prefetch"] / "Prefetch"
    tool_out.mkdir(exist_ok=True)

    cmd = [str(get_tool("PECmd.exe")), "-d", str(src_dir), "--csv", str(tool_out)]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"Prefetch parsed -> {tool_out}")


def parse_srum(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    src = artifact_paths.get("SRUM")
    if not src:
        log_warn("SRUM missing in config; skipping.")
        return
    ensure_exists(src, "SRUDB.dat")

    base_dir = outdirs["SRUM"] / "SRUM"
    base_dir.mkdir(exist_ok=True)

    #out1 = base_dir / "SRUM-DUMP"
    #out1.mkdir(exist_ok=True)
    #cmd1 = [str(get_tool("srum-dump.exe")),
    #        "-i",
    #        str(src),
    #        "-o",
    #        str(out1),
    #        "-f",
    #        "csv",
    #        "-q"]
    #run_cmd(cmd1, out1 / "stdout.log", out1 / "stderr.log", check=False)

    out2 = base_dir / "SrumECmd"
    out2.mkdir(exist_ok=True)
    cmd2 = [str(get_tool("SrumECmd.exe")), "-f", str(src), "--csv", str(out2)]
    run_cmd(cmd2, out2 / "stdout.log", out2 / "stderr.log", check=False)
    log_success(f"SRUM parsed -> {base_dir}")


def parse_wer(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    wer_root = artifact_paths.get("WER")
    if wer_root is None:
        log_warn("WER: WER path not resolved; skipping.")
        return
    if not wer_root.exists():
        log_warn(f"WER: WER directory not found: {wer_root}")
        return

    report_archive = wer_root / "ReportArchive"
    if not report_archive.exists():
        if wer_root.name.lower() == "reportarchive":
            report_archive = wer_root
        else:
            log_warn(f"WER: ReportArchive not found under: {wer_root}")
            return

    out_dir = outdirs["WER"] / "WER"
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / "WER_Report.csv"

    rows: list[dict[str, str]] = []
    for wer_file in sorted(report_archive.rglob("Report.wer")):
        kv = _parse_wer_kv(wer_file)
        if not kv:
            continue

        event_time_raw = kv.get("EventTime", "")
        event_time_iso = _wer_filetime_to_iso(event_time_raw) if event_time_raw else ""

        ns_app = kv.get("NsAppName", "")
        if not ns_app:
            for i in range(0, 32):
                n = kv.get(f"Sig[{i}].Name", "")
                if n == "ApplicationName":
                    ns_app = kv.get(f"Sig[{i}].Value", "")
                    break

        rows.append(
            {
                "EventTime": event_time_iso or event_time_raw,
                "NsAppName": ns_app,
                "OriginalFilename": kv.get("OriginalFilename", ""),
                "AppName": kv.get("AppName", ""),
                "AppPath": kv.get("AppPath", ""),
            }
        )

    fieldnames = ["EventTime", "NsAppName", "OriginalFilename", "AppName", "AppPath"]
    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    log_success(f"WER parsed: {len(rows)} -> {out_csv}")


# Persistence parsers
def parse_scheduled_tasks(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    tasks_dir = artifact_paths.get("ScheduledTasks")
    if not tasks_dir:
        log_warn("ScheduledTasks missing in config; skipping.")
        return
    ensure_exists(tasks_dir, "Scheduled Tasks directory")

    out_dir = outdirs["ScheduledTasks"] / "ScheduledTasks"
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / "ScheduledTasks.csv"

    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    rows: list[dict[str, str]] = []

    for f in sorted(tasks_dir.rglob("*")):
        if f.is_dir():
            continue

        root = _safe_read_task_xml(f)
        if root is None:
            continue

        description = _xml_find_text(root, ".//t:RegistrationInfo/t:Description", ns)
        uri = _xml_find_text(root, ".//t:RegistrationInfo/t:URI", ns)

        start_boundaries: list[str] = []
        for sb in root.findall(".//t:Triggers//t:StartBoundary", ns):
            if sb is not None and sb.text:
                start_boundaries.append(sb.text.strip())
        startboundary = min(start_boundaries) if start_boundaries else ""

        userid = _xml_find_text(root, ".//t:Principals//t:Principal/t:UserId", ns)
        runlevel = _xml_find_text(root, ".//t:Principals//t:Principal/t:RunLevel", ns)
        enabled = _xml_find_text(root, ".//t:Settings/t:Enabled", ns)

        command = _xml_find_text(root, ".//t:Actions//t:Exec/t:Command", ns)
        arguments = _xml_find_text(root, ".//t:Actions//t:Exec/t:Arguments", ns)

        rows.append(
            {
                "FileName": str(f.relative_to(tasks_dir)).replace("\\", "/"),
                "URI": uri,
                "Description": description,
                "StartBoundary": startboundary,
                "UserID": userid,
                "RunLevel": runlevel,
                "Enabled": enabled,
                "Command": command,
                "Arguments": arguments,
            }
        )

    fieldnames = ["FileName", "URI", "Description", "StartBoundary", "UserID", "RunLevel", "Enabled", "Command", "Arguments"]
    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        w = csv.DictWriter(fp, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    log_success(f"Scheduled tasks parsed: {len(rows)} -> {out_csv}")


def parse_wmi(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    wmi_objects = artifact_paths.get("WMI")
    if wmi_objects is None:
        log_warn("WMI: OBJECTS.DATA path not resolved; skipping.")
        return
    if not wmi_objects.exists():
        log_warn(f"WMI: OBJECTS.DATA not found: {wmi_objects}")
        return

    out_dir = outdirs["WMI"] / "WMI"
    out_dir.mkdir(exist_ok=True)

    exe = get_tool("PyWMIPersistenceFinder.exe")
    if not exe.exists():
        log_error(f"WMI: PyWMIPersistenceFinder.exe not found at: {exe}")
        return

    stdout_path = out_dir / "stdout.txt"
    stderr_path = out_dir / "stderr.txt"
    result_path = out_dir / "result.txt"

    cmd = [str(exe), str(wmi_objects)]
    run_cmd(cmd, stdout_path, stderr_path, check=False)

    with result_path.open("w", encoding="utf-8", errors="replace") as out:
        if stdout_path.exists():
            out.write("=== STDOUT ===\n")
            out.write(stdout_path.read_text(encoding="utf-8", errors="replace"))
            out.write("\n\n")
        if stderr_path.exists():
            out.write("=== STDERR ===\n")
            out.write(stderr_path.read_text(encoding="utf-8", errors="replace"))

    log_success(f"WMI persistence parsed -> {out_dir}")


# Registry parsers
def parse_bam_dam(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    system32 = artifact_paths.get("System32")
    if not system32 or not Path(system32).exists():
        log_warn("BAM/DAM: SYSTEM32 path not resolved; skipping.")
        return

    system_hive = (Path(system32) / "config" / "SYSTEM").resolve()
    if not system_hive.exists():
        log_warn(f"BAM/DAM: SYSTEM hive not found: {system_hive}")
        return

    system = hive_open(system_hive)
    ccs = system_current_control_set(system)

    def filetime_to_utc(ft_bytes: bytes) -> str:
        try:
            ft = int.from_bytes(ft_bytes[0:8], "little")
            unix_ts = (ft - 116444736000000000) / 1e7
            dtx = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            return dtx.isoformat()
        except Exception:
            return ""

    out_dir = outdirs["Registry"] / "BamDam"
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / "BamDamExecution.csv"

    with out_csv.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=["UserSID", "ArtifactType", "ExePath", "LastExecutionUTC"])
        writer.writeheader()

        for name, base_key in [("bam", "bam"), ("dam", "dam")]:
            root1 = rf"{ccs}\Services\{base_key}\state\UserSettings"
            root2 = rf"{ccs}\Services\{base_key}\UserSettings"

            for root in (root1, root2):
                for sid in reg_list_subkeys(system, root):
                    if not sid:
                        continue
                    key_path = rf"{root}\{sid}"
                    for val_name, val_data in reg_list_values(system, key_path):
                        if not isinstance(val_data, (bytes, bytearray)):
                            continue
                        last_exec = filetime_to_utc(val_data)
                        writer.writerow(
                            {
                                "UserSID": sid,
                                "ArtifactType": name.upper(),
                                "ExePath": val_name,
                                "LastExecutionUTC": last_exec,
                            }
                        )

    log_success(f"BAM/DAM execution artifacts parsed -> {out_csv}")


def parse_lastvisitedmru(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("LastVisitedMRU: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "LastVisitedMRU.csv"
    rows: list[dict[str, Any]] = []

    keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    ]

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue

        for key_path in keys:
            vmap = _get_key_values_map(nt, key_path)
            if not vmap:
                continue
            order = _decode_mru_listex(vmap.get("MRUListEx"))

            for vn, vv in vmap.items():
                if vn in ("MRUListEx", ""):
                    continue
                rows.append(
                    {
                        "User": user,
                        "Key": key_path,
                        "MruIndices": ",".join(str(x) for x in order) if order else "",
                        "ValueName": vn,
                        "ValueData": _bytes_to_text_or_hex(vv),
                    }
                )

    _write_rows_csv(out_csv, ["User", "Key", "MruIndices", "ValueName", "ValueData"], rows)
    log_success(f"LastVisitedMRU -> {out_csv} ({len(rows)} rows)")


def parse_muicache(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    # MUICache registry paths (in UsrClass.dat)
    mui_path_new = r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    mui_path_old = r"Software\Microsoft\Windows\ShellNoRoam\MUICache"

    users_dir = artifact_paths.get("Users")
    if not users_dir or not Path(users_dir).exists():
        log_warn("MUICache: users directory not resolved; skipping.")
        return

    out_base = outdirs["Users"] / "MUICache"
    out_base.mkdir(exist_ok=True)
    out_csv = out_base / "MUICache.csv"

    with out_csv.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["User", "ExePath", "Description"])
        writer.writeheader()

        for user_dir in sorted(Path(users_dir).glob("*")):
            if not user_dir.is_dir():
                continue

            usrclass = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            if not usrclass.exists():
                continue

            try:
                hive = hive_open(usrclass)
            except Exception:
                continue

            for path in (mui_path_new, mui_path_old):
                for name, data in reg_list_values(hive, path):
                    exe_path = name or ""
                    if not exe_path:
                        continue
                    writer.writerow({"User": user_dir.name, "ExePath": exe_path, "Description": _bytes_to_text_or_hex(data)})

    log_success(f"MUICache parsed -> {out_csv}")


def parse_officemru(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("OfficeMRU: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "OfficeMRU.csv"
    rows: list[dict[str, Any]] = []

    office_root = r"Software\Microsoft\Office"

    def walk(nt, user: str) -> None:
        versions = reg_list_subkeys(nt, office_root)
        for ver in versions:
            ver_key = rf"{office_root}\{ver}"
            programs = reg_list_subkeys(nt, ver_key)
            for prog in programs:
                prog_key = rf"{ver_key}\{prog}"

                for sub in reg_list_subkeys(nt, prog_key):
                    sub_key = rf"{prog_key}\{sub}"
                    sl = sub.lower()
                    if "mru" not in sl and "recent" not in sl:
                        continue

                    vmap = _get_key_values_map(nt, sub_key)
                    if not vmap:
                        continue

                    for vn, vv in vmap.items():
                        if not vn:
                            continue
                        rows.append(
                            {
                                "User": user,
                                "OfficeVersion": ver,
                                "Program": prog,
                                "Key": sub_key,
                                "ValueName": vn,
                                "ValueData": _bytes_to_text_or_hex(vv),
                            }
                        )

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue
        walk(nt, user)

    _write_rows_csv(out_csv, ["User", "OfficeVersion", "Program", "Key", "ValueName", "ValueData"], rows)
    log_success(f"OfficeMRU -> {out_csv} ({len(rows)} rows)")


def parse_opensavemru(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("OpenSaveMRU: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "OpenSaveMRU.csv"
    rows: list[dict[str, Any]] = []

    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"
    base_pidl = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"

    def parse_branch(nt, user: str, branch: str, branch_type: str) -> None:
        for sub in reg_list_subkeys(nt, branch):
            subkey = rf"{branch}\{sub}"
            vmap = _get_key_values_map(nt, subkey)
            if not vmap:
                continue

            order = _decode_mru_listex(vmap.get("MRUListEx"))
            for vn, vv in vmap.items():
                if vn in ("MRUListEx", ""):
                    continue
                rows.append(
                    {
                        "User": user,
                        "Branch": branch_type,
                        "Subkey": sub,
                        "Key": subkey,
                        "MruIndices": ",".join(str(x) for x in order) if order else "",
                        "ValueName": vn,
                        "ValueData": _bytes_to_text_or_hex(vv),
                    }
                )

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue

        parse_branch(nt, user, base, "OpenSaveMRU")
        parse_branch(nt, user, base_pidl, "OpenSavePidlMRU")

    _write_rows_csv(out_csv, ["User", "Branch", "Subkey", "Key", "MruIndices", "ValueName", "ValueData"], rows)
    log_success(f"OpenSaveMRU/OpenSavePidlMRU -> {out_csv} ({len(rows)} rows)")


def parse_runmru(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("RunMRU: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "RunMRU.csv"
    rows: list[dict[str, Any]] = []
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

    for user in get_available_users(users_dir):
        ntuser = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if ntuser is None:
            continue

        values = _get_key_values_map(ntuser, key_path)
        if not values:
            continue

        mru_list = _bytes_to_text_or_hex(values.get("MRUList", ""))

        for name, val in values.items():
            if name in ("MRUList", ""):
                continue
            rows.append(
                {
                    "User": user,
                    "Key": key_path,
                    "MruOrder": mru_list,
                    "EntryName": name,
                    "EntryValue": _bytes_to_text_or_hex(val),
                }
            )

    _write_rows_csv(out_csv, ["User", "Key", "MruOrder", "EntryName", "EntryValue"], rows)
    log_success(f"RunMRU -> {out_csv} ({len(rows)} rows)")


def parse_shellbags(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None:
        log_warn("Shellbags: Users path not resolved; skipping.")
        return

    if not users_dir.exists():
        log_warn(f"Shellbags: Users directory not found: {users_dir}")
        return

    tool_out = outdirs["Users"] / "Shellbags"
    tool_out.mkdir(exist_ok=True)

    cmd = [str(get_tool("SBECmd.exe")), "-d", str(users_dir), "--csv", str(tool_out), "--csvf", "Shellbags.csv"]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"Shellbags processed -> {tool_out}")


def parse_shimcache(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    src_dir = artifact_paths.get("System32")
    if not src_dir:
        log_warn("Shimcache missing in config; skipping.")
        return
    ensure_exists(src_dir, "System32 directory")

    tool_out = outdirs["Registry"] / "Shimcache"
    tool_out.mkdir(exist_ok=True)

    system_hive = Path(str(src_dir)) / "config" / "SYSTEM"
    cmd = [str(get_tool("AppCompatCacheParser.exe")), "-f", str(system_hive), "--csv", str(tool_out), "--csvf", "Shimcache.csv"]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"Shimcache processed -> {tool_out}")


def parse_typedpaths(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("TypedPaths: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "TypedPaths.csv"
    rows: list[dict[str, Any]] = []

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue

        vmap = _get_key_values_map(nt, key_path)
        if not vmap:
            continue

        for vn, vv in vmap.items():
            if not vn:
                continue
            rows.append(
                {
                    "User": user,
                    "Key": key_path,
                    "ValueName": vn,
                    "ValueData": _bytes_to_text_or_hex(vv),
                }
            )

    _write_rows_csv(out_csv, ["User", "Key", "ValueName", "ValueData"], rows)
    log_success(f"TypedPaths -> {out_csv} ({len(rows)} rows)")


def parse_usb(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    system32 = artifact_paths.get("System32")
    if not system32:
        log_warn("USB: system32 path not available; skipping")
        return

    system_hive = Path(system32) / "config" / "SYSTEM"
    if not system_hive.exists():
        log_warn(f"USB: SYSTEM hive not found at {system_hive}; skipping")
        return

    system = hive_open(system_hive)
    ccs = system_current_control_set(system)

    def safe_str(x):
        return "" if x is None else str(x)

    def reg_map(hive_obj, key_path: str):
        try:
            return {name: value for name, value in reg_list_values(hive_obj, key_path)}
        except Exception:
            return {}

    def parse_vid_pid(s: str):
        m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", s)
        if m:
            return m.group(1).upper(), m.group(2).upper()
        return "", ""

    devices: list[dict[str, str]] = []

    def extract_devices(root_key, category):
        for devname in reg_list_subkeys(system, root_key):
            dev_key_path = rf"{root_key}\{devname}"
            for inst in reg_list_subkeys(system, dev_key_path):
                inst_path = rf"{dev_key_path}\{inst}"
                vals = reg_map(system, inst_path)
                if not vals:
                    continue

                vid, pid = parse_vid_pid(devname + " " + inst)
                devices.append(
                    {
                        "Category": category,
                        "DeviceKey": devname,
                        "InstanceId": inst,
                        "VID": vid,
                        "PID": pid,
                        "FriendlyName": safe_str(vals.get("FriendlyName")),
                        "DeviceDesc": safe_str(vals.get("DeviceDesc")),
                        "Mfg": safe_str(vals.get("Mfg")),
                        "Service": safe_str(vals.get("Service")),
                        "Driver": safe_str(vals.get("Driver")),
                        "SerialNumber": safe_str(vals.get("ParentIdPrefix")),
                    }
                )

    extract_devices(rf"{ccs}\Enum\USBSTOR", "USBSTOR")
    extract_devices(rf"{ccs}\Enum\USB", "USB")

    mounted: dict[str, dict[str, list[str]]] = {}
    for name, _ in reg_list_values(system, "MountedDevices"):
        if not name:
            continue
        m = re.search(r"(Volume\{[0-9A-Fa-f\-]{36}\})", name)
        if m:
            vol = m.group(1)
            mounted.setdefault(vol, {"drive_letters": [], "names": []})
            mounted[vol]["names"].append(name)
        d = re.match(r"\\DosDevices\\([A-Za-z]:)", name)
        if d:
            letter = d.group(1)
            for vol_guid in mounted:
                mounted[vol_guid]["drive_letters"].append(letter)

    users_dir = artifact_paths.get("Users")
    timeline_rows: list[dict[str, str]] = []

    if users_dir and Path(users_dir).exists():
        for user_nt in sorted(Path(users_dir).glob("*\\NTUSER.DAT")):
            user = user_nt.parent.name
            try:
                nt_hive = hive_open(user_nt)
            except Exception:
                continue

            mp_root = r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
            for sub in reg_list_subkeys(nt_hive, mp_root):
                if "Volume{" not in sub:
                    continue
                timeline_rows.append(
                    {
                        "User": user,
                        "VolumeGuid": sub,
                        "LastWrite": system_current_control_set(nt_hive),
                    }
                )

    out_reg = outdirs["Registry"] / "USB"
    out_reg.mkdir(exist_ok=True)

    dev_csv = out_reg / "USB_History_Devices.csv"
    with dev_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Category",
                "DeviceKey",
                "InstanceId",
                "VID",
                "PID",
                "FriendlyName",
                "DeviceDesc",
                "Mfg",
                "Service",
                "Driver",
                "SerialNumber",
            ],
        )
        writer.writeheader()
        for d in devices:
            writer.writerow(d)

    tl_csv = out_reg / "USB_History_Timeline.csv"
    with tl_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["User", "VolumeGuid", "DriveLetters", "MountedNames", "LastWrite"])
        writer.writeheader()
        for row in timeline_rows:
            vol = row["VolumeGuid"]
            ml = mounted.get(vol, {})
            writer.writerow(
                {
                    "User": row["User"],
                    "VolumeGuid": vol,
                    "DriveLetters": ", ".join(ml.get("drive_letters", [])),
                    "MountedNames": " | ".join(ml.get("names", [])),
                    "LastWrite": row["LastWrite"],
                }
            )

    log_success(f"USB inventory written: {dev_csv}")
    log_success(f"USB timeline written: {tl_csv}")


def parse_userassist(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("UserAssist: Users directory not found/resolved; skipping.")
        return

    exe = get_tool("uareport.exe")
    if not exe.exists():
        log_error(f"UserAssist: uareport.exe not found at: {exe}")
        return

    out_dir = outdirs["Users"] / "UserAssist"
    out_dir.mkdir(exist_ok=True)

    out_csv = out_dir / "UserAssist.csv"
    cmd = [str(exe), "-d", str(users_dir), "--csv", str(out_csv)]
    run_cmd(cmd, out_dir / "stdout.log", out_dir / "stderr.log", check=False)

    if out_csv.exists():
        log_success(f"UserAssist parsed -> {out_csv}")
    else:
        log_warn("UserAssist: no CSV produced. Check users/userassist/stderr.log.")


def parse_wordwheelquery(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("WordWheelQuery: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "WordWheelQuery.csv"
    rows: list[dict[str, Any]] = []

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue

        vmap = _get_key_values_map(nt, key_path)
        if not vmap:
            continue

        order = _decode_mru_listex(vmap.get("MRUListEx"))
        for vn, vv in vmap.items():
            if vn in ("MRUListEx", ""):
                continue
            rows.append(
                {
                    "User": user,
                    "Key": key_path,
                    "MruIndices": ",".join(str(x) for x in order) if order else "",
                    "ValueName": vn,
                    "ValueData": _bytes_to_text_or_hex(vv),
                }
            )

    _write_rows_csv(out_csv, ["User", "Key", "MruIndices", "ValueName", "ValueData"], rows)
    log_success(f"WordWheelQuery -> {out_csv} ({len(rows)} rows)")


# User artifacts
def parse_browser_history(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None:
        log_warn("BrowserHistory: users path not resolved; skipping.")
        return

    if not users_dir.exists():
        log_warn(f"BrowserHistory: users directory not found: {users_dir}")
        return

    tool_out = outdirs["Users"] / "BrowserHistory"
    tool_out.mkdir(exist_ok=True)
    out_csv = tool_out / "BrowserHistory.csv"

    cmd1 = [
        str(get_tool("BrowsingHistoryView.exe")),
        "/HistorySource", "3",
        "/HistorySourceFolder", str(users_dir),
        "/VisitTimeFilterType", "1",
        "/ShowTimeInGMT", "1",
        "/scomma", str(out_csv),
    ]
    run_cmd(cmd1, tool_out / "stdout.log", tool_out / "stderr.log", check=False)

    if out_csv.exists():
        log_success(f"Browser history exported -> {out_csv}")
    else:
        log_error("Browser history export failed. Check browser_history_browsinghistoryview/stderr*.log.")


def parse_certutil_artifacts(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not Path(users_dir).exists():
        log_warn("Certutil: Users directory not resolved; skipping.")
        return

    out_base = outdirs["Users"] / "Certutil"
    out_base.mkdir(exist_ok=True)
    out_csv = out_base / "certutil_downloads.csv"

    def compute_sha256(path: Path) -> str:
        try:
            h = hashlib.sha256()
            with path.open("rb") as fp:
                for chunk in iter(lambda: fp.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    FILETIME_EPOCH = 116444736000000000
    HUNDREDS_OF_NS = 10_000_000

    with out_csv.open("w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "User",
            "CacheFilename",
            "URL",
            "DownloadFileSize",
            "DownloadTimestampUTC",
            "EtagHash",
            "EtagHashType",
            "LastModTimeUTC",
            "DownloadFileSHA256",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for user_dir in sorted(Path(users_dir).iterdir()):
            if not user_dir.is_dir():
                continue

            meta_dir = user_dir / "AppData" / "LocalLow" / "Microsoft" / "CryptnetUrlCache" / "MetaData"
            content_dir = user_dir / "AppData" / "LocalLow" / "Microsoft" / "CryptnetUrlCache" / "Content"
            if not meta_dir.exists():
                continue

            for f in sorted(meta_dir.iterdir()):
                if not f.is_file():
                    continue
                try:
                    data = f.read_bytes()
                except Exception:
                    continue

                if len(data) < 0x70:
                    continue

                try:
                    url_size = struct.unpack_from("<I", data, 0x0C)[0]

                    raw_ts = struct.unpack_from("<Q", data, 0x10)[0]
                    download_ts = ""
                    if raw_ts:
                        unix_ts = (raw_ts - FILETIME_EPOCH) / HUNDREDS_OF_NS
                        dt_ts = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                        download_ts = dt_ts.isoformat().replace("+00:00", "Z")

                    raw_mod = struct.unpack_from("<Q", data, 0x58)[0]
                    last_mod = ""
                    if raw_mod:
                        unix_ts = (raw_mod - FILETIME_EPOCH) / HUNDREDS_OF_NS
                        dt_mod = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
                        last_mod = dt_mod.isoformat().replace("+00:00", "Z")

                    hash_size = struct.unpack_from("<I", data, 0x64)[0]
                    file_size = struct.unpack_from("<I", data, 0x70)[0]

                    url_start = 0x74
                    url_end = url_start + url_size
                    raw_url = data[url_start:url_end]
                    try:
                        url_str = raw_url.decode("utf-16le", errors="ignore")
                    except Exception:
                        url_str = ""

                    hash_start = url_end
                    hash_end = hash_start + hash_size
                    raw_hash = data[hash_start:hash_end]
                    try:
                        etag_hash = raw_hash.decode("utf-16le", errors="ignore")
                    except Exception:
                        etag_hash = ""

                    etag_type = ""
                    if etag_hash:
                        L = len(etag_hash)
                        if L == 32:
                            etag_type = "MD5"
                        elif L == 40:
                            etag_type = "SHA1"
                        elif L == 64:
                            etag_type = "SHA256"
                        else:
                            etag_type = "UNKNOWN"

                    content_file = content_dir / f.name
                    download_sha256 = ""
                    if content_file.exists() and content_file.is_file():
                        download_sha256 = compute_sha256(content_file)

                    writer.writerow(
                        {
                            "User": user_dir.name,
                            "CacheFilename": f.name,
                            "URL": url_str,
                            "DownloadFileSize": file_size or "",
                            "DownloadTimestampUTC": download_ts,
                            "EtagHash": etag_hash,
                            "EtagHashType": etag_type,
                            "LastModTimeUTC": last_mod,
                            "DownloadFileSHA256": download_sha256,
                        }
                    )

                except Exception as ex:
                    log_error(f"certutil_artifacts: failed parsing {f.name}: {ex}")

    log_success(f"Certutil download artifacts parsed -> {out_csv}")


def parse_jumplists(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None:
        log_warn("JumpLists: users path not resolved; skipping.")
        return

    if not users_dir.exists():
        log_warn(f"JumpLists: Users directory not found: {users_dir}")
        return

    tool_out = outdirs["Users"] / "JumpLists"
    tool_out.mkdir(exist_ok=True)

    cmd = [str(get_tool("JLECmd.exe")), "-d", str(users_dir), "--csv", str(tool_out), "--csvf", "jumplists.csv"]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"JumpLists parsed -> {tool_out}")


def parse_notepad_files(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("NotepadFiles: Users directory not found/resolved; skipping.")
        return

    base_out = outdirs["Users"] / "NotepadFiles"
    base_out.mkdir(exist_ok=True)

    copied = 0
    for user in get_available_users(users_dir):
        src = (
            users_dir
            / user
            / "AppData"
            / "Local"
            / "Packages"
            / "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
            / "LocalState"
        )
        if not src.exists() or not src.is_dir():
            continue

        dst = base_out / user / "LocalState"
        if dst.exists():
            log_warn(f"NotepadFiles: destination already exists, skipping (no overwrite): {dst}")
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, dst)
        copied += 1

    if copied == 0:
        log_warn("NotepadFiles: no Notepad LocalState directories found for any user.")
    else:
        log_success(f"Notepad LocalState copied for {copied} user(s) -> {base_out}")


def parse_psreadline(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("PSReadLine: Users directory not found/resolved; skipping.")
        return

    out_dir = outdirs["Users"] / "PSReadLine"
    out_dir.mkdir(exist_ok=True)

    copied = 0
    for user in get_available_users(users_dir):
        src = (
            users_dir
            / user
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "PowerShell"
            / "PSReadLine"
            / "ConsoleHost_history.txt"
        )

        if not src.exists() or not src.is_file():
            continue

        dst = out_dir / f"PSReadLine_{user}.txt"
        if dst.exists():
            log_warn(f"PSReadLine: destination exists, skipping (no overwrite): {dst}")
            continue

        shutil.copy2(src, dst)
        copied += 1

    if copied == 0:
        log_warn("PSReadLine: no PSReadLine history files found.")
    else:
        log_success(f"PSReadLine history copied for {copied} user(s) -> {out_dir}")


def parse_rdp_cache(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("RDPCache: Users directory not found/resolved; skipping.")
        return

    out_base = outdirs["Users"] / "RDPCache"
    out_base.mkdir(exist_ok=True)

    exe = get_tool("bmc-tools.exe")
    if not exe.exists():
        log_error(f"RDPCache: bmc-tools.exe not found at: {exe}")
        return

    total_files = 0
    users_processed = 0

    for user in get_available_users(users_dir):
        cache_dir = users_dir / user / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache"
        if not cache_dir.exists():
            continue

        cache_files = sorted(cache_dir.glob("Cache*.bin")) + sorted(cache_dir.glob("cache*.bin"))
        cache_files = [p for p in cache_files if p.is_file()]
        if not cache_files:
            continue

        users_processed += 1
        user_out = out_base / user
        user_out.mkdir(exist_ok=True)

        for cache_file in cache_files:
            total_files += 1
            dest_dir = user_out / cache_file.stem
            dest_dir.mkdir(exist_ok=True)

            cmd = [str(exe), "-s", str(cache_file), "-d", str(dest_dir)]
            run_cmd(cmd, dest_dir / "stdout.log", dest_dir / "stderr.log", check=False)

    if users_processed == 0:
        log_warn("RDPCache: no RDP cache directories/files found for any user.")
    else:
        log_success(f"RDP cache extracted for {users_processed} user(s), {total_files} cache file(s) -> {out_base}")


def parse_recentdocs(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("RecentDocs: Users directory not found/resolved; skipping.")
        return

    out_csv = outdirs["Users"] / "NTUSER_Artifacts" / "RecentDocs.csv"
    rows: list[dict[str, Any]] = []

    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

    for user in get_available_users(users_dir):
        nt = _safe_open_ntuser(_ntuser_path_for_user(users_dir, user))
        if nt is None:
            continue

        for key_path in [base] + [rf"{base}\{sk}" for sk in reg_list_subkeys(nt, base)]:
            vmap = _get_key_values_map(nt, key_path)
            if not vmap:
                continue
            order = _decode_mru_listex(vmap.get("MRUListEx"))

            for vn, vv in vmap.items():
                if vn in ("MRUListEx", ""):
                    continue
                rows.append(
                    {
                        "User": user,
                        "Key": key_path,
                        "MruIndices": ",".join(str(x) for x in order) if order else "",
                        "ValueName": vn,
                        "ValueData": _bytes_to_text_or_hex(vv),
                    }
                )

    _write_rows_csv(out_csv, ["User", "Key", "MruIndices", "ValueName", "ValueData"], rows)
    log_success(f"RecentDocs -> {out_csv} ({len(rows)} rows)")


def parse_recent_lnk(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("RecentLnk: Users directory not found/resolved; skipping.")
        return

    out_base = outdirs["Users"] / "RecentLnk"
    out_base.mkdir(exist_ok=True)

    per_file_dir = out_base / "PerFileCSV"
    per_file_dir.mkdir(exist_ok=True)

    lnk_files: list[tuple[str, Path]] = []
    for user in get_available_users(users_dir):
        recent_dir = users_dir / user / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
        if not recent_dir.exists():
            continue
        for lnk in sorted(recent_dir.rglob("*.lnk")):
            if lnk.is_file():
                lnk_files.append((user, lnk))

    if not lnk_files:
        log_warn("RecentLnk: no .lnk files found under Users\\<USER>\\...\\Recent; skipping.")
        return

    produced_csvs: list[tuple[str, Path, Path]] = []
    for idx, (user, lnk_path) in enumerate(lnk_files, 1):
        try:
            rel = str(lnk_path.relative_to(users_dir / user)).replace("\\", "_").replace("/", "_")
        except Exception:
            rel = lnk_path.name

        csv_name = f"{idx:06d}_{user}_{rel}.csv"
        csv_path = per_file_dir / csv_name

        cmd = [str(get_tool("LECmd.exe")), "-f", str(lnk_path), "--csv", str(per_file_dir), "--csvf", csv_name]
        run_cmd(cmd, out_base / "stdout.log", out_base / "stderr.log", check=False)

        if csv_path.exists() and csv_path.stat().st_size > 0:
            produced_csvs.append((user, lnk_path, csv_path))

    if not produced_csvs:
        log_warn("recent_lnk: LECmd did not produce any CSV output. Check logs.")
        return

    merged_csv = out_base / "recent_lnk_merged.csv"

    header_set: dict[str, None] = {}
    for _, _, csvp in produced_csvs:
        try:
            with csvp.open("r", encoding="utf-8", errors="replace", newline="") as fp:
                r = csv.DictReader(fp)
                if r.fieldnames:
                    for h in r.fieldnames:
                        header_set[h] = None
        except Exception:
            continue

    merged_fields = ["User", "SourceLnk"] + list(header_set.keys())

    with merged_csv.open("w", encoding="utf-8", newline="") as out_fp:
        w = csv.DictWriter(out_fp, fieldnames=merged_fields)
        w.writeheader()

        for user, lnk_path, csvp in produced_csvs:
            try:
                with csvp.open("r", encoding="utf-8", errors="replace", newline="") as fp:
                    r = csv.DictReader(fp)
                    for row in r:
                        merged_row = {k: "" for k in merged_fields}
                        merged_row["User"] = user
                        merged_row["SourceLnk"] = str(lnk_path)
                        for k, v in row.items():
                            if k in merged_row:
                                merged_row[k] = v if v is not None else ""
                        w.writerow(merged_row)
            except Exception:
                continue

    log_success(f"Recent .lnk parsed: {len(produced_csvs)} file(s) -> {merged_csv}")


def parse_thumbnails(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None or not users_dir.exists():
        log_warn("Thumbnails: Users directory not found/resolved; skipping.")
        return

    exe = get_tool("thumbcache_viewer_cmd.exe")
    if not exe.exists():
        log_error(f"Thumbnails: thumbcache_viewer_cmd.exe not found: {exe}")
        return

    base_out = outdirs["Users"] / "Thumbnails"
    base_out.mkdir(exist_ok=True)

    users_processed = 0
    dbs_processed = 0

    for user in get_available_users(users_dir):
        explorer_dir = users_dir / user / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
        if not explorer_dir.exists():
            continue

        db_files = [p for p in sorted(explorer_dir.glob("thumbcache*.db")) if p.is_file()]
        if not db_files:
            continue

        users_processed += 1
        user_out = base_out / user
        user_out.mkdir(exist_ok=True)

        for db in db_files:
            dbs_processed += 1
            db_out = user_out / db.stem
            db_out.mkdir(exist_ok=True)

            cmd = [str(exe), "-o", str(db_out), "-c", "-w", "-z", "-t", str(db)]
            run_cmd(cmd, db_out / "stdout.log", db_out / "stderr.log", check=False)

    if users_processed == 0:
        log_warn("Thumbnails: no thumbcache databases found for any user.")
    else:
        log_success(f"Thumbnails parsed for {users_processed} user(s), {dbs_processed} DB(s) -> {base_out}")


def parse_win10_timelines(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("Users")
    if users_dir is None:
        log_warn("Win10Timelines: users path not resolved; skipping.")
        return

    if not users_dir.exists():
        log_warn(f"Win10Timelines: Users directory not found: {users_dir}")
        return

    base_out = outdirs["Users"] / "Win10Timelines"
    base_out.mkdir(exist_ok=True)

    users = get_available_users(users_dir)
    if not users:
        log_warn("Win10Timelines: no user profiles found; skipping.")
        return

    total = 0
    for user in users:
        activities_db = (
            users_dir
            / user
            / "AppData"
            / "Local"
            / "ConnectedDevicesPlatform"
            / f"L.{user}"
            / "ActivitiesCache.db"
        )
        if not activities_db.exists():
            continue

        user_out = base_out / user
        user_out.mkdir(exist_ok=True)

        cmd = [str(get_tool("WxTCmd.exe")), "-f", str(activities_db), "--csv", str(user_out)]
        run_cmd(cmd, user_out / "stdout.log", user_out / "stderr.log", check=False)
        total += 1

    if total == 0:
        log_warn("Win10Timelines: no ActivitiesCache.db found for any user.")
    else:
        log_success(f"Windows 10 Timeline parsed for {total} user(s)")


# File system artifacts parsers
def parse_logfile(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    logfile_path = artifact_paths.get("LogFile")
    if not logfile_path:
        log_warn("LogFile missing in config; skipping.")
        return

    ensure_exists(logfile_path, "$LogFile file")

    tool_out = outdirs["LogFile"] / "NTFS_Log_Tracker"
    tool_out.mkdir(parents=True, exist_ok=True)

    csv_name = "LogFile.csv"

    cmd = [
        str(get_tool("logfileparser", "NTFS_Log_Tracker_CMD.exe")),
        "-l", str(logfile_path),
        "-t", "0",
        "-o", str(tool_out),
        "-c", csv_name,
    ]

    run_cmd(
        cmd,
        tool_out / "stdout.log",
        tool_out / "stderr.log",
        check=False,
    )

    log_success(f"$LogFile parsed -> {tool_out / csv_name}")


def parse_mft(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    mft_path = artifact_paths.get("MFT")
    if not mft_path:
        log_warn("MFT missing in config; skipping.")
        return
    ensure_exists(mft_path, "$MFT file")

    tool_out = outdirs["MFT"] / "MFT"
    tool_out.mkdir(exist_ok=True)

    cmd = [str(get_tool("MFTECmd.exe")), "-f", str(mft_path), "--csv", str(tool_out), "--csvf", "mftecmd_results.csv"]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"MFT parsed -> {tool_out}")


def parse_recycle_bin(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    users_dir = artifact_paths.get("RecycleBin")
    if users_dir is None:
        log_warn("RecycleBin: 'RecycleBin' not set in config; skipping.")
        return

    users_dir = Path(users_dir)
    if not users_dir.exists():
        log_warn(f"RecycleBin: RecycleBin root not found: {users_dir}")
        return

    tool_path = get_tool("RBCmd.exe")
    if not tool_path.exists():
        log_error(f"RecycleBin: RBCmd.exe not found at: {tool_path}")
        return

    out_base = outdirs["RecycleBin"] / "RecycleBin"
    out_base.mkdir(parents=True, exist_ok=True)

    total_processed = 0
    sids_processed = 0

    for sid_dir in sorted(users_dir.iterdir()):
        if not sid_dir.is_dir():
            continue

        sid_outdir = out_base / sid_dir.name
        sid_outdir.mkdir(exist_ok=True)

        bin_files = sorted(sid_dir.glob("$I*"))
        if not bin_files:
            continue

        sids_processed += 1

        for binf in bin_files:
            cmd = [str(tool_path), "-f", str(binf), "--csv", str(sid_outdir), "--csvf", f"{binf.stem}.csv"]
            run_cmd(cmd, sid_outdir / f"{binf.stem}.stdout.log", sid_outdir / f"{binf.stem}.stderr.log", check=False)
            total_processed += 1

    if sids_processed == 0:
        log_warn("RecycleBin: no Recycle Bin subfolders found or no $I* files present.")
    else:
        log_success(f"Recycle Bin parsed for {sids_processed} user(s), {total_processed} files -> {out_base}")


def parse_usnjournal(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    usn_path = artifact_paths.get("USNJournal")
    if not usn_path:
        log_warn("USNJournal missing in config; skipping.")
        return
    ensure_exists(usn_path, "USN Journal ($UsnJrnl$J)")

    tool_out = outdirs["USNJournal"] / "USNJournal"
    tool_out.mkdir(exist_ok=True)

    cmd = [str(get_tool("MFTECmd.exe")), "-f", str(usn_path), "--csv", str(tool_out), "--csvf", "usnjournal.csv"]
    run_cmd(cmd, tool_out / "stdout.log", tool_out / "stderr.log", check=False)
    log_success(f"USN Journal parsed -> {tool_out}")


# Event logs parsers
def parse_event_logs(artifact_paths: PathMap, outdirs: dict[str, Path]) -> None:
    src_dir = artifact_paths.get("EventLogs")
    if not src_dir:
        log_warn("EventLogs missing in config; skipping.")
        return
    ensure_exists(src_dir, "Event Logs directory")

    base_out = outdirs["EventLogs"]
    base_out.mkdir(exist_ok=True)

    # Hayabusa
    log_step(f"Analyzing Event Logs with Hayabusa...")
    hayabusa_out = base_out / "Hayabusa"
    hayabusa_out.mkdir(exist_ok=True)
    cmd = [str(get_tool("hayabusa", "hayabusa.exe")),
           "csv-timeline",
           "-d", str(src_dir),
           "--output", "{}/hayabusa.csv".format(str(hayabusa_out)),
           "-K", "-A", "-U", "-w",
           "-H", "{}/report.html".format(str(hayabusa_out))
           ]
    run_cmd(cmd, hayabusa_out / "stdout.log", hayabusa_out / "stderr.log", check=False)

    # APT-Hunter
    log_step(f"Analyzing Event Logs with APT-Hunter...")
    apthunter_out = base_out / "APT-Hunter"
    apthunter_out.mkdir(parents=True, exist_ok=True)

    # Copy APT-Hunter binary to output directory
    src_exe = get_tool("APT-Hunter.exe")
    dst_exe = apthunter_out / "APT-Hunter.exe"

    shutil.copy2(src_exe, dst_exe)

    # Run APT-Hunter from the context of apthunter_out
    cmd = [
        "APT-Hunter.exe",
        "-p", str(src_dir),
        "-o", "Results",
        "-tz", "utc",
        "-allreport"
    ]

    old_cwd = os.getcwd()
    try:
        os.chdir(apthunter_out)

        run_cmd(
            cmd,
            apthunter_out / "stdout.log",
            apthunter_out / "stderr.log",
            check=False
        )
    finally:
        os.chdir(old_cwd)

    # Copy everything from Results to apthunter_out
    results_dir = apthunter_out / "Results"
    if results_dir.exists():
        for item in results_dir.iterdir():
            dst = apthunter_out / item.name
            if item.is_dir():
                if dst.exists():
                    shutil.rmtree(dst)
                shutil.copytree(item, dst)
            else:
                shutil.copy2(item, dst)

    # Delete copied APT-Hunter binary and Results directory
    dst_exe.unlink(missing_ok=True)
    shutil.rmtree(results_dir, ignore_errors=True)

    # Chainsaw
    log_step(f"Analyzing Event Logs with Chainsaw...")
    chainsaw_out = base_out / "Chainsaw"
    chainsaw_out.mkdir(exist_ok=True)
    cmd = [str(get_tool("chainsaw", "chainsaw.exe")),
           "hunt", str(src_dir), "-s", "{}\\sigma\\".format(str(get_tool("chainsaw"))),
           "--mapping", "{}\\mappings\\sigma-event-logs-all.yml".format(str(get_tool("chainsaw"))),
           "-r", "{}\\rules\\".format(str(get_tool("chainsaw"))), "--csv", "--output", str(chainsaw_out)
           ]
    run_cmd(cmd, chainsaw_out / "stdout.log", chainsaw_out / "stderr.log", check=False)

    # EvtxECmd
    log_step(f"Parsing Event Logs with EvtxECmd...")
    evtxecmd_out = base_out / "EvtxECmd"
    evtxecmd_out.mkdir(exist_ok=True)
    evtx_files = sorted(src_dir.glob("*.evtx")) or sorted(src_dir.rglob("*.evtx"))
    for evtx in evtx_files:
        out_csv_name = evtx.name + ".csv"
        cmd2 = [str(get_tool("evtxecmd", "EvtxECmd.exe")), "-f", str(evtx), "--csv", str(evtxecmd_out), "--csvf", out_csv_name]
        run_cmd(cmd2, evtxecmd_out / f"{evtx.stem}.stdout.log", evtxecmd_out / f"{evtx.stem}.stderr.log", check=False)

    log_success(f"Event logs parsed")


# Orchestration
PARSER_TOOLS: list[tuple[str, Callable[[PathMap, dict[str, Path]], None]]] = [
    # Evidence of execution
    ("AmCache", parse_amcache),
    ("Defender", parse_defender_logs),
    ("PCA", parse_pca),
    ("Prefetch", parse_prefetch),
    ("SRUM", parse_srum),
    ("WER", parse_wer),

    # Persistence
    ("ScheduledTasks", parse_scheduled_tasks),
    ("WMI", parse_wmi),

    # Registry
    ("BamDam", parse_bam_dam),
    ("LastVisitedMRU", parse_lastvisitedmru),
    ("MUICache", parse_muicache),
    ("OfficeMRU", parse_officemru),
    ("OpenSaveMRU", parse_opensavemru),
    ("RunMRU", parse_runmru),
    ("Shellbags", parse_shellbags),
    ("Shimcache", parse_shimcache),
    ("TypedPaths", parse_typedpaths),
    ("USB", parse_usb),
    ("UserAssist", parse_userassist),
    ("WordWheelQuery", parse_wordwheelquery),

    # User artifacts
    ("BrowserHistory", parse_browser_history),
    ("Certutil", parse_certutil_artifacts),
    ("JumpLists", parse_jumplists),
    ("Notepad", parse_notepad_files),
    ("PSReadLine", parse_psreadline),
    ("RDPCache", parse_rdp_cache),
    ("RecentDocs", parse_recentdocs),
    ("RecentLnk", parse_recent_lnk),
    ("Thumbcache", parse_thumbnails),
    ("Win10Timelines", parse_win10_timelines),

    # File system artifacts
    ("MFT", parse_mft),
    ("RecycleBin", parse_recycle_bin),
    ("USNJournal", parse_usnjournal),

    # Event logs
    ("EventLog", parse_event_logs),

    # Slow parsers
    ("LogFile", parse_logfile),
]


def _normalize_parser_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _parser_token_matches(user_token: str, tool_name: str) -> bool:
    user_norm = _normalize_parser_name(user_token)
    if not user_norm:
        return False
    tool_norm = _normalize_parser_name(tool_name)
    if user_norm == tool_norm:
        return True

    return len(user_norm) >= 3 and tool_norm.startswith(user_norm)


def run_selected_parsers(
    artifact_paths: PathMap,
    outdirs: dict[str, Path],
    *,
    workers: int = 0,
    exclude: set[str] | None = None,
) -> None:
    TOOLS = PARSER_TOOLS
    if exclude:
        excluded_names: list[str] = []
        matched_tokens: set[str] = set()
        for name, _ in TOOLS:
            for token in exclude:
                if _parser_token_matches(token, name):
                    excluded_names.append(name)
                    matched_tokens.add(token)
                    break
        unmatched = set(exclude) - matched_tokens
        if unmatched:
            log_warn(f"--exclude-parser: no parser matched: {', '.join(sorted(unmatched))} (see --list-parsers)")
        if excluded_names:
            log_info(f"Excluding parser(s): {', '.join(excluded_names)}")
        excluded_set = set(excluded_names)
        TOOLS = [(name, fn) for name, fn in TOOLS if name not in excluded_set]

    # Don't spawn too many heavy external tools at once
    if workers and workers > 0:
        max_workers = workers
    else:
        max_workers = min(8, (os.cpu_count() or 4))

    def _run_one(name: str, fn: Callable[[PathMap, dict[str, Path]], None]) -> tuple[str, float, str | None]:
        start = time.perf_counter()
        try:
            log_info(f"Running: {name}")
            fn(artifact_paths, outdirs)
            elapsed = time.perf_counter() - start
            log_success(f"Finished: {name} ({elapsed:.2f}s)")
            return (name, elapsed, None)
        except Exception as ex:
            elapsed = time.perf_counter() - start
            log_error(f"Error in {name} ({elapsed:.2f}s): {ex}")
            return (name, elapsed, str(ex))

    log_info(f"Running parsers in parallel (workers={max_workers})")

    results: list[tuple[str, float, str | None]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_run_one, name, fn): name for name, fn in TOOLS}
        for fut in as_completed(futs):
            results.append(fut.result())

    log_info("All parser threads finished and the thread pool has shut down.")

    ok = [r for r in results if r[2] is None]
    bad = [r for r in results if r[2] is not None]
    log_info(f"\nParser summary: OK={len(ok)} FAIL={len(bad)}")
    if bad:
        log_error("Failed parsers:")
        for name, elapsed, err in sorted(bad, key=lambda x: x[0].lower()):
            log_error(f"    - {name} ({elapsed:.2f}s): {err}")


# Search text in evidence
def iter_text_lines_best_effort(
    path: Path,
    encodings: tuple[str, ...] = ("utf-16", "utf-8", "utf-16-le", "utf-16-be", "latin-1"),
):
    """
    Yields (lineno, line) from a text file using best-effort encoding detection.
    Uses streaming reads to handle large files.
    """
    for enc in encodings:
        try:
            with path.open("r", encoding=enc, errors="strict") as f:
                for i, line in enumerate(f, 1):
                    yield i, line.rstrip("\r\n")
            return
        except Exception:
            continue

    # Last resort: ignore errors
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                yield i, line.rstrip("\r\n")
    except Exception:
        return


def search_output_dir(
    output_dir: Path,
    term: str,
    *,
    case_sensitive: bool = False,
    max_hits: int = 0,
    include_exts: tuple[str, ...] = (".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm", ".md", ".yml", ".yaml"),
) -> int:
    """
    Searches for a string in the output directory.
    """
    ensure_exists(output_dir, "Output directory")
    if not output_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {output_dir}")

    needle = term if case_sensitive else term.lower()
    hits = 0

    for p in sorted(output_dir.rglob("*")):
        try:
            if p.is_dir():
                continue

            if include_exts and p.suffix.lower() not in include_exts:
                continue

            for lineno, line in iter_text_lines_best_effort(p):
                hay = line if case_sensitive else line.lower()
                if needle in hay:
                    log_dim(f"{p}:{lineno}:{line}")
                    hits += 1
                    if max_hits and hits >= max_hits:
                        return hits
        except Exception:
            continue

    return hits

# Find IOCs
def load_iocs(path: Path) -> list[str]:
    ensure_exists(path, "IOC file")

    txt = read_text_best_effort(path) or ""
    iocs: list[str] = []

    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        iocs.append(line)

    return iocs


def find_iocs_in_output_dir(
    output_dir: Path,
    iocs: list[str],
    *,
    case_sensitive: bool = False,
    max_hits: int = 0,
    save_dir: Path | None = None,
) -> int:
    total_hits = 0

    for ioc in iocs:
        log_step(f"Searching IOC: {ioc}")

        fp = None
        out_file = None

        if save_dir is not None:
            save_dir.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w.-]+", "_", ioc)
            out_file = save_dir / f"{safe_name}.txt"
            fp = out_file.open("w", encoding="utf-8")

        needle = ioc if case_sensitive else ioc.lower()
        hits = 0

        for p in sorted(output_dir.rglob("*")):
            try:
                if p.is_dir():
                    continue

                for lineno, line in iter_text_lines_best_effort(p):
                    hay = line if case_sensitive else line.lower()
                    if needle in hay:
                        entry = f"{p}:{lineno}:{line}"
                        print(entry)
                        if fp:
                            fp.write(entry + "\n")
                        hits += 1
                        total_hits += 1
                        if max_hits and hits >= max_hits:
                            break
            except Exception:
                continue

        if fp:
            fp.close()
            if hits == 0:
                out_file.unlink(missing_ok=True)
            else:
                log_info(f"Saved {hits} hits to {out_file}")

    return total_hits


# Extract .ZIP compressed triage
def _extract_zip_to_temp(
    zip_path: Path,
    skip_large_files: bool = False,
    max_file_size_bytes: int = 0,
) -> Path:
    """
    Extract ZIP to a unique temp directory and return the extracted root.
    """

    ensure_exists(zip_path, "ZIP file")
    if not zip_path.is_file():
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    if zipfile.is_zipfile(zip_path) is False:
        raise ValueError(f"Not a valid zip file: {zip_path}")

    tmp_root = Path(tempfile.mkdtemp(prefix="triage_zip_")).resolve()

    # Windows-illegal filename chars + control chars
    illegal = set('<>:"/\\|?*')
    def _sanitize_component(s: str) -> str:
        s = "".join("_" if (c in illegal or ord(c) < 32) else c for c in s)
        s = s.strip(" .")
        return s or "_"

    def _safe_join(root: Path, rel: str) -> Path:
        # Normalize separators
        rel = rel.replace("\\", "/")
        # Block absolute and traversal
        if rel.startswith("/") or rel.startswith("../") or "/../" in rel:
            raise ValueError(f"Unsafe zip member path: {rel}")

        parts = [p for p in rel.split("/") if p not in ("", ".",)]
        safe_parts = [_sanitize_component(p) for p in parts]
        return (root / Path(*safe_parts)).resolve()

    def _truncate_path(p: Path, max_name: int = 120) -> Path:
        """
        Truncate only the leaf filename if needed.
        Keeps extension, adds short hash suffix.
        """
        name = p.name
        if len(name) <= max_name:
            return p
        stem, ext = os.path.splitext(name)
        h = hashlib.sha1(name.encode("utf-8", errors="ignore")).hexdigest()[:10]
        keep = max(1, max_name - len(ext) - 11)
        new_name = f"{stem[:keep]}_{h}{ext}"
        return p.with_name(new_name)

    warned = 0
    skipped_large = 0
    skipped_large_bytes = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        for zi in zf.infolist():
            raw_name = zi.filename.replace("\\", "/")
            if raw_name.endswith("/"):
                continue

            if skip_large_files and max_file_size_bytes and zi.file_size > max_file_size_bytes:
                skipped_large += 1
                skipped_large_bytes += zi.file_size
                log_warn(
                    f"Skipping large file ({zi.file_size / (1024 * 1024):.1f} MB, "
                    f"over {max_file_size_bytes / (1024 * 1024):.0f} MB limit): {zi.filename}"
                )
                continue

            try:
                out_path = _safe_join(tmp_root, raw_name)
                out_path = _truncate_path(out_path)

                # Create parent dirs
                out_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract by streaming to avoid zipfile path issues
                with zf.open(zi, "r") as src, out_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)

            except Exception as ex:
                warned += 1
                log_warn(f"ZIP extract warning: skipped '{zi.filename}': {ex}")
                continue

    if warned:
        log_warn(f"ZIP extraction completed with {warned} skipped file(s) due to invalid paths/names.")
    if skipped_large:
        log_warn(
            f"Skipped {skipped_large} large file(s) ({skipped_large_bytes / (1024 * 1024):.1f} MB total) "
            f"not extracted due to --skip-large-files."
        )

    # If the zip contains a single top-level directory, use it as triage root.
    try:
        children = [p for p in tmp_root.iterdir() if p.name not in (".DS_Store", "__MACOSX")]
        if len(children) == 1 and children[0].is_dir():
            return children[0].resolve()
    except Exception:
        pass

    return tmp_root


def _flatten_exclude_parser(raw: list[str]) -> set[str]:
    names: set[str] = set()
    for entry in raw or []:
        for part in entry.split(","):
            part = part.strip()
            if part:
                names.add(part)
    return names


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="DFIR triage automation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=f"Triager {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )

    ap.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Triager {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of worker threads for running parsers in parallel (0 = auto).",
    )
    ap.add_argument(
        "-d",
        "--dir",
        help="Existing OUTPUT directory to post-process (use with --search or --find-iocs)",
    )
    ap.add_argument(
        "--search",
        help="Search for a string in the OUTPUT directory (use with -d/--dir). Prints path:line:content.",
    )
    ap.add_argument(
        "--find-iocs",
        help="Search for common malicious IOCs from a text file (one IOC per line). Use with -d/--dir.",
    )
    ap.add_argument(
        "--save-iocs",
        help="Directory where IOC hits will be saved (one file per IOC). If not set, results are only printed.",
    )
    ap.add_argument("--search-case-sensitive", action="store_true", help="Make --search case sensitive")
    ap.add_argument("--search-max-hits", type=int, default=0, help="Stop after N hits (0 = no limit)")

    ap.add_argument(
        "-z",
        "--zip",
        help="ZIP file containing the triage directory. The ZIP will be extracted to a temp folder for processing.",
    )

    ap.add_argument(
        "--profile",
        choices=sorted(CONFIG_PROFILES),
        default=DEFAULT_CONFIG_PROFILE,
        help="Built-in triage collection profile to use when -c/--config is not given.",
    )
    ap.add_argument(
        "-c",
        "--config",
        default=None,
        help="Path to an external config.yml file. Overrides --profile if given.",
    )
    ap.add_argument("--root", help="Override triage root path for this run (directory path)")
    ap.add_argument(
        "-o",
        "--output",
        help="Output directory to create (must not exist). Required unless using --search/--find-iocs with -d.",
    )
    ap.add_argument(
        "--compress",
        action="store_true",
        help="After processing, zip the whole output directory into <output_directory>.zip alongside it.",
    )
    ap.add_argument(
        "--skip-large-files",
        action="store_true",
        help="Don't extract files from --zip larger than --max-file-size-mb.",
    )
    ap.add_argument(
        "--max-file-size-mb",
        type=int,
        default=1024,
        help="Size threshold in MB used with --skip-large-files.",
    )
    ap.add_argument(
        "--exclude-parser",
        action="append",
        default=[],
        metavar="NAME",
        help="Skip a parser (comma-separated).",
    )
    ap.add_argument(
        "--list-parsers",
        action="store_true",
        help="Print every available parser name and exit.",
    )

    args = ap.parse_args()

    if args.list_parsers:
        return args

    # Validate mode combinations
    if args.search or args.find_iocs:
        if not args.dir:
            ap.error("When using --search or --find-iocs you must provide -d/--dir pointing to an existing OUTPUT directory.")
        if args.output:
            ap.error("Do not use -o/--output with --search/--find-iocs. Use -d/--dir instead.")
        if args.zip:
            ap.error("Do not use --zip with --search/--find-iocs. --zip is for processing mode only.")
        return args

    # Processing mode validations
    if not args.output:
        ap.error("Missing -o/--output (required unless using --search/--find-iocs with -d/--dir).")

    if args.zip and args.root:
        ap.error("Use either --zip or --root (not both). --zip is extracted and becomes the effective root.")

    return args


def main() -> int:
    if not TOOLS_DIR.exists():
        log_error(f"Tools directory not found: {TOOLS_DIR}")

    args = parse_args()

    if args.list_parsers:
        for name, _ in PARSER_TOOLS:
            print(name)
        return 0

    # Post-processing mode: SEARCH
    if args.search:
        out_dir = Path(args.dir).expanduser().resolve()
        hits = search_output_dir(
            out_dir,
            args.search,
            case_sensitive=bool(args.search_case_sensitive),
            max_hits=int(args.search_max_hits or 0),
        )
        log_info(f"Search done. Hits: {hits}")
        return 0 if hits > 0 else 2

    # Post-processing mode: FIND IOCs
    if args.find_iocs:
        out_dir = Path(args.dir).expanduser().resolve()
        ioc_file = Path(args.find_iocs).expanduser().resolve()

        iocs = load_iocs(ioc_file)

        if not iocs:
            log_warn("IOC file is empty.")
            return 2

        hits = find_iocs_in_output_dir(
            out_dir,
            iocs,
            case_sensitive=bool(args.search_case_sensitive),
            max_hits=int(args.search_max_hits or 0),
            save_dir=Path(args.save_iocs).expanduser().resolve() if args.save_iocs else None,
        )

        log_info(f"\nIOC scan finished. Total hits: {hits}")
        return 0 if hits > 0 else 2

    extracted_root: Path | None = None

    try:
        if args.config:
            cfg_path_desc = str(Path(args.config).expanduser().resolve())
            cfg = load_yaml_config(Path(args.config).expanduser().resolve())
            log_info(f"Config source: custom file ({cfg_path_desc})")
        else:
            cfg_path_desc = f"built-in profile '{args.profile}'"
            cfg = load_yaml_config_from_text(CONFIG_PROFILES[args.profile])
            log_info(f"Config source: {cfg_path_desc}")

        # If --zip was provided, extract and force root to extracted directory
        if args.zip:
            log_info("Extracting ZIP file")
            zip_path = Path(args.zip).expanduser().resolve()
            extracted_root = _extract_zip_to_temp(
                zip_path,
                skip_large_files=bool(args.skip_large_files),
                max_file_size_bytes=int(args.max_file_size_mb or 0) * 1024 * 1024,
            )

            # Override config root
            cfg["root"] = str(extracted_root)

        # Apply CLI overrides
        cfg = apply_overrides(cfg, args)

        output_directory = Path(args.output).expanduser().resolve()

        ctx = build_paths(cfg)
        triage_root: Path = ctx["root"]
        artifact_paths: PathMap = ctx["artifact_paths"]
        hive_paths: PathMap = ctx["hive_paths"]
        user_hive_globs: dict[str, str] = ctx["user_hive_globs"]

        outdirs = create_main_dir(output_directory)
        meta_dir = outdirs["Meta"]

        # Save config snapshot
        write_json(meta_dir / "config_effective.json", cfg)
        write_json(
            meta_dir / "paths_resolved.json",
            {
                "triage_root": str(triage_root),
                "artifact_paths": {k: str(v) for k, v in artifact_paths.items()},
                "hive_paths": {k: str(v) for k, v in hive_paths.items()},
                "user_hive_globs": user_hive_globs,
            },
        )

        # Collect host info
        hp = collect_host_info_from_triage(hive_paths, triage_root, meta_dir, user_hive_globs, artifact_paths)

        log_info(f"Output: {output_directory}")
        log_info(f"Target: {hp.summary}")
        if hp.operating_system:
            log_info(f"OS: {hp.operating_system}")
        if hp.timezone:
            log_info(f"TZ: {hp.timezone}")
        if hp.os_install_date:
            log_info(f"Install: {hp.os_install_date}")

        run_selected_parsers(
            artifact_paths, outdirs, workers=int(args.workers or 0),
            exclude=_flatten_exclude_parser(args.exclude_parser),
        )

        if args.compress:
            log_step("Compressing output directory...")
            compress_output_directory(output_directory)

        log_info("Done.")
        return 0

    except Exception as ex:
        log_error(f"Processing failed: {ex!r}")
        for line in traceback.format_exc().splitlines():
            log_error(f"    {line}")
        return 1

    finally:
        # Cleanup extracted triage directory, if any
        if args.zip:
            try:
                if extracted_root is not None:
                    tmp = extracted_root.parent if extracted_root.parent.name.startswith("triage_zip_") else extracted_root
                    shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                pass


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        try:
            sys.stderr.write("\n[FATAL] Unhandled exception:\n")
            sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
        except Exception:
            pass
        exit_code = 1
    raise SystemExit(exit_code)
