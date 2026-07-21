"""
Safe ZIP extraction for both evidence collections and pre-processed Triager
output archives. Ported from Triager's own _extract_zip_to_temp, but writes
into a stable, case-scoped directory (not a temp dir that gets wiped), and
extracts in a background thread since evidence archives can be tens of GB.
"""
import hashlib
import os
import shutil
import time
import zipfile
from pathlib import Path
from typing import Callable, Optional

ILLEGAL_CHARS = set('<>:"/\\|?*')


def _sanitize_component(s: str) -> str:
    s = "".join("_" if (c in ILLEGAL_CHARS or ord(c) < 32) else c for c in s)
    s = s.strip(" .")
    return s or "_"


def _safe_join(root: Path, rel: str) -> Path:
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or rel.startswith("../") or "/../" in rel:
        raise ValueError(f"Unsafe zip member path: {rel}")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    safe_parts = [_sanitize_component(p) for p in parts]
    return (root / Path(*safe_parts)).resolve()


def _truncate_path(p: Path, max_name: int = 120) -> Path:
    name = p.name
    if len(name) <= max_name:
        return p
    stem, ext = os.path.splitext(name)
    h = hashlib.sha1(name.encode("utf-8", errors="ignore")).hexdigest()[:10]
    keep = max(1, max_name - len(ext) - 11)
    return p.with_name(f"{stem[:keep]}_{h}{ext}")


def _apply_zip_mtime(path: Path, zi: zipfile.ZipInfo) -> None:
    """Better than every extracted file silently looking like
    it was touched right now."""
    try:
        ts = time.mktime(zi.date_time + (0, 0, -1))
        os.utime(path, (ts, ts))
    except (ValueError, OverflowError, OSError):
        pass  # some entries carry an all-zero/invalid date; leave extraction time as-is


def extract_zip(
    zip_path: Path,
    dest_root: Path,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    skip_large_files: bool = False,
    max_file_size_bytes: int = 0,
    log_cb: Optional[Callable[[str], None]] = None,
) -> Path:
    """
    Extracts zip_path under dest_root. Returns the effective root
    (unwraps a single top-level directory, matching Triager's own
    behavior, so config-relative paths resolve the same via web or CLI).

    If skip_large_files, any member over max_file_size_bytes is never
    written to disk (size is already known from the archive's own
    central directory, so this is free to check).
    """
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"Not a valid zip file: {zip_path}")

    dest_root.mkdir(parents=True, exist_ok=True)
    warned = 0
    skipped_large = 0
    skipped_large_bytes = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = [zi for zi in zf.infolist() if not zi.filename.endswith("/")]
        total = len(members)
        for i, zi in enumerate(members, 1):
            raw_name = zi.filename.replace("\\", "/")

            if skip_large_files and max_file_size_bytes and zi.file_size > max_file_size_bytes:
                skipped_large += 1
                skipped_large_bytes += zi.file_size
                if log_cb:
                    log_cb(
                        f"Skipping large file ({zi.file_size / (1024 * 1024):.1f} MB, "
                        f"over {max_file_size_bytes / (1024 * 1024):.0f} MB limit): {zi.filename}"
                    )
                if progress_cb:
                    progress_cb(i, total)
                continue

            try:
                out_path = _safe_join(dest_root, raw_name)
                out_path = _truncate_path(out_path)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(zi, "r") as src, out_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
                _apply_zip_mtime(out_path, zi)
            except Exception:
                warned += 1
                continue
            if progress_cb:
                progress_cb(i, total)

    if skipped_large and log_cb:
        log_cb(
            f"Skipped {skipped_large} large file(s) ({skipped_large_bytes / (1024 * 1024):.1f} MB total) "
            f"not extracted (skip-large-files enabled)."
        )

    try:
        children = [p for p in dest_root.iterdir() if p.name not in (".DS_Store", "__MACOSX")]
        if len(children) == 1 and children[0].is_dir():
            return children[0].resolve()
    except Exception:
        pass

    return dest_root
