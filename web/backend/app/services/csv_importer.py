"""
Imports Triager's CSV output into the case's queryable SQLite database, for
one machine at a time.

Design choices:
  - Every column is stored as TEXT. Forensic CSV output is heterogeneous
    (mixed date formats, hex, free text); type coercion happens at query
    time, not import time, so nothing is silently dropped or reinterpreted.
  - Each artifact table gets a companion FTS5 table (<table>_fts) over
    all its columns, for fast correlation search even over multi-million-
    row exports.
  - Tables are namespaced per machine (m_<machine_id>__<artifact>) so one
    case's database holds many machines without collisions.
  - Import is streamed and batched (5000 rows/txn) so multi-GB CSVs don't
    blow up memory.
  - Re-running import for a machine drops and recreates its tables so
    re-imports don't leave stale duplicate rows.
"""
import csv
import re
import sqlite3
import time
from pathlib import Path
from typing import Callable, Optional

from ..config import settings
from ..core.taxonomy import category_for_relpath, SKIP_NAME_HINTS
from .case_db import get_connection, safe_ident, ensure_meta_table, ensure_timeline_table, table_columns

_NON_IDENT = re.compile(r"[^A-Za-z0-9_]+")


def _sanitize_ident(name: str) -> str:
    s = _NON_IDENT.sub("_", name).strip("_")
    if not s:
        s = "col"
    if s[0].isdigit():
        s = f"c_{s}"
    return s


def _artifact_name_for(rel_path: Path) -> str:
    # e.g. Registry/Shimcache/Shimcache.csv -> registry_shimcache_shimcache
    parts = [p for p in rel_path.with_suffix("").parts]
    joined = "_".join(_sanitize_ident(p) for p in parts)
    return joined.lower()[:100]


def _humanize_table_name(artifact_name: str, category_folder_prefix_words: set[str]) -> str:
    """Turns 'evidence_of_execution_prefetch_prefetch' into 'Prefetch' by
    stripping the leading category-folder words and de-duplicating the
    trailing repeat (Triager's own tool CSVs are often named the same as
    their parent folder, e.g. Prefetch/Prefetch.csv)."""
    words = artifact_name.split("_")
    while words and words[0].lower() in category_folder_prefix_words:
        words.pop(0)
    deduped = []
    for w in words:
        if deduped and deduped[-1].lower() == w.lower():
            continue
        deduped.append(w)
    if not deduped:
        deduped = artifact_name.split("_")
    return " ".join(w.capitalize() if w.islower() else w for w in deduped)


ENCODING_CANDIDATES = ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "latin-1")


def _iter_csv_files(output_dir: Path):
    for p in sorted(output_dir.rglob("*.csv")):
        if not p.is_file():
            continue
        if any(hint in p.name.lower() for hint in SKIP_NAME_HINTS):
            continue
        if p.stat().st_size == 0:
            continue
        yield p


def import_output_dir(
    case_id: str,
    machine_id: str,
    machine_label: str,
    table_prefix: str,
    output_dir: Path,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> dict:
    """Returns {tables: [...], total_rows: N, skipped: [...]}. Drops and
    recreates every table tagged with this machine_id first, so re-ingest
    doesn't duplicate rows. This is the final, authoritative import --
    always supersedes whatever import_incremental() produced meanwhile."""
    from .case_db import delete_machine_data
    delete_machine_data(case_id, machine_id)

    conn = get_connection(case_id)
    ensure_meta_table(conn)
    ensure_timeline_table(conn)
    summary = {"tables": [], "total_rows": 0, "skipped": []}

    csv_files = list(_iter_csv_files(output_dir))
    total_files = len(csv_files)

    for idx, csv_path in enumerate(csv_files, 1):
        rel_path = csv_path.relative_to(output_dir)
        result = _import_single_file(conn, machine_id, machine_label, table_prefix, output_dir, csv_path)

        if result is None:
            if progress_cb:
                progress_cb(str(rel_path), idx, total_files)
            continue
        if "error" in result:
            summary["skipped"].append({"path": str(rel_path), "error": result["error"]})
            if progress_cb:
                progress_cb(str(rel_path), idx, total_files)
            continue

        summary["tables"].append({"table": result["table"], "category": result["category"], "rows": result["rows"]})
        summary["total_rows"] += result["rows"]

        if progress_cb:
            progress_cb(str(rel_path), idx, total_files)

    conn.close()
    return summary


def _import_single_file(
    conn: sqlite3.Connection,
    machine_id: str,
    machine_label: str,
    table_prefix: str,
    output_dir: Path,
    csv_path: Path,
) -> Optional[dict]:
    """Imports exactly one CSV into its table and records it in
    _artifact_meta (+ timeline detection). Returns {"table", "category",
    "rows"} on success, {"error": ...} if the import failed, or None if the
    file was empty (nothing to record). Shared by the full rebuild
    (import_output_dir) and the incremental, best-effort importer that runs
    while Triager is still executing (import_incremental)."""
    rel_path = csv_path.relative_to(output_dir)
    artifact_name = _artifact_name_for(rel_path)
    table = f"{table_prefix}__{artifact_name}"
    category = category_for_relpath(str(rel_path)) or "meta"

    from ..core.taxonomy import CATEGORIES
    folder_words = {w.lower() for w in CATEGORIES.get(category, {}).get("folder", "").split(" ")}
    table_label = _humanize_table_name(artifact_name, folder_words)

    try:
        row_count = _import_one_csv(conn, table, csv_path)
    except Exception as ex:  # noqa: BLE001
        return {"error": str(ex)}

    conn.execute(
        "INSERT OR REPLACE INTO _artifact_meta "
        "(table_name, category, source_path, row_count, machine_id, machine_label, table_label) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (table, category, str(rel_path), row_count, machine_id, machine_label, table_label),
    )
    conn.commit()

    if row_count > 0:
        try:
            _detect_and_populate_timeline_columns(conn, table)
        except Exception:  # noqa: BLE001
            # Timeline enrichment is a bonus, never a reason to fail the
            # whole import, the table itself is already good.
            pass

    return {"table": table, "category": category, "rows": row_count}


def import_incremental(
    case_id: str,
    machine_id: str,
    machine_label: str,
    table_prefix: str,
    output_dir: Path,
    already_imported: set[str],
    quiet_seconds: float = 5.0,
) -> set[str]:
    """
    Best-effort partial import, run periodically while Triager is still
    executing (each parser writes its CSV as soon as it finishes, well
    before the whole run exits), so an investigator can start browsing
    before the run completes.

    Unlike import_output_dir(), never wipes existing tables -- only adds
    files not already in already_imported, and only once a file has been
    "quiet" (unchanged size/mtime) for quiet_seconds, a cheap guard against
    reading one Triager might still be writing.

    Not the final word: once Triager exits, import_output_dir() does a
    full clean rebuild, so anything picked up here just becomes visible
    sooner.

    Returns the updated already_imported set for the next call.
    """
    conn = get_connection(case_id)
    ensure_meta_table(conn)
    ensure_timeline_table(conn)
    now = time.time()
    updated = set(already_imported)

    try:
        for csv_path in _iter_csv_files(output_dir):
            rel_path = str(csv_path.relative_to(output_dir))
            if rel_path in updated:
                continue
            try:
                mtime = csv_path.stat().st_mtime
            except OSError:
                continue
            if now - mtime < quiet_seconds:
                continue  # possibly still being written, try again next pass

            _import_single_file(conn, machine_id, machine_label, table_prefix, output_dir, csv_path)
            updated.add(rel_path)
    finally:
        conn.close()

    return updated


def _import_one_csv(conn: sqlite3.Connection, table: str, csv_path: Path) -> int:
    """
    Imports one CSV, auto-detecting its text encoding.

    A short-prefix probe isn't reliable here: decode errors are relative
    to the internal read buffer, not the file offset, so a file can look
    fine for a while (e.g. BrowsingHistoryView's UTF-16 CSVs, which pass
    as valid UTF-8 until a real non-ASCII byte finally shows up) and still
    fail later. So detection does a full-file pass, but a cheap one --
    just decoding in large chunks, no CSV parsing or SQLite writes. Only
    once an encoding is confirmed to decode the whole file does the real
    import run, exactly once, rather than re-running the expensive
    row-by-row import per candidate and rolling back on failure (which,
    on a multi-GB artifact like MFT, could look like a hang if a wrong
    guess failed deep into the file).
    """
    safe_ident(table)
    encoding = _detect_encoding(csv_path)
    errors = "strict" if encoding else "replace"
    # Detection already proved this encoding decodes cleanly, or (if every
    # candidate failed) falls back to UTF-8/errors='replace', which never
    # raises -- a CSV is never skipped outright over an encoding guess.
    return _import_one_csv_with_encoding(conn, table, csv_path, encoding or "utf-8", errors=errors)


def _detect_encoding(csv_path: Path) -> Optional[str]:
    """Cheap full-file validation: decode in large chunks with no CSV
    parsing or database work, so trying several candidates on a huge file
    is fast. Returns None if nothing decodes cleanly (caller falls back to
    utf-8/errors=replace)."""
    chunk_chars = 1024 * 1024  # 1M characters per read, not the whole file at once
    for encoding in ENCODING_CANDIDATES:
        try:
            with csv_path.open("r", encoding=encoding, errors="strict", newline="") as f:
                while f.read(chunk_chars):
                    pass
            return encoding
        except UnicodeError:
            continue
    return None


def _import_one_csv_with_encoding(conn: sqlite3.Connection, table: str, csv_path: Path, encoding: str, errors: str) -> int:
    row_count = 0
    f = csv_path.open("r", encoding=encoding, errors=errors, newline="")

    try:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return 0

        columns = [_sanitize_ident(h) for h in header]
        seen: dict[str, int] = {}
        final_columns = []
        for c in columns:
            if c in seen:
                seen[c] += 1
                c = f"{c}_{seen[c]}"
            else:
                seen[c] = 0
            final_columns.append(c)
        columns = final_columns

        conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.execute(f"DROP TABLE IF EXISTS {table}_fts")
        col_defs = ", ".join(f'"{c}" TEXT' for c in columns)
        conn.execute(f"CREATE TABLE {table} ({col_defs})")

        placeholders = ", ".join(["?"] * len(columns))
        insert_sql = f"INSERT INTO {table} VALUES ({placeholders})"

        batch: list[tuple] = []
        batch_size = settings.csv_import_batch_rows

        # Iterating reader is where a bad-encoding guess actually surfaces
        # (csv.reader pulls from the underlying text file lazily, so this is
        # the point a UnicodeDecodeError from a later buffer would raise).
        for row in reader:
            if len(row) < len(columns):
                row = row + [""] * (len(columns) - len(row))
            elif len(row) > len(columns):
                row = row[: len(columns)]
            batch.append(tuple(row))
            row_count += 1
            if len(batch) >= batch_size:
                conn.executemany(insert_sql, batch)
                conn.commit()
                batch.clear()

        if batch:
            conn.executemany(insert_sql, batch)
            conn.commit()

        fts_cols = ", ".join(f'"{c}"' for c in columns)
        conn.execute(
            f"CREATE VIRTUAL TABLE {table}_fts USING fts5({fts_cols}, content='{table}', content_rowid='rowid')"
        )
        conn.execute(f"INSERT INTO {table}_fts(rowid, {fts_cols}) SELECT rowid, {fts_cols} FROM {table}")
        conn.commit()

        return row_count
    finally:
        f.close()


def _detect_and_populate_timeline_columns(conn: sqlite3.Connection, table: str) -> None:
    """
    Finds columns that look like timestamps by name (see
    core/timeline_heuristics.py), confirms by sampling values, and adds a
    "<col>__ts_epoch" REAL column with each row's parsed Unix epoch,
    computed once here so the unified timeline can ORDER BY/range-filter
    in SQL instead of parsing timestamps per request.
    """
    from ..core.timeline_heuristics import looks_like_timestamp_name, sample_parse_rate, try_parse_datetime

    columns = table_columns(conn, table)
    candidates = [c for c in columns if looks_like_timestamp_name(c)]
    if not candidates:
        return

    for col in candidates:
        sample_rows = conn.execute(
            f'SELECT "{col}" FROM {table} WHERE "{col}" IS NOT NULL AND "{col}" != \'\' LIMIT 300'
        ).fetchall()
        values = [r[0] for r in sample_rows]
        if not values or sample_parse_rate(values) < 0.5:
            continue

        epoch_col = f"{col}__ts_epoch"
        conn.execute(f'ALTER TABLE {table} ADD COLUMN "{epoch_col}" REAL')

        cursor = conn.execute(f'SELECT rowid, "{col}" FROM {table}')
        batch: list[tuple] = []
        while True:
            chunk = cursor.fetchmany(5000)
            if not chunk:
                break
            for rowid, value in chunk:
                parsed = try_parse_datetime(value) if value else None
                if parsed is not None:
                    batch.append((parsed.timestamp(), rowid))
            if batch:
                conn.executemany(f'UPDATE {table} SET "{epoch_col}" = ? WHERE rowid = ?', batch)
                conn.commit()
                batch.clear()

        conn.execute(
            "INSERT OR REPLACE INTO _timeline_columns (table_name, column_name, epoch_column) VALUES (?, ?, ?)",
            (table, col, epoch_col),
        )
        conn.commit()


def list_categories(case_id: str, machine_id: str) -> list[dict]:
    """Categories + tables for exactly one machine (used to drive the
    per-machine artifact sidebar/category grid)."""
    from ..core.taxonomy import CATEGORIES

    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        rows = conn.execute(
            "SELECT table_name, category, row_count, table_label FROM _artifact_meta "
            "WHERE machine_id = ? ORDER BY category, table_name",
            (machine_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()

    by_category: dict[str, list[dict]] = {}
    for r in rows:
        by_category.setdefault(r["category"], []).append(
            {"table_name": r["table_name"], "row_count": r["row_count"] or 0, "table_label": r["table_label"]}
        )

    result = []
    for key, meta in CATEGORIES.items():
        tables = [
            {"name": t["table_name"], "label": t["table_label"] or t["table_name"], "row_count": t["row_count"]}
            for t in by_category.get(key, [])
        ]
        result.append({"key": key, "label": meta["label"], "tables": tables})
    return result
