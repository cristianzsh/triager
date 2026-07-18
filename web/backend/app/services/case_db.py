"""Per-case SQLite access: one file per case, shared by every machine in it."""
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Optional

from ..config import settings
from ..core import query_lang

_IDENT_RE = re.compile(r"^[A-Za-z0-9_]+$")


def case_db_path(case_id: str) -> Path:
    return settings.storage_root / "cases" / case_id / "case.sqlite"


def get_connection(case_id: str) -> sqlite3.Connection:
    path = case_db_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.create_function("REGEXP", 2, _regexp)
    return conn


def _regexp(pattern: str, value) -> bool:
    if value is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def safe_ident(name: str) -> str:
    """Only accepts identifiers our own importer generated, never raw user input."""
    if not _IDENT_RE.match(name):
        raise ValueError(f"Unsafe identifier rejected: {name!r}")
    return name


def ensure_meta_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _artifact_meta ("
        " table_name TEXT PRIMARY KEY, category TEXT, source_path TEXT, row_count INTEGER,"
        " machine_id TEXT, machine_label TEXT, table_label TEXT)"
    )
    conn.commit()


def ensure_timeline_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _timeline_columns ("
        " table_name TEXT, column_name TEXT, epoch_column TEXT, PRIMARY KEY(table_name, column_name))"
    )
    conn.commit()


def delete_machine_data(case_id: str, machine_id: str) -> None:
    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        ensure_timeline_table(conn)
        rows = conn.execute(
            "SELECT table_name FROM _artifact_meta WHERE machine_id = ?", (machine_id,)
        ).fetchall()
        for r in rows:
            conn.execute(f"DROP TABLE IF EXISTS {r['table_name']}")
            conn.execute(f"DROP TABLE IF EXISTS {r['table_name']}_fts")
            conn.execute("DELETE FROM _timeline_columns WHERE table_name = ?", (r["table_name"],))
        conn.execute("DELETE FROM _artifact_meta WHERE machine_id = ?", (machine_id,))
        conn.commit()
    finally:
        conn.close()


def list_tables(case_id: str, machine_id: Optional[str] = None) -> list[str]:
    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        if machine_id:
            rows = conn.execute(
                "SELECT table_name FROM _artifact_meta WHERE machine_id = ? ORDER BY table_name", (machine_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT table_name FROM _artifact_meta ORDER BY table_name").fetchall()
        return [r["table_name"] for r in rows]
    finally:
        conn.close()


def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    safe_ident(table)
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [r["name"] for r in rows]


def get_table_page(
    case_id: str,
    table: str,
    page: int = 1,
    page_size: int = 100,
    sort_column: Optional[str] = None,
    sort_dir: str = "asc",
    filters: Optional[dict[str, str]] = None,
    search: Optional[str] = None,
    query: Optional[str] = None,
) -> dict[str, Any]:
    """query is a structured filter string (see core/query_lang); search is
    the plain substring-across-all-columns mode. query takes precedence."""
    conn = get_connection(case_id)
    try:
        safe_ident(table)
        columns = table_columns(conn, table)
        if not columns:
            raise ValueError(f"Unknown artifact table: {table}")

        where_clauses: list[str] = []
        params: list[Any] = []

        if query:
            frag, frag_params = where_fragment_for_query(query, columns)
            if frag:
                where_clauses.append(frag)
                params.extend(frag_params)
        else:
            if filters:
                for col, val in filters.items():
                    if col not in columns:
                        continue
                    where_clauses.append(f'"{col}" LIKE ?')
                    params.append(f"%{val}%")
            if search:
                or_parts = [f'"{c}" LIKE ?' for c in columns]
                where_clauses.append("(" + " OR ".join(or_parts) + ")")
                params.extend([f"%{search}%"] * len(columns))

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        total_rows = conn.execute(f"SELECT COUNT(*) AS c FROM {table} {where_sql}", params).fetchone()["c"]

        order_sql = ""
        if sort_column and sort_column in columns:
            direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
            order_sql = f'ORDER BY "{sort_column}" {direction}'

        page = max(1, page)
        offset = (page - 1) * page_size
        rows = conn.execute(
            f"SELECT * FROM {table} {where_sql} {order_sql} LIMIT ? OFFSET ?",
            params + [page_size, offset],
        ).fetchall()

        return {
            "table": table,
            "columns": columns,
            "rows": [dict(r) for r in rows],
            "total_rows": total_rows,
            "page": page,
            "page_size": page_size,
        }
    finally:
        conn.close()


def where_fragment_for_query(query_text: str, columns: list[str]) -> tuple[str, list]:
    parsed = query_lang.parse_query(query_text)
    return _build_condition_group(parsed, columns)


def _resolve_column(name: str, columns: list[str]) -> Optional[str]:
    lower_map = {c.lower(): c for c in columns}
    return lower_map.get(name.lower())


def _build_condition_group(parsed: "query_lang.ParsedQuery", columns: list[str]) -> tuple[str, list]:
    """Builds one WHERE fragment for a single-table query, ignoring any
    table prefix on conditions (there's only one table in scope here)."""
    frags: list[str] = []
    params: list[Any] = []
    for cond in parsed.conditions:
        if cond.column:
            real_col = _resolve_column(cond.column, columns)
            if not real_col:
                continue
            frag, frag_params = query_lang.condition_sql(cond.op, real_col, cond.value)
        else:
            or_parts = [f'"{c}" LIKE ?' for c in columns]
            frag = "(" + " OR ".join(or_parts) + ")"
            frag_params = [f"%{cond.value}%"] * len(columns)
        frags.append(frag)
        params.extend(frag_params)

    if not frags:
        return "", []
    joiner = " AND " if parsed.logic == "and" else " OR "
    return "(" + joiner.join(frags) + ")", params


def field_catalog(
    case_id: str,
    machine_ids: Optional[Iterable[str]] = None,
    tables: Optional[Iterable[str]] = None,
) -> list[dict[str, Any]]:
    """Distinct artifact types (by table_label) available for filtering,
    with the union of their columns, powers the autocomplete while typing
    a structured query."""
    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        rows = conn.execute("SELECT table_name, table_label, machine_id FROM _artifact_meta").fetchall()
        if machine_ids:
            wanted = set(machine_ids)
            rows = [r for r in rows if r["machine_id"] in wanted]
        if tables:
            wanted_tables = set(tables)
            rows = [r for r in rows if r["table_name"] in wanted_tables]

        by_label: dict[str, set[str]] = {}
        for r in rows:
            label = r["table_label"] or r["table_name"]
            cols = by_label.setdefault(label, set())
            cols.update(table_columns(conn, r["table_name"]))

        return [
            {"label": label, "columns": sorted(c for c in cols if not c.endswith("__ts_epoch"))}
            for label, cols in sorted(by_label.items())
        ]
    finally:
        conn.close()


def _value_matches_case_sensitive(op: str, cell_value, needle: str) -> bool:
    """SQLite's LIKE is case-insensitive by default, so a case_sensitive=True
    request still needs this Python-level re-check against the actual cell
    value for the ops that compile to LIKE/NOT LIKE. = and != already do a
    byte-wise (case-sensitive) comparison at the SQL level, so they don't
    need this."""
    cell = "" if cell_value is None else str(cell_value)
    if op == "contains":
        return needle in cell
    if op == "not_contains":
        return needle not in cell
    if op == "startswith":
        return cell.startswith(needle)
    if op == "endswith":
        return cell.endswith(needle)
    return True


def correlate_query(
    case_id: str,
    query_text: str,
    machine_ids: Optional[Iterable[str]] = None,
    case_sensitive: bool = False,
    max_hits_per_table: int = 500,
) -> dict[str, Any]:
    """Structured, cross-table, cross-machine correlation. A plain term
    (no table/column/operator) behaves like a simple search across every
    table via FTS. A structured query (e.g. amcache.column contains X and
    prefetch.executablename contains X) resolves each condition against
    every table whose artifact label matches, then AND/OR-combines the set
    of machines that satisfy each condition."""
    parsed = query_lang.parse_query(query_text)
    if not parsed.conditions:
        return {"hits": [], "structured": False}

    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        meta_rows = conn.execute(
            "SELECT table_name, table_label, machine_id, machine_label FROM _artifact_meta"
        ).fetchall()
        meta_by_table = {r["table_name"]: dict(r) for r in meta_rows}
        if machine_ids:
            wanted = set(machine_ids)
            meta_by_table = {t: m for t, m in meta_by_table.items() if m["machine_id"] in wanted}

        if not parsed.structured:
            hits = _simple_term_search(conn, parsed.conditions[0].value, meta_by_table, case_sensitive, max_hits_per_table)
            return {"hits": hits, "structured": False}

        per_condition_hits: list[list[dict]] = []
        per_condition_machines: list[set] = []

        for cond in parsed.conditions:
            candidate_tables = _tables_for_condition(cond, meta_by_table)
            cond_hits: list[dict] = []
            cond_machines: set = set()

            for table in candidate_tables:
                columns = table_columns(conn, table)
                if not columns:
                    continue

                if cond.column:
                    real_col = _resolve_column(cond.column, columns)
                    if not real_col:
                        continue
                    op_value = cond.value
                    if cond.op == "regex" and not case_sensitive:
                        # REGEXP's registered function (_regexp below) is
                        # always case-sensitive regardless of this flag --
                        # an inline (?i) makes it respect case_sensitive=False.
                        op_value = f"(?i){cond.value}"
                    frag, params = query_lang.condition_sql(cond.op, real_col, op_value)
                else:
                    or_parts = [f'"{c}" LIKE ?' for c in columns]
                    frag = "(" + " OR ".join(or_parts) + ")"
                    params = [f"%{cond.value}%"] * len(columns)

                try:
                    rows = conn.execute(
                        f"SELECT * FROM {table} WHERE {frag} LIMIT ?", params + [max_hits_per_table]
                    ).fetchall()
                except sqlite3.OperationalError:
                    continue

                meta = meta_by_table.get(table, {})
                for r in rows:
                    row_dict = dict(r)
                    if cond.column:
                        matched_col = cond.column
                        if case_sensitive and cond.op in ("contains", "not_contains", "startswith", "endswith"):
                            if not _value_matches_case_sensitive(cond.op, row_dict.get(real_col), cond.value):
                                continue
                    else:
                        matched_col = _first_matching_column(row_dict, columns, cond.value, case_sensitive)
                        if case_sensitive and cond.op in ("contains", "not_contains") and not matched_col:
                            continue
                    cond_hits.append({
                        "table": table,
                        "table_label": meta.get("table_label") or table,
                        "machine_id": meta.get("machine_id") or "",
                        "machine_label": meta.get("machine_label") or "(unknown machine)",
                        "row": row_dict,
                        "matched_column": matched_col or "",
                    })
                    cond_machines.add(meta.get("machine_id"))

            per_condition_hits.append(cond_hits)
            per_condition_machines.append(cond_machines)

        if parsed.logic == "and":
            qualifying = set.intersection(*per_condition_machines) if per_condition_machines else set()
        else:
            qualifying = set.union(*per_condition_machines) if per_condition_machines else set()

        final_hits = [h for cond_hits in per_condition_hits for h in cond_hits if h["machine_id"] in qualifying]
        return {"hits": final_hits, "structured": True, "logic": parsed.logic}
    finally:
        conn.close()


def _tables_for_condition(cond, meta_by_table: dict[str, dict]) -> list[str]:
    if not cond.table:
        return list(meta_by_table.keys())
    target = query_lang.normalize_label(cond.table)
    return [
        t for t, m in meta_by_table.items()
        if query_lang.normalize_label(m.get("table_label") or "") == target
        or target in query_lang.normalize_label(t)
    ]


def _first_matching_column(row: dict, columns: list[str], value: str, case_sensitive: bool) -> str:
    needle = value if case_sensitive else value.lower()
    for c in columns:
        val = str(row.get(c, "") or "")
        hay = val if case_sensitive else val.lower()
        if needle in hay:
            return c
    return ""


def _simple_term_search(
    conn: sqlite3.Connection,
    term: str,
    meta_by_table: dict[str, dict],
    case_sensitive: bool,
    max_hits_per_table: int,
) -> list[dict]:
    hits: list[dict] = []
    for table in meta_by_table:
        safe_ident(table)
        fts_table = f"{table}_fts"
        has_fts = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (fts_table,)
        ).fetchone()
        columns = table_columns(conn, table)
        if not columns:
            continue

        fetch_limit = max_hits_per_table * 5 if case_sensitive else max_hits_per_table

        if has_fts:
            rows = conn.execute(
                f"SELECT t.* FROM {fts_table} f JOIN {table} t ON t.rowid = f.rowid "
                f"WHERE {fts_table} MATCH ? LIMIT ?",
                (f'"{term}"*', fetch_limit),
            ).fetchall()
        else:
            needle = f"%{term}%"
            or_parts = [f'"{c}" LIKE ?' for c in columns]
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE (" + " OR ".join(or_parts) + ") LIMIT ?",
                [needle] * len(columns) + [fetch_limit],
            ).fetchall()

        meta = meta_by_table.get(table, {})
        table_hits = 0
        for r in rows:
            if table_hits >= max_hits_per_table:
                break
            row_dict = dict(r)
            matched_col = _first_matching_column(row_dict, columns, term, case_sensitive)
            if not matched_col:
                continue
            hits.append({
                "table": table,
                "table_label": meta.get("table_label") or table,
                "machine_id": meta.get("machine_id") or "",
                "machine_label": meta.get("machine_label") or "(unknown machine)",
                "row": row_dict,
                "matched_column": matched_col,
            })
            table_hits += 1

    return hits
