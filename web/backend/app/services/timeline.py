"""Unified timeline: merges rows from every table with a detected timestamp
column (see csv_importer._detect_and_populate_timeline_columns) into one
chronological stream across every machine in a case.

Cross-table pagination is a bounded k-way merge, not an exact sort over
everything: each table contributes up to offset + page_size rows (already
epoch-sorted at the SQL level), then the merge/slice happens in Python.
Exact for normal paging depth; very deep pagination may skip entries from
a table with more matches than its per-table cap allowed.
"""
from typing import Any, Optional

from .case_db import get_connection, ensure_meta_table, ensure_timeline_table, table_columns, safe_ident
from ..core import query_lang

_PER_TABLE_CAP = 5000


def list_timeline_sources(
    case_id: str, machine_ids: Optional[list[str]] = None, categories: Optional[list[str]] = None
) -> list[dict[str, Any]]:
    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        ensure_timeline_table(conn)
        rows = conn.execute(
            "SELECT tc.table_name, tc.column_name, tc.epoch_column, "
            "       am.category, am.table_label, am.machine_id, am.machine_label "
            "FROM _timeline_columns tc JOIN _artifact_meta am ON am.table_name = tc.table_name"
        ).fetchall()
        result = [dict(r) for r in rows]
        if machine_ids:
            wanted = set(machine_ids)
            result = [r for r in result if r["machine_id"] in wanted]
        if categories:
            wanted_cats = set(categories)
            result = [r for r in result if r["category"] in wanted_cats]
        return result
    finally:
        conn.close()


def timeline_field_catalog(case_id: str) -> list[dict[str, Any]]:
    conn = get_connection(case_id)
    try:
        ensure_meta_table(conn)
        ensure_timeline_table(conn)
        rows = conn.execute(
            "SELECT DISTINCT am.table_name, am.table_label "
            "FROM _timeline_columns tc JOIN _artifact_meta am ON am.table_name = tc.table_name"
        ).fetchall()
        by_label: dict[str, set[str]] = {}
        for r in rows:
            label = r["table_label"] or r["table_name"]
            by_label.setdefault(label, set()).update(table_columns(conn, r["table_name"]))
        return [
            {"label": label, "columns": sorted(c for c in cols if not c.endswith("__ts_epoch"))}
            for label, cols in sorted(by_label.items())
        ]
    finally:
        conn.close()


def query_timeline(
    case_id: str,
    machine_ids: Optional[list[str]] = None,
    categories: Optional[list[str]] = None,
    search: Optional[str] = None,
    query: Optional[str] = None,
    start_epoch: Optional[float] = None,
    end_epoch: Optional[float] = None,
    page: int = 1,
    page_size: int = 200,
) -> dict[str, Any]:
    conn = get_connection(case_id)
    try:
        sources = list_timeline_sources(case_id, machine_ids, categories)
        if not sources:
            return {"entries": [], "page": page, "page_size": page_size, "approx_total": 0, "sources_used": 0}

        parsed = query_lang.parse_query(query) if query else None

        offset = max(0, (page - 1) * page_size)
        per_table_limit = min(_PER_TABLE_CAP, offset + page_size)

        candidates: list[dict[str, Any]] = []
        approx_total = 0

        for src in sources:
            table = src["table_name"]
            safe_ident(table)
            epoch_col = src["epoch_column"]
            columns = table_columns(conn, table)
            if epoch_col not in columns:
                continue

            where_clauses = [f'"{epoch_col}" IS NOT NULL']
            params: list[Any] = []
            if start_epoch is not None:
                where_clauses.append(f'"{epoch_col}" >= ?')
                params.append(start_epoch)
            if end_epoch is not None:
                where_clauses.append(f'"{epoch_col}" <= ?')
                params.append(end_epoch)

            if parsed and parsed.conditions:
                frag, frag_params = _timeline_condition_group(parsed, src["table_label"], columns)
                if frag:
                    where_clauses.append(frag)
                    params.extend(frag_params)
            elif search:
                or_parts = [f'"{c}" LIKE ?' for c in columns if not c.endswith("__ts_epoch")]
                where_clauses.append("(" + " OR ".join(or_parts) + ")")
                params.extend([f"%{search}%"] * len(or_parts))

            where_sql = "WHERE " + " AND ".join(where_clauses)

            count_row = conn.execute(f"SELECT COUNT(*) AS c FROM {table} {where_sql}", params).fetchone()
            approx_total += count_row["c"] if count_row else 0

            rows = conn.execute(
                f'SELECT * FROM {table} {where_sql} ORDER BY "{epoch_col}" ASC LIMIT ?',
                params + [per_table_limit],
            ).fetchall()

            for r in rows:
                row_dict = dict(r)
                candidates.append({
                    "epoch": row_dict.get(epoch_col),
                    "machine_id": src["machine_id"],
                    "machine_label": src["machine_label"],
                    "category": src["category"],
                    "table": table,
                    "table_label": src["table_label"],
                    "timestamp_column": src["column_name"],
                    "row": row_dict,
                })

        candidates.sort(key=lambda c: c["epoch"])
        page_slice = candidates[offset: offset + page_size]

        return {
            "entries": page_slice,
            "page": page,
            "page_size": page_size,
            "approx_total": approx_total,
            "sources_used": len(sources),
        }
    finally:
        conn.close()


def _timeline_condition_group(parsed, table_label: str, columns: list[str]) -> tuple[str, list]:
    """A row belongs to one table, so conditions scoped to a different
    artifact label are dropped for that table (contributing nothing)
    rather than making it impossible for an AND query to ever match."""
    label_norm = query_lang.normalize_label(table_label)
    applicable = [c for c in parsed.conditions if not c.table or query_lang.normalize_label(c.table) == label_norm]
    if not applicable:
        if parsed.conditions and all(c.table for c in parsed.conditions):
            return "1=0", []
        return "", []

    lower_map = {c.lower(): c for c in columns}
    frags: list[str] = []
    params: list[Any] = []
    for cond in applicable:
        if cond.column:
            real_col = lower_map.get(cond.column.lower())
            if not real_col:
                continue
            frag, frag_params = query_lang.condition_sql(cond.op, real_col, cond.value)
        else:
            or_parts = [f'"{c}" LIKE ?' for c in columns if not c.endswith("__ts_epoch")]
            frag = "(" + " OR ".join(or_parts) + ")"
            frag_params = [f"%{cond.value}%"] * len(or_parts)
        frags.append(frag)
        params.extend(frag_params)

    if not frags:
        return "", []
    joiner = " AND " if parsed.logic == "and" else " OR "
    return "(" + joiner.join(frags) + ")", params
