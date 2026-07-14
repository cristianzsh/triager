import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import ArtifactCategory, ArtifactQuery, ArtifactPage
from ..security import get_current_user, require_case_access
from ..services import case_db, csv_importer
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/machines/{machine_id}/artifacts", tags=["artifacts"])


@router.get("/categories", response_model=list[ArtifactCategory])
def get_categories(case_id: str, machine_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Powers the per-machine artifact picker: one entry per artifact
    category (Prefetch, Event Logs, Registry, ...) for this machine only."""
    require_case_access(case_id, user, db)
    return csv_importer.list_categories(case_id, machine_id)


@router.post("/query", response_model=ArtifactPage)
def query_table(case_id: str, machine_id: str, payload: ArtifactQuery, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    try:
        result = case_db.get_table_page(
            case_id,
            payload.table,
            page=payload.page,
            page_size=min(payload.page_size, 1000),
            sort_column=payload.sort_column,
            sort_dir=payload.sort_dir or "asc",
            filters=payload.filters,
            search=payload.search,
            query=payload.query,
        )
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    return result


@router.get("/tables/{table}/export.csv")
def export_table_csv(
    case_id: str,
    machine_id: str,
    table: str,
    request: Request,
    query: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Streams a table as CSV. Pass ?query=<term or structured query> to
    export only the filtered rows; omit it for a full export. Requires a
    Bearer JWT, so a plain <a href> won't work, fetch with credentials
    and trigger a blob download instead."""
    require_case_access(case_id, user, db)
    conn = case_db.get_connection(case_id)
    case_db.safe_ident(table)
    columns = case_db.table_columns(conn, table)
    if not columns:
        conn.close()
        raise HTTPException(404, "Unknown table")

    log_event(
        db, user, "artifact.export_csv", case_id=case_id, target_type="table", target_id=table,
        target_label=table, details={"machine_id": machine_id, "filtered": bool(query), "query": query},
        request=request,
    )
    db.commit()

    where_sql = ""
    params: list[str] = []
    if query:
        frag, params = case_db.where_fragment_for_query(query, columns)
        if frag:
            where_sql = f"WHERE {frag}"

    def generate():
        # conn must stay open until streaming finishes, not just this handler
        try:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(columns)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            cursor = conn.execute(f"SELECT * FROM {table} {where_sql}", params)
            while True:
                rows = cursor.fetchmany(2000)
                if not rows:
                    break
                for row in rows:
                    writer.writerow(list(row))
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        finally:
            conn.close()

    suffix = "_filtered" if query else ""
    return StreamingResponse(
        generate(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{table}{suffix}.csv"'},
    )
