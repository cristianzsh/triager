import csv
import io
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import CorrelationQuery, CorrelationResult, CorrelationHit, FieldCatalogEntry
from ..security import get_current_user, require_case_access
from ..services import case_db
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/correlation", tags=["correlation"])


@router.get("/fields", response_model=list[FieldCatalogEntry])
def get_fields(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Artifact types and their columns, for the query-builder autocomplete."""
    require_case_access(case_id, user, db)
    return case_db.field_catalog(case_id)


@router.post("/search", response_model=CorrelationResult)
def correlate(case_id: str, payload: CorrelationQuery, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """A plain term searches across every table. A structured query like
    amcache.column contains x and prefetch.executablename contains x resolves
    each condition against matching tables and AND/OR-combines by machine."""
    require_case_access(case_id, user, db)
    result = case_db.correlate_query(
        case_id,
        payload.query,
        machine_ids=payload.machine_ids,
        case_sensitive=payload.case_sensitive,
        max_hits_per_table=payload.max_hits_per_table,
    )
    return CorrelationResult(
        query=payload.query,
        total_hits=len(result["hits"]),
        structured=result["structured"],
        hits=[CorrelationHit(**h) for h in result["hits"]],
    )


@router.get("/export.csv")
def export_correlation_csv(
    case_id: str,
    request: Request,
    query: str,
    machine_ids: list[str] | None = Query(None),
    case_sensitive: bool = False,
    max_hits_per_table: int = 500,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Streams correlation search results as CSV. Requires a Bearer JWT,
    so a plain <a href> won't work -- fetch with the auth header and
    trigger a blob download instead (see downloadAuthenticated() in the
    frontend)."""
    require_case_access(case_id, user, db)
    result = case_db.correlate_query(
        case_id, query, machine_ids=machine_ids, case_sensitive=case_sensitive,
        max_hits_per_table=max_hits_per_table,
    )

    log_event(
        db, user, "correlation.export_csv", case_id=case_id, target_type="correlation",
        details={"query": query}, request=request,
    )
    db.commit()

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Machine", "Table", "Matched Column", "Row Data (JSON)"])
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for h in result["hits"]:
            writer.writerow([
                h["machine_label"], h["table_label"], h["matched_column"],
                json.dumps(h["row"], ensure_ascii=False),
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return StreamingResponse(
        generate(), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="correlation_results.csv"'},
    )
