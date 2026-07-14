from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import CorrelationQuery, CorrelationResult, CorrelationHit, FieldCatalogEntry
from ..security import get_current_user, require_case_access
from ..services import case_db

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
