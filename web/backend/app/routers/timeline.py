import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.taxonomy import CATEGORIES
from ..database import get_db
from ..models import User
from ..schemas import TimelineQuery, TimelineResult, TimelineEntry, FieldCatalogEntry
from ..security import get_current_user, require_case_access
from ..services import timeline

_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def _safe_timestamp(epoch):
    if epoch is None:
        return None
    try:
        return _EPOCH + dt.timedelta(seconds=float(epoch))
    except (OverflowError, ValueError, OSError, TypeError):
        return None


router = APIRouter(prefix="/cases/{case_id}/timeline", tags=["timeline"])


@router.get("/sources")
def get_timeline_sources(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Categories that actually have timeline data, for the filter checkboxes."""
    require_case_access(case_id, user, db)
    sources = timeline.list_timeline_sources(case_id)
    seen = {}
    for s in sources:
        seen.setdefault(s["category"], CATEGORIES.get(s["category"], {}).get("label", s["category"]))
    return [{"key": k, "label": v} for k, v in seen.items()]


@router.get("/fields", response_model=list[FieldCatalogEntry])
def get_fields(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Artifact types and columns available in the timeline, for query autocomplete."""
    require_case_access(case_id, user, db)
    return timeline.timeline_field_catalog(case_id)


@router.post("/query", response_model=TimelineResult)
def query_timeline(case_id: str, payload: TimelineQuery, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)

    start_epoch = payload.start.replace(tzinfo=dt.timezone.utc).timestamp() if payload.start else None
    end_epoch = payload.end.replace(tzinfo=dt.timezone.utc).timestamp() if payload.end else None

    result = timeline.query_timeline(
        case_id,
        machine_ids=payload.machine_ids,
        categories=payload.categories,
        search=payload.search,
        query=payload.query,
        start_epoch=start_epoch,
        end_epoch=end_epoch,
        page=payload.page,
        page_size=min(payload.page_size, 1000),
    )

    entries = []
    for e in result["entries"]:
        ts = _safe_timestamp(e["epoch"])
        if ts is None:
            continue
        entries.append(TimelineEntry(
            timestamp=ts,
            machine_id=e["machine_id"],
            machine_label=e["machine_label"],
            category=e["category"],
            category_label=CATEGORIES.get(e["category"], {}).get("label", e["category"]),
            table=e["table"],
            table_label=e["table_label"],
            timestamp_column=e["timestamp_column"],
            row=e["row"],
        ))

    return TimelineResult(
        entries=entries,
        page=result["page"],
        page_size=result["page_size"],
        approx_total=result["approx_total"],
        sources_used=result["sources_used"],
    )
