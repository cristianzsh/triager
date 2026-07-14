from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas import IOCScanRequest, IOCScanResult, IOCHitGroup, CorrelationHit
from ..security import get_current_user, require_case_access
from ..services import case_db
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/ioc-scan", tags=["ioc-scan"])


def _parse_iocs(text: str) -> list[str]:
    """Same format as Triager CLI's iocs.txt: one IOC per line, '#'-prefixed
    lines are comments, blank lines are ignored."""
    iocs: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        iocs.append(line)
    return iocs


@router.post("", response_model=IOCScanResult)
def scan_iocs(case_id: str, payload: IOCScanRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Scans a pasted IOC list across every artifact table in the case, like Triager CLI's --find-iocs."""
    require_case_access(case_id, user, db)
    iocs = _parse_iocs(payload.iocs_text)

    groups: list[IOCHitGroup] = []
    for ioc in iocs:
        result = case_db.correlate_query(
            case_id, ioc,
            machine_ids=payload.machine_ids,
            case_sensitive=payload.case_sensitive,
            max_hits_per_table=payload.max_hits_per_ioc,
        )
        hits = result["hits"]
        if hits:
            groups.append(IOCHitGroup(
                ioc=ioc, total_hits=len(hits),
                hits=[CorrelationHit(**h) for h in hits[: payload.max_hits_per_ioc]],
            ))

    log_event(
        db, user, "ioc_scan.run", case_id=case_id, target_type="ioc_scan",
        details={"scanned": len(iocs), "matched": len(groups)},
        request=request,
    )
    db.commit()

    return IOCScanResult(scanned_iocs=len(iocs), matched_iocs=len(groups), groups=groups)
