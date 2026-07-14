from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditEvent, User, Role
from ..schemas import AuditEventOut
from ..security import get_current_user, require_case_access, require_role

router = APIRouter(tags=["audit"])


@router.get("/cases/{case_id}/audit", response_model=list[AuditEventOut])
def case_audit_log(case_id: str, limit: int = 300, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Everything recorded against this case: ingests started, exports,
    membership changes, AI questions asked, deletions, oldest history
    first isn't useful here, so newest first."""
    require_case_access(case_id, user, db)
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.case_id == case_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(min(limit, 1000))
        .all()
    )


@router.get("/audit", response_model=list[AuditEventOut])
def global_audit_log(limit: int = 300, db: Session = Depends(get_db), _admin: User = Depends(require_role(Role.admin))):
    """System-wide feed (logins, user management, every case's activity), admin only, since it spans cases the requester may not otherwise have
    access to."""
    return db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(limit, 1000)).all()
