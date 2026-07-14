from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Finding, User
from ..schemas import FindingCreate, FindingUpdate, FindingOut
from ..security import get_current_user, require_case_access
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    return db.query(Finding).filter(Finding.case_id == case_id).order_by(Finding.created_at.desc()).all()


@router.post("", response_model=FindingOut)
def create_finding(case_id: str, payload: FindingCreate, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    """Flags a specific artifact row (or a free-standing note, if no row is
    given) as an investigator's own finding, independent of anything the
    AI panel said. row_snapshot is stored as given (a snapshot of the row
    at flag time), so the finding still means something even if that row
    is later edited or the table re-imported."""
    require_case_access(case_id, user, db, need_edit=True)
    finding = Finding(
        case_id=case_id,
        machine_id=payload.machine_id,
        machine_label=payload.machine_label,
        table_name=payload.table_name,
        table_label=payload.table_label,
        row_rowid=payload.row_rowid,
        row_snapshot=payload.row_snapshot,
        note=payload.note,
        created_by=user.id,
        created_by_username=user.username,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    log_event(db, user, "finding.create", case_id=case_id, target_type="finding", target_id=finding.id,
              target_label=payload.table_label or "note", request=request)
    db.commit()
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(case_id: str, finding_id: str, payload: FindingUpdate, request: Request,
                    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.case_id == case_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.note = payload.note
    log_event(db, user, "finding.update", case_id=case_id, target_type="finding", target_id=finding.id,
              target_label=finding.table_label or "note", request=request)
    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/{finding_id}")
def delete_finding(case_id: str, finding_id: str, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.case_id == case_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    db.delete(finding)
    log_event(db, user, "finding.delete", case_id=case_id, target_type="finding", target_id=finding_id,
              target_label=finding.table_label or "note", request=request)
    db.commit()
    return {"ok": True}
