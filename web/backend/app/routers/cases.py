import shutil
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Case, CaseMember, Machine, Job, AIMessage, Finding, User, Role
from ..schemas import CaseCreate, CaseOut, CaseMemberAdd, CaseMemberOut, CaseStatusUpdate
from ..security import get_current_user, require_case_access, require_role
from ..services.audit import log_event

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseOut)
def create_case(payload: CaseCreate, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.admin, Role.lead))):
    case = Case(name=payload.name, reference=payload.reference, description=payload.description,
                created_by=user.id)
    db.add(case)
    db.commit()
    db.refresh(case)
    # Creator is automatically a case member with edit rights.
    db.add(CaseMember(case_id=case.id, user_id=user.id, can_edit=True))
    log_event(db, user, "case.create", case_id=case.id, target_type="case", target_id=case.id,
              target_label=case.name, request=request)
    db.commit()
    return case


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == Role.admin:
        return db.query(Case).order_by(Case.updated_at.desc()).all()
    case_ids = [m.case_id for m in db.query(CaseMember).filter(CaseMember.user_id == user.id).all()]
    return db.query(Case).filter(Case.id.in_(case_ids)).order_by(Case.updated_at.desc()).all()


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.patch("/{case_id}/status", response_model=CaseOut)
def set_case_status(case_id: str, payload: CaseStatusUpdate, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(require_role(Role.admin, Role.lead))):
    """Closes or reopens a case. Closing doesn't delete anything, it's
    just a status marker (the UI hides mutating actions like adding
    machines on a closed case); reopen it any time to keep working."""
    require_case_access(case_id, user, db, need_edit=True)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    case.status = payload.status
    log_event(db, user, f"case.{payload.status.value}", case_id=case_id, target_type="case",
              target_id=case_id, target_label=case.name, request=request)
    db.commit()
    db.refresh(case)
    return case


@router.delete("/{case_id}")
def delete_case(case_id: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role(Role.admin, Role.lead))):
    """
    Permanently deletes a case: every machine, job, and case-membership
    row, plus the on-disk case directory (case.sqlite with every machine's
    artifact tables, all raw/triager_out/job-log data). This cannot be
    undone, there is no soft-delete/trash for cases.
    """
    require_case_access(case_id, user, db, need_edit=True)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    case_name = case.name
    db.query(Job).filter(Job.case_id == case_id).delete()
    db.query(AIMessage).filter(AIMessage.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id).delete()
    db.query(Machine).filter(Machine.case_id == case_id).delete()
    db.query(CaseMember).filter(CaseMember.case_id == case_id).delete()
    db.delete(case)
    # The case itself is gone, so this event is recorded without a case_id
    # (it would otherwise dangle, the audit_events.case_id FK isn't
    # enforced by SQLite by default, but keeping it consistent matters more
    # than that leniency) while still naming what was deleted.
    log_event(db, user, "case.delete", case_id=None, target_type="case", target_id=case_id,
              target_label=case_name, request=request)
    db.commit()

    shutil.rmtree(settings.storage_root / "cases" / case_id, ignore_errors=True)
    return {"ok": True}


@router.get("/{case_id}/members", response_model=list[CaseMemberOut])
def list_members(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    rows = (
        db.query(CaseMember, User)
        .join(User, User.id == CaseMember.user_id)
        .filter(CaseMember.case_id == case_id)
        .order_by(User.username)
        .all()
    )
    return [
        CaseMemberOut(
            user_id=u.id, username=u.username, full_name=u.full_name, role=u.role, can_edit=m.can_edit
        )
        for m, u in rows
    ]


@router.post("/{case_id}/members")
def add_member(case_id: str, payload: CaseMemberAdd, request: Request, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)

    target: Optional[User] = None
    if payload.user_id:
        target = db.query(User).filter(User.id == payload.user_id).first()
        if not target:
            raise HTTPException(404, f"No user with id \"{payload.user_id}\"")
    elif payload.username:
        target = db.query(User).filter(User.username == payload.username).first()
        if not target:
            raise HTTPException(404, f"No user with username \"{payload.username}\"")
    else:
        raise HTTPException(400, "Provide either user_id or username")

    existing = db.query(CaseMember).filter(
        CaseMember.case_id == case_id, CaseMember.user_id == target.id
    ).first()
    if existing:
        existing.can_edit = payload.can_edit
    else:
        db.add(CaseMember(case_id=case_id, user_id=target.id, can_edit=payload.can_edit))
    log_event(db, user, "case.member_add", case_id=case_id, target_type="user", target_id=target.id,
              target_label=target.username, details={"can_edit": payload.can_edit}, request=request)
    db.commit()
    return {"ok": True, "user_id": target.id, "username": target.username}


@router.delete("/{case_id}/members/{user_id}")
def remove_member(case_id: str, user_id: str, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    target = db.query(User).filter(User.id == user_id).first()
    db.query(CaseMember).filter(
        CaseMember.case_id == case_id, CaseMember.user_id == user_id
    ).delete()
    log_event(db, user, "case.member_remove", case_id=case_id, target_type="user", target_id=user_id,
              target_label=target.username if target else user_id, request=request)
    db.commit()
    return {"ok": True}
