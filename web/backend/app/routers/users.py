from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Role, CaseMember
from ..schemas import UserCreate, UserUpdate, UserOut, UserSearchResult
from ..security import hash_password, require_role, get_current_user
from ..services.audit import log_event

router = APIRouter(prefix="/users", tags=["users"])


def _active_admin_count(db: Session, excluding_user_id: str | None = None) -> int:
    q = db.query(User).filter(User.role == Role.admin, User.is_active.is_(True))
    if excluding_user_id:
        q = q.filter(User.id != excluding_user_id)
    return q.count()


@router.get("/me", response_model=UserOut)
def read_me(user: User = Depends(get_current_user)):
    return user


@router.get("/search", response_model=list[UserSearchResult])
def search_users(q: str = "", db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """
    Username/full-name lookup available to any signed-in user (not just
    admins), powers the "Add member" autocomplete on a case, so a case
    lead can find the right person by name instead of being handed a raw
    user_id to copy-paste (and possibly mistype).
    """
    query = db.query(User).filter(User.is_active.is_(True))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.username.ilike(like), User.full_name.ilike(like)))
    return query.order_by(User.username).limit(20).all()


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_role(Role.admin))):
    return db.query(User).order_by(User.username).all()


@router.post("", response_model=UserOut)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(Role.admin))):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already exists")
    user = User(
        username=payload.username,
        full_name=payload.full_name,
        email=payload.email,
        role=payload.role,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    log_event(db, admin, "user.create", target_type="user", target_id=user.id,
              target_label=user.username, details={"role": payload.role.value}, request=request)
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: str, payload: UserUpdate, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(Role.admin))):
    """
    Unified edit endpoint: full name, email, role, active status, and an
    optional password reset, any subset at a time. Guards against locking
    everyone out: you can't demote or deactivate the last remaining active
    admin (including yourself).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")

    changes: dict = {}

    demoting = payload.role is not None and payload.role != Role.admin and user.role == Role.admin
    deactivating = payload.is_active is False and user.is_active
    if (demoting or deactivating) and _active_admin_count(db, excluding_user_id=user.id) == 0:
        raise HTTPException(400, "Can't remove the last remaining active admin")

    if payload.full_name is not None:
        changes["full_name"] = payload.full_name
        user.full_name = payload.full_name
    if payload.email is not None:
        changes["email"] = payload.email
        user.email = payload.email
    if payload.role is not None and payload.role != user.role:
        changes["role"] = {"old": user.role.value, "new": payload.role.value}
        user.role = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes["is_active"] = payload.is_active
        user.is_active = payload.is_active
    if payload.new_password:
        user.hashed_password = hash_password(payload.new_password)
        changes["password_reset"] = True

    if changes:
        log_event(db, admin, "user.update", target_type="user", target_id=user.id,
                  target_label=user.username, details=changes, request=request)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(user_id: str, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(Role.admin))):
    """
    Permanently deletes a user account and their case memberships. Case
    data they created/worked on is untouched, audit log entries and
    findings keep a denormalized username snapshot, so history stays
    readable even after the account is gone. You can't delete your own
    account, and you can't delete the last remaining active admin.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id:
        raise HTTPException(400, "You can't delete your own account while signed in as it")
    if user.role == Role.admin and user.is_active and _active_admin_count(db, excluding_user_id=user.id) == 0:
        raise HTTPException(400, "Can't delete the last remaining active admin")

    username = user.username
    db.query(CaseMember).filter(CaseMember.user_id == user_id).delete()
    db.delete(user)
    log_event(db, admin, "user.delete", target_type="user", target_id=user_id,
              target_label=username, request=request)
    db.commit()
    return {"ok": True}


@router.patch("/{user_id}/deactivate", response_model=UserOut)
def deactivate_user(user_id: str, request: Request, db: Session = Depends(get_db),
                     admin: User = Depends(require_role(Role.admin))):
    """Kept for backward compatibility, prefer PATCH /users/{id} with
    {"is_active": false}, which has the same last-admin safety guard."""
    return update_user(user_id, UserUpdate(is_active=False), request, db, admin)


@router.patch("/{user_id}/role", response_model=UserOut)
def change_role(user_id: str, role: Role, request: Request, db: Session = Depends(get_db),
                 admin: User = Depends(require_role(Role.admin))):
    """Kept for backward compatibility, prefer PATCH /users/{id} with
    {"role": ...}, which has the same last-admin safety guard."""
    return update_user(user_id, UserUpdate(role=role), request, db, admin)
