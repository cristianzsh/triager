from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from ..core.config_validate import ConfigValidationError, validate_triage_config
from ..database import get_db
from ..models import CustomTriageConfig, Role, User
from ..schemas import CustomConfigOut
from ..security import get_current_user, require_role
from ..services.audit import log_event

router = APIRouter(prefix="/configs", tags=["configs"])


@router.get("", response_model=list[CustomConfigOut])
def list_configs(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return db.query(CustomTriageConfig).order_by(CustomTriageConfig.created_at.desc()).all()


@router.post("", response_model=CustomConfigOut)
async def upload_config(
    request: Request,
    name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.admin, Role.lead, Role.investigator)),
):
    """Validates and stores a custom triage .yml, reusable across future
    ingests without re-uploading. See core/config_validate.py for why
    every path in it gets checked before it's ever handed to Triager."""
    raw = await file.read()
    try:
        text = validate_triage_config(raw)
    except ConfigValidationError as ex:
        raise HTTPException(400, str(ex))

    clean_name = (name or file.filename or "config").strip()[:200]
    cfg = CustomTriageConfig(
        name=clean_name, content=text, uploaded_by=user.id, uploaded_by_username=user.username,
    )
    db.add(cfg)
    log_event(db, user, "config.upload", target_type="config", target_id=cfg.id,
              target_label=clean_name, request=request)
    db.commit()
    db.refresh(cfg)
    return cfg


@router.delete("/{config_id}")
def delete_config(
    config_id: str, request: Request, db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    cfg = db.query(CustomTriageConfig).filter(CustomTriageConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(404, "Config not found")
    if user.role != Role.admin and cfg.uploaded_by != user.id:
        raise HTTPException(403, "Only an admin or the person who uploaded it can delete this config")

    log_event(db, user, "config.delete", target_type="config", target_id=config_id,
              target_label=cfg.name, request=request)
    db.delete(cfg)
    db.commit()
    return {"ok": True}
