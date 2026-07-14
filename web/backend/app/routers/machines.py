import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Machine, Job, AIMessage, User
from ..schemas import MachineCreate, MachineOut
from ..security import get_current_user, require_case_access
from ..services import case_db, ingest_pipeline
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/machines", tags=["machines"])


@router.post("", response_model=MachineOut)
def create_machine(case_id: str, payload: MachineCreate, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    existing_count = db.query(Machine).filter(Machine.case_id == case_id).count()
    label = payload.label or f"Machine {existing_count + 1}"
    machine = Machine(case_id=case_id, label=label)
    db.add(machine)
    db.commit()
    db.refresh(machine)
    log_event(db, user, "machine.create", case_id=case_id, target_type="machine", target_id=machine.id,
              target_label=machine.label, request=request)
    db.commit()
    return machine


@router.get("", response_model=list[MachineOut])
def list_machines(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    return db.query(Machine).filter(Machine.case_id == case_id).order_by(Machine.created_at).all()


@router.get("/{machine_id}", response_model=MachineOut)
def get_machine(case_id: str, machine_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    machine = db.query(Machine).filter(Machine.id == machine_id, Machine.case_id == case_id).first()
    if not machine:
        raise HTTPException(404, "Machine not found")
    return machine


@router.get("/{machine_id}/download")
def download_processed_data(case_id: str, machine_id: str, request: Request,
                             db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Downloads the machine's processed evidence (its triager_out/ directory)
    as a ZIP, the CSV artifacts and Meta/ folder, for manual inspection
    outside the console. Works the same way regardless of whether this
    machine's data came from a raw-evidence Triager run or an
    already-processed archive uploaded directly: both end up as a
    triager_out/ directory, so there's nothing source_kind-specific here.
    """
    require_case_access(case_id, user, db)
    machine = db.query(Machine).filter(Machine.id == machine_id, Machine.case_id == case_id).first()
    if not machine:
        raise HTTPException(404, "Machine not found")

    triager_out_dir = ingest_pipeline.machine_dir(case_id, machine_id) / "triager_out"
    if not triager_out_dir.exists() or not any(triager_out_dir.iterdir()):
        raise HTTPException(404, "No processed data available for this machine yet")

    safe_label = "".join(c if c.isalnum() or c in " -_" else "_" for c in machine.label).strip() or machine_id
    root_name = safe_label.replace(" ", "_")

    # Build the archive into a temp file rather than in memory, triage
    # output for one machine can easily be many GB, and buffering that
    # entirely in RAM before streaming it back would be a good way to take
    # the server down on a large case.
    tmp_fd, tmp_path_str = tempfile.mkstemp(suffix=".zip")
    os.close(tmp_fd)
    tmp_path = Path(tmp_path_str)

    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for p in sorted(triager_out_dir.rglob("*")):
                if p.is_dir():
                    continue
                try:
                    arcname = Path(root_name) / p.relative_to(triager_out_dir)
                    zf.write(p, arcname)
                except Exception:
                    # Skip any individual problem file (long path, transient
                    # lock, ...) rather than failing the whole download.
                    continue
    except Exception as ex:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(500, f"Could not build the archive: {ex}")

    log_event(db, user, "machine.download_processed", case_id=case_id, target_type="machine", target_id=machine_id,
              target_label=machine.label, request=request)
    db.commit()

    def stream_and_cleanup():
        try:
            with tmp_path.open("rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
        finally:
            tmp_path.unlink(missing_ok=True)

    return StreamingResponse(
        stream_and_cleanup(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{root_name}_processed.zip"'},
    )


@router.patch("/{machine_id}", response_model=MachineOut)
def rename_machine(case_id: str, machine_id: str, payload: MachineCreate, request: Request,
                    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    machine = db.query(Machine).filter(Machine.id == machine_id, Machine.case_id == case_id).first()
    if not machine:
        raise HTTPException(404, "Machine not found")
    old_label = machine.label
    if payload.label:
        machine.label = payload.label
        log_event(db, user, "machine.rename", case_id=case_id, target_type="machine", target_id=machine.id,
                  target_label=machine.label, details={"old_label": old_label}, request=request)
    db.commit()
    db.refresh(machine)
    return machine


@router.delete("/{machine_id}")
def delete_machine(case_id: str, machine_id: str, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    """
    Permanently deletes a machine: its job rows, its artifact tables (and
    FTS indexes) in the case's shared database, and its on-disk
    raw/triager_out/job-log directory. The rest of the case (other
    machines) is untouched. This cannot be undone.
    """
    require_case_access(case_id, user, db, need_edit=True)
    machine = db.query(Machine).filter(Machine.id == machine_id, Machine.case_id == case_id).first()
    if not machine:
        raise HTTPException(404, "Machine not found")

    machine_label = machine.label
    db.query(Job).filter(Job.machine_id == machine_id).delete()
    db.query(AIMessage).filter(
        AIMessage.case_id == case_id, AIMessage.conversation_key.like(f"%{machine_id}%")
    ).delete(synchronize_session=False)
    db.delete(machine)
    log_event(db, user, "machine.delete", case_id=case_id, target_type="machine", target_id=machine_id,
              target_label=machine_label, request=request)
    db.commit()

    case_db.delete_machine_data(case_id, machine_id)
    shutil.rmtree(settings.storage_root / "cases" / case_id / "machines" / machine_id, ignore_errors=True)
    return {"ok": True}
