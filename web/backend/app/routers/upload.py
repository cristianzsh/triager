import shutil
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import User, Machine, CustomTriageConfig
from ..schemas import IngestRequest
from ..security import get_current_user, require_case_access
from ..services import ingest_pipeline
from ..services.audit import log_event

router = APIRouter(prefix="/cases/{case_id}/machines/{machine_id}", tags=["ingest"])


def _get_machine(case_id: str, machine_id: str, db: Session) -> Machine:
    machine = db.query(Machine).filter(Machine.id == machine_id, Machine.case_id == case_id).first()
    if not machine:
        raise HTTPException(404, "Machine not found in this case")
    return machine


@router.post("/upload")
async def upload_zip(
    case_id: str,
    machine_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Streams a large .zip (evidence collection or pre-processed Triager
    output, for this one machine) to disk in chunks, never loads the
    whole archive into memory, so multi-hundred-GB evidence sets are fine
    on modest RAM.
    """
    require_case_access(case_id, user, db, need_edit=True)
    _get_machine(case_id, machine_id, db)

    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Only .zip archives are accepted")

    upload_id = uuid.uuid4().hex
    upload_dir = settings.storage_root / "uploads" / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / "archive.zip"

    size = 0
    with dest.open("wb") as out:
        while chunk := await file.read(settings.upload_chunk_bytes):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                out.close()
                shutil.rmtree(upload_dir, ignore_errors=True)
                raise HTTPException(413, "Upload exceeds configured maximum size")
            out.write(chunk)

    return {"upload_id": upload_id, "size_bytes": size, "filename": file.filename}


@router.post("/ingest", response_model=list[str])
def ingest(
    case_id: str,
    machine_id: str,
    payload: IngestRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Kicks off the background pipeline for this machine: extract -> (Triager
    run, if this is raw evidence) -> CSV import. Returns the job ids to poll.
    """
    require_case_access(case_id, user, db, need_edit=True)
    machine = _get_machine(case_id, machine_id, db)

    if payload.source_kind not in ("evidence", "processed"):
        raise HTTPException(400, "source_kind must be 'evidence' or 'processed'")

    custom_config = None
    if payload.source_kind == "evidence":
        if payload.custom_config_id:
            custom_config = db.query(CustomTriageConfig).filter(
                CustomTriageConfig.id == payload.custom_config_id
            ).first()
            if not custom_config:
                raise HTTPException(404, "Selected custom config not found")
        elif payload.triage_profile not in ("velociraptor", "aralez"):
            raise HTTPException(400, "triage_profile must be 'velociraptor' or 'aralez', or pass custom_config_id")

    upload_zip_path = settings.storage_root / "uploads" / payload.upload_id / "archive.zip"
    if not upload_zip_path.exists():
        raise HTTPException(404, "Unknown upload_id (upload may have expired or failed)")

    if payload.max_file_size_mb <= 0:
        raise HTTPException(400, "max_file_size_mb must be positive")

    log_event(
        db, user, "machine.ingest_start", case_id=case_id, target_type="machine", target_id=machine_id,
        target_label=machine.label,
        details={
            "source_kind": payload.source_kind,
            "triage_profile": payload.triage_profile,
            "custom_config": custom_config.name if custom_config else None,
            "skip_large_files": payload.skip_large_files,
            "max_file_size_mb": payload.max_file_size_mb if payload.skip_large_files else None,
            "exclude_parsers": payload.exclude_parsers,
        },
        request=request,
    )
    db.commit()

    job_ids = ingest_pipeline.start_ingest(
        case_id=case_id,
        machine_id=machine_id,
        upload_zip_path=upload_zip_path,
        source_kind=payload.source_kind,
        triage_profile=payload.triage_profile,
        workers=payload.workers,
        custom_config_content=custom_config.content if custom_config else None,
        custom_config_name=custom_config.name if custom_config else None,
        skip_large_files=payload.skip_large_files,
        max_file_size_mb=payload.max_file_size_mb,
        exclude_parsers=payload.exclude_parsers,
    )
    return job_ids
