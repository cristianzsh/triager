from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Job, User
from ..schemas import JobOut
from ..security import get_current_user, require_case_access

router = APIRouter(tags=["jobs"])


@router.get("/cases/{case_id}/machines/{machine_id}/jobs", response_model=list[JobOut])
def list_machine_jobs(case_id: str, machine_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db)
    return (
        db.query(Job)
        .filter(Job.case_id == case_id, Job.machine_id == machine_id)
        .order_by(Job.created_at.desc())
        .all()
    )


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    require_case_access(job.case_id, user, db)
    return job


@router.get("/jobs/{job_id}/log", response_class=PlainTextResponse)
def get_job_log(job_id: str, tail_lines: int = 500, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    require_case_access(job.case_id, user, db)
    if not job.log_path:
        return "(no log yet -- the job hasn't started writing output)"
    try:
        with open(job.log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if not lines:
            return "(log file exists but is empty so far)"
        return "".join(lines[-tail_lines:])
    except FileNotFoundError:
        return "(log file not found on disk)"
