"""
Runs the actual Triager binary against an extracted evidence collection.

This is intentionally a thin wrapper around the exact CLI Triager already
exposes (see triager.py's parse_args()) rather than re-implementing any
forensic parsing logic in the web app, Triager remains the single source
of truth for artifact processing. The web layer's job is orchestration:
queueing, running as a background job, tailing output, and updating the
Job row so the UI can show progress.

Windows-only: Triager is currently only built for Windows (Triager.exe).
Always uses settings.triager_exe_path.

NOTE: Triager itself doesn't emit a numeric percentage, so progress here is
coarse (based on which of its ~30 parsers has started, parsed from stdout
"[INFO] Running: <name>" lines) rather than exact, good enough for a
progress bar, not for ETA math.
"""
import re
import subprocess
import threading
import datetime as dt
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal
from ..models import Job, JobStatus

# Triager logs "[INFO] Running: <parser name>" for each of ~30 parsers.
# Used only to estimate progress_pct; see run_selected_parsers() in triager.py.
EXPECTED_PARSER_COUNT = 30
RUNNING_RE = re.compile(r"\[INFO\]\s+Running:\s+(.+)")


def start_triager_job(
    job_id: str,
    evidence_root: Path,
    output_dir: Path,
    log_path: Path,
    triage_profile: str,
    workers: int = 0,
) -> None:
    """Spawns a background thread that runs Triager and updates the Job row.
    Use this for a standalone re-run; the multi-stage upload pipeline calls
    run_triager() directly since it already owns a background thread."""
    t = threading.Thread(
        target=run_triager,
        args=(job_id, evidence_root, output_dir, log_path, triage_profile, workers),
        daemon=True,
    )
    t.start()


def _set_job(db: Session, job_id: str, **fields):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        return
    for k, v in fields.items():
        setattr(job, k, v)
    db.add(job)
    db.commit()


def run_triager(
    job_id: str,
    evidence_root: Path,
    output_dir: Path,
    log_path: Path,
    triage_profile: str,
    workers: int,
) -> None:
    db = SessionLocal()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        _set_job(db, job_id, status=JobStatus.running, started_at=dt.datetime.utcnow(),
                  log_path=str(log_path), message="Launching Triager")

        cmd = [
            settings.triager_exe_path,
            "--root", str(evidence_root),
            "--profile", triage_profile,
            "-o", str(output_dir),
            "--workers", str(workers or 0),
        ]

        parsed_count = 0
        with log_path.open("w", encoding="utf-8", errors="replace") as logf:
            logf.write(f"$ {' '.join(cmd)}\n\n")
            logf.flush()

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                logf.write(line)
                logf.flush()
                m = RUNNING_RE.search(line)
                if m:
                    parsed_count += 1
                    pct = min(95, int(parsed_count / EXPECTED_PARSER_COUNT * 100))
                    _set_job(db, job_id, progress_pct=pct, message=f"Running: {m.group(1).strip()}")

            returncode = proc.wait()

        if returncode == 0:
            _set_job(
                db, job_id, status=JobStatus.success, progress_pct=100,
                message="Triager finished successfully",
                finished_at=dt.datetime.utcnow(),
            )
        else:
            _set_job(
                db, job_id, status=JobStatus.failed,
                message=f"Triager exited with code {returncode}. See job log.",
                finished_at=dt.datetime.utcnow(),
            )
    except Exception as ex:  # noqa: BLE001
        with log_path.open("a", encoding="utf-8", errors="replace") as logf:
            logf.write(f"\n[web] Error launching Triager: {ex}\n")
        _set_job(
            db, job_id, status=JobStatus.failed, message=f"Error launching Triager: {ex}",
            finished_at=dt.datetime.utcnow(),
        )
    finally:
        db.close()
