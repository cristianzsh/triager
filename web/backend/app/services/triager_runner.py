"""
Runs Triager's own CLI mode against an extracted evidence collection.
"""
import re
import shutil
import subprocess
import sys
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


def resolve_triager_command() -> list[str]:
    """
    Argv prefix to invoke Triager's CLI as a subprocess.
    - Frozen (merged binary): re-invoke ourselves, just without --web.
    - Dev: run triager.py at the repo root with this same interpreter.
    - Neither (standalone web-only deployment): fall back to
      settings.triager_exe_path or the system PATH.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]

    triager_py = Path(__file__).resolve().parents[4] / "triager.py"
    if triager_py.exists():
        return [sys.executable, str(triager_py)]

    configured = settings.triager_exe_path
    if Path(configured).is_file():
        return [configured]

    found = shutil.which(configured) or shutil.which("Triager.exe") or shutil.which("Triager")
    return [found] if found else [configured]

PARSER_NAMES = [
    "AmCache",
    "Defender",
    "PCA",
    "Prefetch",
    "SRUM",
    "WER",
    "ScheduledTasks",
    "WMI",
    "BamDam",
    "LastVisitedMRU",
    "MUICache",
    "OfficeMRU",
    "OpenSaveMRU",
    "RunMRU",
    "Shellbags",
    "Shimcache",
    "TypedPaths",
    "USB",
    "UserAssist",
    "WordWheelQuery",
    "BrowserHistory",
    "Certutil",
    "JumpLists",
    "Notepad",
    "PSReadLine",
    "RDPCache",
    "RecentDocs",
    "RecentLnk",
    "Thumbcache",
    "Win10Timelines",
    "MFT",
    "RecycleBin",
    "USNJournal",
    "EventLog",
    "LogFile",
]


def list_parser_names() -> list[str]:
    return PARSER_NAMES


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
    triage_profile: str | None,
    workers: int,
    config_path: Path | None = None,
    exclude_parsers: list[str] | None = None,
) -> None:
    """Either triage_profile (a built-in "velociraptor"/"aralez" name,
    passed as --profile) or config_path (a specific .yml on disk, passed
    as -c) should be given; config_path takes precedence if both are."""
    db = SessionLocal()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        _set_job(db, job_id, status=JobStatus.running, started_at=dt.datetime.utcnow(),
                  log_path=str(log_path), message="Launching Triager")

        cmd = resolve_triager_command() + [
            "--root", str(evidence_root), "-o", str(output_dir), "--workers", str(workers or 0),
        ]
        if config_path:
            cmd += ["-c", str(config_path)]
        else:
            cmd += ["--profile", triage_profile or "velociraptor"]
        if exclude_parsers:
            cmd += ["--exclude-parser", ",".join(exclude_parsers)]

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
