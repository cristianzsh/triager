"""
Ties together zip_handler, triager_runner, and csv_importer into the
pipeline the "Upload evidence" button triggers for a single machine:

  evidence.zip  -(extract)->  raw/  -(Triager.exe)->  triager_out/
                                                                   |
                                                          (CSV importer)
                                                                   v
                                                       case.sqlite (m_<machine_id>__*)

  processed.zip -(extract)-> triager_out/ -(CSV importer)-> case.sqlite

After a successful import, Triager's own Meta/host_profile.json (written by
collect_host_info_from_triage() in triager.py) is read back to populate the
Machine's hostname/OS/IP/timezone fields, so the investigator doesn't have
to type in host identity that's already sitting in the evidence.

Runs entirely in one background thread per upload so the HTTP request that
kicks it off returns immediately (this can legitimately take hours against
a large evidence collection) while the UI polls /jobs for progress.

Every stage (extract, Triager run, import) writes its own log file and sets
Job.log_path, so "view log" always has something to show, not just the
Triager-run stage.
"""
import datetime as dt
import json
import threading
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal
from ..models import Job, JobType, JobStatus, Machine, MachineStatus
from . import zip_handler, csv_importer
from .triager_runner import run_triager


def machine_dir(case_id: str, machine_id: str) -> Path:
    d = settings.storage_root / "cases" / case_id / "machines" / machine_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _job_log_path(case_id: str, machine_id: str, job_id: str) -> Path:
    p = machine_dir(case_id, machine_id) / "jobs" / f"{job_id}.log"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_log(log_path: Path, line: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="replace") as f:
        f.write(line.rstrip("\n") + "\n")


def _new_job(db: Session, case_id: str, machine_id: str, job_type: JobType) -> Job:
    job = Job(case_id=case_id, machine_id=machine_id, job_type=job_type, status=JobStatus.queued)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def start_ingest(
    case_id: str,
    machine_id: str,
    upload_zip_path: Path,
    source_kind: str,
    triage_profile: str | None,
    workers: int,
    custom_config_content: str | None = None,
    custom_config_name: str | None = None,
    skip_large_files: bool = False,
    max_file_size_mb: int = 1024,
    exclude_parsers: list[str] | None = None,
) -> list[str]:
    """Creates the job rows synchronously (so the API response can return
    their ids right away) and launches the pipeline thread."""
    db = SessionLocal()
    try:
        machine = db.query(Machine).filter(Machine.id == machine_id).first()
        if machine:
            machine.status = MachineStatus.ingesting
            machine.source_kind = source_kind
            machine.triage_profile = f"custom: {custom_config_name}" if custom_config_content else triage_profile
            machine.error_message = None
            db.commit()

        extract_job_id = _new_job(db, case_id, machine_id, JobType.extract_zip).id

        triager_job_id = None
        if source_kind == "evidence":
            triager_job_id = _new_job(db, case_id, machine_id, JobType.run_triager).id

        import_job_id = _new_job(db, case_id, machine_id, JobType.import_csv).id

        # Read every id into a plain string before closing the session:
        # each db.commit() above expires all objects in the session
        # (SQLAlchemy's default expire_on_commit), so touching a Job
        # attribute again after db.close() raises DetachedInstanceError.
        job_ids = [j for j in (extract_job_id, triager_job_id, import_job_id) if j]
    finally:
        db.close()

    t = threading.Thread(
        target=_run_pipeline,
        args=(
            case_id, machine_id, upload_zip_path, source_kind, triage_profile, workers,
            extract_job_id, triager_job_id, import_job_id, custom_config_content,
            skip_large_files, max_file_size_mb, exclude_parsers,
        ),
        daemon=True,
    )
    t.start()
    return job_ids


def _set_job(db: Session, job_id: str, **fields):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        return
    for k, v in fields.items():
        setattr(job, k, v)
    db.add(job)
    db.commit()


def _run_pipeline(
    case_id: str,
    machine_id: str,
    upload_zip_path: Path,
    source_kind: str,
    triage_profile: str | None,
    workers: int,
    extract_job_id: str,
    triager_job_id: str | None,
    import_job_id: str,
    custom_config_content: str | None = None,
    skip_large_files: bool = False,
    max_file_size_mb: int = 1024,
    exclude_parsers: list[str] | None = None,
) -> None:
    db = SessionLocal()
    mdir = machine_dir(case_id, machine_id)
    try:
        # Stage 1: extract
        extract_log = _job_log_path(case_id, machine_id, extract_job_id)
        _set_job(db, extract_job_id, status=JobStatus.running, started_at=dt.datetime.utcnow(),
                  log_path=str(extract_log))
        _write_log(extract_log, f"Extracting {upload_zip_path.name} for machine {machine_id}")

        dest_root = mdir / ("raw" if source_kind == "evidence" else "triager_out")

        def _extract_progress(done: int, total: int):
            pct = int(done / total * 100) if total else 100
            _set_job(db, extract_job_id, progress_pct=pct, message=f"Extracting {done}/{total} files")
            if done == total or done % 500 == 0:
                _write_log(extract_log, f"Extracted {done}/{total} files")

        try:
            effective_root = zip_handler.extract_zip(
                upload_zip_path, dest_root, _extract_progress,
                skip_large_files=skip_large_files,
                max_file_size_bytes=int(max_file_size_mb or 0) * 1024 * 1024,
                log_cb=lambda msg: _write_log(extract_log, msg),
            )
        except Exception as ex:  # noqa: BLE001
            _write_log(extract_log, f"ERROR: {ex}")
            _set_job(db, extract_job_id, status=JobStatus.failed, message=str(ex),
                      finished_at=dt.datetime.utcnow())
            _mark_machine_error(db, machine_id, f"Extraction failed: {ex}")
            return

        _write_log(extract_log, "Extraction complete.")
        _set_job(db, extract_job_id, status=JobStatus.success, progress_pct=100,
                  message="Archive extracted", finished_at=dt.datetime.utcnow())

        machine = db.query(Machine).filter(Machine.id == machine_id).first()
        machine_label = machine.label if machine else machine_id
        table_prefix = machine.table_prefix if machine else f"m_{machine_id}"

        # Stage 2: run Triager (raw evidence only)
        triager_out_dir = mdir / "triager_out"
        if source_kind == "evidence":
            assert triager_job_id is not None
            triager_log = _job_log_path(case_id, machine_id, triager_job_id)

            # Triager's own parsers write each artifact's CSV as soon as
            # that parser finishes (run_selected_parsers() runs them
            # concurrently), well before the whole process exits, often
            # the longest single stage of the pipeline. Rather than making
            # the investigator wait for all of it, periodically import
            # whatever's already done in the background while Triager is
            # still running; see csv_importer.import_incremental()'s
            # docstring for why this is safe (never the final word, the
            # full rebuild in Stage 3 always supersedes it).
            stop_incremental = threading.Event()
            incremental_thread = threading.Thread(
                target=_run_incremental_import_loop,
                args=(case_id, machine_id, machine_label, table_prefix, triager_out_dir, stop_incremental),
                daemon=True,
            )
            incremental_thread.start()

            try:
                config_path = None
                if custom_config_content:
                    config_path = mdir / "custom_config.yml"
                    config_path.write_text(custom_config_content, encoding="utf-8")

                run_triager(
                    job_id=triager_job_id,
                    evidence_root=effective_root,
                    output_dir=triager_out_dir,
                    log_path=triager_log,
                    triage_profile=triage_profile or "velociraptor",
                    workers=workers,
                    config_path=config_path,
                    exclude_parsers=exclude_parsers,
                )
            finally:
                stop_incremental.set()
                incremental_thread.join(timeout=30)

            db.expire_all()
            triager_job = db.query(Job).filter(Job.id == triager_job_id).first()
            if triager_job and triager_job.status == JobStatus.failed:
                _mark_machine_error(db, machine_id, "Triager run failed; see job log")
                return
        else:
            # Already-processed archive: the extracted root is the output dir.
            triager_out_dir = effective_root

        # Stage 3: import CSVs into case.sqlite
        import_log = _job_log_path(case_id, machine_id, import_job_id)
        _set_job(db, import_job_id, status=JobStatus.running, started_at=dt.datetime.utcnow(),
                  log_path=str(import_log))
        _write_log(import_log, f"Importing CSV artifacts from {triager_out_dir}")

        def _import_progress(name: str, done: int, total: int):
            pct = int(done / total * 100) if total else 100
            _set_job(db, import_job_id, progress_pct=pct, message=f"Importing {name} ({done}/{total})")
            _write_log(import_log, f"[{done}/{total}] {name}")

        try:
            summary = csv_importer.import_output_dir(
                case_id, machine_id, machine_label, table_prefix, triager_out_dir, _import_progress
            )
        except Exception as ex:  # noqa: BLE001
            _write_log(import_log, f"ERROR: {ex}")
            _set_job(db, import_job_id, status=JobStatus.failed, message=str(ex),
                      finished_at=dt.datetime.utcnow())
            _mark_machine_error(db, machine_id, f"CSV import failed: {ex}")
            return

        for skip in summary.get("skipped", []):
            _write_log(import_log, f"SKIPPED {skip['path']}: {skip['error']}")
        _write_log(
            import_log,
            f"Import complete: {len(summary['tables'])} tables, {summary['total_rows']} rows, "
            f"{len(summary['skipped'])} skipped.",
        )

        _set_job(
            db, import_job_id, status=JobStatus.success, progress_pct=100,
            message=f"Imported {len(summary['tables'])} tables, {summary['total_rows']} rows",
            extra=summary, finished_at=dt.datetime.utcnow(),
        )

        _apply_host_profile(db, machine_id, triager_out_dir)

        machine = db.query(Machine).filter(Machine.id == machine_id).first()
        if machine:
            machine.status = MachineStatus.ready
            db.commit()
    finally:
        db.close()


def _apply_host_profile(db: Session, machine_id: str, triager_out_dir: Path) -> None:
    """Reads Triager's Meta/host_profile.json (written by
    collect_host_info_from_triage()) and fills in the machine's real host
    identity, so the investigator sees the actual hostname/OS instead of
    just the label they typed when creating the machine."""
    profile_path = triager_out_dir / "Meta" / "host_profile.json"
    if not profile_path.exists():
        return
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return

    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        return

    machine.hostname = data.get("COMPUTER_NAME") or machine.hostname
    machine.operating_system = data.get("OPERATING_SYSTEM") or machine.operating_system
    machine.timezone = data.get("TIMEZONE") or machine.timezone
    machine.os_install_date = data.get("OS_INSTALL_DATE") or machine.os_install_date
    ips = data.get("IP_ADDRESSES")
    if ips:
        machine.ip_addresses = ips
    db.commit()


def _run_incremental_import_loop(
    case_id: str,
    machine_id: str,
    machine_label: str,
    table_prefix: str,
    output_dir: Path,
    stop_event: threading.Event,
) -> None:
    """Runs in a background thread for the duration of the Triager
    subprocess, periodically importing whatever artifact CSVs are already
    complete. Best-effort by design: any exception here is swallowed (the
    authoritative full import in Stage 3 will pick up anything missed or
    gotten wrong) rather than risking taking down the whole ingest over a
    bonus feature."""
    already_imported: set[str] = set()
    # A short first wait, Triager needs a moment to even create the
    # output directory, let alone finish a parser.
    if stop_event.wait(10):
        return
    while not stop_event.is_set():
        try:
            already_imported = csv_importer.import_incremental(
                case_id, machine_id, machine_label, table_prefix, output_dir, already_imported
            )
        except Exception:  # noqa: BLE001
            pass
        if stop_event.wait(20):
            return


def _mark_machine_error(db: Session, machine_id: str, message: str) -> None:
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if machine:
        machine.status = MachineStatus.error
        machine.error_message = message
        db.commit()
