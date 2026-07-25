"""
Case export/import: packages a case's investigation data (metadata plus
its full artifact database) into a single password-protected file that
one analyst can hand another, independent of which Triager instance
either of them runs.

Encrypted with AES-256-GCM, key derived from the password via PBKDF2-
HMAC-SHA256 (a random salt per export). Encrypted in fixed-size chunks,
each independently authenticated, so building or reading an export never
has to hold a multi-GB case.sqlite entirely in memory.
"""
import datetime as dt
import json
import os
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy.orm import Session

from ..models import AIMessage, Case, CaseMember, CaseStatus, Finding, Machine, MachineStatus, User
from .case_db import case_db_path

MAGIC = b"TRIAGERCASE1"
FORMAT_VERSION = 1
_SALT_LEN = 16
_NONCE_LEN = 12
_KDF_ITERATIONS = 480_000
_CHUNK_SIZE = 64 * 1024 * 1024  # plaintext bytes per chunk


class CaseTransferError(ValueError):
    """Raised for anything the caller should show back to the user as-is
    (wrong password, corrupted file, already-imported, ...)."""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def _encrypt_stream(src_path: Path, dest_path: Path, password: str) -> None:
    salt = os.urandom(_SALT_LEN)
    aesgcm = AESGCM(_derive_key(password, salt))
    with src_path.open("rb") as src, dest_path.open("wb") as dst:
        dst.write(MAGIC)
        dst.write(salt)
        while chunk := src.read(_CHUNK_SIZE):
            nonce = os.urandom(_NONCE_LEN)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            dst.write(nonce)
            dst.write(struct.pack(">I", len(ciphertext)))
            dst.write(ciphertext)
        # Explicit end marker (zero-length record) so a truncated file is
        # never silently accepted as a complete one.
        dst.write(b"\x00" * _NONCE_LEN)
        dst.write(struct.pack(">I", 0))


def _decrypt_stream(src_path: Path, dest_path: Path, password: str) -> None:
    with src_path.open("rb") as src:
        if src.read(len(MAGIC)) != MAGIC:
            raise CaseTransferError("Not a valid Triager case export file")
        salt = src.read(_SALT_LEN)
        aesgcm = AESGCM(_derive_key(password, salt))
        with dest_path.open("wb") as dst:
            first_chunk = True
            while True:
                nonce = src.read(_NONCE_LEN)
                length_bytes = src.read(4)
                if len(nonce) < _NONCE_LEN or len(length_bytes) < 4:
                    raise CaseTransferError("Corrupted export file (unexpected end of data)")
                length = struct.unpack(">I", length_bytes)[0]
                if length == 0:
                    break  # end marker
                ciphertext = src.read(length)
                if len(ciphertext) < length:
                    raise CaseTransferError("Corrupted export file (unexpected end of data)")
                try:
                    dst.write(aesgcm.decrypt(nonce, ciphertext, None))
                except InvalidTag:
                    if first_chunk:
                        raise CaseTransferError("Incorrect password")
                    raise CaseTransferError("Corrupted export file (failed integrity check)")
                first_chunk = False


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _safe_filename(name: str, fallback: str) -> str:
    safe = "".join(c if c.isalnum() or c in " -_" else "_" for c in name).strip()
    return (safe or fallback).replace(" ", "_")


def build_export(case_id: str, password: str, db: Session) -> tuple[Path, str]:
    """Builds a password-protected export of one case. Returns (path to
    the encrypted temp file, suggested filename) -- caller must delete
    the returned path once done streaming it back."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise CaseTransferError("Case not found")

    machines = db.query(Machine).filter(Machine.case_id == case_id).all()
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    ai_messages = db.query(AIMessage).filter(AIMessage.case_id == case_id).all()

    manifest = {
        "format_version": FORMAT_VERSION,
        "exported_at": dt.datetime.utcnow().isoformat(),
        "case": {
            "name": case.name, "reference": case.reference, "description": case.description,
            "status": case.status.value, "created_at": _iso(case.created_at),
        },
        "machines": [
            {
                "id": m.id, "label": m.label, "hostname": m.hostname,
                "operating_system": m.operating_system, "ip_addresses": m.ip_addresses,
                "timezone": m.timezone, "os_install_date": m.os_install_date,
                "status": m.status.value, "source_kind": m.source_kind,
                "triage_profile": m.triage_profile, "created_at": _iso(m.created_at),
            }
            for m in machines
        ],
        "findings": [
            {
                "machine_id": f.machine_id, "machine_label": f.machine_label,
                "table_name": f.table_name, "table_label": f.table_label,
                "row_rowid": f.row_rowid, "row_snapshot": f.row_snapshot, "note": f.note,
                "created_by_username": f.created_by_username,
                "created_at": _iso(f.created_at), "updated_at": _iso(f.updated_at),
            }
            for f in findings
        ],
        "ai_messages": [
            {"conversation_key": a.conversation_key, "role": a.role, "content": a.content,
             "created_at": _iso(a.created_at)}
            for a in ai_messages
        ],
    }

    work_dir = Path(tempfile.mkdtemp(prefix="triager_export_"))
    try:
        (work_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

        src_db = case_db_path(case_id)
        if src_db.exists():
            shutil.copy2(src_db, work_dir / "case.sqlite")

        bundle_path = work_dir / "bundle.zip"
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            zf.write(work_dir / "manifest.json", "manifest.json")
            if (work_dir / "case.sqlite").exists():
                zf.write(work_dir / "case.sqlite", "case.sqlite")

        out_fd, out_path_str = tempfile.mkstemp(suffix=".triagercase")
        os.close(out_fd)
        out_path = Path(out_path_str)
        _encrypt_stream(bundle_path, out_path, password)

        filename = f"{_safe_filename(case.name, case_id)}.triagercase"
        return out_path, filename
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def import_case(upload_path: Path, password: str, importing_user: User, db: Session) -> Case:
    """Decrypts a .triagercase export and imports it as a brand-new case.
    Machine ids are preserved from the export (never regenerated), since
    case.sqlite's own table names are prefixed with them -- a fresh case
    id is still generated so importing the same export twice never
    collides with the first import."""
    work_dir = Path(tempfile.mkdtemp(prefix="triager_import_"))
    try:
        bundle_path = work_dir / "bundle.zip"
        _decrypt_stream(upload_path, bundle_path, password)

        try:
            with zipfile.ZipFile(bundle_path) as zf:
                manifest = json.loads(zf.read("manifest.json"))
                zf.extractall(work_dir)
        except (zipfile.BadZipFile, KeyError):
            raise CaseTransferError("Corrupted export file (unreadable archive)")

        if manifest.get("format_version") != FORMAT_VERSION:
            raise CaseTransferError(f"Unsupported export format version: {manifest.get('format_version')!r}")

        # Collision safety net: machine ids are reused as-is, so refuse to
        # import if any of them already exist anywhere in this system.
        incoming_ids = [m["id"] for m in manifest.get("machines", []) if m.get("id")]
        if incoming_ids and db.query(Machine.id).filter(Machine.id.in_(incoming_ids)).first():
            raise CaseTransferError("This export has already been imported into this system")

        case_data = manifest.get("case", {})
        new_case = Case(
            name=case_data.get("name") or "Imported case",
            reference=case_data.get("reference"),
            description=case_data.get("description"),
            status=CaseStatus(case_data.get("status") or "open"),
            created_by=importing_user.id,
        )
        db.add(new_case)
        db.flush()  # need new_case.id for the rows below

        db.add(CaseMember(case_id=new_case.id, user_id=importing_user.id, can_edit=True))

        for m in manifest.get("machines", []):
            if not m.get("id"):
                continue
            db.add(Machine(
                id=m["id"], case_id=new_case.id, label=m.get("label") or "Machine",
                hostname=m.get("hostname"), operating_system=m.get("operating_system"),
                ip_addresses=m.get("ip_addresses"), timezone=m.get("timezone"),
                os_install_date=m.get("os_install_date"),
                status=MachineStatus(m.get("status") or "ready"),
                source_kind=m.get("source_kind"), triage_profile=m.get("triage_profile"),
            ))

        for f in manifest.get("findings", []):
            db.add(Finding(
                case_id=new_case.id, machine_id=f.get("machine_id"), machine_label=f.get("machine_label"),
                table_name=f.get("table_name"), table_label=f.get("table_label"),
                row_rowid=f.get("row_rowid"), row_snapshot=f.get("row_snapshot"),
                note=f.get("note") or "", created_by=importing_user.id,
                created_by_username=f.get("created_by_username"),
            ))

        for a in manifest.get("ai_messages", []):
            db.add(AIMessage(
                case_id=new_case.id, conversation_key=a.get("conversation_key") or "",
                role=a.get("role") or "user", content=a.get("content") or "",
            ))

        src_db = work_dir / "case.sqlite"
        if src_db.exists():
            dest_db = case_db_path(new_case.id)
            dest_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_db, dest_db)

        db.commit()
        db.refresh(new_case)
        return new_case
    except Exception:
        db.rollback()
        raise
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
