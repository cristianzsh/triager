import enum
import uuid
import datetime as dt

from sqlalchemy import (
    Column, String, DateTime, Boolean, ForeignKey, Enum, Integer, Text, JSON
)
from sqlalchemy.orm import relationship

from .database import Base


def uid() -> str:
    return uuid.uuid4().hex


class Role(str, enum.Enum):
    admin = "admin"          # full system administration, user management
    lead = "lead"            # can create cases, manage case membership
    investigator = "investigator"  # can work cases they're assigned to
    read_only = "read_only"  # view-only access to assigned cases


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=uid)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    email = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.investigator, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    memberships = relationship("CaseMember", back_populates="user")


class CaseStatus(str, enum.Enum):
    open = "open"
    closed = "closed"


class Case(Base):
    """
    A case is the investigation container. It holds one or more Machines, each Machine corresponds to one evidence/triage ZIP (one host). Artifact
    data, correlation, and AI analysis can operate on a single machine or
    span every machine in the case.
    """
    __tablename__ = "cases"

    id = Column(String, primary_key=True, default=uid)
    name = Column(String, nullable=False)
    reference = Column(String, nullable=True)   # e.g. ticket / matter number
    description = Column(Text, nullable=True)
    status = Column(Enum(CaseStatus), default=CaseStatus.open, nullable=False)
    created_by = Column(String, ForeignKey("users.id"))
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    members = relationship("CaseMember", back_populates="case")
    machines = relationship("Machine", back_populates="case")


class CaseMember(Base):
    """Per-case access control (many-to-many users <-> cases)."""
    __tablename__ = "case_members"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    can_edit = Column(Boolean, default=True)

    case = relationship("Case", back_populates="members")
    user = relationship("User", back_populates="memberships")


class MachineStatus(str, enum.Enum):
    new = "new"                # created, nothing uploaded yet
    ingesting = "ingesting"     # upload/extraction/triager run/import in progress
    ready = "ready"              # CSV data imported, browsable
    error = "error"


class Machine(Base):
    """
    One evidence/triage ZIP == one Machine (one host). Its artifact tables
    live in the case's shared SQLite database (see case_db.py), each
    prefixed by this machine's id, so correlation can span every machine in
    a case with a single query while a single machine's artifacts stay
    trivially scoped by table-name prefix.
    """
    __tablename__ = "machines"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False)

    # User-facing label, editable any time (defaults to "Machine N").
    label = Column(String, nullable=False)

    # Populated from Triager's own Meta/host_profile.json after a
    # successful import, real host identity, not something the
    # investigator has to type in.
    hostname = Column(String, nullable=True)
    operating_system = Column(String, nullable=True)
    ip_addresses = Column(JSON, nullable=True)
    timezone = Column(String, nullable=True)
    os_install_date = Column(String, nullable=True)

    status = Column(Enum(MachineStatus), default=MachineStatus.new, nullable=False)
    source_kind = Column(String, nullable=True)     # "evidence" | "processed"
    triage_profile = Column(String, nullable=True)  # "velociraptor" | "aralez"
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    case = relationship("Case", back_populates="machines")
    jobs = relationship("Job", back_populates="machine")

    @property
    def table_prefix(self) -> str:
        """SQLite table-name prefix for this machine's artifact tables.
        Prefixed with a letter since SQL identifiers shouldn't start with
        a digit, and this id is a hex uuid that could start with one."""
        return f"m_{self.id}"


class JobType(str, enum.Enum):
    extract_zip = "extract_zip"
    run_triager = "run_triager"
    import_csv = "import_csv"
    ai_analysis = "ai_analysis"


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    success = "success"
    failed = "failed"


class Job(Base):
    """
    Tracks any long-running background operation (Triager can take hours on
    large evidence sets). The frontend polls GET /jobs/{id} for status/progress
    and streams /jobs/{id}/log for live output.
    """
    __tablename__ = "jobs"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False)
    machine_id = Column(String, ForeignKey("machines.id"), nullable=True)
    job_type = Column(Enum(JobType), nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.queued, nullable=False)
    progress_pct = Column(Integer, default=0)
    message = Column(Text, nullable=True)
    log_path = Column(String, nullable=True)
    extra = Column(JSON, nullable=True)  # arbitrary metadata (e.g. tables imported)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    machine = relationship("Machine", back_populates="jobs")


class AIMessage(Base):
    """
    One turn of an AI conversation. conversation_key is an opaque string
    the frontend derives per "page", e.g. broad:case for the whole-case
    broad analysis view, broad:<machine_id> for that view scoped to one
    machine, or table:<machine_id>:<table> for a specific artifact
    table's quick-analysis panel, so each place "AI analysis" appears
    keeps its own persisted, continuable conversation, exactly like
    separate chat threads.
    """
    __tablename__ = "ai_messages"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False)
    conversation_key = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False)  # "user" | "assistant"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class AuditEvent(Base):
    """
    Append-only record of who did what, when. Not tied to Job (which only
    tracks the ingest pipeline), this covers logins, case/machine
    lifecycle, membership changes, exports, IOC scans, and AI questions
    asked, so a case's history can actually be reconstructed later rather
    than just its current state.

    case_id is nullable because some events aren't scoped to a case
    (login, user creation/role changes). target_type/target_id name
    whatever the action was performed on (a machine, a user, a table
    export, ...) independent of the actor.
    """
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    username = Column(String, nullable=True)  # snapshot, survives the user account later changing/being removed
    action = Column(String, nullable=False, index=True)   # e.g. "case.create", "machine.delete", "artifact.export"
    target_type = Column(String, nullable=True)            # e.g. "case", "machine", "user", "table"
    target_id = Column(String, nullable=True)
    target_label = Column(String, nullable=True)            # human-readable, e.g. a case name or table label
    details = Column(JSON, nullable=True)                    # small structured extra context (never full AI answers)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)


class Finding(Base):
    """
    An investigator's own flagged conclusion about a specific artifact row, independent of AI, and the actual analytical work product of an
    investigation (the AI conversation history captures what was asked/
    answered; this captures what the human decided actually matters).

    Row identity is a snapshot, not a live reference: row_snapshot stores
    the full row as JSON at the moment it was flagged, so the finding still
    means something even if that row is later edited or the artifact table
    is dropped and re-imported (row_rowid becomes best-effort only in
    that case, not authoritative).
    """
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False, index=True)
    machine_id = Column(String, ForeignKey("machines.id"), nullable=True)
    machine_label = Column(String, nullable=True)
    table_name = Column(String, nullable=True)
    table_label = Column(String, nullable=True)
    row_rowid = Column(Integer, nullable=True)
    row_snapshot = Column(JSON, nullable=True)
    note = Column(Text, nullable=False)
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_by_username = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)
