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
    """One evidence/triage ZIP == one Machine (one host). Its artifact
    tables live in the case's shared SQLite database (case_db.py),
    prefixed by this machine's id, so correlation spans every machine
    with a single query while one machine stays trivially scoped."""
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
    """One turn of an AI conversation. conversation_key is an opaque
    per-page string (broad:case, broad:<machine_id>, table:<machine_id>:
    <table>) so every place "AI analysis" appears keeps its own
    persisted, continuable conversation, like separate chat threads."""
    __tablename__ = "ai_messages"

    id = Column(String, primary_key=True, default=uid)
    case_id = Column(String, ForeignKey("cases.id"), nullable=False)
    conversation_key = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False)  # "user" | "assistant"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class AuditEvent(Base):
    """Append-only record of who did what, when -- logins, case/machine
    lifecycle, membership changes, exports, IOC scans, AI questions.
    case_id is nullable for events not scoped to a case (login, user
    creation). target_type/target_id name whatever was acted on."""
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
    """An investigator's own flagged conclusion about a specific artifact
    row -- the human's analytical work product, independent of the AI
    conversation history. row_snapshot stores the full row as JSON at
    flag time, so it stays meaningful even if the row is later edited or
    the table is re-imported (row_rowid becomes best-effort only then)."""
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


class CustomTriageConfig(Base):
    """A reusable triage config .yml uploaded through the web UI, alongside
    the built-in velociraptor/aralez profiles. Content is validated and
    stored as text (not a path) so ingest never touches a file a user
    could later move/replace out from under a running job."""
    __tablename__ = "custom_triage_configs"

    id = Column(String, primary_key=True, default=uid)
    name = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    uploaded_by = Column(String, ForeignKey("users.id"), nullable=True)
    uploaded_by_username = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
