import datetime as dt
from typing import Any, Optional
from pydantic import BaseModel

from .models import Role, CaseStatus, MachineStatus, JobType, JobStatus


# Auth
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    user_id: str
    username: str


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Role = Role.investigator


class UserOut(BaseModel):
    id: str
    username: str
    full_name: Optional[str]
    email: Optional[str]
    role: Role
    is_active: bool

    class Config:
        from_attributes = True


class UserSearchResult(BaseModel):
    id: str
    username: str
    full_name: Optional[str] = None

    class Config:
        from_attributes = True


# Cases
class CaseCreate(BaseModel):
    name: str
    reference: Optional[str] = None
    description: Optional[str] = None


class CaseOut(BaseModel):
    id: str
    name: str
    reference: Optional[str]
    description: Optional[str]
    status: CaseStatus
    created_at: dt.datetime
    updated_at: dt.datetime

    class Config:
        from_attributes = True


class CaseMemberAdd(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None  # convenience alternative to pasting a raw user_id
    can_edit: bool = True


class CaseMemberOut(BaseModel):
    user_id: str
    username: str
    full_name: Optional[str] = None
    role: Role
    can_edit: bool


class CaseStatusUpdate(BaseModel):
    status: CaseStatus


# Machines
class MachineCreate(BaseModel):
    label: Optional[str] = None  # defaults to "Machine N" if omitted


class MachineOut(BaseModel):
    id: str
    case_id: str
    label: str
    hostname: Optional[str]
    operating_system: Optional[str]
    ip_addresses: Optional[list[str]]
    timezone: Optional[str]
    os_install_date: Optional[str]
    status: MachineStatus
    source_kind: Optional[str]
    triage_profile: Optional[str]
    error_message: Optional[str]
    created_at: dt.datetime
    updated_at: dt.datetime

    class Config:
        from_attributes = True


# Upload / ingestion (per machine)
class IngestRequest(BaseModel):
    upload_id: str
    # What kind of archive was just uploaded.
    source_kind: str          # "evidence" (raw, needs Triager run) | "processed" (already Triager CSV output)
    triage_profile: Optional[str] = None   # "velociraptor" | "aralez", required when source_kind == "evidence"
    workers: int = 0


class JobOut(BaseModel):
    id: str
    case_id: str
    machine_id: Optional[str]
    job_type: JobType
    status: JobStatus
    progress_pct: int
    message: Optional[str]
    extra: Optional[dict[str, Any]]
    created_at: dt.datetime
    started_at: Optional[dt.datetime]
    finished_at: Optional[dt.datetime]

    class Config:
        from_attributes = True


# Artifact browsing (scoped to one machine)
class TableMeta(BaseModel):
    name: str
    label: str
    row_count: int


class ArtifactCategory(BaseModel):
    key: str
    label: str
    tables: list[TableMeta]


class ArtifactQuery(BaseModel):
    table: str
    page: int = 1
    page_size: int = 100
    sort_column: Optional[str] = None
    sort_dir: Optional[str] = "asc"
    filters: Optional[dict[str, str]] = None
    search: Optional[str] = None
    query: Optional[str] = None   # structured filter, e.g. col contains x and col2 = y


class ArtifactPage(BaseModel):
    table: str
    columns: list[str]
    rows: list[dict[str, Any]]
    total_rows: int
    page: int
    page_size: int


class FieldCatalogEntry(BaseModel):
    label: str
    columns: list[str]


# Correlation (case-wide, optionally scoped to specific machines)
class CorrelationQuery(BaseModel):
    query: str   # plain term, or a structured query like amcache.column contains x and prefetch.executablename contains x
    machine_ids: Optional[list[str]] = None
    case_sensitive: bool = False
    max_hits_per_table: int = 500


class CorrelationHit(BaseModel):
    table: str
    table_label: str
    machine_id: str
    machine_label: str
    row: dict[str, Any]
    matched_column: str


class CorrelationResult(BaseModel):
    query: str
    total_hits: int
    structured: bool
    hits: list[CorrelationHit]


# AI
class AIAnalysisRequest(BaseModel):
    conversation_key: str      # opaque per-page id, e.g. "broad:case" or "table:<machine_id>:<table>"
    provider: str = "custom"   # "claude" (Anthropic API) | "custom" (any OpenAI-compatible endpoint)
    endpoint: Optional[str] = None   # base URL or full chat/completions URL, required when provider == "custom"
    model: str
    api_key: Optional[str] = None   # Anthropic API key for provider=="claude"; optional for local custom endpoints
    max_tokens: Optional[int] = None
    question: str
    machine_id: Optional[str] = None     # restrict context to one machine (None = whole case)
    tables: Optional[list[str]] = None   # which artifact tables to include as context
    query: Optional[str] = None          # structured or plain query, same syntax as table search
    max_rows_per_table: int = 150
    history_turns: int = 10   # how many prior Q/A pairs from this conversation to include for continuity


class AIAnalysisResponse(BaseModel):
    answer: str
    context_tables_used: list[str]
    truncated: bool


class AIMessageOut(BaseModel):
    id: str
    role: str
    content: str
    created_at: dt.datetime

    class Config:
        from_attributes = True


# Audit log
class AuditEventOut(BaseModel):
    id: str
    case_id: Optional[str]
    username: Optional[str]
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    target_label: Optional[str]
    details: Optional[dict[str, Any]]
    ip_address: Optional[str]
    created_at: dt.datetime

    class Config:
        from_attributes = True


# Timeline
class TimelineQuery(BaseModel):
    machine_ids: Optional[list[str]] = None
    categories: Optional[list[str]] = None
    search: Optional[str] = None
    query: Optional[str] = None
    start: Optional[dt.datetime] = None
    end: Optional[dt.datetime] = None
    page: int = 1
    page_size: int = 200


class TimelineEntry(BaseModel):
    timestamp: dt.datetime
    machine_id: str
    machine_label: str
    category: str
    category_label: str
    table: str
    table_label: str
    timestamp_column: str
    row: dict[str, Any]


class TimelineResult(BaseModel):
    entries: list[TimelineEntry]
    page: int
    page_size: int
    approx_total: int
    sources_used: int


# IOC scan
class IOCScanRequest(BaseModel):
    iocs_text: str   # one IOC per line, "#" prefix = comment, blank lines ignored (matches Triager's iocs.txt format)
    machine_ids: Optional[list[str]] = None
    case_sensitive: bool = False
    max_hits_per_ioc: int = 200


class IOCHitGroup(BaseModel):
    ioc: str
    total_hits: int
    hits: list[CorrelationHit]


class IOCScanResult(BaseModel):
    scanned_iocs: int
    matched_iocs: int
    groups: list[IOCHitGroup]


# Findings (feature #3)
class FindingCreate(BaseModel):
    machine_id: Optional[str] = None
    machine_label: Optional[str] = None
    table_name: Optional[str] = None
    table_label: Optional[str] = None
    row_rowid: Optional[int] = None
    row_snapshot: Optional[dict[str, Any]] = None
    note: str


class FindingUpdate(BaseModel):
    note: str


class FindingOut(BaseModel):
    id: str
    case_id: str
    machine_id: Optional[str]
    machine_label: Optional[str]
    table_name: Optional[str]
    table_label: Optional[str]
    row_rowid: Optional[int]
    row_snapshot: Optional[dict[str, Any]]
    note: str
    created_by_username: Optional[str]
    created_at: dt.datetime
    updated_at: dt.datetime

    class Config:
        from_attributes = True


# User management
class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = None
