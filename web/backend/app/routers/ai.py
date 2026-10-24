import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import User, Job, JobType, JobStatus, AIMessage, Machine
from ..schemas import (
    AIAnalysisRequest, AIAnalysisResponse, AIMessageOut, AnonymizationMapOut,
    AnonymizationCustomIn, AnonymizationCustomOut, AIPreviewOut,
)
from ..security import get_current_user, require_case_access
from ..services.audit import log_event
from ..services import case_db
from ..services import anonymizer as anonymization
from ..services.anonymizer import Anonymizer

# System-level defaults (not case-specific), powers the centralized
# "AI Settings" screen the frontend uses once for every AI entry point
# (broad case analysis, per-machine analysis, per-table quick analysis).
settings_router = APIRouter(prefix="/ai", tags=["ai"])


@settings_router.get("/defaults")
def get_ai_defaults():
    return {"endpoint": settings.default_llm_endpoint, "model": settings.default_llm_model}


router = APIRouter(prefix="/cases/{case_id}/ai", tags=["ai"])

MAX_CONTEXT_CHARS = 700_000
MAX_TABLE_SNIPPET_CHARS = 150_000
MAX_ROWS_PER_TABLE_CEILING = 5_000

_CATEGORY_WEIGHTS = {
    "execution_evidence": 4.0,  # Amcache, Prefetch, SRUM, WER, PCA - what ran, when
    "persistence": 3.0,         # ScheduledTasks, WMI - how it stays around
    "registry": 3.0,
    "system_config": 3.0,       # Shimcache, BAM/DAM, USB - also execution/device evidence
    "user_artifacts": 2.0,      # UserAssist, JumpLists, browser history, etc.
    "filesystem": 1.5,          # MFT, USN Journal, LogFile, RecycleBin
    "event_logs": 1.0,
    "logs": 1.0,
    "meta": 0.5,
}
_DEFAULT_CATEGORY_WEIGHT = 1.0
_LOW_VALUE_EVENTLOG_PREFIX = "evtxecmd"
_MIN_TABLE_BUDGET_CHARS = 2_000


def _table_weight(category: str, table_label: str) -> float:
    weight = _CATEGORY_WEIGHTS.get(category, _DEFAULT_CATEGORY_WEIGHT)
    if category == "event_logs" and (table_label or "").lower().startswith(_LOW_VALUE_EVENTLOG_PREFIX):
        weight *= 0.25
    return weight
SYSTEM_PROMPT = (
    "You are a DFIR forensic analyst assistant helping investigate a case. "
    "You are given structured forensic artifact data (Prefetch, Event Logs, "
    "Registry, Scheduled Tasks, browser/user activity, etc.) extracted by the "
    "Triager tool, possibly from multiple machines in the same case (each "
    "table's context notes which machine it came from). Columns that were "
    "entirely empty across every shown row for a table have been removed "
    "from that table's rows to save space -- their absence means no value "
    "was present in the sample, not that the field wasn't collected. Only "
    "reason from the evidence provided; if something is not present in the "
    "context, say so explicitly rather than guessing. When you flag "
    "something as suspicious, cite the specific machine/table/row/field. "
    "You may be shown earlier turns of this same conversation for "
    "continuity -- treat them as prior context, not as new evidence to "
    "re-verify."
)

_MAX_CELL_CHARS = 500
_EMPTY_SENTINELS = {"none", "null", "n/a", "na", "-", "0001-01-01t00:00:00", "0001-01-01 00:00:00"}


def _is_empty_value(v) -> bool:
    if v is None:
        return True
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return True
    normalized = s.lower().replace(".0000000", "").rstrip("z")
    return normalized in _EMPTY_SENTINELS


def _prune_empty_columns(rows: list[dict]) -> list[dict]:
    """Drops columns entirely empty/null (or all placeholder sentinels)
    across every row -- safe since an all-empty column carries nothing
    to lose, and forensic CSVs routinely have 20-40 mostly-unused columns."""
    if not rows:
        return rows
    keys = rows[0].keys()
    populated = {k for k in keys if any(not _is_empty_value(r.get(k)) for r in rows)}
    if len(populated) == len(keys):
        return rows
    return [{k: v for k, v in r.items() if k in populated} for r in rows]


def _truncate_long_values(rows: list[dict]) -> list[dict]:
    """Truncates unusually long cell values (raw blobs, huge paths) so one
    field doesn't crowd out the rest of the table's budget."""
    out = []
    for r in rows:
        new_row = {}
        for k, v in r.items():
            if isinstance(v, str) and len(v) > _MAX_CELL_CHARS:
                new_row[k] = v[:_MAX_CELL_CHARS] + "...(truncated)"
            else:
                new_row[k] = v
        out.append(new_row)
    return out


@router.get("/history", response_model=list[AIMessageOut])
def get_history(case_id: str, conversation_key: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Returns the persisted conversation for one page (broad analysis at a
    given scope, or one table's quick-analysis panel), oldest first."""
    require_case_access(case_id, user, db)
    return (
        db.query(AIMessage)
        .filter(AIMessage.case_id == case_id, AIMessage.conversation_key == conversation_key)
        .order_by(AIMessage.created_at)
        .all()
    )


@router.delete("/history")
def delete_history(case_id: str, conversation_key: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Clears one conversation's history. Does not affect any other
    conversation (e.g. clearing a table's quick-analysis history leaves the
    broad case analysis conversation untouched, and vice versa)."""
    require_case_access(case_id, user, db, need_edit=True)
    db.query(AIMessage).filter(
        AIMessage.case_id == case_id, AIMessage.conversation_key == conversation_key
    ).delete()
    db.commit()
    return {"ok": True}


def _fit_rows_to_budget(rows: list[dict], budget: int) -> tuple[list[dict], bool]:
    """Returns as many whole rows as fit within budget chars of JSON, never
    a partial row (slicing the string directly can cut mid-object and
    produce invalid JSON)."""
    if not rows:
        return rows, False
    full_len = len(json.dumps(rows, ensure_ascii=False))
    if full_len <= budget:
        return rows, False
    lo, hi = 0, len(rows)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(json.dumps(rows[:mid], ensure_ascii=False)) <= budget:
            lo = mid
        else:
            hi = mid - 1
    return rows[:lo], True


def _build_context(
    case_id: str, payload: AIAnalysisRequest, db: Session, anonymizer: Optional[Anonymizer] = None,
) -> tuple[str, bool, list[str]]:
    """Builds the "CASE ARTIFACT CONTEXT: ...\\n\\nQUESTION: ..." text that
    gets sent as the current turn's content."""
    rows_per_table = max(1, min(payload.max_rows_per_table, MAX_ROWS_PER_TABLE_CEILING))

    if payload.tables:
        tables = payload.tables
    else:
        tables = case_db.list_tables(case_id, machine_id=payload.machine_id)

    context_parts = []
    truncated = False
    used_tables = []

    table_labels = _table_label_map(case_id)

    weights = {
        t: _table_weight(table_labels.get(t, {}).get("category", ""), table_labels.get(t, {}).get("table_label", t))
        for t in tables
    }
    tables = sorted(tables, key=lambda t: weights[t], reverse=True)
    total_weight = sum(weights.values()) or 1.0

    def _budget_for(table: str) -> int:
        share = MAX_CONTEXT_CHARS * (weights[table] / total_weight)
        return int(min(MAX_TABLE_SNIPPET_CHARS, max(_MIN_TABLE_BUDGET_CHARS, share)))

    # Phase 1: fetch + fit every table (and harvest identifiers when masking).
    prepared = []  # (table, fitted_rows when masking else None, snippet when not masking else None, row_count, row_level_truncated)
    for table in tables:
        try:
            page = case_db.get_table_page(
                case_id, table, page=1, page_size=rows_per_table, query=payload.query
            )
        except ValueError:
            continue
        if not page["rows"]:
            continue  # nothing to show; a header with an empty array wastes budget for zero information
        rows = _truncate_long_values(_prune_empty_columns(page["rows"]))
        fitted_rows, row_level_truncated = _fit_rows_to_budget(rows, _budget_for(table))
        if not fitted_rows:
            truncated = True  # doesn't even fit one row (e.g. very wide rows) -- skip the table
            continue
        if anonymizer:
            anonymizer.harvest_rows(rows) # all fetched rows, not only the ones that fit: better recall
            prepared.append((table, fitted_rows, None, len(fitted_rows), row_level_truncated))
        else:
            prepared.append((table, None, json.dumps(fitted_rows, ensure_ascii=False), len(fitted_rows), row_level_truncated))

    # Phase 2: mask (tokens are longer than most values they replace, so refit against the table's budget afterwards) and emit.
    for table, fitted_rows, snippet, row_count, row_level_truncated in prepared:
        if anonymizer:
            fitted_rows = anonymizer.anonymize_rows(fitted_rows)
            snippet = json.dumps(fitted_rows, ensure_ascii=False)
            budget = _budget_for(table)
            if len(snippet) > budget * 1.05 and len(fitted_rows) > 1:
                fitted_rows, refit_truncated = _fit_rows_to_budget(fitted_rows, budget)
                row_level_truncated = row_level_truncated or refit_truncated
                snippet = json.dumps(fitted_rows, ensure_ascii=False)
            row_count = len(fitted_rows)
        if row_level_truncated:
            truncated = True
        meta = table_labels.get(table, {})
        label = meta.get("table_label") or table
        machine_label = meta.get("machine_label") or "unknown machine"
        query_note = payload.query or ""
        if anonymizer:
            label = anonymizer.anonymize_text(label)
            machine_label = anonymizer.anonymize_text(machine_label)
            query_note = anonymizer.anonymize_text(query_note)
        filter_note = f" (filtered by \"{query_note}\")" if payload.query else ""
        shown_note = f" -- showing {row_count} of up to {rows_per_table} row(s)" if row_level_truncated else f" -- showing up to {rows_per_table} rows"
        used_tables.append(table)
        context_parts.append(
            f"### Machine: {machine_label} | Table: {label} ({table}){filter_note}{shown_note}\n{snippet}"
        )

    # Safety net: header overhead across many tables could still push
    # slightly over budget. Trim whole sections from the end (never
    # mid-section) so everything included stays complete.
    included_parts = []
    included_tables = []
    total = 0
    for table, part in zip(used_tables, context_parts):
        part_len = len(part) + 2  # +2 for the "\n\n" joiner
        if total + part_len > MAX_CONTEXT_CHARS and included_parts:
            truncated = True
            break
        included_parts.append(part)
        included_tables.append(table)
        total += part_len
    context_blob = "\n\n".join(included_parts)

    return context_blob, truncated, included_tables


@dataclass
class PreparedAsk:
    """Everything that leaves for the model."""
    case_id: str
    user_id: str
    question: str # as typed (stored in the conversation)
    user_content: str
    question_sent: str # as sent (masked when anonymizing)
    history_messages: list[dict]
    system_prompt: str
    used_tables: list[str]
    truncated: bool
    anonymizer: Optional[Anonymizer]
    created_at: float = field(default_factory=time.time)


_PREVIEW_TTL_SECONDS = 15 * 60
_PREVIEW_MAX = 20
_previews: dict[str, PreparedAsk] = {}
_previews_lock = threading.Lock()


def _store_preview(prepared: PreparedAsk) -> str:
    preview_id = uuid.uuid4().hex
    now = time.time()
    with _previews_lock:
        for k in [k for k, v in _previews.items() if now - v.created_at > _PREVIEW_TTL_SECONDS]:
            _previews.pop(k, None)
        while len(_previews) >= _PREVIEW_MAX:  # oldest out
            _previews.pop(min(_previews, key=lambda k: _previews[k].created_at), None)
        _previews[preview_id] = prepared
    return preview_id


def _get_preview(preview_id: str, case_id: str, user_id: str, pop: bool) -> Optional[PreparedAsk]:
    with _previews_lock:
        prepared = _previews.get(preview_id)
        if not prepared or prepared.case_id != case_id or prepared.user_id != user_id:
            return None
        if time.time() - prepared.created_at > _PREVIEW_TTL_SECONDS:
            _previews.pop(preview_id, None)
            return None
        if pop:
            _previews.pop(preview_id, None)
        return prepared


def _validate_provider(payload: AIAnalysisRequest) -> None:
    if payload.provider == "claude":
        if not payload.api_key:
            raise HTTPException(400, "An Anthropic API key is required when using the Claude provider")
    elif not payload.endpoint:
        raise HTTPException(400, "An endpoint is required when using a custom/local LLM provider")


def _prepare_ask(case_id: str, payload: AIAnalysisRequest, db: Session, user: User) -> PreparedAsk:
    """Context + question + replayed history, masked through the case's
    seeded token map when anonymize is on (same value, same token across
    turns)."""
    anonymizer = None
    if payload.anonymize:
        machines = db.query(Machine).filter(Machine.case_id == case_id).all()
        anonymizer = Anonymizer.for_case(case_id, machines)

    context_blob, truncated, used_tables = _build_context(case_id, payload, db, anonymizer)
    question_sent = anonymizer.anonymize_text(payload.question) if anonymizer else payload.question
    user_content = f"CASE ARTIFACT CONTEXT:\n{context_blob}\n\nQUESTION:\n{question_sent}"

    # Only question/answer text of prior turns is stored
    prior = (
        db.query(AIMessage)
        .filter(AIMessage.case_id == case_id, AIMessage.conversation_key == payload.conversation_key)
        .order_by(AIMessage.created_at.desc())
        .limit(max(0, payload.history_turns) * 2)
        .all()
    )
    prior = list(reversed(prior))  # oldest first
    history_messages = [
        {"role": m.role, "content": anonymizer.anonymize_text(m.content) if anonymizer else m.content}
        for m in prior
    ]
    system_prompt = SYSTEM_PROMPT + (anonymization.PROMPT_SUFFIX if anonymizer else "")
    return PreparedAsk(
        case_id=case_id, user_id=user.id, question=payload.question, user_content=user_content, question_sent=question_sent,
        history_messages=history_messages, system_prompt=system_prompt, used_tables=used_tables,
        truncated=truncated, anonymizer=anonymizer,
    )


@router.post("/ask/preview", response_model=AIPreviewOut)
def preview_ask(case_id: str, payload: AIAnalysisRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Builds the anonymized request without sending it and returns what
    would be masked, so the analyst can confirm (or add missed values and
    preview again). The prepared request is cached briefly; /ask with the
    preview_id sends exactly that."""
    require_case_access(case_id, user, db, need_edit=True)
    payload.anonymize = True
    prepared = _prepare_ask(case_id, payload, db, user)
    preview_id = _store_preview(prepared)
    anon = prepared.anonymizer
    return AIPreviewOut(
        preview_id=preview_id, expires_in_seconds=_PREVIEW_TTL_SECONDS, question_sent=prepared.question_sent,
        context_tables_used=prepared.used_tables, truncated=prepared.truncated,
        context_chars=len(prepared.user_content), history_turns=len(prepared.history_messages) // 2,
        entries=anon.used_entries(), stats=anon.stats(),
    )


@router.get("/ask/preview/{preview_id}", response_class=PlainTextResponse)
def download_preview(case_id: str, preview_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """The exact text a reviewed request would send (system prompt, replayed
    history, context and question), for offline inspection."""
    require_case_access(case_id, user, db)
    prepared = _get_preview(preview_id, case_id, user.id, pop=False)
    if not prepared:
        raise HTTPException(404, "Preview expired or not found; review the request again")
    parts = [f"=== SYSTEM PROMPT ===\n{prepared.system_prompt}\n"]
    for m in prepared.history_messages:
        parts.append(f"=== HISTORY ({m['role']}) ===\n{m['content']}\n")
    parts.append(f"=== CURRENT TURN (user) ===\n{prepared.user_content}\n")
    return "\n".join(parts)


@router.post("/ask", response_model=AIAnalysisResponse)
def ask_ai(case_id: str, payload: AIAnalysisRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Sends a context snapshot of the requested (or all) artifact tables,
    the question and recent history to the configured LLM. Scoped by conversation_key
    so every page keeps its own continuable conversation."""
    require_case_access(case_id, user, db, need_edit=True)
    _validate_provider(payload)

    if payload.preview_id:
        prepared = _get_preview(payload.preview_id, case_id, user.id, pop=True)
        if not prepared:
            raise HTTPException(409, "The reviewed request has expired; please review it again")
    else:
        prepared = _prepare_ask(case_id, payload, db, user)
    anonymizer = prepared.anonymizer
    user_content, history_messages, system_prompt = prepared.user_content, prepared.history_messages, prepared.system_prompt
    used_tables, truncated = prepared.used_tables, prepared.truncated
    if anonymizer:
        anonymizer.persist(case_id)  # kept even if the provider call fails below

    job = Job(case_id=case_id, machine_id=payload.machine_id, job_type=JobType.ai_analysis,
              status=JobStatus.running, message=f"Asking model {payload.model}")
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        if payload.provider == "claude":
            raw_answer = _call_claude(payload.model, payload.api_key, payload.max_tokens, history_messages, user_content, system_prompt)
        else:
            raw_answer = _call_openai_compatible(payload.endpoint, payload.model, payload.api_key, payload.max_tokens, history_messages, user_content, system_prompt)
    except Exception as ex:  # noqa: BLE001
        job.status = JobStatus.failed
        job.message = f"LLM call failed: {ex}"
        db.commit()
        raise HTTPException(502, f"Could not reach or parse response from the LLM provider: {ex}")

    job.status = JobStatus.success
    job.message = "AI analysis complete"
    db.commit()

    stats = None
    answer = raw_answer
    if anonymizer:
        answer, unrestored = anonymizer.restore_text(raw_answer)
        stats = anonymizer.stats(unrestored)

    # Persist this turn (question text only, not the context blob) so the
    # conversation can be replayed/continued next time this page is opened.
    db.add(AIMessage(case_id=case_id, conversation_key=payload.conversation_key, role="user", content=prepared.question))
    db.add(AIMessage(case_id=case_id, conversation_key=payload.conversation_key, role="assistant", content=answer))
    log_event(
        db, user, "ai.ask", case_id=case_id, target_type="conversation", target_id=payload.conversation_key,
        target_label=payload.conversation_key,
        details={
            "provider": payload.provider, "model": payload.model, "anonymized": bool(anonymizer),
            "question": prepared.question[:500], # question only, never the answer, keeps the audit log lean
        },
        request=request,
    )
    db.commit()

    return AIAnalysisResponse(
        answer=answer, context_tables_used=used_tables, truncated=truncated,
        anonymized=bool(anonymizer), anonymization=stats, raw_answer=raw_answer if anonymizer else None,
    )


@router.get("/anonymization", response_model=AnonymizationMapOut)
def get_anonymization_map(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """The case's token -> original map (and seed), kept in case.sqlite so
    it is shared by every analyst on the case and travels with export."""
    require_case_access(case_id, user, db)
    entries = anonymization.load_mapping(case_id)
    return AnonymizationMapOut(seed=anonymization.load_seed(case_id), count=len(entries), entries=entries)


@router.delete("/anonymization")
def clear_anonymization_map(case_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Forgets the map and seed; stored conversations already hold restored
    text, so nothing displayed changes. The next anonymized request starts
    a fresh token namespace."""
    require_case_access(case_id, user, db, need_edit=True)
    removed = anonymization.clear_mapping(case_id)
    log_event(db, user, "ai.anonymization_cleared", case_id=case_id, target_type="case", target_id=case_id,
              details={"entries_removed": removed}, request=request)
    db.commit()
    return {"ok": True, "removed": removed}


@router.get("/anonymization/custom", response_model=list[AnonymizationCustomOut])
def list_custom_values(case_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Analyst-defined sensitive values for this case (company, project,
    people, anything the heuristics would miss)."""
    require_case_access(case_id, user, db)
    return anonymization.list_custom(case_id)


@router.post("/anonymization/custom", response_model=AnonymizationCustomOut)
def add_custom_value(case_id: str, payload: AnonymizationCustomIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    try:
        entry = anonymization.add_custom(case_id, payload.value, payload.kind, payload.substring, user.username)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    log_event(db, user, "ai.anonymization_custom_added", case_id=case_id, target_type="case", target_id=case_id,
              details={"kind": entry["kind"], "substring": entry["substring"]}, request=request)  # value itself stays out of the audit log
    db.commit()
    return entry


@router.delete("/anonymization/custom/{custom_id}")
def delete_custom_value(case_id: str, custom_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    require_case_access(case_id, user, db, need_edit=True)
    if not anonymization.delete_custom(case_id, custom_id):
        raise HTTPException(404, "Custom value not found")
    log_event(db, user, "ai.anonymization_custom_removed", case_id=case_id, target_type="case", target_id=case_id,
              details={"id": custom_id}, request=request)
    db.commit()
    return {"ok": True}


_RETRYABLE_STATUSES = {429, 503, 529}
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 2.0


def _post_with_retry(url: str, **kwargs) -> requests.Response:
    last_resp = None
    for attempt in range(_MAX_RETRIES + 1):
        resp = requests.post(url, **kwargs)
        if resp.status_code not in _RETRYABLE_STATUSES:
            return resp
        last_resp = resp
        if attempt < _MAX_RETRIES:
            time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))
    return last_resp


def _raise_for_status_with_body(resp: requests.Response, provider_name: str) -> None:
    """raise_for_status() discards the response body, which is where the
    provider explains why the request was rejected. Surface that instead
    of a bare '400 Client Error'."""
    if resp.ok:
        return
    try:
        body = resp.json()
        detail = body.get("error", {}).get("message") if isinstance(body.get("error"), dict) else body.get("error")
        detail = detail or json.dumps(body)
    except Exception:
        detail = resp.text[:500] if resp.text else "(empty response body)"
    raise RuntimeError(f"{provider_name} rejected the request (HTTP {resp.status_code}): {detail}")


def _call_openai_compatible(
    endpoint: str, model: str, api_key: Optional[str], max_tokens: Optional[int],
    history_messages: list[dict], user_content: str, system_prompt: str = SYSTEM_PROMPT,
) -> str:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(history_messages)
    messages.append({"role": "user", "content": user_content})

    body = {"model": model, "messages": messages, "temperature": 0.2}
    if max_tokens:
        body["max_tokens"] = max_tokens

    url = _normalize_openai_endpoint(endpoint)
    resp = _post_with_retry(url, headers=headers, data=json.dumps(body), timeout=300)
    _raise_for_status_with_body(resp, "The LLM endpoint")
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _normalize_openai_endpoint(endpoint: str) -> str:
    """Accepts either a bare base URL (as in an OpenAI(base_url=...) client)
    or a full chat/completions URL, and always posts to the latter."""
    url = endpoint.rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    return f"{url}/chat/completions"


def _call_claude(
    model: str, api_key: str, max_tokens: Optional[int],
    history_messages: list[dict], user_content: str, system_prompt: str = SYSTEM_PROMPT,
) -> str:
    """Calls Anthropic's Messages API directly (not an OpenAI-compatible
    shape), x-api-key auth, a required anthropic-version header, and a
    content block list in the response rather than choices[0].message."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    messages = list(history_messages)
    messages.append({"role": "user", "content": user_content})

    body = {
        "model": model,
        "max_tokens": max_tokens or 4096,
        "system": system_prompt,
        "messages": messages,
    }
    resp = _post_with_retry("https://api.anthropic.com/v1/messages", headers=headers, data=json.dumps(body), timeout=300)
    _raise_for_status_with_body(resp, "Anthropic")
    data = resp.json()
    text_blocks = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(text_blocks).strip()


def _table_label_map(case_id: str) -> dict[str, dict]:
    conn = case_db.get_connection(case_id)
    try:
        case_db.ensure_meta_table(conn)
        rows = conn.execute("SELECT table_name, table_label, machine_label, category FROM _artifact_meta").fetchall()
        return {r["table_name"]: dict(r) for r in rows}
    except Exception:
        return {}
    finally:
        conn.close()
