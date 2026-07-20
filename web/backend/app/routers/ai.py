import json
import time
from typing import Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import User, Job, JobType, JobStatus, AIMessage
from ..schemas import AIAnalysisRequest, AIAnalysisResponse, AIMessageOut
from ..security import get_current_user, require_case_access
from ..services.audit import log_event
from ..services import case_db

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
    "execution_evidence": 4.0,  # Amcache, Prefetch, SRUM, WER, PCA -- what ran, when
    "persistence": 3.0,         # ScheduledTasks, WMI -- how it stays around
    "registry": 3.0,            # Shimcache, BAM/DAM, USB -- also execution/device evidence
    "user_artifacts": 2.0,      # UserAssist, JumpLists, browser history, etc.
    "filesystem": 1.5,          # MFT, USN Journal, LogFile, RecycleBin
    "event_logs": 1.0,
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


def _build_context(case_id: str, payload: AIAnalysisRequest, db: Session) -> tuple[str, bool, list[str]]:
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

    for table in tables:
        try:
            page = case_db.get_table_page(
                case_id, table, page=1, page_size=rows_per_table, query=payload.query
            )
        except ValueError:
            continue
        if not page["rows"]:
            continue  # nothing to show; a header with an empty array wastes budget for zero information
        meta = table_labels.get(table, {})
        label = meta.get("table_label") or table
        machine_label = meta.get("machine_label") or "unknown machine"
        rows = _truncate_long_values(_prune_empty_columns(page["rows"]))
        fitted_rows, row_level_truncated = _fit_rows_to_budget(rows, _budget_for(table))
        if not fitted_rows:
            truncated = True  # doesn't even fit one row (e.g. very wide rows) -- skip the table
            continue
        if row_level_truncated:
            truncated = True
        snippet = json.dumps(fitted_rows, ensure_ascii=False)
        filter_note = f" (filtered by \"{payload.query}\")" if payload.query else ""
        shown_note = f" -- showing {len(fitted_rows)} of up to {rows_per_table} row(s)" if row_level_truncated else f" -- showing up to {rows_per_table} rows"
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


@router.post("/ask", response_model=AIAnalysisResponse)
def ask_ai(case_id: str, payload: AIAnalysisRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Builds a context snapshot from the requested (or all) artifact
    tables and sends it, with the question and recent conversation
    history, to the specified LLM (local/OpenAI-compatible or Claude).
    Nothing is sent unless the investigator explicitly triggers this.

    Scoped by conversation_key (per page) so history persists per scope
    without mixing between broad/machine/table-level conversations."""
    require_case_access(case_id, user, db, need_edit=True)

    if payload.provider == "claude":
        if not payload.api_key:
            raise HTTPException(400, "An Anthropic API key is required when using the Claude provider")
    elif not payload.endpoint:
        raise HTTPException(400, "An endpoint is required when using a custom/local LLM provider")

    context_blob, truncated, used_tables = _build_context(case_id, payload, db)
    user_content = f"CASE ARTIFACT CONTEXT:\n{context_blob}\n\nQUESTION:\n{payload.question}"

    # TEMP DEBUG -- prints the exact payload to the server terminal.
    #print(f"\n===== AI PAYLOAD (case_id={case_id}, conversation_key={payload.conversation_key}) =====")
    #print(user_content)
    #print("===== END AI PAYLOAD =====\n")

    # Prior turns of this same conversation, for continuity. Only the
    # question/answer text is stored (not the artifact context each turn
    # sent), so replaying them back doesn't re-bloat every request with
    # the same rows, only the current question gets fresh context.
    prior = (
        db.query(AIMessage)
        .filter(AIMessage.case_id == case_id, AIMessage.conversation_key == payload.conversation_key)
        .order_by(AIMessage.created_at.desc())
        .limit(max(0, payload.history_turns) * 2)
        .all()
    )
    prior = list(reversed(prior))  # oldest first
    history_messages = [{"role": m.role, "content": m.content} for m in prior]

    job = Job(case_id=case_id, machine_id=payload.machine_id, job_type=JobType.ai_analysis,
              status=JobStatus.running, message=f"Asking model {payload.model}")
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        if payload.provider == "claude":
            answer = _call_claude(payload.model, payload.api_key, payload.max_tokens, history_messages, user_content)
        else:
            answer = _call_openai_compatible(payload.endpoint, payload.model, payload.api_key, payload.max_tokens, history_messages, user_content)
    except Exception as ex:  # noqa: BLE001
        job.status = JobStatus.failed
        job.message = f"LLM call failed: {ex}"
        db.commit()
        raise HTTPException(502, f"Could not reach or parse response from the LLM provider: {ex}")

    job.status = JobStatus.success
    job.message = "AI analysis complete"
    db.commit()

    # Persist this turn (question text only, not the context blob) so the
    # conversation can be replayed/continued next time this page is opened.
    db.add(AIMessage(case_id=case_id, conversation_key=payload.conversation_key, role="user", content=payload.question))
    db.add(AIMessage(case_id=case_id, conversation_key=payload.conversation_key, role="assistant", content=answer))
    log_event(
        db, user, "ai.ask", case_id=case_id, target_type="conversation", target_id=payload.conversation_key,
        target_label=payload.conversation_key,
        details={
            "provider": payload.provider, "model": payload.model,
            "question": payload.question[:500],  # question only, never the answer, keeps the audit log lean
        },
        request=request,
    )
    db.commit()

    return AIAnalysisResponse(answer=answer, context_tables_used=used_tables, truncated=truncated)


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
    history_messages: list[dict], user_content: str,
) -> str:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
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
    history_messages: list[dict], user_content: str,
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
        "system": SYSTEM_PROMPT,
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
