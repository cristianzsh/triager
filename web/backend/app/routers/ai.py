import json
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

MAX_CONTEXT_CHARS = 180_000
SYSTEM_PROMPT = (
    "You are a DFIR forensic analyst assistant helping investigate a case. "
    "You are given structured forensic artifact data (Prefetch, Event Logs, "
    "Registry, Scheduled Tasks, browser/user activity, etc.) extracted by the "
    "Triager tool, possibly from multiple machines in the same case (each "
    "table's context notes which machine it came from). Only reason from "
    "the evidence provided; if something is not present in the context, say "
    "so explicitly rather than guessing. When you flag something as "
    "suspicious, cite the specific machine/table/row/field. You may be "
    "shown earlier turns of this same conversation for continuity -- treat "
    "them as prior context, not as new evidence to re-verify."
)


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


@router.post("/ask", response_model=AIAnalysisResponse)
def ask_ai(case_id: str, payload: AIAnalysisRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Builds a context snapshot from the requested (or all) artifact tables and
    sends it, alongside the investigator's question and recent prior turns
    of this same conversation, to the LLM endpoint they specify, local
    (Ollama/vLLM/LM Studio, OpenAI-compatible) or Claude directly. Nothing
    is sent anywhere unless the investigator explicitly triggers this.

    Every call is scoped to a conversation_key (opaque, frontend-derived
    per page), the question and answer are persisted under that key so
    reopening the same page later shows the same conversation, and multiple
    pages (broad case analysis, one machine's analysis, each table's quick
    analysis) never mix history together.

    Two calling patterns share this one endpoint:
      - Broad analysis: no tables (or no machine_id) -> whole case, or
        whole machine, becomes context.
      - Quick per-table analysis: tables=[<one table>] plus the
        investigator's current search term, so the AI sees exactly the
        filtered view they're looking at on screen.
    """
    require_case_access(case_id, user, db, need_edit=True)

    if payload.provider == "claude":
        if not payload.api_key:
            raise HTTPException(400, "An Anthropic API key is required when using the Claude provider")
    elif not payload.endpoint:
        raise HTTPException(400, "An endpoint is required when using a custom/local LLM provider")

    if payload.tables:
        tables = payload.tables
    else:
        tables = case_db.list_tables(case_id, machine_id=payload.machine_id)

    context_parts = []
    truncated = False
    used_tables = []

    table_labels = _table_label_map(case_id)

    for table in tables:
        try:
            page = case_db.get_table_page(
                case_id, table, page=1, page_size=payload.max_rows_per_table, query=payload.query
            )
        except ValueError:
            continue
        used_tables.append(table)
        meta = table_labels.get(table, {})
        label = meta.get("table_label") or table
        machine_label = meta.get("machine_label") or "unknown machine"
        snippet = json.dumps(page["rows"], ensure_ascii=False)
        if len(snippet) > 40_000:
            snippet = snippet[:40_000]
            truncated = True
        filter_note = f" (filtered by \"{payload.query}\")" if payload.query else ""
        context_parts.append(
            f"### Machine: {machine_label} | Table: {label} ({table}){filter_note} "
            f"-- showing up to {payload.max_rows_per_table} rows\n{snippet}"
        )

    context_blob = "\n\n".join(context_parts)
    if len(context_blob) > MAX_CONTEXT_CHARS:
        context_blob = context_blob[:MAX_CONTEXT_CHARS]
        truncated = True

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

    user_content = f"CASE ARTIFACT CONTEXT:\n{context_blob}\n\nQUESTION:\n{payload.question}"

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


def _raise_for_status_with_body(resp: requests.Response, provider_name: str) -> None:
    """requests' own raise_for_status() only gives you the URL and status
    code, it throws away the response body, which is exactly where the
    provider explains why the request was rejected (bad model name,
    context too long, malformed message, etc). Surface that instead so the
    investigator sees the actual reason, not just '400 Client Error'."""
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
    resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=300)
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
    resp = requests.post("https://api.anthropic.com/v1/messages", headers=headers, data=json.dumps(body), timeout=300)
    _raise_for_status_with_body(resp, "Anthropic")
    data = resp.json()
    text_blocks = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(text_blocks).strip()


def _table_label_map(case_id: str) -> dict[str, dict]:
    conn = case_db.get_connection(case_id)
    try:
        case_db.ensure_meta_table(conn)
        rows = conn.execute("SELECT table_name, table_label, machine_label FROM _artifact_meta").fetchall()
        return {r["table_name"]: dict(r) for r in rows}
    except Exception:
        return {}
    finally:
        conn.close()
