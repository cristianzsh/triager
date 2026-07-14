"""
Thin helper for writing AuditEvent rows. Deliberately synchronous and
best-effort within the same DB session as the action it's logging (so a
committed action and its audit record land together), callers pass their
already-open db session and call db.commit() themselves as usual.
"""
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditEvent, User


def log_event(
    db: Session,
    user: Optional[User],
    action: str,
    case_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    target_label: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    event = AuditEvent(
        case_id=case_id,
        user_id=user.id if user else None,
        username=user.username if user else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        details=details,
        ip_address=(request.client.host if request and request.client else None),
    )
    db.add(event)
    # Intentionally not committing here, callers already commit as part of
    # their own transaction; this just adds the row to that same commit.
