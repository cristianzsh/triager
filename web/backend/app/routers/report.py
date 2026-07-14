from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Case, User
from ..security import get_current_user, require_case_access
from ..services import report
from ..services.audit import log_event

router = APIRouter(tags=["report"])


@router.get("/cases/{case_id}/report.docx")
def download_report(case_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Generates a Word document combining case metadata, machine host
    profiles and artifact summaries, every persisted AI conversation, and
    the case's activity log, a self-contained deliverable that doesn't
    require the recipient to have access to the console.
    """
    require_case_access(case_id, user, db)
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    docx_bytes = report.build_case_report(db, case, generated_by=user.username)

    log_event(db, user, "report.generate", case_id=case_id, target_type="case", target_id=case_id,
              target_label=case.name, request=request)
    db.commit()

    safe_name = "".join(c if c.isalnum() or c in " -_" else "_" for c in case.name).strip() or "case"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.docx"'},
    )
