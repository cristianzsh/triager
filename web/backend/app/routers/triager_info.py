from fastapi import APIRouter, Depends, Query

from ..models import User
from ..security import get_current_user
from ..services import triager_runner

router = APIRouter(prefix="/triager", tags=["triager"])


@router.get("/parsers", response_model=list[str])
def get_parsers(platform: str | None = Query(None), _user: User = Depends(get_current_user)):
    """Names Triager understands for --exclude-parser (hardcoded to match
    triager.py's PARSER_TOOLS / UNIX_PARSER_TOOLS). platform=windows|unix
    filters to one set; unset returns both."""
    return triager_runner.list_parser_names(platform)
