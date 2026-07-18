from fastapi import APIRouter, Depends

from ..models import User
from ..security import get_current_user
from ..services import triager_runner

router = APIRouter(prefix="/triager", tags=["triager"])


@router.get("/parsers", response_model=list[str])
def get_parsers(_user: User = Depends(get_current_user)):
    """Names Triager understands for --exclude-parser (hardcoded to match
    cli/triager.py's PARSER_TOOLS -- see triager_runner.PARSER_NAMES)."""
    return triager_runner.list_parser_names()
