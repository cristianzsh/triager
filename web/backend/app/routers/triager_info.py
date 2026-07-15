from fastapi import APIRouter, Depends

from ..models import User
from ..security import get_current_user
from ..services import triager_runner

router = APIRouter(prefix="/triager", tags=["triager"])


@router.get("/parsers", response_model=list[str])
def get_parsers(_user: User = Depends(get_current_user)):
    """Names Triager understands for --exclude-parser, read from the
    actual binary rather than a hardcoded copy that could drift."""
    return triager_runner.list_parser_names()
