from fastapi import APIRouter, Depends

from ..models import Role, User
from ..runtime_paths import is_frozen, writable_data_dir
from ..security import require_role

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/info")
def get_system_info(_user: User = Depends(require_role(Role.admin))):
    """Where this instance's case data, uploads, and app database live on
    disk -- shown in the Users admin page so whoever's operating it knows
    where to look for backups, without needing to dig through env vars."""
    return {
        "data_dir": str(writable_data_dir()),
        "packaged": is_frozen(),
    }
