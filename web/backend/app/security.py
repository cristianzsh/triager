import datetime as dt
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User, Role, CaseMember

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# bcrypt's own hard limit is 72 bytes; truncate deliberately (rather than
# letting the library raise) so an unusually long passphrase still hashes
# instead of crashing the login/create-user flow.
_BCRYPT_MAX_BYTES = 72


def _prep(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prep(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(plain), hashed.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(user: User) -> str:
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": user.id, "username": user.username, "role": user.role.value, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def require_role(*allowed: Role):
    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role for this action")
        return user
    return _checker


def require_case_access(case_id: str, user: User, db: Session, need_edit: bool = False) -> None:
    """Admins and leads can access any case; others must be explicit members.
    Role.read_only can never satisfy need_edit, regardless of what that
    membership's can_edit flag says -- the global role is an absolute
    ceiling, not just a default."""
    if user.role in (Role.admin,):
        return
    member = (
        db.query(CaseMember)
        .filter(CaseMember.case_id == case_id, CaseMember.user_id == user.id)
        .first()
    )
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have access to this case")
    effective_can_edit = member.can_edit and user.role != Role.read_only
    if need_edit and not effective_can_edit:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Read-only access to this case")
