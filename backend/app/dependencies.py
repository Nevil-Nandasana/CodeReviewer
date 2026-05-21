"""
FastAPI dependency injection — Database session, Redis client, JWT auth.
"""
from __future__ import annotations
import uuid
from typing import Annotated, Generator
import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
import redis as redis_lib

from app.config import settings
from app.db.session import SessionLocal
from app.models.user import User

logger = structlog.get_logger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# ── Database ────────────────────────────────────────────────────────────────

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbDep = Annotated[Session, Depends(get_db)]

# ── Redis ────────────────────────────────────────────────────────────────────

_redis_client: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis | None:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)
            _redis_client.ping()
        except Exception as e:
            logger.warning("redis_unavailable", error=str(e))
            _redis_client = None
    return _redis_client


RedisDep = Annotated[redis_lib.Redis | None, Depends(get_redis)]

# ── JWT Authentication ───────────────────────────────────────────────────────

def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: DbDep,
) -> User:
    # 401, not 403. 401 means "you are not authenticated"; 403 means
    # "authenticated, but not allowed". The frontend's axios interceptor keys
    # its auto-logout on 401 (see frontend/src/api/client.ts), so returning 403
    # for an expired token left the user staring at failing requests with no
    # redirect to the login page.
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc from None

    try:
        user_uuid = uuid.UUID(user_id)
    except (ValueError, AttributeError, TypeError):
        # A token whose `sub` is not a UUID is malformed, not a server fault.
        raise credentials_exc from None

    user = db.query(User).filter(User.id == user_uuid).first()
    if user is None:
        raise credentials_exc
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
