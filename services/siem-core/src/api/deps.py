"""
FastAPI dependency functions shared across all route modules.
"""

from __future__ import annotations

import hashlib
from typing import AsyncGenerator

import structlog
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.database import get_session
from src.models.api_key import APIKey
from src.models.user import User

log = structlog.get_logger(__name__)

_bearer = HTTPBearer(auto_error=False)


async def get_db(
    session: AsyncSession = Depends(get_session),
) -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession — thin alias kept for import ergonomics."""
    yield session


async def get_redis(request: Request):
    """Return the Redis client stored on app.state."""
    return request.app.state.redis


async def _resolve_user_from_token(token: str, db: AsyncSession) -> User:
    """
    Decode a JWT access token and return the corresponding User.

    Raises HTTPException 401 on any validation failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


async def _resolve_user_from_api_key(api_key: str, db: AsyncSession) -> User:
    """
    Validate an API key (sk_ prefixed) and return the associated User.

    Raises HTTPException 401 if the key is invalid or revoked.
    """
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
    )
    api_key_record = result.scalar_one_or_none()
    if api_key_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    user_result = await db.execute(
        select(User).where(User.id == api_key_record.user_id, User.is_active.is_(True))
    )
    user = user_result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key owner not found or inactive",
        )

    # Update last_used_at without blocking
    from datetime import datetime, timezone
    api_key_record.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    return user


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    db: AsyncSession = Depends(get_session),
) -> User:
    """
    Extract and validate the caller identity from either:
      • Authorization: Bearer <JWT>
      • X-API-Key: sk_...

    Returns the authenticated User or raises HTTP 401.
    """
    # --- X-API-Key header takes precedence if present ---
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        return await _resolve_user_from_api_key(api_key_header, db)

    # --- Bearer JWT ---
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await _resolve_user_from_token(credentials.credentials, db)


def require_role(*allowed_roles: str):
    """
    Return a FastAPI dependency that enforces role-based access control.

    Usage::

        @router.get("/admin-only")
        async def admin_view(user: User = Depends(require_role("admin"))):
            ...

    Roles are hierarchical: admin > analyst > viewer.
    Passing multiple roles means "any of these roles is accepted".
    """
    _ROLE_RANK = {"admin": 3, "analyst": 2, "viewer": 1}
    min_rank = min(_ROLE_RANK.get(r, 0) for r in allowed_roles)

    async def _check(user: User = Depends(get_current_user)) -> User:
        user_rank = _ROLE_RANK.get(user.role, 0)
        if user_rank < min_rank:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed_roles)}",
            )
        return user

    return _check
