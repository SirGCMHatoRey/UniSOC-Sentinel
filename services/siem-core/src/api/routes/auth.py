"""
Authentication routes.

POST /api/v1/auth/login    — issue access + refresh tokens
POST /api/v1/auth/logout   — revoke refresh token
POST /api/v1/auth/refresh  — issue new access token from refresh token
GET  /api/v1/auth/me       — return current user profile
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_user, get_db
from src.config import settings
from src.models.session import Session
from src.models.user import User

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------


def _create_access_token(user_id: str, role: str, jti: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {
        "sub": user_id,
        "role": role,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _create_refresh_token(user_id: str, jti: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )
    payload = {
        "sub": user_id,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validate username + password and issue JWT access + refresh tokens."""
    result = await db.execute(
        select(User).where(User.username == body.username, User.is_active.is_(True))
    )
    user = result.scalar_one_or_none()

    if user is None or not _pwd_context.verify(body.password, user.password_hash):
        log.warning("Failed login attempt", username=body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    jti = str(uuid.uuid4())
    access_token = _create_access_token(user.id, user.role, jti)
    refresh_token = _create_refresh_token(user.id, jti)

    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )

    session_record = Session(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=_hash_token(refresh_token),
        jti=jti,
        expires_at=expires_at,
        user_agent=request.headers.get("User-Agent"),
        ip_address=(
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        ),
    )
    db.add(session_record)

    # Update last_login_at
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(last_login_at=datetime.now(timezone.utc))
    )
    await db.commit()

    log.info("Login successful", user_id=user.id, username=user.username)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke the given refresh token so it cannot be used again."""
    token_hash = _hash_token(body.refresh_token)
    result = await db.execute(
        select(Session).where(
            Session.token_hash == token_hash,
            Session.is_revoked.is_(False),
        )
    )
    session = result.scalar_one_or_none()
    if session:
        session.is_revoked = True
        await db.commit()
        log.info("Session revoked", session_id=session.id, user_id=session.user_id)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Issue a new access token given a valid, non-revoked refresh token."""
    invalid_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )

    try:
        payload = jwt.decode(
            body.refresh_token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        if payload.get("type") != "refresh":
            raise invalid_exc
        user_id: str = payload["sub"]
        old_jti: str = payload["jti"]
    except JWTError:
        raise invalid_exc

    token_hash = _hash_token(body.refresh_token)
    result = await db.execute(
        select(Session).where(
            Session.token_hash == token_hash,
            Session.is_revoked.is_(False),
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise invalid_exc

    # Fetch current user role
    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_active.is_(True))
    )
    user = user_result.scalar_one_or_none()
    if user is None:
        raise invalid_exc

    # Rotate: revoke old session, issue new tokens
    session.is_revoked = True

    new_jti = str(uuid.uuid4())
    new_access_token = _create_access_token(user.id, user.role, new_jti)
    new_refresh_token = _create_refresh_token(user.id, new_jti)

    new_expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )
    new_session = Session(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=_hash_token(new_refresh_token),
        jti=new_jti,
        expires_at=new_expires_at,
    )
    db.add(new_session)
    await db.commit()

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserResponse)
async def me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the authenticated user's profile."""
    return UserResponse.model_validate(current_user)
