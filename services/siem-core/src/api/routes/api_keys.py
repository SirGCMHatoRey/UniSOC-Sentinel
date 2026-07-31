"""
API key management routes.

GET    /api/v1/api-keys       — list current user's keys (prefix only)
POST   /api/v1/api-keys       — create new key (full key returned once)
DELETE /api/v1/api-keys/{id}  — deactivate a key
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db, get_current_user
from src.models.api_key import APIKey
from src.models.user import User

log = structlog.get_logger(__name__)
router = APIRouter(prefix="/api-keys", tags=["api-keys"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None

    model_config = {"from_attributes": True}


class CreateAPIKeyRequest(BaseModel):
    name: str


class CreateAPIKeyResponse(APIKeyResponse):
    """Extended response that includes the full raw key — returned only once."""
    key: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=list[APIKeyResponse])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[APIKeyResponse]:
    """Return all API keys owned by the current user (prefix only, not full key)."""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == current_user.id)
        .order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [APIKeyResponse.model_validate(k) for k in keys]


@router.post("", response_model=CreateAPIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: CreateAPIKeyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CreateAPIKeyResponse:
    """
    Generate a new API key.

    The key format is: sk_<32 random hex chars>
    The full key is returned ONCE in the response and never stored.
    Only the SHA-256 hash is persisted.
    """
    raw_random = os.urandom(32).hex()  # 64 hex chars
    raw_key = f"sk_{raw_random}"
    key_prefix = raw_key[:10]  # "sk_" + first 7 chars
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = APIKey(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    log.info(
        "API key created",
        key_id=api_key.id,
        name=api_key.name,
        user_id=current_user.id,
    )

    return CreateAPIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        key=raw_key,
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Deactivate an API key owned by the current user."""
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        )
    )
    key = result.scalar_one_or_none()
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found",
        )

    key.is_active = False
    await db.commit()

    log.info("API key deactivated", key_id=key_id, user_id=current_user.id)
