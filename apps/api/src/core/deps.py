import hashlib
import uuid
from typing import Optional
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.src.core.config import settings
from apps.api.src.core.database import get_db
from apps.api.src.core.models import ApiKeyRecord
from apps.api.src.services.budget_manager import BudgetManager
from apps.api.src.services.rate_limiter import RateLimiter

# Global service singletons
rate_limiter = RateLimiter(redis_client=None)
budget_manager = BudgetManager(redis_client=None)


async def get_current_api_key(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> ApiKeyRecord:
    """
    Authenticates the client via Bearer API Key.
    Compares SHA-256 hash against stored api_keys table.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. Expected 'Bearer <api_key>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Use 'Bearer <api_key>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Master Admin Key bypass
    if token == settings.ADMIN_API_KEY:
        return ApiKeyRecord(
            id="admin-master",
            name="Master Admin Key",
            key_hash="admin_master_hash",
            prefix="aegis_admin",
            role="admin",
            is_active=True,
            rate_limit_rpm=10_000,
            daily_token_budget=10_000_000,
        )

    # Hash incoming key
    key_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    # Query DB
    query = select(ApiKeyRecord).where(ApiKeyRecord.key_hash == key_hash)
    result = await db.execute(query)
    api_key_record = result.scalars().first()

    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not api_key_record.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key has been revoked or deactivated",
        )

    return api_key_record


def get_correlation_id(
    x_correlation_id: Optional[str] = Header(None)
) -> str:
    return x_correlation_id or f"corr_{uuid.uuid4().hex[:12]}"
