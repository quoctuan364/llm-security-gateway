import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.src.core.database import get_db
from apps.api.src.core.deps import get_current_api_key
from apps.api.src.core.models import ApiKeyRecord, AuditRecord, PolicyRuleRecord
from apps.api.src.services.audit_service import AuditService
from packages.shared.src.utils.crypto import generate_api_key

router = APIRouter(prefix="/v1/admin", tags=["Security Administration & Audit"])
audit_service = AuditService()


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    project_id: Optional[str] = "default-project"
    rate_limit_rpm: Optional[int] = 60
    daily_token_budget: Optional[int] = 100_000
    role: Optional[str] = "client"


class CreateApiKeyResponse(BaseModel):
    id: str
    name: str
    plaintext_key: str
    prefix: str
    rate_limit_rpm: int
    daily_token_budget: int
    role: str
    warning: str = "This plaintext API key is shown ONLY ONCE. Store it securely!"


@router.post("/api-keys", response_model=CreateApiKeyResponse)
async def create_api_key(
    request: CreateApiKeyRequest,
    current_key: ApiKeyRecord = Depends(get_current_api_key),
    db: AsyncSession = Depends(get_db),
):
    if current_key.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to provision API keys",
        )

    plaintext, key_hash = generate_api_key()
    prefix = plaintext[:14]

    record = ApiKeyRecord(
        name=request.name,
        key_hash=key_hash,
        prefix=prefix,
        project_id=request.project_id or "default-project",
        role=request.role or "client",
        rate_limit_rpm=request.rate_limit_rpm or 60,
        daily_token_budget=request.daily_token_budget or 100_000,
        is_active=True,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    return CreateApiKeyResponse(
        id=record.id,
        name=record.name,
        plaintext_key=plaintext,
        prefix=record.prefix,
        rate_limit_rpm=record.rate_limit_rpm,
        daily_token_budget=record.daily_token_budget,
        role=record.role,
    )


@router.get("/api-keys")
async def list_api_keys(
    current_key: ApiKeyRecord = Depends(get_current_api_key),
    db: AsyncSession = Depends(get_db),
):
    if current_key.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    query = select(ApiKeyRecord).order_by(ApiKeyRecord.created_at.desc())
    res = await db.execute(query)
    records = res.scalars().all()

    return [
        {
            "id": r.id,
            "name": r.name,
            "prefix": f"{r.prefix}...",
            "project_id": r.project_id,
            "role": r.role,
            "rate_limit_rpm": r.rate_limit_rpm,
            "daily_token_budget": r.daily_token_budget,
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]


@router.get("/audit-logs")
async def list_audit_logs(
    limit: int = 50,
    action: Optional[str] = None,
    current_key: ApiKeyRecord = Depends(get_current_api_key),
    db: AsyncSession = Depends(get_db),
):
    if current_key.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    query = select(AuditRecord).order_by(AuditRecord.timestamp.desc()).limit(limit)
    if action:
        query = query.where(AuditRecord.action == action)

    res = await db.execute(query)
    records = res.scalars().all()

    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "correlation_id": r.correlation_id,
            "api_key_id": r.api_key_id,
            "route": r.route,
            "action": r.action,
            "risk_score": r.risk_score,
            "tokens": {"prompt": r.prompt_tokens, "completion": r.completion_tokens},
            "detections": json.loads(r.detections_json),
            "prev_hash": r.prev_hash,
            "current_hash": r.current_hash,
        }
        for r in records
    ]


@router.post("/audit-logs/verify")
async def verify_audit_chain(
    current_key: ApiKeyRecord = Depends(get_current_api_key),
    db: AsyncSession = Depends(get_db),
):
    """
    Cryptographic verification endpoint that walks through the entire audit chain
    verifying HMAC integrity for every single record.
    """
    if current_key.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    is_valid, count, err = await audit_service.verify_chain_integrity(db)
    return {
        "is_valid": is_valid,
        "verified_records_count": count,
        "error": err,
        "status": "PASS" if is_valid else "INTEGRITY_COMPROMISED",
    }


@router.get("/metrics/summary")
async def get_metrics_summary(
    current_key: ApiKeyRecord = Depends(get_current_api_key),
    db: AsyncSession = Depends(get_db),
):
    if current_key.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

    total_reqs = await db.scalar(select(func.count(AuditRecord.id))) or 0
    blocked_reqs = await db.scalar(select(func.count(AuditRecord.id)).where(AuditRecord.action == "BLOCK")) or 0
    redacted_reqs = await db.scalar(select(func.count(AuditRecord.id)).where(AuditRecord.action == "REDACT")) or 0
    total_tokens = await db.scalar(select(func.sum(AuditRecord.prompt_tokens + AuditRecord.completion_tokens))) or 0

    return {
        "total_inspected_requests": total_reqs,
        "blocked_attacks_count": blocked_reqs,
        "redacted_pii_requests_count": redacted_reqs,
        "total_tokens_processed": int(total_tokens),
        "block_rate_percentage": round((blocked_reqs / total_reqs * 100), 2) if total_reqs > 0 else 0.0,
        "security_gateway_status": "ONLINE_SECURE",
    }
