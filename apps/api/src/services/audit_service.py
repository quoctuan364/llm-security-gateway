import datetime
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.src.core.config import settings
from apps.api.src.core.models import AuditRecord
from packages.shared.src.utils.crypto import compute_audit_hash


class AuditService:
    """
    Append-only, cryptographically chained audit logging service.
    Each record's hash depends on the previous record's hash (HMAC-SHA256).
    """

    GENESIS_HASH = "0" * 64

    async def log_security_event(
        self,
        db: AsyncSession,
        correlation_id: str,
        route: str,
        action: str,
        risk_score: float,
        detections: List[Dict[str, Any]],
        api_key_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> AuditRecord:
        """
        Appends an immutable audit record chained to the latest existing record.
        """
        # Fetch the most recent audit record to get previous hash
        query = select(AuditRecord).order_by(AuditRecord.timestamp.desc()).limit(1)
        res = await db.execute(query)
        latest_record = res.scalars().first()
        prev_hash = latest_record.current_hash if latest_record else self.GENESIS_HASH

        record_id = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc)
        ts_normalized = now.strftime("%Y-%m-%d %H:%M:%S")

        normalized_dets = json.loads(json.dumps(detections, default=str))
        details = {
            "route": route,
            "correlation_id": correlation_id,
            "detections": normalized_dets,
            "tokens": {"prompt": prompt_tokens, "completion": completion_tokens},
        }

        current_hash = compute_audit_hash(
            record_id=record_id,
            timestamp_iso=ts_normalized,
            client_id=api_key_id or "anonymous",
            action=action,
            risk_score=risk_score,
            details=details,
            prev_hash=prev_hash,
            hmac_secret=settings.AUDIT_HMAC_SECRET,
        )

        record = AuditRecord(
            id=record_id,
            timestamp=now,
            correlation_id=correlation_id,
            api_key_id=api_key_id,
            client_ip=client_ip,
            route=route,
            action=action,
            risk_score=risk_score,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            detections_json=json.dumps(detections),
            prev_hash=prev_hash,
            current_hash=current_hash,
        )

        db.add(record)
        await db.commit()
        await db.refresh(record)
        return record

    async def verify_chain_integrity(self, db: AsyncSession) -> tuple[bool, int, Optional[str]]:
        """
        Scans all records in chronological order and validates HMAC chain integrity.
        Returns:
            (is_valid, verified_count, error_message)
        """
        query = select(AuditRecord).order_by(AuditRecord.timestamp.asc())
        res = await db.execute(query)
        records = list(res.scalars().all())

        if not records:
            return True, 0, None

        expected_prev = self.GENESIS_HASH
        for idx, rec in enumerate(records):
            if rec.prev_hash != expected_prev:
                return (
                    False,
                    idx,
                    f"Chain broken at record {rec.id}: expected prev_hash '{expected_prev}', got '{rec.prev_hash}'"
                )

            details = {
                "route": rec.route,
                "correlation_id": rec.correlation_id,
                "detections": json.loads(rec.detections_json),
                "tokens": {"prompt": rec.prompt_tokens, "completion": rec.completion_tokens},
            }
            computed_current = compute_audit_hash(
                record_id=rec.id,
                timestamp_iso=rec.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                client_id=rec.api_key_id or "anonymous",
                action=rec.action,
                risk_score=rec.risk_score,
                details=details,
                prev_hash=rec.prev_hash,
                hmac_secret=settings.AUDIT_HMAC_SECRET,
            )

            if computed_current != rec.current_hash:
                return (
                    False,
                    idx,
                    f"Tampered record detected at ID {rec.id}! Content does not match HMAC."
                )

            expected_prev = rec.current_hash

        return True, len(records), None
