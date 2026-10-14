import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apps.api.src.core.database import Base
from apps.api.src.services.audit_service import AuditService
from apps.api.src.services.budget_manager import BudgetManager
from apps.api.src.services.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_in_memory_token_bucket():
    limiter = RateLimiter(redis_client=None)
    key = "test-client-1"

    # Limit = 2 RPM
    allowed_1, rem_1, _ = await limiter.check_rate_limit(key, limit_rpm=2, cost_tokens=1)
    allowed_2, rem_2, _ = await limiter.check_rate_limit(key, limit_rpm=2, cost_tokens=1)
    allowed_3, rem_3, retry_after = await limiter.check_rate_limit(key, limit_rpm=2, cost_tokens=1)

    assert allowed_1 is True
    assert allowed_2 is True
    assert allowed_3 is False
    assert rem_3 == 0
    assert retry_after > 0


@pytest.mark.asyncio
async def test_budget_manager_reservation_and_settlement():
    manager = BudgetManager(redis_client=None)
    key = "test-project-1"

    # Reserve 500 tokens from 1000 limit
    allowed, rem, _ = await manager.reserve_budget(key, estimated_tokens=500, daily_limit=1000)
    assert allowed is True
    assert rem == 500

    # Reserve another 600 tokens -> should exceed 1000 limit
    allowed_exceed, _, reason = await manager.reserve_budget(key, estimated_tokens=600, daily_limit=1000)
    assert allowed_exceed is False
    assert "exceeded" in reason

    # Settle actual tokens: estimated 500, but actually only used 400
    settled = await manager.settle_budget(key, estimated_tokens=500, actual_tokens=400)
    assert settled == 400


@pytest.mark.asyncio
async def test_audit_service_hmac_chain_and_tamper_detection():
    # Use in-memory SQLite for audit test
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    audit_svc = AuditService()

    async with session_maker() as session:
        # Record 1
        rec1 = await audit_svc.log_security_event(
            db=session,
            correlation_id="corr-1",
            route="/v1/chat/completions",
            action="ALLOW",
            risk_score=0.1,
            detections=[],
            api_key_id="key-123",
        )
        assert rec1.prev_hash == AuditService.GENESIS_HASH

        # Record 2
        rec2 = await audit_svc.log_security_event(
            db=session,
            correlation_id="corr-2",
            route="/v1/chat/completions",
            action="BLOCK",
            risk_score=0.95,
            detections=[{"rule_id": "INJECTION_INSTRUCTION_OVERRIDE"}],
            api_key_id="key-123",
        )
        assert rec2.prev_hash == rec1.current_hash

        # Verify integrity -> should be valid
        is_valid, count, err = await audit_svc.verify_chain_integrity(session)
        assert is_valid is True
        assert count == 2
        assert err is None

        # Simulate database tampering: modify rec1 risk_score
        rec1.risk_score = 0.99
        session.add(rec1)
        await session.commit()

        # Re-verify -> MUST detect tampering!
        is_valid_after_tamper, _, tamper_err = await audit_svc.verify_chain_integrity(session)
        assert is_valid_after_tamper is False
        assert "Tampered record detected" in tamper_err

    await engine.dispose()
