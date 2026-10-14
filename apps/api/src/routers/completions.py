import json
import time
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.src.core.config import settings
from apps.api.src.core.database import get_db
from apps.api.src.core.deps import (
    budget_manager,
    get_correlation_id,
    get_current_api_key,
    rate_limiter,
)
from apps.api.src.core.models import ApiKeyRecord
from apps.api.src.services.audit_service import AuditService
from packages.provider_adapters.src.adapters.base import BaseLLMAdapter
from packages.provider_adapters.src.adapters.mock_adapter import MockLLMAdapter
from packages.provider_adapters.src.adapters.openai_adapter import OpenAICompatibleAdapter
from packages.security_engine.src.policies.engine import SecurityPolicyEngine
from packages.shared.src.models.decision import SecurityAction
from packages.shared.src.models.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)

router = APIRouter(prefix="/v1", tags=["Chat Completions Gateway"])

# Global singletons
policy_engine = SecurityPolicyEngine(
    block_threshold=settings.PROMPT_INJECTION_BLOCK_THRESHOLD,
    warn_threshold=settings.PROMPT_INJECTION_WARN_THRESHOLD,
    redact_pii_by_default=True,
)
audit_service = AuditService()


def get_provider_adapter() -> BaseLLMAdapter:
    if settings.PROVIDER_MODE == "openai" and settings.OPENAI_API_KEY:
        return OpenAICompatibleAdapter(
            base_url=settings.OPENAI_BASE_URL,
            api_key=settings.OPENAI_API_KEY,
            timeout_seconds=settings.PROVIDER_TIMEOUT_SECONDS,
        )
    return MockLLMAdapter(latency_ms=30)


@router.post("/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(
    request: ChatCompletionRequest,
    req_raw: Request,
    api_key: ApiKeyRecord = Depends(get_current_api_key),
    correlation_id: str = Depends(get_correlation_id),
    db: AsyncSession = Depends(get_db),
):
    client_ip = req_raw.client.host if req_raw.client else "127.0.0.1"

    # 1. Rate Limiting Check
    is_allowed_rpm, rem_tokens, retry_after = await rate_limiter.check_rate_limit(
        identifier=api_key.id,
        limit_rpm=api_key.rate_limit_rpm,
        cost_tokens=1,
    )
    if not is_allowed_rpm:
        await audit_service.log_security_event(
            db=db,
            correlation_id=correlation_id,
            route="/v1/chat/completions",
            action="BLOCK",
            risk_score=1.0,
            detections=[{"rule_id": "RATE_LIMIT_EXCEEDED", "description": f"Exceeded {api_key.rate_limit_rpm} RPM"}],
            api_key_id=api_key.id,
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit of {api_key.rate_limit_rpm} RPM exceeded. Retry after {retry_after}s.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    # 2. Token Budget Reservation
    full_prompt_text = request.get_full_text_for_inspection()
    estimated_prompt_tokens = max(1, len(full_prompt_text) // 4)
    estimated_total = estimated_prompt_tokens + (request.max_tokens or 256)

    budget_ok, rem_budget, budget_reason = await budget_manager.reserve_budget(
        api_key_id=api_key.id,
        estimated_tokens=estimated_total,
        daily_limit=api_key.daily_token_budget,
    )
    if not budget_ok:
        await audit_service.log_security_event(
            db=db,
            correlation_id=correlation_id,
            route="/v1/chat/completions",
            action="BLOCK",
            risk_score=0.9,
            detections=[{"rule_id": "DAILY_BUDGET_EXCEEDED", "description": budget_reason}],
            api_key_id=api_key.id,
            client_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=budget_reason,
        )

    # 3. Security Engine Inspection on Input Prompt
    tools_payload = None
    if request.tools:
        tools_payload = [{"name": t.function.name, "arguments": t.function.parameters or {}} for t in request.tools]

    decision = policy_engine.inspect_request(
        text=full_prompt_text,
        correlation_id=correlation_id,
        tools_called=tools_payload,
    )

    # 4. Handle Security Policy Decision
    if decision.action == SecurityAction.BLOCK:
        # Revert budget reservation
        await budget_manager.settle_budget(api_key.id, estimated_tokens=estimated_total, actual_tokens=0)

        # Log Security Incident to Audit Log
        await audit_service.log_security_event(
            db=db,
            correlation_id=correlation_id,
            route="/v1/chat/completions",
            action="BLOCK",
            risk_score=decision.risk_score,
            detections=[d.model_dump() for d in decision.detections],
            api_key_id=api_key.id,
            client_ip=client_ip,
        )

        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": {
                    "message": f"Security violation detected: {decision.blocked_reason}",
                    "type": "security_policy_violation",
                    "code": "request_blocked_by_aegis_firewall",
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level.value,
                    "correlation_id": correlation_id,
                    "violations": [
                        {
                            "category": d.category.value,
                            "rule_id": d.rule_id,
                            "description": d.description,
                            "evidence": d.sanitized_evidence,
                        }
                        for d in decision.detections
                    ],
                }
            },
            headers={
                "X-Aegis-Security-Action": decision.action.value,
                "X-Aegis-Risk-Score": str(decision.risk_score),
                "X-Aegis-Correlation-ID": correlation_id,
            },
        )

    # 5. Sanitize Request if PII was Redacted
    forward_request = request
    if decision.action == SecurityAction.REDACT and decision.sanitized_prompt:
        # Apply sanitized content to messages
        sanitized_messages = []
        for msg in request.messages:
            if isinstance(msg.content, str):
                clean_msg, _, _ = policy_engine.pii_detector.scan_and_redact(msg.content)
                sanitized_messages.append(msg.model_copy(update={"content": clean_msg}))
            else:
                sanitized_messages.append(msg)
        forward_request = request.model_copy(update={"messages": sanitized_messages})

    # 6. Dispatch to Downstream LLM Provider
    adapter = get_provider_adapter()

    # Handle Streaming responses
    if request.stream:
        async def stream_generator():
            try:
                async for chunk in adapter.stream_complete(forward_request, correlation_id=correlation_id):
                    yield f"data: {json.dumps(chunk)}\n\n"
                yield "data: [DONE]\n\n"
            finally:
                # Settle budget estimate for stream
                await budget_manager.settle_budget(
                    api_key.id,
                    estimated_tokens=estimated_total,
                    actual_tokens=estimated_prompt_tokens + 50,
                )

        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
            headers={
                "X-Aegis-Security-Action": decision.action.value,
                "X-Aegis-Risk-Score": str(decision.risk_score),
                "X-Aegis-Redaction-Count": str(decision.redaction_count),
                "X-Aegis-Correlation-ID": correlation_id,
            },
        )

    # Non-streaming standard response
    try:
        response: ChatCompletionResponse = await adapter.complete(
            forward_request, correlation_id=correlation_id
        )
    except Exception as exc:
        # Revert reservation
        await budget_manager.settle_budget(api_key.id, estimated_tokens=estimated_total, actual_tokens=0)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Downstream LLM provider error: {str(exc)}",
        )

    # 7. Egress Inspection on Output Text
    output_text = ""
    for choice in response.choices:
        if isinstance(choice.message.content, str):
            output_text += choice.message.content + " "

    redacted_output, output_pii_dets, _ = policy_engine.pii_detector.scan_and_redact(output_text)
    if output_pii_dets:
        # Update choice with sanitized content
        for choice in response.choices:
            if isinstance(choice.message.content, str):
                c_clean, _, _ = policy_engine.pii_detector.scan_and_redact(choice.message.content)
                choice.message.content = c_clean

    # 8. Settle Token Budget with Exact Counts
    actual_tokens = response.usage.total_tokens
    await budget_manager.settle_budget(
        api_key_id=api_key.id,
        estimated_tokens=estimated_total,
        actual_tokens=actual_tokens,
    )

    # 9. Append-Only Cryptographic Audit Log
    all_record_detections = [d.model_dump() for d in decision.detections] + [
        d.model_dump() for d in output_pii_dets
    ]
    await audit_service.log_security_event(
        db=db,
        correlation_id=correlation_id,
        route="/v1/chat/completions",
        action=decision.action.value,
        risk_score=decision.risk_score,
        detections=all_record_detections,
        api_key_id=api_key.id,
        client_ip=client_ip,
        prompt_tokens=response.usage.prompt_tokens,
        completion_tokens=response.usage.completion_tokens,
    )

    return JSONResponse(
        content=response.model_dump(exclude_none=True),
        headers={
            "X-Aegis-Security-Action": decision.action.value,
            "X-Aegis-Risk-Score": str(decision.risk_score),
            "X-Aegis-Redaction-Count": str(decision.redaction_count),
            "X-Aegis-Correlation-ID": correlation_id,
        },
    )
