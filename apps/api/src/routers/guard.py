from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field

from apps.api.src.core.deps import get_correlation_id
from apps.api.src.routers.completions import policy_engine
from packages.shared.src.models.schemas import (
    SecurityInspectionRequest,
    SecurityInspectionResponse,
)

router = APIRouter(prefix="/v1", tags=["Standalone Security Guardrails"])


class ToolAuthorizeRequest(BaseModel):
    tool_name: str = Field(..., description="Name of tool to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    user_id: Optional[str] = None


class ToolAuthorizeResponse(BaseModel):
    is_allowed: bool
    requires_human_approval: bool
    risk_score: float
    detections: list[Dict[str, Any]]
    correlation_id: str


@router.post("/guard/inspect", response_model=SecurityInspectionResponse)
async def inspect_content(
    request: SecurityInspectionRequest,
    correlation_id: str = Depends(get_correlation_id),
):
    """
    Direct security evaluation endpoint for text payloads, prompt templates,
    or retrieved RAG documents before crossing trust boundaries.
    """
    decision = policy_engine.inspect_request(
        text=request.text,
        correlation_id=correlation_id,
        tools_called=request.tools_called,
    )

    return SecurityInspectionResponse(
        action=decision.action.value,
        risk_score=decision.risk_score,
        risk_level=decision.risk_level.value,
        sanitized_text=decision.sanitized_prompt or request.text,
        redaction_count=decision.redaction_count,
        detections=[d.model_dump() for d in decision.detections],
        correlation_id=correlation_id,
    )


@router.post("/tools/authorize", response_model=ToolAuthorizeResponse)
async def authorize_tool_execution(
    request: ToolAuthorizeRequest,
    correlation_id: str = Depends(get_correlation_id),
):
    """
    Validates autonomous AI agent tool execution requests against permission tiers,
    schema adherence, and command-injection / privilege escalation rules.
    """
    is_allowed, req_app, detections = policy_engine.tool_engine.evaluate_tool_call(
        tool_name=request.tool_name,
        arguments=request.arguments,
    )

    max_score = 0.0
    for d in detections:
        if d.risk_score > max_score:
            max_score = d.risk_score

    return ToolAuthorizeResponse(
        is_allowed=is_allowed,
        requires_human_approval=req_app,
        risk_score=max_score,
        detections=[d.model_dump() for d in detections],
        correlation_id=correlation_id,
    )
