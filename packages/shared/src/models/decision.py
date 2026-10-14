from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityAction(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PII_LEAK = "PII_LEAK"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    UNAUTHORIZED_TOOL = "UNAUTHORIZED_TOOL"
    EXCESSIVE_AGENCY = "EXCESSIVE_AGENCY"
    OUTPUT_HALLUCINATION = "OUTPUT_HALLUCINATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class DetectionDetail(BaseModel):
    category: DetectionCategory
    rule_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    description: str
    sanitized_evidence: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityDecision(BaseModel):
    action: SecurityAction
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    detections: List[DetectionDetail] = Field(default_factory=list)
    sanitized_prompt: Optional[str] = None
    redaction_count: int = 0
    blocked_reason: Optional[str] = None
    correlation_id: str = ""
    evaluated_policies: List[str] = Field(default_factory=list)

    @classmethod
    def allow_clean(cls, correlation_id: str = "") -> "SecurityDecision":
        return cls(
            action=SecurityAction.ALLOW,
            risk_score=0.0,
            risk_level=RiskLevel.LOW,
            correlation_id=correlation_id,
        )
