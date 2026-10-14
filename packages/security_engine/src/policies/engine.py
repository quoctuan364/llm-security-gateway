from typing import Any, Dict, List, Optional
from packages.security_engine.src.detectors.pii import PIIDetector
from packages.security_engine.src.detectors.prompt_injection import PromptInjectionDetector
from packages.security_engine.src.detectors.tool_security import ToolSecurityEngine
from packages.shared.src.models.decision import (
    RiskLevel,
    SecurityAction,
    SecurityDecision,
)


class SecurityPolicyEngine:
    """
    Unified security policy engine that orchestrates PII detection/redaction,
    prompt injection evaluation, tool security, and policy-driven action resolution.
    """

    def __init__(
        self,
        block_threshold: float = 0.70,
        warn_threshold: float = 0.40,
        redact_pii_by_default: bool = True,
        pii_detector: Optional[PIIDetector] = None,
        injection_detector: Optional[PromptInjectionDetector] = None,
        tool_engine: Optional[ToolSecurityEngine] = None,
    ):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        self.redact_pii_by_default = redact_pii_by_default
        self.pii_detector = pii_detector or PIIDetector()
        self.injection_detector = injection_detector or PromptInjectionDetector()
        self.tool_engine = tool_engine or ToolSecurityEngine()

    def inspect_request(
        self,
        text: str,
        correlation_id: str = "",
        tools_called: Optional[List[Dict[str, Any]]] = None,
    ) -> SecurityDecision:
        """
        Executes end-to-end inspection on an incoming client request.
        """
        # 1. Scan and redact PII & credentials
        redacted_text, pii_detections, _ = self.pii_detector.scan_and_redact(text)

        # 2. Evaluate Prompt Injection & Jailbreak risk
        # Note: we inspect the original text so obfuscated injection payloads are not hidden by redactions
        inj_score, inj_detections = self.injection_detector.evaluate(text)

        all_detections = pii_detections + inj_detections

        # 3. Evaluate Tool Calls (if any)
        tool_requires_approval = False
        tool_blocked = False
        if tools_called:
            for tc in tools_called:
                name = tc.get("name", "")
                args = tc.get("arguments", {})
                is_allowed, req_app, tool_dets = self.tool_engine.evaluate_tool_call(name, args)
                all_detections.extend(tool_dets)
                if not is_allowed:
                    tool_blocked = True
                if req_app:
                    tool_requires_approval = True

        # Calculate composite risk score
        max_score = inj_score
        for d in pii_detections:
            if d.risk_score > max_score:
                max_score = d.risk_score

        # Determine Risk Level
        if max_score >= 0.80 or tool_blocked:
            risk_level = RiskLevel.CRITICAL
        elif max_score >= self.block_threshold:
            risk_level = RiskLevel.HIGH
        elif max_score >= self.warn_threshold:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Resolve Action
        if tool_blocked:
            action = SecurityAction.BLOCK
            reason = "Blocked by Agent Tool Security Policy (Undeclared tool or command injection)"
        elif inj_score >= self.block_threshold:
            action = SecurityAction.BLOCK
            reason = f"Prompt injection risk score ({inj_score:.2f}) exceeded blocking threshold ({self.block_threshold:.2f})"
        elif tool_requires_approval:
            action = SecurityAction.REQUIRE_APPROVAL
            reason = "Action requires explicit administrative approval before execution"
        elif len(pii_detections) > 0 and self.redact_pii_by_default:
            action = SecurityAction.REDACT
            reason = f"Sanitized {len(pii_detections)} sensitive PII / credential instances"
        elif inj_score >= self.warn_threshold:
            action = SecurityAction.WARN
            reason = f"Elevated security risk score ({inj_score:.2f})"
        else:
            action = SecurityAction.ALLOW
            reason = None

        return SecurityDecision(
            action=action,
            risk_score=round(max_score, 4),
            risk_level=risk_level,
            detections=all_detections,
            sanitized_prompt=redacted_text if len(pii_detections) > 0 else text,
            redaction_count=len(pii_detections),
            blocked_reason=reason,
            correlation_id=correlation_id,
            evaluated_policies=["default-hierarchical-policy-v1"],
        )
