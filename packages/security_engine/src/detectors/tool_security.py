from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from packages.shared.src.models.decision import (
    DetectionCategory,
    DetectionDetail,
)


class ToolRiskTier(str, Enum):
    SAFE_READ = "SAFE_READ"
    SENSITIVE_WRITE = "SENSITIVE_WRITE"
    DESTRUCTIVE_EXEC = "DESTRUCTIVE_EXEC"


class ToolPermissionSpec(BaseModel):
    name: str
    risk_tier: ToolRiskTier
    requires_human_approval: bool = False
    allowed_argument_patterns: Dict[str, str] = Field(default_factory=dict)
    blocked_argument_patterns: List[str] = Field(default_factory=list)


class ToolSecurityEngine:
    """
    Validates autonomous AI agent tool execution requests, enforcing least privilege,
    schema adherence, and blocking command injection / privilege escalation.
    """

    # Dangerous command injection patterns in tool arguments
    RE_COMMAND_INJECTION = re.compile(
        r'(?:;|\||&&|`|\$\(|\b(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-i|powershell\s+-enc|cmd\.exe|nc\s+-e|cat\s+/etc/passwd|chmod\s+777)\b)'
    )

    # Path traversal patterns
    RE_PATH_TRAVERSAL = re.compile(r'(?:\.\./|\.\.\\|/etc/|C:\\Windows\\)')

    def __init__(self, registered_tools: Optional[Dict[str, ToolPermissionSpec]] = None):
        self.registered_tools = registered_tools or {
            "search_knowledge_base": ToolPermissionSpec(
                name="search_knowledge_base",
                risk_tier=ToolRiskTier.SAFE_READ,
                requires_human_approval=False,
            ),
            "lookup_user_account": ToolPermissionSpec(
                name="lookup_user_account",
                risk_tier=ToolRiskTier.SENSITIVE_WRITE,
                requires_human_approval=False,
            ),
            "execute_shell_command": ToolPermissionSpec(
                name="execute_shell_command",
                risk_tier=ToolRiskTier.DESTRUCTIVE_EXEC,
                requires_human_approval=True,
            ),
        }

    def evaluate_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Tuple[bool, bool, List[DetectionDetail]]:
        """
        Evaluates a tool call.
        Returns:
            (is_allowed, requires_approval, detections)
        """
        detections: List[DetectionDetail] = []

        # 1. Check if tool is registered
        if tool_name not in self.registered_tools:
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.UNAUTHORIZED_TOOL,
                    rule_id="TOOL_UNDECLARED_SELECTION",
                    risk_score=0.95,
                    description=f"Attempted execution of unregistered tool '{tool_name}'",
                    sanitized_evidence=f"tool={tool_name}",
                )
            )
            return False, False, detections

        spec = self.registered_tools[tool_name]

        # 2. Check for command injection or path traversal across arguments
        raw_args_str = str(arguments)
        if self.RE_COMMAND_INJECTION.search(raw_args_str):
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.EXCESSIVE_AGENCY,
                    rule_id="TOOL_ARGUMENT_SHELL_INJECTION",
                    risk_score=1.0,
                    description=f"Dangerous shell characters or command sequences found in tool '{tool_name}' arguments",
                    sanitized_evidence="Found command injection pattern in args",
                )
            )
            return False, False, detections

        if self.RE_PATH_TRAVERSAL.search(raw_args_str):
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.EXCESSIVE_AGENCY,
                    rule_id="TOOL_ARGUMENT_PATH_TRAVERSAL",
                    risk_score=0.90,
                    description=f"Path traversal characters detected in tool '{tool_name}' arguments",
                    sanitized_evidence="Found path traversal sequence (../)",
                )
            )
            return False, False, detections

        # 3. Check risk tier and human approval requirement
        if spec.risk_tier == ToolRiskTier.DESTRUCTIVE_EXEC or spec.requires_human_approval:
            detections.append(
                DetectionDetail(
                    category=DetectionCategory.EXCESSIVE_AGENCY,
                    rule_id="TOOL_HIGH_RISK_REQUIRE_APPROVAL",
                    risk_score=0.75,
                    description=f"Tool '{tool_name}' classified as {spec.risk_tier.value} requires explicit approval",
                    sanitized_evidence=f"tool={tool_name}",
                )
            )
            return True, True, detections

        return True, False, detections
