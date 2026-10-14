from packages.security_engine.src.detectors.tool_security import ToolSecurityEngine
from packages.security_engine.src.policies.engine import SecurityPolicyEngine
from packages.shared.src.models.decision import SecurityAction


def test_tool_security_allows_safe_registered_tool():
    engine = ToolSecurityEngine()
    is_allowed, req_approval, detections = engine.evaluate_tool_call(
        "search_knowledge_base", {"query": "cybersecurity guidelines"}
    )
    assert is_allowed is True
    assert req_approval is False
    assert len(detections) == 0


def test_tool_security_blocks_undeclared_tool():
    engine = ToolSecurityEngine()
    is_allowed, req_approval, detections = engine.evaluate_tool_call(
        "arbitrary_admin_backdoor", {"arg": "val"}
    )
    assert is_allowed is False
    assert any(d.rule_id == "TOOL_UNDECLARED_SELECTION" for d in detections)


def test_tool_security_blocks_shell_command_injection():
    engine = ToolSecurityEngine()
    is_allowed, _, detections = engine.evaluate_tool_call(
        "lookup_user_account", {"username": "admin; rm -rf /"}
    )
    assert is_allowed is False
    assert any(d.rule_id == "TOOL_ARGUMENT_SHELL_INJECTION" for d in detections)


def test_tool_security_blocks_path_traversal():
    engine = ToolSecurityEngine()
    is_allowed, _, detections = engine.evaluate_tool_call(
        "lookup_user_account", {"file": "../../etc/shadow"}
    )
    assert is_allowed is False
    assert any(d.rule_id == "TOOL_ARGUMENT_PATH_TRAVERSAL" for d in detections)


def test_tool_security_requires_approval_for_destructive_tool():
    engine = ToolSecurityEngine()
    is_allowed, req_approval, detections = engine.evaluate_tool_call(
        "execute_shell_command", {"cmd": "ls"}
    )
    assert is_allowed is True
    assert req_approval is True
    assert any(d.rule_id == "TOOL_HIGH_RISK_REQUIRE_APPROVAL" for d in detections)


def test_policy_engine_with_malicious_tool_call():
    policy = SecurityPolicyEngine()
    decision = policy.inspect_request(
        text="Please lookup this user",
        tools_called=[{"name": "lookup_user_account", "arguments": {"user": "test | bash -i"}}]
    )
    assert decision.action == SecurityAction.BLOCK
    assert any(d.rule_id == "TOOL_ARGUMENT_SHELL_INJECTION" for d in decision.detections)
