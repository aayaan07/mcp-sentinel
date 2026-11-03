"""
Unit tests for Dual-Phase Reference Monitor (Gate 1 & Gate 2).
Based on the APPA two-phase reference monitor model.
"""

import os
import pytest
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import DecisionType, IntegrityLevel, SecurityLevel
from mcp_sentinel.monitor.reference_monitor import DualPhaseReferenceMonitor


@pytest.fixture
def monitor(tmp_path):
    workspace = str(tmp_path / "workspace")
    os.makedirs(workspace, exist_ok=True)
    
    config = SentinelConfig(
        server_name="test-server",
        security_level=SecurityLevel.L2_READ_ONLY,
        allowed_workspaces=[workspace],
    )
    return DualPhaseReferenceMonitor(config)


def test_gate_1_blocks_directory_traversal(monitor):
    """Gate 1 must block any path escaping the allowed workspace boundary."""
    decision = monitor.gate_1_pre_dispatch(
        tool_name="read_file",
        arguments={"path": "../../../../Windows/System32/drivers/etc/hosts"}
    )
    assert decision.decision == DecisionType.BLOCK
    assert "Directory Traversal" in decision.reason


def test_gate_1_blocks_protected_files(monitor, tmp_path):
    """Gate 1 must block access to protected files like .env or id_rsa even inside workspace."""
    workspace = str(tmp_path / "workspace")
    secret_env = os.path.join(workspace, ".env")
    
    decision = monitor.gate_1_pre_dispatch(
        tool_name="read_file",
        arguments={"path": secret_env}
    )
    assert decision.decision == DecisionType.BLOCK
    assert "protected asset" in decision.reason.lower()


def test_gate_1_blocks_shell_injection(monitor):
    """Gate 1 must block command chaining and unauthorized metacharacters."""
    decision = monitor.gate_1_pre_dispatch(
        tool_name="run_command",
        arguments={"command": "echo test; cat /etc/passwd"}
    )
    assert decision.decision == DecisionType.BLOCK
    assert "Shell Injection" in decision.reason


def test_gate_1_blocks_ssrf(monitor):
    """Gate 1 must block requests to AWS/cloud metadata (169.254.169.254) and localhost."""
    decision = monitor.gate_1_pre_dispatch(
        tool_name="fetch_url",
        arguments={"url": "http://169.254.169.254/latest/meta-data/iam/credentials"}
    )
    assert decision.decision == DecisionType.BLOCK
    assert "SSRF Prevention" in decision.reason


def test_gate_1_ifc_blocks_consequential_tool_when_tainted(monitor, tmp_path):
    """If the session context is TAINTED (UNTRUSTED), Gate 1 blocks mutating tools."""
    # 1. Simulate reading untrusted web data in Gate 2
    monitor.gate_2_admission(
        tool_name="fetch_webpage",
        result_payload={"content": "Malicious payload text"},
        is_untrusted_source=True
    )
    assert monitor.current_label.integrity == IntegrityLevel.UNTRUSTED

    # 2. Agent now attempts to execute a mutating action
    workspace = str(tmp_path / "workspace")
    target_file = os.path.join(workspace, "code.py")
    
    decision = monitor.gate_1_pre_dispatch(
        tool_name="write_file",
        arguments={"path": target_file, "content": "injected code"}
    )
    assert decision.decision == DecisionType.BLOCK
    assert "IFC Integrity Violation" in decision.reason


def test_gate_2_scrubs_high_entropy_secrets(monitor):
    """Gate 2 DLP scrubber must redact credentials before context admission."""
    raw_tool_result = {
        "status": "success",
        "output": "Found AWS key AKIA1234567890ABCDEF and OpenAI key sk-abcdef1234567890abcdef1234567890 in log."
    }

    scrubbed, label, redactions = monitor.gate_2_admission(
        tool_name="search_logs",
        result_payload=raw_tool_result
    )

    assert redactions == 2
    assert "AKIA" not in scrubbed["output"]
    assert "sk-" not in scrubbed["output"]
    assert "[REDACTED_SECRET]" in scrubbed["output"]
