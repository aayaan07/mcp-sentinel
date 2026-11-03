"""
Adversarial Evasion Stress Test Suite.
Tests MCP-Sentinel's defenses against advanced obfuscation, encoding tricks, and evasion techniques.
"""

import os
import pytest
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import DecisionType
from mcp_sentinel.monitor.reference_monitor import DualPhaseReferenceMonitor


@pytest.fixture
def monitor(tmp_path):
    workspace = str(tmp_path / "workspace")
    os.makedirs(workspace, exist_ok=True)
    config = SentinelConfig(allowed_workspaces=[workspace])
    return DualPhaseReferenceMonitor(config)


def test_double_url_encoded_traversal(monitor):
    """Evasion 1: Double URL-encoded traversal (%252e%252e%252f)."""
    # %252e -> %2e -> .
    evasion_path = "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    decision = monitor.gate_1_pre_dispatch("read_file", {"path": evasion_path})
    assert decision.decision == DecisionType.BLOCK
    assert "Directory Traversal" in decision.reason


def test_unicode_fullwidth_traversal(monitor):
    """Evasion 2: Unicode fullwidth characters (\\uff0e\\uff0e\\uff0f)."""
    # \uff0e is fullwidth dot (．), \uff0f is fullwidth slash (／)
    evasion_path = "\uff0e\uff0e\uff0f\uff0e\uff0e\uff0fetc\uff0fpasswd"
    decision = monitor.gate_1_pre_dispatch("read_file", {"path": evasion_path})
    assert decision.decision == DecisionType.BLOCK
    assert "Directory Traversal" in decision.reason


def test_null_byte_truncation(monitor, tmp_path):
    """Evasion 3: Null-byte injection to trick string length checks."""
    workspace = str(tmp_path / "workspace")
    evasion_path = os.path.join(workspace, "valid.txt\0/../../etc/shadow")
    decision = monitor.gate_1_pre_dispatch("read_file", {"path": evasion_path})
    assert decision.decision == DecisionType.BLOCK


def test_base64_obfuscated_shellcode(monitor):
    """Evasion 4: Dangerous commands hidden inside Base64 strings (cm0gLXJmIC8= -> rm -rf /)."""
    # cm0gLXJmIC8= is 'rm -rf /'
    evasion_cmd = "echo cm0gLXJmIC8= | base64 -d | sh"
    decision = monitor.gate_1_pre_dispatch("run_command", {"command": evasion_cmd})
    assert decision.decision == DecisionType.BLOCK
    # Caught either by metacharacters or by deep Base64 inspection
    assert ("Shell Injection" in decision.reason) or ("Obfuscated" in decision.reason)


def test_quote_separated_binary(monitor):
    """Evasion 5: Quote-separated binary names to evade string matching (b'a's'h)."""
    evasion_cmd = "b'a's'h -c 'whoami'"
    decision = monitor.gate_1_pre_dispatch("run_command", {"command": evasion_cmd})
    assert decision.decision == DecisionType.BLOCK
    assert ("Blocked Binary" in decision.reason) or ("Shell Injection" in decision.reason)


def test_backslash_escaped_binary(monitor):
    """Evasion 6: Backslash-escaped binary names (b\\a\\s\\h)."""
    evasion_cmd = "b\\a\\s\\h -c 'whoami'"
    decision = monitor.gate_1_pre_dispatch("run_command", {"command": evasion_cmd})
    assert decision.decision == DecisionType.BLOCK
    assert "Blocked Binary" in decision.reason


def test_ifs_whitespace_bypass(monitor):
    """Evasion 7: $IFS internal field separator bypass."""
    evasion_cmd = "cat$IFS/etc/passwd"
    decision = monitor.gate_1_pre_dispatch("run_command", {"command": evasion_cmd})
    assert decision.decision == DecisionType.BLOCK


def test_decimal_ip_ssrf(monitor):
    """Evasion 8: Decimal IP representation for localhost (2130706433 = 127.0.0.1)."""
    evasion_url = "http://2130706433/admin/keys"
    decision = monitor.gate_1_pre_dispatch("fetch_url", {"url": evasion_url})
    assert decision.decision == DecisionType.BLOCK
    assert "SSRF Prevention" in decision.reason


def test_hex_ip_ssrf(monitor):
    """Evasion 9: Hexadecimal IP representation for localhost (0x7f000001 = 127.0.0.1)."""
    evasion_url = "http://0x7f000001/status"
    decision = monitor.gate_1_pre_dispatch("fetch_url", {"url": evasion_url})
    assert decision.decision == DecisionType.BLOCK
    assert "SSRF Prevention" in decision.reason


def test_gcp_metadata_dns_ssrf(monitor):
    """Evasion 10: GCP metadata internal DNS probe."""
    evasion_url = "http://metadata.google.internal/computeMetadata/v1/instance/token"
    decision = monitor.gate_1_pre_dispatch("fetch_url", {"url": evasion_url})
    assert decision.decision == DecisionType.BLOCK
    assert "SSRF Prevention" in decision.reason
