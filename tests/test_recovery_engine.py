"""
Unit tests for Recovery Engine and Soft-Delete Quarantine.
Demonstrates preservation of task utility under destructive actions.
"""

import os
import pytest
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import DecisionType
from mcp_sentinel.monitor.reference_monitor import DualPhaseReferenceMonitor


@pytest.fixture
def test_env(tmp_path):
    workspace = str(tmp_path / "workspace")
    os.makedirs(workspace, exist_ok=True)
    
    config = SentinelConfig(
        server_name="test-server",
        allowed_workspaces=[workspace],
    )
    monitor = DualPhaseReferenceMonitor(config)
    return workspace, monitor


def test_soft_delete_remedy_preserves_task_utility(test_env):
    """
    When an agent calls delete_file on a project file, Sentinel must not crash/abort.
    It executes a soft-delete to .sentinel_trash and returns synthetic success.
    """
    workspace, monitor = test_env
    test_file = os.path.join(workspace, "old_cache.json")
    with open(test_file, "w") as f:
        f.write('{"cached": true}')

    assert os.path.exists(test_file)

    # Agent issues delete_file
    decision = monitor.gate_1_pre_dispatch(
        tool_name="delete_file",
        arguments={"path": test_file}
    )

    # Must RECOVER with synthetic success rather than dead-end block!
    assert decision.decision == DecisionType.RECOVER
    assert decision.remedy_applied == "soft_delete_quarantine"
    assert decision.synthetic_result["status"] == "success"

    # Original file is moved out of active directory
    assert not os.path.exists(test_file)

    # File must exist inside .sentinel_trash quarantine!
    quarantine_dir = monitor.config.get_quarantine_path()
    quarantined_files = [f for f in os.listdir(quarantine_dir) if "old_cache.json" in f]
    assert len(quarantined_files) == 1

    # Verify restore capability
    success, msg = monitor.quarantine.restore_quarantined_file(test_file)
    assert success is True
    assert os.path.exists(test_file)
