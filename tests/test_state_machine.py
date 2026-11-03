"""
Unit tests for Session Security State Machine and Call-Scoped Authority Rulings.
"""

import pytest
from mcp_sentinel.models import SecurityLevel
from mcp_sentinel.monitor.state_machine import SessionStateMachine
from mcp_sentinel.recovery.rulings import AuthorityRulingRegistry


def test_state_machine_level_transitions():
    """Verify state machine transitions from L2 read-only to L3 approval."""
    sm = SessionStateMachine(initial_level=SecurityLevel.L2_READ_ONLY)
    assert sm.get_level() == SecurityLevel.L2_READ_ONLY

    # Mutation denied under L2
    assert sm.is_mutation_permitted() is False

    # Elevate to L3 for specific hash
    target_hash = "abc123hash"
    sm.elevate_atomically(target_hash)
    assert sm.get_level() == SecurityLevel.L3_APPROVAL

    # Permitted only for matching hash
    assert sm.is_mutation_permitted("wrong_hash") is False
    assert sm.is_mutation_permitted(target_hash) is True

    # Consuming elevation must auto-revert to L2 to prevent privilege drift
    sm.consume_atomic_elevation()
    assert sm.get_level() == SecurityLevel.L2_READ_ONLY
    assert sm.is_mutation_permitted(target_hash) is False


def test_atomic_call_scoped_ruling_single_use():
    """Verify that authority rulings cannot be replayed (Anti-Replay Property)."""
    registry = AuthorityRulingRegistry(secret_key="test-secret-key")
    tool = "git_push"
    args = {"remote": "origin", "branch": "main"}

    call_hash = registry.compute_call_hash(tool, args)
    registry.grant_ruling(call_hash, ttl_seconds=10.0)

    # First verification must succeed and consume the token
    assert registry.verify_and_consume_ruling(call_hash) is True

    # Second verification must fail (token was consumed!)
    assert registry.verify_and_consume_ruling(call_hash) is False
