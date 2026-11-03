"""
Unit tests for Information Flow Control (IFC) Product Lattice.
Verifies Non-Interference for Integrity and Monotonic Taint Descent.
"""

import pytest
from mcp_sentinel.models import SecurityLabel, IntegrityLevel
from mcp_sentinel.monitor.lattice import ProductLattice


def test_lattice_meet_monotonic_descent():
    """Verify that meet (∧) monotonically narrows capabilities."""
    l_trusted = SecurityLabel(readers={"alice", "bob"}, integrity=IntegrityLevel.TRUSTED)
    l_untrusted = SecurityLabel(readers={"alice"}, integrity=IntegrityLevel.UNTRUSTED)

    # Meet operation
    l_meet = ProductLattice.meet(l_trusted, l_untrusted)

    # Reader set must intersect: {"alice"}
    assert l_meet.readers == {"alice"}
    # Integrity must descend to UNTRUSTED
    assert l_meet.integrity == IntegrityLevel.UNTRUSTED
    assert not l_meet.is_trusted()
    # Meet must be more restrictive than original
    assert l_meet.is_more_restrictive_than(l_trusted)


def test_prospective_gate_1_label():
    """Verify Gate 1 prospective computation: c_tau(L) = L ∧ d_tau."""
    current = SecurityLabel(readers={"*"}, integrity=IntegrityLevel.TRUSTED)
    tool_contribution = SecurityLabel(readers={"internal"}, integrity=IntegrityLevel.UNTRUSTED)

    prospective = ProductLattice.prospective_label(current, tool_contribution)
    assert prospective.integrity == IntegrityLevel.UNTRUSTED
    assert prospective.readers == {"internal"}


def test_policy_p_t_trusted_action():
    """Verify Policy P-T: Consequential tools require TRUSTED context."""
    l_clean = SecurityLabel(readers={"*"}, integrity=IntegrityLevel.TRUSTED)
    l_tainted = SecurityLabel(readers={"*"}, integrity=IntegrityLevel.UNTRUSTED)

    assert ProductLattice.verify_trusted_action(l_clean) is True
    assert ProductLattice.verify_trusted_action(l_tainted) is False


def test_policy_p_f_permitted_flow():
    """Verify Policy P-F: Egress data must flow only to authorized readers."""
    l_restricted = SecurityLabel(readers={"corp_users", "admin"}, integrity=IntegrityLevel.TRUSTED)

    # Egress to subset is allowed
    assert ProductLattice.verify_permitted_flow(l_restricted, {"admin"}) is True
    # Egress to unauthorized recipient is blocked
    assert ProductLattice.verify_permitted_flow(l_restricted, {"external_attacker"}) is False
