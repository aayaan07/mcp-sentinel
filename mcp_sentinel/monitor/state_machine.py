"""
Session-Level Security State Machine.
Implements the 4-tier capability hierarchy (L0-L3) with atomic call-scoped transitions.
"""

from typing import Dict, Any, Optional
from mcp_sentinel.models import SecurityLevel, PolicyDecision, DecisionType


class SessionStateMachine:
    """
    Manages session-level privileges across an agent trace lifecycle:
    L0: Baseline (Unrestricted read/write)
    L1: Scoped Access (Whitelist of tools)
    L2: Read-Only Defaults (Mutating calls suppressed/quarantined)
    L3: Approval-Gated Elevation (Atomic, single-use elevation)
    """

    def __init__(self, initial_level: SecurityLevel = SecurityLevel.L2_READ_ONLY):
        self.current_level = initial_level
        self.mutation_count = 0
        self.pending_call_hash: Optional[str] = None

    def get_level(self) -> SecurityLevel:
        return self.current_level

    def transition_to(self, new_level: SecurityLevel) -> None:
        self.current_level = new_level

    def is_mutation_permitted(self, call_hash: Optional[str] = None) -> bool:
        """
        Evaluates whether a mutating action is permitted in the current state.
        """
        if self.current_level == SecurityLevel.L0_BASELINE:
            return True
        elif self.current_level == SecurityLevel.L1_SCOPED:
            # L1 allows scoped actions, but mutating actions still need verification
            return True
        elif self.current_level == SecurityLevel.L2_READ_ONLY:
            # L2 enforces read-only defaults: mutations are forbidden without elevation
            return False
        elif self.current_level == SecurityLevel.L3_APPROVAL:
            # L3 requires atomic call-scoped match
            if call_hash and self.pending_call_hash == call_hash:
                return True
            return False
        return False

    def elevate_atomically(self, call_hash: str) -> None:
        """Elevates to L3 for this exact tool call hash."""
        self.current_level = SecurityLevel.L3_APPROVAL
        self.pending_call_hash = call_hash

    def consume_atomic_elevation(self) -> None:
        """
        Consumes the single-use L3 elevation and auto-reverts to L2.
        Prevents privilege drift!
        """
        self.current_level = SecurityLevel.L2_READ_ONLY
        self.pending_call_hash = None
        self.mutation_count += 1
