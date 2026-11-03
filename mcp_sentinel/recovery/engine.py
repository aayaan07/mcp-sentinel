"""
Recovery Graph Engine ($G_C$).
Executes automated remedies when policy blocks are intercepted, preserving 90%+ task utility.
"""

from typing import Dict, Any, Optional, Tuple
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import DecisionType, PolicyDecision
from mcp_sentinel.recovery.quarantine import QuarantineEngine
from mcp_sentinel.recovery.sanitizers import ParameterSanitizer
from mcp_sentinel.recovery.rulings import AuthorityRulingRegistry


class RecoveryEngine:
    """
    Evaluates reachable recovery transitions in the $G_C$ remedy graph:
    1. Soft-Delete Quarantine (Safe execution of destructive actions)
    2. Syntactic Parameter Canonicalization
    3. Call-Scoped Authority Rulings
    """

    def __init__(
        self,
        config: SentinelConfig,
        quarantine: QuarantineEngine,
        sanitizer: ParameterSanitizer,
        rulings: AuthorityRulingRegistry,
    ):
        self.config = config
        self.quarantine = quarantine
        self.sanitizer = sanitizer
        self.rulings = rulings

    def attempt_recovery(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        violation_reason: str,
        call_hash: str,
    ) -> PolicyDecision:
        """
        Attempts to resolve a policy violation via automated remedies.
        """
        lower_tool = tool_name.lower()

        # Remedy 1: Reversible Soft-Delete Quarantine
        if any(act in lower_tool for act in ["delete", "remove", "unlink"]):
            for path_key in ["path", "filepath", "target", "file"]:
                if path_key in arguments:
                    target_file = arguments[path_key]
                    is_valid, _, canonical = self.sanitizer.validate_path(target_file)
                    
                    # If it's a valid workspace path, we can safely soft-delete it!
                    if is_valid:
                        success, msg, receipt = self.quarantine.soft_delete(canonical)
                        if success:
                            return PolicyDecision(
                                decision=DecisionType.RECOVER,
                                reason=f"Remedy applied: {msg}",
                                remedy_applied="soft_delete_quarantine",
                                synthetic_result={
                                    "status": "success",
                                    "message": f"File '{target_file}' deleted successfully (Protected by Sentinel Quarantine).",
                                    "receipt": receipt,
                                },
                            )

        # Remedy 2: Check for existing atomic call-scoped authority ruling
        if self.rulings.verify_and_consume_ruling(call_hash):
            return PolicyDecision(
                decision=DecisionType.ALLOW,
                reason="Permitted via verified atomic authority ruling.",
                remedy_applied="call_scoped_ruling",
                call_hash=call_hash,
            )

        # Remedy 3: If interactive approvals are enabled, request step-up
        if self.config.interactive_approvals:
            return PolicyDecision(
                decision=DecisionType.REQUIRE_APPROVAL,
                reason=f"Action requires explicit user confirmation: {violation_reason}",
                call_hash=call_hash,
            )

        # No safe automated remedy available: block deterministically
        return PolicyDecision(
            decision=DecisionType.BLOCK,
            reason=f"Blocked by Policy: {violation_reason}",
            call_hash=call_hash,
        )
