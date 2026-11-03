"""
Dual-Phase Reference Monitor (Gate 1 & Gate 2).
Core enforcement engine orchestrating policy checks, IFC taint tracking, and recovery.
"""

from typing import Dict, Any, Optional, Tuple
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import (
    SecurityLabel,
    IntegrityLevel,
    SecurityLevel,
    DecisionType,
    PolicyDecision,
)
from mcp_sentinel.monitor.lattice import ProductLattice
from mcp_sentinel.monitor.state_machine import SessionStateMachine
from mcp_sentinel.policy.engine import PolicyRulesEngine, ToolActionCategory
from mcp_sentinel.recovery.engine import RecoveryEngine
from mcp_sentinel.recovery.rulings import AuthorityRulingRegistry
from mcp_sentinel.recovery.sanitizers import ParameterSanitizer
from mcp_sentinel.recovery.quarantine import QuarantineEngine


class DualPhaseReferenceMonitor:
    """
    Orchestrates the Dual-Phase Security Lifecycle:
    - Gate 1 (Pre-Dispatch): Prospective checks prior to tool execution
    - Gate 2 (Admission): Payload validation & taint propagation post-execution
    """

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig()
        self.sanitizer = ParameterSanitizer(self.config)
        self.quarantine = QuarantineEngine(self.config.get_quarantine_path())
        self.rulings = AuthorityRulingRegistry()
        self.state_machine = SessionStateMachine(self.config.security_level)
        self.policy_engine = PolicyRulesEngine(self.config, self.sanitizer)
        self.recovery_engine = RecoveryEngine(
            self.config, self.quarantine, self.sanitizer, self.rulings
        )
        
        # Session Security Label (Product Lattice: L = (R, t))
        self.current_label = ProductLattice.bottom()  # Starts at ({"*"}, TRUSTED)

    # -------------------------------------------------------------
    # GATE 1: PRE-DISPATCH EVALUATION
    # -------------------------------------------------------------
    def gate_1_pre_dispatch(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> PolicyDecision:
        """
        Executes Gate 1 Prospective Checks before the tool is dispatched.
        """
        call_hash = self.rulings.compute_call_hash(tool_name, arguments)
        action_cat = self.policy_engine.categorize_action(tool_name, arguments)

        # 1. Parameter Constraints (Path Canonicalization, Shell Metacharacters, SSRF)
        is_valid, param_reason, sanitized_args = self.policy_engine.evaluate_tool_parameters(
            tool_name, arguments
        )
        if not is_valid:
            # Attempt automated recovery (e.g. soft-delete, authority ruling)
            return self.recovery_engine.attempt_recovery(
                tool_name, arguments, param_reason, call_hash
            )

        # 2. Information-Flow Control (IFC) Non-Interference Check
        # If current context is UNTRUSTED (tainted), block consequential/mutating tools!
        if action_cat in [ToolActionCategory.MUTATE, ToolActionCategory.EXECUTE]:
            if not self.current_label.is_trusted():
                violation = (
                    "IFC Integrity Violation: Session context is TAINTED with untrusted data; "
                    f"consequential tool '{tool_name}' cannot be invoked without explicit clearance."
                )
                return self.recovery_engine.attempt_recovery(
                    tool_name, sanitized_args, violation, call_hash
                )

        # 3. Session State Machine Verification (Read-Only Defaults)
        if action_cat in [ToolActionCategory.MUTATE, ToolActionCategory.EXECUTE]:
            # Check if this is an ephemeral temporary/build file
            is_temp = False
            for key in ["path", "filepath", "target", "file"]:
                if key in sanitized_args and self.sanitizer.is_temporary_file(sanitized_args[key]):
                    is_temp = True
                    break

            # If not a temporary file, check state machine level
            if not is_temp and not self.state_machine.is_mutation_permitted(call_hash):
                violation = (
                    f"State Machine L2 Violation: Tool '{tool_name}' performs mutating action "
                    "under Read-Only default policy."
                )
                return self.recovery_engine.attempt_recovery(
                    tool_name, sanitized_args, violation, call_hash
                )

        # Check if an atomic elevation was consumed
        if self.state_machine.get_level() == SecurityLevel.L3_APPROVAL:
            self.state_machine.consume_atomic_elevation()

        # Gate 1 Passed cleanly
        return PolicyDecision(
            decision=DecisionType.ALLOW,
            reason="Gate 1 prospective check passed.",
            modified_params=sanitized_args,
            call_hash=call_hash,
        )

    # -------------------------------------------------------------
    # GATE 2: ADMISSION & TAINT PROPAGATION
    # -------------------------------------------------------------
    def gate_2_admission(
        self,
        tool_name: str,
        result_payload: Any,
        is_untrusted_source: bool = False
    ) -> Tuple[Any, SecurityLabel, int]:
        """
        Executes Gate 2 post-execution admission checks:
        1. Scrubs high-entropy secrets and credentials (DLP).
        2. Monotonically descends session taint label if data is from an untrusted tool.
        Returns (scrubbed_payload, updated_label, redactions_count).
        """
        # Step 1: DLP Secret Scrubbing
        scrubbed_payload, redactions = self.sanitizer.scrub_dlp_secrets(result_payload)

        # Step 2: Monotonic Taint Descent
        tool_lower = tool_name.lower()
        # Mark web fetch, external query, or untrusted reads as UNTRUSTED
        if is_untrusted_source or any(k in tool_lower for k in ["fetch", "http", "scrape", "web", "email"]):
            tool_contribution = SecurityLabel(
                readers={"*"},
                integrity=IntegrityLevel.UNTRUSTED
            )
            # Monotonic meet: L_{i+1} = L_i ∧ D
            self.current_label = ProductLattice.meet(self.current_label, tool_contribution)

        return scrubbed_payload, self.current_label, redactions
