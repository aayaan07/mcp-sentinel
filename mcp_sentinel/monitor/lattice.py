"""
Information Flow Control (IFC) Product Lattice Module.
Based on formal models from FIDES (Microsoft) and APPA (Archestra AI).
"""

from typing import Set, Tuple, Optional
from mcp_sentinel.models import SecurityLabel, IntegrityLevel


class ProductLattice:
    """
    Formal Product Lattice for Agent Taint Tracking:
    L = (R, t) in P(U) x {TRUSTED, UNTRUSTED}
    
    Ordered by restrictiveness:
    (R', t') <= (R, t) iff R' subseteq R and t' <= t
    """
    
    @staticmethod
    def top() -> SecurityLabel:
        """Top element: completely untrusted and secret/restricted readers."""
        return SecurityLabel(readers=set(), integrity=IntegrityLevel.UNTRUSTED)
    
    @staticmethod
    def bottom() -> SecurityLabel:
        """Bottom element: fully trusted and public readers."""
        return SecurityLabel(readers={"*"}, integrity=IntegrityLevel.TRUSTED)
    
    @staticmethod
    def meet(l1: SecurityLabel, l2: SecurityLabel) -> SecurityLabel:
        """
        Component-wise meet:
        (R1, t1) ∧ (R2, t2) = (R1 ∩ R2, min(t1, t2))
        Monotonically narrows capabilities as untrusted data enters context.
        """
        return l1.meet(l2)
    
    @staticmethod
    def prospective_label(current_label: SecurityLabel, tool_contribution: SecurityLabel) -> SecurityLabel:
        """
        Gate 1 Prospective Check: c_tau(L) = L ∧ d_tau
        Computes expected security label before tool execution.
        """
        return ProductLattice.meet(current_label, tool_contribution)
    
    @staticmethod
    def verify_trusted_action(prospective_label: SecurityLabel) -> bool:
        """
        Policy P-T (Trusted Action): Consequential/mutating actions 
        require the decision context to be strictly TRUSTED (t = T).
        Mathematically guarantees Non-Interference for Integrity.
        """
        return prospective_label.integrity == IntegrityLevel.TRUSTED
    
    @staticmethod
    def verify_permitted_flow(prospective_label: SecurityLabel, egress_recipients: Set[str]) -> bool:
        """
        Policy P-F (Permitted Flow): Egress tools proceed only if all 
        recipients are authorized readers in R.
        Guarantees Explicit Secrecy for Confidentiality.
        """
        if "*" in prospective_label.readers:
            return True
        return egress_recipients.issubset(prospective_label.readers)
