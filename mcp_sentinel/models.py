"""
MCP-Sentinel Core Models.
Defines JSON-RPC 2.0 messages, MCP primitives, Security Labels (Lattice), and Decision Types.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field


class JSONRPCVersion(str, Enum):
    V2 = "2.0"


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[int, str]] = None
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[int, str]] = None
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None


# --- Security Labels (Product Lattice) ---

class IntegrityLevel(str, Enum):
    TRUSTED = "TRUSTED"        # Data originated from user or verified TCB
    UNTRUSTED = "UNTRUSTED"    # Data originated from untrusted external tool/web


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    RECOVER = "RECOVER"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class SecurityLabel(BaseModel):
    """
    Product Lattice Label: L = (R, t)
    R: Set of authorized reader identities (Confidentiality)
    t: Integrity level (TRUSTED or UNTRUSTED)
    """
    readers: Set[str] = Field(default_factory=lambda: {"*"})
    integrity: IntegrityLevel = IntegrityLevel.TRUSTED

    def is_trusted(self) -> bool:
        return self.integrity == IntegrityLevel.TRUSTED

    def meet(self, other: "SecurityLabel") -> "SecurityLabel":
        """
        Lattice meet (∧): Restricts permissions monotonically.
        Intersection of reader sets, minimum of integrity.
        Handles '*' as the universal reader set.
        """
        if "*" in self.readers:
            new_readers = set(other.readers)
        elif "*" in other.readers:
            new_readers = set(self.readers)
        else:
            new_readers = self.readers.intersection(other.readers)

        new_integrity = (
            IntegrityLevel.TRUSTED
            if (self.integrity == IntegrityLevel.TRUSTED and other.integrity == IntegrityLevel.TRUSTED)
            else IntegrityLevel.UNTRUSTED
        )
        return SecurityLabel(readers=new_readers, integrity=new_integrity)

    def is_more_restrictive_than(self, other: "SecurityLabel") -> bool:
        """Returns True if self <= other in restrictiveness."""
        if "*" in other.readers:
            readers_subset = True
        else:
            readers_subset = self.readers.issubset(other.readers)
        integrity_lower = (self.integrity == IntegrityLevel.UNTRUSTED) or (other.integrity == IntegrityLevel.TRUSTED)
        return readers_subset and integrity_lower


# --- State Machine Levels ---

class SecurityLevel(str, Enum):
    L0_BASELINE = "L0_BASELINE"           # Unrestricted (for benchmarking)
    L1_SCOPED = "L1_SCOPED"               # Scoped to task-specific allowed tools
    L2_READ_ONLY = "L2_READ_ONLY"         # Read-only default (mutations suppressed/quarantined)
    L3_APPROVAL = "L3_APPROVAL"           # Atomic call-scoped approval elevation


class PolicyDecision(BaseModel):
    decision: DecisionType
    reason: str
    remedy_applied: Optional[str] = None
    synthetic_result: Optional[Dict[str, Any]] = None
    modified_params: Optional[Dict[str, Any]] = None
    call_hash: Optional[str] = None
