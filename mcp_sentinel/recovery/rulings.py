"""
Call-Scoped Authority Rulings.
Implements atomic, single-use approval tokens bound strictly to the hash of tool arguments.
Based on formal mechanisms from APPA (Archestra AI).
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Any, Optional, Set


class AuthorityRulingRegistry:
    """
    Manages atomic, call-scoped rulings for high-consequence operations.
    Unlike time-boxed windows, a ruling applies strictly to ONE execution matching the exact hash.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self._secret = secret_key or secrets.token_hex(32)
        # Set of consumed hash tokens to prevent replay attacks
        self._consumed_hashes: Set[str] = set()
        # Active approved hashes: hash -> expiration_timestamp
        self._active_rulings: Dict[str, float] = {}

    def compute_call_hash(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """
        Computes a deterministic hash over tool name and sorted arguments.
        """
        canonical_payload = {
            "tool": tool_name,
            "args": arguments,
        }
        serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(self._secret.encode("utf-8"), serialized.encode("utf-8"), hashlib.sha256).hexdigest()

    def grant_ruling(self, call_hash: str, ttl_seconds: float = 60.0) -> str:
        """Grants an atomic ruling for a specific call hash."""
        expiration = time.time() + ttl_seconds
        self._active_rulings[call_hash] = expiration
        return call_hash

    def verify_and_consume_ruling(self, call_hash: str) -> bool:
        """
        Verifies if an active, unconsumed ruling exists for this call.
        If valid, atomically consumes the token and invalidates it immediately.
        """
        now = time.time()
        if call_hash in self._consumed_hashes:
            return False  # Already replayed!

        if call_hash in self._active_rulings:
            expiration = self._active_rulings[call_hash]
            if now <= expiration:
                # Atomically consume
                del self._active_rulings[call_hash]
                self._consumed_hashes.add(call_hash)
                return True
            else:
                # Expired
                del self._active_rulings[call_hash]

        return False
