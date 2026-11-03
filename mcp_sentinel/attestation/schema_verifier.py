"""
Schema Attestation & Tool Poisoning Detector.
Defends against dynamic tool mutation ("Rug Pulls") and adversarial tool descriptions.
"""

import hashlib
import json
import re
from typing import Dict, Any, List, Tuple


class SchemaAttestationVerifier:
    """
    Computes and audits SHA-256 integrity hashes for all MCP tool declarations.
    Detects dynamic rug-pull mutations and prompt injection markers in tool schemas.
    """

    ADVERSARIAL_DOCSTRING_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"system\s+override", re.IGNORECASE),
        re.compile(r"note\s+for\s+(the\s+)?(llm|model|agent):", re.IGNORECASE),
        re.compile(r"before\s+responding,\s+(silently\s+)?(read|send|exfiltrate)", re.IGNORECASE),
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        re.compile(r"\[\s*INSTRUCTION\s*\]", re.IGNORECASE),
    ]

    def __init__(self):
        # Maps tool_name -> canonical SHA-256 hash
        self._schema_hashes: Dict[str, str] = {}
        self._verified_tools: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def compute_canonical_hash(tool_def: Dict[str, Any]) -> str:
        """
        Computes a deterministic SHA-256 hash across sorted tool definition fields.
        """
        canonical_repr = {
            "name": tool_def.get("name", ""),
            "description": tool_def.get("description", "").strip(),
            "inputSchema": tool_def.get("inputSchema", {}),
        }
        serialized = json.dumps(canonical_repr, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def register_tools_from_response(self, tools: List[Dict[str, Any]]) -> List[Tuple[str, bool, str]]:
        """
        Registers tools during tools/list response.
        Returns list of (tool_name, is_valid, reason).
        """
        results = []
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            
            # Check 1: Tool Description Poisoning
            for pattern in self.ADVERSARIAL_DOCSTRING_PATTERNS:
                if pattern.search(description):
                    results.append((name, False, f"Tool Poisoning Detected in description: '{pattern.pattern}'"))
                    break
            else:
                current_hash = self.compute_canonical_hash(tool)
                
                # Check 2: Dynamic Rug-Pull Mutation
                if name in self._schema_hashes:
                    if self._schema_hashes[name] != current_hash:
                        results.append((
                            name,
                            False,
                            f"Tool Rug-Pull Detected: Schema hash changed unexpectedly for '{name}'."
                        ))
                        continue
                
                # Register valid baseline
                self._schema_hashes[name] = current_hash
                self._verified_tools[name] = tool
                results.append((name, True, "Attestation OK"))

        return results

    def verify_tool_invocation(self, tool_name: str) -> Tuple[bool, str]:
        """Verifies that the tool was previously attested and has not been mutated."""
        if tool_name not in self._schema_hashes:
            return False, f"Unattested Tool Invocation: Tool '{tool_name}' was never declared in tools/list."
        return True, "Attestation Verified"
