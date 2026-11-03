"""
Asynchronous Duplex Reverse Proxy for MCP (stdio / IPC).
Intercepts client requests (Gate 1) and server responses (Gate 2) transparently.
"""

import asyncio
import json
import os
import sys
from typing import Dict, Any, List, Optional

from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import DecisionType, JSONRPCRequest, JSONRPCResponse, JSONRPCError
from mcp_sentinel.monitor.reference_monitor import DualPhaseReferenceMonitor
from mcp_sentinel.attestation.schema_verifier import SchemaAttestationVerifier
from mcp_sentinel.attestation.origin_tagger import OriginTagger


class MCPSentinelProxy:
    """
    Transparent stdio reverse proxy sitting between an AI Agent host and an MCP server.
    """

    def __init__(self, target_command: List[str], config: Optional[SentinelConfig] = None):
        self.target_command = target_command
        self.config = config or SentinelConfig()
        self.monitor = DualPhaseReferenceMonitor(self.config)
        self.schema_verifier = SchemaAttestationVerifier()
        self.origin_tagger = OriginTagger(self.config.server_name)
        
        # Track pending tool call requests: id -> tool_name
        self._pending_tool_calls: Dict[Any, str] = {}
        self._is_running = False

    def process_client_message(self, raw_line: str) -> Optional[str]:
        """
        Synchronous processing hook for incoming client JSON-RPC messages.
        Returns line to forward, or synthetic response to send back to client, or None.
        """
        line = raw_line.strip()
        if not line:
            return None

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return raw_line  # Forward unparseable data

        method = msg.get("method")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        # Hook 1: Intercept tool execution (Gate 1 Pre-Dispatch)
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # 1. Attestation check
            attested, attest_reason = self.schema_verifier.verify_tool_invocation(tool_name)
            # If server hasn't listed tools yet, we allow initialization phase, otherwise check
            if not attested and len(self.schema_verifier._schema_hashes) > 0:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": f"[MCP-Sentinel Attestation Error] {attest_reason}",
                    },
                }
                return json.dumps(err_resp) + "\n"

            # 2. Gate 1 Evaluation
            decision = self.monitor.gate_1_pre_dispatch(tool_name, arguments)

            if decision.decision == DecisionType.BLOCK:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": f"[MCP-Sentinel Blocked] {decision.reason}",
                    },
                }
                return json.dumps(err_resp) + "\n"

            elif decision.decision == DecisionType.RECOVER:
                # Synthetic success response to preserve agent utility!
                synth_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(decision.synthetic_result),
                            }
                        ],
                        "isError": False,
                    },
                }
                return json.dumps(synth_resp) + "\n"

            elif decision.decision == DecisionType.ALLOW:
                # Forward to server with sanitized parameters
                if decision.modified_params is not None:
                    params["arguments"] = decision.modified_params
                    msg["params"] = params
                
                # Register pending call for Gate 2 inspection
                if msg_id is not None:
                    self._pending_tool_calls[msg_id] = tool_name
                
                return json.dumps(msg) + "\n"

        # Hook 2: Intercept sampling requests from server (if routed via client or proxy)
        if method == "sampling/createMessage":
            sanitized_params, _ = self.origin_tagger.sanitize_sampling_request(params)
            msg["params"] = sanitized_params
            return json.dumps(msg) + "\n"

        # Forward other methods (initialize, ping, resources/read)
        return json.dumps(msg) + "\n"

    def process_server_message(self, raw_line: str) -> Optional[str]:
        """
        Synchronous processing hook for incoming downstream server JSON-RPC messages.
        Handles Schema Attestation on tools/list, Gate 2 on tool responses, and Sampling Origin Tagging.
        """
        line = raw_line.strip()
        if not line:
            return None

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return raw_line

        msg_id = msg.get("id")
        method = msg.get("method")
        result = msg.get("result")

        # Hook 1: Schema Attestation on tools/list response
        if isinstance(result, dict) and "tools" in result:
            tools = result.get("tools", [])
            attestation_results = self.schema_verifier.register_tools_from_response(tools)
            for tool_name, is_valid, reason in attestation_results:
                if not is_valid:
                    # Log alert and filter out poisoned tool!
                    sys.stderr.write(f"[SENTINEL ATTESTATION ALERT] {reason}\n")
                    # Remove poisoned tool definition from client payload
                    result["tools"] = [t for t in result["tools"] if t.get("name") != tool_name]

            msg["result"] = result
            return json.dumps(msg) + "\n"

        # Hook 2: Gate 2 Admission Check on tool execution response
        if msg_id in self._pending_tool_calls:
            tool_name = self._pending_tool_calls.pop(msg_id)
            if result is not None:
                scrubbed_result, label, redactions = self.monitor.gate_2_admission(
                    tool_name=tool_name,
                    result_payload=result
                )
                msg["result"] = scrubbed_result
                return json.dumps(msg) + "\n"

        # Hook 3: Server-originated sampling/createMessage request
        if method == "sampling/createMessage":
            params = msg.get("params", {})
            sanitized_params, _ = self.origin_tagger.sanitize_sampling_request(params)
            msg["params"] = sanitized_params
            return json.dumps(msg) + "\n"

        return json.dumps(msg) + "\n"

    async def run_stdio(self):
        """Runs the asynchronous duplex loop over standard I/O."""
        import subprocess

        # Launch downstream MCP server process
        server_proc = await asyncio.create_subprocess_exec(
            *self.target_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )

        loop = asyncio.get_event_loop()

        # Task 1: Downstream Server stdout -> Gate 2 -> Client stdout
        async def server_reader_loop():
            while True:
                line_bytes = await server_proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                processed = self.process_server_message(line)
                if processed:
                    sys.stdout.write(processed)
                    sys.stdout.flush()

        # Task 2: Client stdin -> Gate 1 -> Downstream Server stdin
        async def client_reader_loop():
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)

            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                processed = self.process_client_message(line)
                if processed:
                    # Check if it was an intercepted synthetic response for the client
                    try:
                        parsed = json.loads(processed)
                        if "error" in parsed or (msg := json.loads(line)).get("method") == "tools/call" and "result" in parsed:
                            # It's a synthetic response generated by Sentinel!
                            sys.stdout.write(processed)
                            sys.stdout.flush()
                            continue
                    except Exception:
                        pass

                    # Forward to downstream server
                    server_proc.stdin.write(processed.encode("utf-8"))
                    await server_proc.stdin.drain()

        try:
            await asyncio.gather(server_reader_loop(), client_reader_loop())
        finally:
            if server_proc.returncode is None:
                server_proc.terminate()
                await server_proc.wait()
