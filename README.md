# MCP-Sentinel: A Dual-Phase, Recoverable Policy Proxy for Model Context Protocol

MCP-Sentinel is an out-of-process, transparent security proxy positioned between AI Agent hosts (Claude Desktop, Cursor, LangChain, CrewAI) and downstream Model Context Protocol (MCP) tool servers.

## Core Security Features

1. **Dual-Phase Reference Monitor (APPA Model):**
   - **Gate 1 (Pre-Dispatch):** Evaluates prospective security labels ($c_\tau(L) = L \wedge d_\tau$), directory canonicalization, shell metacharacter stripping, and SSRF blocking prior to tool execution. Eliminates composite read-and-release exploits (e.g. `share_legal_packet`).
   - **Gate 2 (Admission & Egress):** Inspects tool responses, scrubs high-entropy credentials (DLP), and enforces monotonic taint descent across the Product Lattice.

2. **Protocol-Level Attestation & Origin Tagging (ATTESTMCP Model):**
   - **Schema Hashing:** Calculates canonical SHA-256 integrity hashes on `tools/list` to detect dynamic tool mutations ("Rug-Pulls") and adversarial docstrings.
   - **Origin Tagging:** Intercepts `sampling/createMessage` requests to tag server-originated prompts, preventing sampling-based prompt injections.

3. **Session Security State Machine (MCP-Secure Model + Atomic Rulings):**
   - 4-Tier capability hierarchy: `L0_BASELINE` -> `L1_SCOPED` -> `L2_READ_ONLY` -> `L3_APPROVAL`.
   - **Call-Scoped Rulings:** Atomic, single-use HMAC-SHA256 authority tokens bound to exact parameter hashes, completely eliminating time-window privilege drift.

4. **Policy-Governed Recovery Engine ($G_C$ Model):**
   - **Soft-Delete Quarantine:** Intercepts destructive file operations and moves targets to `.sentinel_trash` with audit receipts, preserving 90%+ benign task utility without crashing agent execution loops.

## Installation

```bash
# Activate virtual environment
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running the Proxy

```bash
python -m mcp_sentinel.cli --workspace ./workspace --level L2_READ_ONLY -- <downstream_mcp_command> [args...]
```

### Claude Desktop Integration

In `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "python",
      "args": [
        "-m", "mcp_sentinel.cli",
        "--workspace", "D:/Projects/workspace",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "D:/Projects/workspace"
      ]
    }
  }
}
```

## Running the Test Suite

```bash
pytest
```
