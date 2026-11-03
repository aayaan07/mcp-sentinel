"""
MCP-Sentinel Command Line Interface.
Usage:
    python -m mcp_sentinel.cli [options] -- <command> [args...]
"""

import argparse
import asyncio
import os
import sys

from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.models import SecurityLevel
from mcp_sentinel.proxy import MCPSentinelProxy


def parse_args():
    parser = argparse.ArgumentParser(
        description="MCP-Sentinel: Transparent Security Proxy for Model Context Protocol"
    )
    parser.add_argument(
        "--server-name",
        type=str,
        default="upstream-server",
        help="Identifier name for the protected MCP server",
    )
    parser.add_argument(
        "--level",
        type=str,
        choices=["L0_BASELINE", "L1_SCOPED", "L2_READ_ONLY", "L3_APPROVAL"],
        default="L2_READ_ONLY",
        help="Initial session security level (default: L2_READ_ONLY)",
    )
    parser.add_argument(
        "--workspace",
        action="append",
        dest="workspaces",
        help="Allowed canonical directory path (can be specified multiple times)",
    )
    parser.add_argument(
        "target",
        nargs=argparse.REMAINDER,
        help="Target MCP server command to wrap, separated by '--'",
    )

    args = parser.parse_args()

    # Clean target command (strips leading '--' if present)
    target_cmd = args.target
    if target_cmd and target_cmd[0] == "--":
        target_cmd = target_cmd[1:]

    if not target_cmd:
        parser.print_help(sys.stderr)
        sys.stderr.write("\nError: No target MCP server command specified.\n")
        sys.exit(1)

    return args, target_cmd


def main():
    args, target_cmd = parse_args()

    # Build config
    workspaces = args.workspaces or [os.getcwd()]
    config = SentinelConfig(
        server_name=args.server_name,
        security_level=SecurityLevel(args.level),
        allowed_workspaces=workspaces,
    )

    proxy = MCPSentinelProxy(target_command=target_cmd, config=config)

    # Run asyncio loop
    try:
        asyncio.run(proxy.run_stdio())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
