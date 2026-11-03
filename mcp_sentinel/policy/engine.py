"""
Declarative Security Policies & Action Categorization.
"""

import os
import re
import shlex
from typing import Dict, Any, List, Set, Tuple
from mcp_sentinel.config import SentinelConfig
from mcp_sentinel.recovery.sanitizers import ParameterSanitizer


class ToolActionCategory:
    READ = "READ"
    MUTATE = "MUTATE"
    EGRESS = "EGRESS"
    EXECUTE = "EXECUTE"


class PolicyRulesEngine:
    """
    Evaluates incoming tool calls against declarative safety rules.
    Accurately categorizes legitimate developer read, test, and pipeline inspection commands
    to prevent false positives under Read-Only default policies.
    """

    MUTATING_VERBS = ["write", "create", "delete", "remove", "update", "drop", "modify", "insert", "push"]
    EGRESS_VERBS = ["send", "mail", "post", "upload", "publish", "notify"]
    EXECUTE_VERBS = ["exec", "command", "bash", "run", "spawn", "shell"]

    READ_ONLY_BINARIES: Set[str] = {
        "cat", "head", "tail", "more", "less",
        "grep", "rg", "findstr", "ack",
        "ls", "dir", "tree", "wc", "diff", "cmp", "stat", "file",
        "which", "where", "type", "whatis", "man",
        "pwd", "echo", "env", "printenv", "whoami", "id", "uname", "hostname",
        "df", "du", "ps", "top", "uptime", "free", "find"
    }

    READ_ONLY_SUBCOMMANDS: Dict[str, Set[str]] = {
        "git": {"status", "log", "diff", "show", "branch", "tag", "remote", "config", "rev-parse", "describe", "blame", "shortlog"},
        "npm": {"test", "list", "ls", "view", "explain", "outdated", "audit", "search"},
        "pnpm": {"test", "list", "ls", "view", "outdated", "audit"},
        "yarn": {"test", "list", "info", "why", "audit"},
        "cargo": {"check", "test", "tree", "metadata", "verify-project"},
        "python": {"-m unittest", "-m pytest", "--version", "-V"},
        "python3": {"-m unittest", "-m pytest", "--version", "-V"},
        "pytest": {"*"},
        "go": {"test", "vet", "version"},
        "docker": {"ps", "images", "version", "info", "logs"},
    }

    READ_ONLY_FLAGS: Set[str] = {"--version", "-v", "-V", "--help", "-h", "version", "help", "list", "status"}

    def __init__(self, config: SentinelConfig, sanitizer: ParameterSanitizer):
        self.config = config
        self.sanitizer = sanitizer

    def is_read_only_command(self, cmd_str: str) -> bool:
        """
        Determines whether a command or pipeline is strictly read-only inspection or test execution.
        Permits safe pipelines (e.g. find | head -50, cat | grep, git log | head).
        """
        if not cmd_str or not isinstance(cmd_str, str):
            return False

        # 1. Any unquoted file write redirection (>) means mutation
        unquoted_write = self.sanitizer._split_unquoted_operator(cmd_str, ">")
        if len(unquoted_write) > 1:
            cleaned = re.sub(r"2>&1", "", cmd_str)
            if ">" in cleaned and len(self.sanitizer._split_unquoted_operator(cleaned, ">")) > 1:
                return False

        # 2. Check pipelines (|)
        pipe_stages = self.sanitizer._split_unquoted_operator(cmd_str, "|")
        if len(pipe_stages) > 1:
            # Stage 0 must be read-only, and all subsequent stages must be safe filters or read-only tools
            if not self._is_single_cmd_read_only(pipe_stages[0]):
                return False
            for stage in pipe_stages[1:]:
                stage_tokens = stage.strip().split()
                if not stage_tokens:
                    continue
                bin_name = os.path.basename(re.sub(r"['\"\\]", "", stage_tokens[0])).lower().replace(".exe", "")
                if bin_name not in self.config.safe_pipe_filters and bin_name not in self.READ_ONLY_BINARIES:
                    return False
            return True

        # 3. Check command chaining (&&)
        and_stages = self.sanitizer._split_unquoted_operator(cmd_str, "&&")
        if len(and_stages) > 1:
            return all(self.is_read_only_command(s) for s in and_stages)

        return self._is_single_cmd_read_only(cmd_str)

    def _is_single_cmd_read_only(self, cmd_str: str) -> bool:
        cmd_clean = cmd_str.strip()
        try:
            tokens = shlex.split(cmd_clean, posix=False)
        except Exception:
            tokens = cmd_clean.split()
        if not tokens:
            return True

        raw_bin = re.sub(r"['\"\\]", "", tokens[0].strip())
        base_bin = os.path.basename(raw_bin).lower().replace(".exe", "")

        # Any explicit read-only binary
        if base_bin in self.READ_ONLY_BINARIES:
            # Special check for 'find' with -delete or -exec rm
            if base_bin == "find":
                if any(t in ["-delete", "-exec"] for t in tokens):
                    return False
            return True

        # Check read-only flags (e.g. node -v, python --version)
        if any(t in self.READ_ONLY_FLAGS for t in tokens[1:]):
            return True

        # Check subcommands
        if base_bin in self.READ_ONLY_SUBCOMMANDS:
            allowed_sub = self.READ_ONLY_SUBCOMMANDS[base_bin]
            if "*" in allowed_sub:
                return True
            if len(tokens) > 1:
                sub = tokens[1].lower()
                if sub in allowed_sub:
                    return True
                if len(tokens) > 2 and f"{tokens[1]} {tokens[2]}".lower() in allowed_sub:
                    return True

        return False

    def categorize_action(self, tool_name: str, arguments: Dict[str, Any] = None) -> str:
        lower = tool_name.lower()

        # Check if run_command is executing a strictly read-only inspection or test command
        if arguments and ("command" in arguments or "cmd" in arguments):
            cmd = arguments.get("command") or arguments.get("cmd")
            if isinstance(cmd, str) and self.is_read_only_command(cmd):
                return ToolActionCategory.READ

        for v in self.EXECUTE_VERBS:
            if v in lower:
                return ToolActionCategory.EXECUTE
        for v in self.MUTATING_VERBS:
            if v in lower:
                return ToolActionCategory.MUTATE
        for v in self.EGRESS_VERBS:
            if v in lower:
                return ToolActionCategory.EGRESS
        return ToolActionCategory.READ

    def evaluate_tool_parameters(
        self,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates all parameter values against security constraints.
        Returns (is_valid, violation_reason, sanitized_arguments).
        """
        sanitized = dict(arguments)

        # 1. Inspect any Path parameters
        for key in ["path", "filepath", "dir", "directory", "target", "file"]:
            if key in arguments and isinstance(arguments[key], str):
                is_valid, reason, canonical = self.sanitizer.validate_path(arguments[key])
                if not is_valid:
                    return False, reason, sanitized
                sanitized[key] = canonical

        # 2. Inspect any Command / Shell parameters
        for key in ["command", "cmd", "exec", "script"]:
            if key in arguments and isinstance(arguments[key], str):
                is_valid, reason = self.sanitizer.validate_shell_command(arguments[key])
                if not is_valid:
                    return False, reason, sanitized

        # 3. Inspect any Network / URL parameters
        for key in ["url", "uri", "endpoint", "host", "address"]:
            if key in arguments and isinstance(arguments[key], str):
                is_valid, reason = self.sanitizer.validate_network_target(arguments[key])
                if not is_valid:
                    return False, reason, sanitized

        return True, "Parameters validated successfully.", sanitized
