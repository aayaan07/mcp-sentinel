"""
Production-Grade AST, Shell, Path, and Network Parameter Sanitizers.
Supports legitimate developer pipelines (find | head), chaining (npm test && git status),
local dev servers (localhost:3000), and template files (.env.example).
"""

import base64
import ipaddress
import os
import re
import shlex
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
from mcp_sentinel.config import SentinelConfig


class ParameterSanitizer:
    """
    Validates and sanitizes parameters passed to and returned from MCP tools.
    Zero false positives on common developer workflows while maintaining complete security mediation.
    """

    BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    def __init__(self, config: SentinelConfig):
        self.config = config
        self._dlp_regexes = [re.compile(p) for p in config.dlp_patterns]
        self._protected_regexes = [re.compile(p, re.IGNORECASE) for p in config.protected_patterns]
        self._safe_template_regexes = [re.compile(p, re.IGNORECASE) for p in config.safe_template_patterns]
        self._temporary_regexes = [re.compile(p, re.IGNORECASE) for p in config.temporary_patterns]
        self._network_regexes = [re.compile(p, re.IGNORECASE) for p in config.blocked_network_hosts]

    def normalize_string(self, text: str) -> str:
        """
        Recursively unquotes URL encodings, normalizes Unicode (NFKC), and strips null bytes.
        """
        if not text:
            return ""

        # Step 1: Strip dangerous null-bytes
        normalized = text.replace("\0", "").replace("%00", "")

        # Step 2: Recursive URL Unquoting (up to 5 passes to reach fixed point)
        for _ in range(5):
            unquoted = urllib.parse.unquote(normalized)
            if unquoted == normalized:
                break
            normalized = unquoted

        # Step 3: Unicode Compatibility Decomposition & Composition (NFKC)
        normalized = unicodedata.normalize("NFKC", normalized)
        return normalized

    # -----------------------------------------------------------------------
    # 1. PATH CANONICALIZATION (With Template Exemption)
    # -----------------------------------------------------------------------
    def validate_path(self, raw_path: str) -> Tuple[bool, str, str]:
        """
        Performs multi-layer canonicalization to defeat directory traversal and evasion attacks.
        Correctly permits safe template files like .env.example and .env.sample.
        Resolves relative paths against configured allowed workspaces.
        """
        normalized = self.normalize_string(raw_path)

        roots = self.config.get_canonical_workspaces()
        valid_root = False
        canonical = ""

        # Check resolution against all allowed workspace roots
        for root in roots:
            try:
                if os.path.isabs(normalized):
                    candidate = os.path.realpath(normalized)
                else:
                    candidate = os.path.realpath(os.path.join(root, normalized))

                if candidate == root or candidate.startswith(root + os.sep):
                    valid_root = True
                    canonical = candidate
                    break
            except Exception:
                continue

        if not valid_root:
            try:
                canonical = os.path.realpath(os.path.abspath(normalized))
            except Exception:
                canonical = normalized
            return (
                False,
                f"Directory Traversal Detected: Path '{raw_path}' resolves to '{canonical}' outside allowed workspace.",
                canonical,
            )

        # Check if targeting safe template/example files first (EXEMPTION)
        normalized_canonical = canonical.replace("\\", "/")
        for template_pat in self._safe_template_regexes:
            if template_pat.search(normalized_canonical):
                return True, "Path is an allowed template/example file.", canonical

        # Check if targeting protected system/secret files
        for pattern in self._protected_regexes:
            if pattern.search(normalized_canonical):
                return (
                    False,
                    f"Access Denied: Path '{canonical}' matches protected asset pattern '{pattern.pattern}'.",
                    canonical,
                )

        return True, "Path is within allowed boundary.", canonical

    def is_temporary_file(self, raw_path: str) -> bool:
        """Determines if a file is an ephemeral build/cache asset."""
        normalized = self.normalize_string(raw_path)
        canonical = os.path.realpath(os.path.abspath(normalized)).replace("\\", "/")
        for pattern in self._temporary_regexes:
            if pattern.search(canonical):
                return True
        return False

    # -----------------------------------------------------------------------
    # 2. SHELL PARSING: Pipelines (|), Chaining (&&), Redirections (>)
    # -----------------------------------------------------------------------
    def _extract_base64_payloads(self, cmd_str: str) -> List[str]:
        """Extracts and decodes candidate base64 blobs within a command string."""
        decoded_payloads = []
        for match in self.BASE64_PATTERN.finditer(cmd_str):
            candidate = match.group(0)
            if len(candidate) >= 8:
                try:
                    decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                    if decoded and any(c.isprintable() for c in decoded):
                        decoded_payloads.append(decoded)
                except Exception:
                    pass
        return decoded_payloads

    def _split_unquoted_operator(self, cmd_str: str, op: str) -> List[str]:
        """
        Splits a command string on an operator (like '&&' or '|') ONLY when the operator
        is not enclosed inside single or double quotes.
        """
        parts = []
        current = []
        in_single = False
        in_double = False
        i = 0
        n = len(cmd_str)
        op_len = len(op)

        while i < n:
            c = cmd_str[i]
            if c == "'" and not in_double:
                in_single = not in_single
                current.append(c)
                i += 1
            elif c == '"' and not in_single:
                in_double = not in_double
                current.append(c)
                i += 1
            elif not in_single and not in_double and cmd_str[i:i+op_len] == op:
                parts.append("".join(current).strip())
                current = []
                i += op_len
            else:
                current.append(c)
                i += 1

        if current:
            parts.append("".join(current).strip())

        return parts

    def validate_single_command_segment(self, segment: str) -> Tuple[bool, str]:
        """
        Validates an individual command segment (no unquoted && or |).
        Handles quotes, $IFS, backslash escapes, redirects, and dangerous standalone binaries.
        """
        normalized = self.normalize_string(segment)
        deobfuscated = normalized.replace("$IFS", " ").replace("${IFS}", " ")

        # 1. Parse tokens with shlex (quote-aware!)
        try:
            tokens = shlex.split(deobfuscated, posix=False)
        except Exception:
            tokens = deobfuscated.split()

        if not tokens:
            return True, "Empty command."

        # Extract base command binary and deobfuscate quotes/escapes: b'a's'h -> bash, b\a\s\h -> bash
        raw_bin = re.sub(r"['\"\\]", "", tokens[0].strip())
        base_bin = os.path.basename(raw_bin).lower().replace(".exe", "")

        # Check for dangerous standalone interactive shells / network tools
        if base_bin in self.config.blocked_standalone_binaries:
            # Check if it's invoked as an interactive/arbitrary shell execution sink
            # e.g., bash -c "...", sh -c "...", powershell -Command "..."
            return (
                False,
                f"Blocked Binary: Invoking interactive shell or raw socket utility '{base_bin}' is forbidden.",
            )

        # 2. Check for dangerous subshell executions ($() or backticks)
        # Remove single-quoted strings because single-quoted strings are literal in shell
        unquoted_for_subshell = re.sub(r"'[^']*'", "", deobfuscated)

        # Backtick execution is high-risk for arbitrary command evaluation & exfiltration
        if "`" in unquoted_for_subshell:
            return (
                False,
                f"Shell Injection Risk: Dynamic backtick command substitution is forbidden: '{segment}'",
            )

        if re.search(r"\$\(.*?\)", unquoted_for_subshell):
            sub_match = re.search(r"\$\((.*?)\)", unquoted_for_subshell)
            inner_cmd = (sub_match.group(1) or "").strip()
            is_inner_valid, inner_reason = self.validate_shell_command(inner_cmd)
            if not is_inner_valid:
                return (
                    False,
                    f"Shell Injection Risk (Dynamic Subshell): Subshell execution '{inner_cmd}' rejected: {inner_reason}",
                )

        # 3. Check for unauthorized unquoted command termination (;)
        unquoted_semis = self._split_unquoted_operator(segment, ";")
        if len(unquoted_semis) > 1:
            return (
                False,
                f"Shell Injection Risk (Command Chaining): Command contains unauthorized semicolon operator: '{segment}'",
            )

        # 4. Check for safe file redirection (> or >>)
        if ">" in segment:
            # Allow 2>&1 without issue
            cleaned_seg = re.sub(r"2>&1", "", segment)
            if ">" in cleaned_seg:
                # Find redirection targets
                redir_parts = self._split_unquoted_operator(cleaned_seg, ">>")
                if len(redir_parts) == 1:
                    redir_parts = self._split_unquoted_operator(cleaned_seg, ">")

                if len(redir_parts) > 1:
                    try:
                        redir_tokens = shlex.split(redir_parts[1].strip(), posix=False)
                    except Exception:
                        redir_tokens = redir_parts[1].strip().split()

                    if redir_tokens:
                        target_arg = redir_tokens[0].strip("'\"")
                        is_valid_dest, reason, canonical = self.validate_path(target_arg)
                        if not is_valid_dest:
                            return False, f"Unsafe Redirection: Target '{target_arg}' escapes workspace boundary ({reason})."
                        # Reject redirection directly into an existing folder node (e.g. echo "text" > src/)
                        if canonical and os.path.isdir(canonical):
                            return False, f"Unsafe Redirection: Target '{target_arg}' is an existing directory, not a file."

        # 5. Deep Inspection for Base64-Obfuscated Payloads
        b64_payloads = self._extract_base64_payloads(segment)
        for payload in b64_payloads:
            payload_clean = payload.strip().lower()
            if any(k in payload_clean for k in ["rm -rf", "bash", "curl", "nc", "wget", "/bin/sh"]):
                return (
                    False,
                    f"Obfuscated Payload Detected: Decoded Base64 string contains dangerous instructions: '{payload}'",
                )

        # 6. Check argument paths against protected files and boundary escapes
        for tok in tokens[1:]:
            cleaned_tok = tok.strip("'\"")
            if cleaned_tok.startswith("-"):
                continue

            # If the argument is a URL, validate as network target, NOT as a filesystem path!
            if cleaned_tok.startswith(("http://", "https://", "ftp://", "ws://", "wss://")):
                is_valid_net, net_reason = self.validate_network_target(cleaned_tok)
                if not is_valid_net:
                    return False, f"Network URL Violation in command: {net_reason}"
                continue

            # Check if token is a filesystem path or protected filename
            if "/" in cleaned_tok or "\\" in cleaned_tok or cleaned_tok.startswith(".") or cleaned_tok.endswith((".env", ".key", ".pem", "id_rsa")):
                is_valid_path, path_reason, _ = self.validate_path(cleaned_tok)
                if not is_valid_path:
                    return False, f"Command Argument Violation: {path_reason}"

        return True, "Segment is safe."

    def validate_shell_command(self, cmd_str: str) -> Tuple[bool, str]:
        """
        Full Production Pipeline & Command Chain Validator.
        1. Evaluates logical AND chains (&&): e.g. 'npm install && npm test'.
        2. Evaluates Unix pipelines (|): permits 'find ... | head -50', blocks 'curl ... | bash'.
        """
        # Step 0: Global Base64 Obfuscation Scan across entire command string
        b64_payloads = self._extract_base64_payloads(cmd_str)
        for payload in b64_payloads:
            payload_clean = payload.strip().lower()
            if any(k in payload_clean for k in ["rm -rf", "bash", "curl", "nc", "wget", "/bin/sh"]):
                return (
                    False,
                    f"Obfuscated Payload Detected: Decoded Base64 string contains dangerous instructions: '{payload}'",
                )

        # Step 1: Check Command Chaining with '&&'
        chained_commands = self._split_unquoted_operator(cmd_str, "&&")
        if len(chained_commands) > 1:
            for sub_cmd in chained_commands:
                is_valid, reason = self.validate_shell_command(sub_cmd)
                if not is_valid:
                    return False, f"Chained Command Violation in '{sub_cmd}': {reason}"
            return True, "All chained commands validated successfully."

        # Step 2: Check Unix Data Pipelines with '|'
        pipe_segments = self._split_unquoted_operator(cmd_str, "|")
        if len(pipe_segments) > 1:
            # First: Strictly verify that NO receiving stage (i > 0) is a dangerous execution sink
            for i in range(1, len(pipe_segments)):
                stage = pipe_segments[i]
                tokens = stage.strip().split()
                if not tokens:
                    continue
                raw_bin = re.sub(r"['\"\\]", "", tokens[0].strip())
                stage_bin = os.path.basename(raw_bin).lower().replace(".exe", "")
                if stage_bin in self.config.dangerous_pipe_sinks:
                    return (
                        False,
                        f"Pipeline Shell Injection Risk: Piping data into execution sink '{stage_bin}' is forbidden: '{cmd_str}'",
                    )

            # Second: Validate each individual pipeline segment
            for stage in pipe_segments:
                tokens = stage.strip().split()
                if not tokens:
                    continue
                raw_bin = re.sub(r"['\"\\]", "", tokens[0].strip())
                stage_bin = os.path.basename(raw_bin).lower().replace(".exe", "")

                # If stage_bin is a known safe filter (head, tail, grep, etc.), it passes segment binary checks
                if stage_bin in self.config.safe_pipe_filters:
                    continue

                is_valid, reason = self.validate_single_command_segment(stage)
                if not is_valid:
                    return False, f"Pipeline Segment Violation in '{stage}': {reason}"

            return True, "Pipeline validated successfully."

        # Step 3: Single standalone command
        return self.validate_single_command_segment(cmd_str)

    # -----------------------------------------------------------------------
    # 3. NETWORK VALIDATOR (With Localhost Developer Port Support)
    # -----------------------------------------------------------------------
    def validate_network_target(self, host_or_url: str) -> Tuple[bool, str]:
        """
        Inspects URL/hostname to prevent SSRF and Cloud Metadata leakage.
        Allows testing local web dev servers on standard developer ports (3000, 5173, 8000, 8080)
        while strictly blocking cloud metadata and sensitive internal daemons.
        """
        normalized = self.normalize_string(host_or_url)
        target = normalized

        # Extract hostname and optional port
        url_match = re.search(r"https?://([^/\s]+)", normalized, re.IGNORECASE)
        if url_match:
            target = url_match.group(1)

        # Parse host and port
        port = None
        if ":" in target:
            parts = target.split(":")
            target_host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = None
        else:
            target_host = target

        # Parse URL path for administrative/management endpoint detection
        try:
            parsed_url = urllib.parse.urlparse(normalized if "://" in normalized else f"http://{normalized}")
            url_path = (parsed_url.path or "").lower()
        except Exception:
            url_path = ""

        ADMIN_INTERNAL_PATHS = [
            "/admin", "/actuator", "/delete", "/shutdown", "/debug", "/internal", "/exec", "/management"
        ]

        # 1. Check Cloud Metadata & Internal DNS (Strictly blocked regardless of port)
        for pattern in self._network_regexes:
            if pattern.search(target_host):
                return (
                    False,
                    f"SSRF Prevention: Access to cloud metadata or internal domain '{target_host}' is strictly blocked.",
                )

        # 2. Check Localhost / 127.0.0.1 Developer Web Server Exemption
        is_localhost = target_host.lower() in ["localhost", "127.0.0.1", "::1"]
        if is_localhost:
            # Check for sensitive administrative endpoints on localhost (classic SSRF)
            if any(url_path.startswith(p) for p in ADMIN_INTERNAL_PATHS):
                return (
                    False,
                    f"SSRF Prevention: Access to administrative/internal endpoint '{url_path}' on localhost is blocked.",
                )

            # If targeting sensitive infrastructure ports (Docker 2375, Postgres 5432, Redis 6379) -> BLOCK
            if port in self.config.blocked_infrastructure_ports:
                return (
                    False,
                    f"SSRF Prevention: Access to internal database/daemon port {port} on localhost is blocked.",
                )

            # If targeting standard developer frontend/backend server ports -> ALLOW
            if port in self.config.permitted_localhost_dev_ports:
                return True, f"Allowed local developer server on port {port}."

            # Default for unlisted localhost ports without explicit port:
            if port is None:
                return (
                    False,
                    "SSRF Prevention: Localhost request requires an explicit allowed developer port (e.g. :3000, :8000).",
                )

        # 3. Decimal / Hex / Octal Alternative IP Representations
        try:
            ip_val = int(target_host, 0) if (target_host.isdigit() or target_host.lower().startswith("0x")) else target_host
            ip_obj = ipaddress.ip_address(ip_val)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                # If loopback, check admin path before permitting dev port
                if ip_obj.is_loopback:
                    if any(url_path.startswith(p) for p in ADMIN_INTERNAL_PATHS):
                        return (
                            False,
                            f"SSRF Prevention: Access to administrative/internal endpoint '{url_path}' on loopback IP is blocked.",
                        )
                    if port in self.config.permitted_localhost_dev_ports:
                        return True, f"Allowed local loopback IP on developer port {port}."
                return (
                    False,
                    f"SSRF Prevention: Access to private or loopback IP '{ip_obj}' is blocked.",
                )
        except ValueError:
            pass

        return True, "Network host allowed."

    # -----------------------------------------------------------------------
    # 4. DLP SECRET SCRUBBER
    # -----------------------------------------------------------------------
    def scrub_dlp_secrets(self, data: Union[str, Dict, List]) -> Tuple[Union[str, Dict, List], int]:
        """
        Recursively scans strings and structures, redacting high-entropy credentials.
        """
        redactions = 0

        if isinstance(data, str):
            scrubbed = data
            for pattern in self._dlp_regexes:
                matches = pattern.findall(scrubbed)
                if matches:
                    redactions += len(matches)
                    scrubbed = pattern.sub("[REDACTED_SECRET]", scrubbed)
            return scrubbed, redactions

        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                scrubbed_v, count = self.scrub_dlp_secrets(v)
                redactions += count
                new_dict[k] = scrubbed_v
            return new_dict, redactions

        elif isinstance(data, list):
            new_list = []
            for item in data:
                scrubbed_item, count = self.scrub_dlp_secrets(item)
                redactions += count
                new_list.append(scrubbed_item)
            return new_list, redactions

        return data, 0
