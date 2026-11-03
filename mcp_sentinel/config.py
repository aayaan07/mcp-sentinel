"""
MCP-Sentinel Production Configuration.
Distinguishes real developer workflows from malicious attacks.
"""

import os
import re
from typing import List, Set
from pydantic import BaseModel, Field

from mcp_sentinel.models import SecurityLevel


class SentinelConfig(BaseModel):
    # Server / Session Identity
    server_name: str = "default-mcp-server"
    security_level: SecurityLevel = SecurityLevel.L2_READ_ONLY
    
    # Workspace & Path Boundaries (Least Privilege)
    allowed_workspaces: List[str] = Field(default_factory=lambda: [os.path.realpath(os.getcwd())])
    quarantine_dir_name: str = ".sentinel_trash"
    
    # Critical Protected Files (Strict regex - allows .env.example, .env.sample, .env.template)
    protected_patterns: List[str] = Field(
        default_factory=lambda: [
            r".*(^|/)(\.env|\.env\.local|\.env\.production|\.env\.staging|\.env\.secret)$",
            r".*(^|/)(id_rsa|id_dsa|id_ed25519)$",
            r".*(^|/)authorized_keys$",
            r".*\.(pem|key)$",
            r".*\.git/(?!config\.sample).*$",
            r".*\.aws/(credentials|config)$",
            r".*\.ssh/(id_.*|config|known_hosts)$",
            r".*(^|/)(/etc/shadow|/etc/sudoers|/etc/master\.passwd)$",
            r".*(^|/)(NTUSER\.DAT|SAM|SYSTEM)$",
        ]
    )

    # Safe Template & Example Files (Always permitted even if named .env.*)
    safe_template_patterns: List[str] = Field(
        default_factory=lambda: [
            r".*\.env\.example$",
            r".*\.env\.sample$",
            r".*\.env\.template$",
            r".*\.env\.dist$",
            r".*\.sample$",
            r".*\.example$",
        ]
    )

    # Temporary / Cache Files (Safe for autonomous deletion/re-creation)
    temporary_patterns: List[str] = Field(
        default_factory=lambda: [
            r".*\.tmp$",
            r".*\.cache$",
            r".*\.log$",
            r".*__pycache__/.*",
            r".*(\.pytest_cache|\.mypy_cache|\.ruff_cache)/.*",
            r".*(dist|build|\.next|\.nuxt|out)/.*",
            r".*node_modules/\.cache/.*",
        ]
    )
    
    # Safe Stream Pipe Filter Binaries (Allowed in pipelines e.g. find ... | head -50)
    safe_pipe_filters: Set[str] = Field(
        default_factory=lambda: {
            "head", "tail", "grep", "rg", "findstr", "wc", "sort", "uniq",
            "awk", "cut", "sed", "tee", "tr", "fold", "column", "jq", "fmt"
        }
    )

    # Dangerous Pipe Sinks (Strictly blocked as targets of pipes e.g. ... | bash, ... | nc)
    dangerous_pipe_sinks: Set[str] = Field(
        default_factory=lambda: {
            "bash", "sh", "zsh", "powershell", "cmd", "pwsh", "csh", "tcsh",
            "nc", "netcat", "curl", "wget", "socat", "telnet", "python", "perl", "ruby", "node"
        }
    )

    # Blocked Interactive Shell Binaries when called directly as execution targets
    blocked_standalone_binaries: Set[str] = Field(
        default_factory=lambda: {
            "bash", "sh", "powershell", "cmd", "zsh", "pwsh", "nc", "netcat", "socat"
        }
    )

    # Permitted Developer Localhost Ports for Web App Testing (Vite, React, Next, FastAPI, Flask)
    permitted_localhost_dev_ports: Set[int] = Field(
        default_factory=lambda: {
            3000, 3001, 4200, 5000, 5173, 5174, 8000, 8080, 8888, 9000
        }
    )

    # Strictly Blocked Infrastructure Ports on Localhost (Database / Daemons / Sockets)
    blocked_infrastructure_ports: Set[int] = Field(
        default_factory=lambda: {
            2375, 2376, # Docker daemon
            5432,       # PostgreSQL
            3306,       # MySQL
            6379,       # Redis
            27017,      # MongoDB
            9200,       # Elasticsearch
            8500,       # Consul
            8200,       # HashiCorp Vault
            22,         # SSH
        }
    )
    
    # Strictly Blocked Cloud Metadata & Private Network Targets
    blocked_network_hosts: List[str] = Field(
        default_factory=lambda: [
            r"^169\.254\.169\.254$",            # AWS/Azure/GCP Metadata IP
            r".*metadata\.google\.internal.*",  # GCP Metadata DNS
            r".*\.internal$",                   # Internal private cloud domains
            r".*\.local$",                      # mDNS local resolution
            r"^0\.0\.0\.0$",
        ]
    )
    
    # DLP & Secret Redaction (Data Loss Prevention)
    dlp_patterns: List[str] = Field(
        default_factory=lambda: [
            r"sk-[a-zA-Z0-9_\-]{20,}",                  # OpenAI / Anthropic / AI API keys
            r"AKIA[0-9A-Z]{16}",                        # AWS Access Key ID
            r"ghp_[a-zA-Z0-9]{30,40}",                  # GitHub Personal Access Token
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",      # RSA / OpenSSH Private Keys
            r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}",          # Bearer JWT / Tokens
        ]
    )

    # Operational Parameters
    rate_limit_mutations_per_turn: int = 10
    interactive_approvals: bool = False
    
    def get_canonical_workspaces(self) -> List[str]:
        return [os.path.realpath(w) for w in self.allowed_workspaces]
    
    def get_quarantine_path(self, workspace_index: int = 0) -> str:
        base = self.get_canonical_workspaces()[workspace_index]
        quarantine = os.path.join(base, self.quarantine_dir_name)
        os.makedirs(quarantine, exist_ok=True)
        return quarantine
