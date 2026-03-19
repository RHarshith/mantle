"""Taint classification rules for mantle taint analysis.

This module defines how sources (tainted origins) and sinks (sensitive
operations) are classified.  The taint engine imports these rules and
applies them during forward propagation.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any


class TaintLabel(Enum):
    """Classification of a data source's trustworthiness."""

    CLEAN = "clean"
    NONDETERMINISTIC = "nondeterministic"
    TAINTED = "tainted"


class TrustPolicy(Enum):
    """User-selectable policy for files not created by the agent."""

    TRUST_EXTERNAL_FILES = "trust"
    NONDETERMINISTIC_EXTERNAL_FILES = "nondeterministic"


# ── Known-safe LLM API hosts ────────────────────────────────────────

LLM_API_HOSTS: set[str] = {
    "api.openai.com",
    "chat-api.tamu.ai",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
    "api.deepseek.com",
}

# ── Sensitive sink path prefixes ─────────────────────────────────────

SENSITIVE_WRITE_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/root/.ssh/",
    "/root/.bashrc",
    "/root/.profile",
    "/usr/local/bin/",
    "/usr/bin/",
    "/var/spool/cron/",
)

# ── Noise filtering ─────────────────────────────────────────────────

_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/usr/lib/",
    "/lib/",
    "/usr/share/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/lib/",
    "/var/cache/",
)

_NOISE_SUBSTRINGS: tuple[str, ...] = (
    ".pyc",
    "__pycache__",
    "site-packages",
    ".venv/",
    "node_modules/",
    ".so",
    ".cache/",
)

# ── MCP detection heuristics ────────────────────────────────────────

_MCP_PATH_PATTERNS: tuple[str, ...] = (
    "/mcp/",
    "/tools/call",
    "/tools/list",
)

_MCP_PORT_RANGE = range(19000, 19100)  # Convention for test MCP servers


# ── Public API ───────────────────────────────────────────────────────


def is_system_path(path: str) -> bool:
    """Return True if *path* is a system/library file (not user-relevant)."""
    if not path or not path.startswith("/"):
        return False
    if any(path.startswith(p) for p in _SYSTEM_PREFIXES):
        return True
    if any(s in path for s in _NOISE_SUBSTRINGS):
        return True
    return False


def classify_network_endpoint(
    dest: str,
    mitm_endpoints: set[str] | None = None,
) -> TaintLabel:
    """Classify a network endpoint.

    Returns CLEAN for known LLM API hosts.  Everything else is TAINTED.
    """
    if not dest or dest.startswith("fd="):
        # Unresolved fd — if we can infer via mitm_endpoints, use those.
        if mitm_endpoints:
            # If all known MITM endpoints are LLM hosts, assume clean.
            hosts = {ep.split(":")[0] for ep in mitm_endpoints}
            if hosts and hosts <= LLM_API_HOSTS:
                return TaintLabel.CLEAN
        return TaintLabel.TAINTED

    host = dest.split(":")[0]
    if host in LLM_API_HOSTS:
        return TaintLabel.CLEAN
    if host in {"127.0.0.1", "localhost", "::1"}:
        # Localhost endpoints may be proxies (mitm) or MCP servers.
        port_str = dest.split(":")[-1] if ":" in dest else ""
        try:
            port = int(port_str)
        except ValueError:
            return TaintLabel.TAINTED
        if port in _MCP_PORT_RANGE:
            return TaintLabel.TAINTED
        # Proxy ports used by mitm are considered clean passthrough.
        if port in {8899, 8898}:
            return TaintLabel.CLEAN
        return TaintLabel.NONDETERMINISTIC
    return TaintLabel.TAINTED


def classify_file_access(
    path: str,
    agent_created_files: set[str],
    trust_policy: TrustPolicy,
) -> TaintLabel:
    """Classify a file read.

    - System/library paths → CLEAN (irrelevant noise).
    - Files the agent created → CLEAN.
    - External files → depends on trust_policy.
    """
    if is_system_path(path):
        return TaintLabel.CLEAN
    if path in agent_created_files:
        return TaintLabel.CLEAN
    if trust_policy == TrustPolicy.TRUST_EXTERNAL_FILES:
        return TaintLabel.CLEAN
    return TaintLabel.NONDETERMINISTIC


def is_sensitive_write_path(path: str) -> bool:
    """Return True if writing to *path* is a security-sensitive operation."""
    return any(path.startswith(p) for p in SENSITIVE_WRITE_PREFIXES)


def is_mcp_endpoint(dest: str) -> bool:
    """Heuristic: return True if *dest* looks like an MCP server."""
    if not dest:
        return False
    if any(pat in dest for pat in _MCP_PATH_PATTERNS):
        return True
    port_str = dest.split(":")[-1] if ":" in dest else ""
    try:
        port = int(port_str)
    except ValueError:
        return False
    return port in _MCP_PORT_RANGE


def extract_file_paths_from_command(command: str) -> list[str]:
    """Extract plausible file paths from a shell command string."""
    paths: list[str] = []
    for token in command.split():
        if token.startswith("/") or token.startswith("./") or token.startswith("../"):
            # Strip trailing shell metacharacters.
            cleaned = token.rstrip(";|&>")
            if cleaned:
                paths.append(cleaned)
    return paths


def is_command_exec_sink(event: dict[str, Any]) -> bool:
    """Return True if *event* represents a command execution sink."""
    payload = event.get("payload", {})
    tool_name = payload.get("tool_name", "")
    return tool_name == "command_exec"


def is_python_exec_sink(event: dict[str, Any]) -> bool:
    """Return True if *event* represents a python execution sink."""
    payload = event.get("payload", {})
    tool_name = payload.get("tool_name", "")
    return tool_name == "python_exec"
