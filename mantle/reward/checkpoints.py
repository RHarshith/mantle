"""Checkpoint predicate library and extraction for guided reward.

Checkpoints are structural BPF predicates extracted from a guide trace.
Each checkpoint represents a significant syscall pattern that the active
trace should also exhibit (e.g. a file was written, a test runner was
executed, a network connection was made).
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Checkpoint:
    """A named predicate over a list of BPF events."""

    name: str
    description: str
    predicate: Callable[[list[dict[str, Any]]], bool]
    satisfied: bool = False


# ── Built-in predicates ──────────────────────────────────────────────


def file_opened_for_write(path_pattern: str) -> Callable[[list[dict]], bool]:
    """Predicate: any openat with O_WRONLY/O_RDWR on a matching path."""

    def _check(events: list[dict[str, Any]]) -> bool:
        for e in events:
            if str(e.get("type") or e.get("event_type") or "") not in {
                "file_open",
                "file_write",
                "openat",
            }:
                continue
            path = str(e.get("path") or "")
            if not path:
                continue
            if fnmatch.fnmatch(os.path.basename(path), path_pattern) or fnmatch.fnmatch(path, path_pattern):
                return True
        return False

    return _check


def file_created(path_pattern: str) -> Callable[[list[dict]], bool]:
    """Predicate: any openat with O_CREAT on a matching path."""

    def _check(events: list[dict[str, Any]]) -> bool:
        for e in events:
            etype = str(e.get("type") or e.get("event_type") or "")
            if etype not in {"file_open", "file_write", "openat"}:
                continue
            path = str(e.get("path") or "")
            if not path:
                continue
            # BPF events may encode flags in payload or label.
            payload = e.get("payload") or {}
            flags = str(payload.get("flags") or e.get("label") or "")
            if "CREAT" not in flags.upper() and "creat" not in flags:
                continue
            if fnmatch.fnmatch(os.path.basename(path), path_pattern) or fnmatch.fnmatch(path, path_pattern):
                return True
        return False

    return _check


def command_executed(cmd_pattern: str) -> Callable[[list[dict]], bool]:
    """Predicate: any execve where the command matches the pattern."""

    def _check(events: list[dict[str, Any]]) -> bool:
        for e in events:
            etype = str(e.get("type") or e.get("event_type") or "")
            if etype not in {"process_exec", "execve", "exec"}:
                continue
            cmd = str(e.get("command") or e.get("exec_path") or "")
            if not cmd:
                continue
            basename = os.path.basename(cmd)
            if fnmatch.fnmatch(basename, cmd_pattern) or fnmatch.fnmatch(cmd, cmd_pattern):
                return True
        return False

    return _check


def command_succeeded(cmd_pattern: str) -> Callable[[list[dict]], bool]:
    """Predicate: an execve matching the pattern followed by exit_code == 0."""

    def _check(events: list[dict[str, Any]]) -> bool:
        # Look for process_exit events with exit_code 0 whose exec_path matches.
        for e in events:
            etype = str(e.get("type") or e.get("event_type") or "")
            if etype not in {"process_exit", "exit_group"}:
                continue
            payload = e.get("payload") or {}
            exit_code = payload.get("exit_code") if isinstance(payload, dict) else None
            if exit_code is None:
                exit_code = e.get("exit_code")
            try:
                if int(exit_code) != 0:
                    continue
            except (TypeError, ValueError):
                continue
            cmd = str(e.get("command") or e.get("exec_path") or "")
            if cmd and (
                fnmatch.fnmatch(os.path.basename(cmd), cmd_pattern)
                or fnmatch.fnmatch(cmd, cmd_pattern)
            ):
                return True
        return False

    return _check


def network_connected(host_pattern: str, port: int | None = None) -> Callable[[list[dict]], bool]:
    """Predicate: a connect syscall to a matching host (and optional port)."""

    def _check(events: list[dict[str, Any]]) -> bool:
        for e in events:
            etype = str(e.get("type") or e.get("event_type") or "")
            if etype not in {"net_connect", "connect"}:
                continue
            dest = str(e.get("dest") or "")
            if not dest:
                continue
            if fnmatch.fnmatch(dest, host_pattern):
                return True
            # Try host:port splitting.
            if ":" in dest:
                host_part, port_part = dest.rsplit(":", 1)
                if fnmatch.fnmatch(host_part, host_pattern):
                    if port is None or port_part == str(port):
                        return True
        return False

    return _check


# ── Checkpoint extraction from guide trace ───────────────────────────

# Well-known test runner basenames.
_TEST_RUNNERS = {"pytest", "python", "node", "npm", "npx", "jest", "mocha", "cargo", "go", "make"}

# Path prefixes to ignore during checkpoint extraction.
_NOISE_PREFIXES = (
    "/usr/", "/lib/", "/etc/", "/proc/", "/sys/", "/dev/", "/run/",
    "/var/lib/", "/var/cache/", "/tmp/",
)
_NOISE_SUFFIXES = (".pyc", ".so", ".o", "__pycache__")


def _is_noisy_path(path: str) -> bool:
    """Return True if a path is unlikely to be user-relevant."""
    if not path:
        return True
    for pfx in _NOISE_PREFIXES:
        if path.startswith(pfx):
            return True
    for sfx in _NOISE_SUFFIXES:
        if path.endswith(sfx):
            return True
    return False


def extract_checkpoints(guide_events: list[dict[str, Any]]) -> list[Checkpoint]:
    """Derive structural checkpoints from a guide trace's BPF events.

    Algorithm:
    1. Scan events in order.
    2. For file writes/creates on user-relevant paths → file_opened_for_write checkpoint.
    3. For execve of known commands → command_executed checkpoint.
    4. For connect syscalls → network_connected checkpoint.
    5. Deduplicate by (type, pattern).
    """
    seen: set[tuple[str, str]] = set()
    checkpoints: list[Checkpoint] = []

    for event in guide_events:
        etype = str(event.get("type") or event.get("event_type") or "")
        path = str(event.get("path") or "")

        # File writes.
        if etype in {"file_open", "file_write", "openat"} and path and not _is_noisy_path(path):
            basename = os.path.basename(path)
            key = ("file_write", basename)
            if key not in seen:
                seen.add(key)
                checkpoints.append(
                    Checkpoint(
                        name=f"file_modified:{basename}",
                        description=f"File '{basename}' should be opened for writing",
                        predicate=file_opened_for_write(basename),
                    )
                )

        # Command execution.
        if etype in {"process_exec", "execve", "exec"}:
            cmd = str(event.get("command") or event.get("exec_path") or "")
            if cmd:
                cmd_basename = os.path.basename(cmd)
                key = ("exec", cmd_basename)
                if key not in seen:
                    seen.add(key)
                    checkpoints.append(
                        Checkpoint(
                            name=f"command_executed:{cmd_basename}",
                            description=f"Command '{cmd_basename}' should be executed",
                            predicate=command_executed(cmd_basename),
                        )
                    )

        # Network connections.
        if etype in {"net_connect", "connect"}:
            dest = str(event.get("dest") or "")
            if dest and not dest.startswith("fd="):
                key = ("connect", dest)
                if key not in seen:
                    seen.add(key)
                    checkpoints.append(
                        Checkpoint(
                            name=f"network_connected:{dest}",
                            description=f"Network connection to '{dest}' should occur",
                            predicate=network_connected(dest),
                        )
                    )

    return checkpoints
