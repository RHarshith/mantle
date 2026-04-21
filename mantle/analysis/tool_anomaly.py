"""Rule-based anomaly detection for tool-call side effects."""

from __future__ import annotations

import os
import re
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

SCOPE_HIGH_LABELS = {"SSH_DIR", "CLOUD_CREDS", "GPG_DIR", "SHELL_HISTORY", "SYSTEM_AUTH"}

SCOPE_ALLOWED_LABELS: dict[str, set[str]] = {
    "npm": {"PROJECT", "TEMP", "NPM_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "npx": {"PROJECT", "TEMP", "NPM_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "node": {"PROJECT", "TEMP", "NPM_CACHE", "SYSTEM_LIB", "SYSTEM_BIN"},
    "python": {"PROJECT", "TEMP", "PY_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CONFIG"},
    "python3": {"PROJECT", "TEMP", "PY_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CONFIG"},
    "pip": {"PROJECT", "TEMP", "PY_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "pip3": {"PROJECT", "TEMP", "PY_CACHE", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "git": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CONFIG", "HOME"},
    "cargo": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "make": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "gcc": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "clang": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "cc": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "go": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN", "USER_CACHE"},
    "cat": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "grep": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "sed": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "awk": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "find": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "ls": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "cp": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "mv": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "rm": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "curl": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "wget": {"PROJECT", "TEMP", "SYSTEM_LIB", "SYSTEM_BIN"},
    "bash": {"*"},
    "sh": {"*"},
    "zsh": {"*"},
}

MUST_NOT_NETWORK = {
    "cat",
    "grep",
    "sed",
    "awk",
    "find",
    "ls",
    "cp",
    "mv",
    "rm",
    "make",
    "gcc",
    "clang",
    "cc",
    "tar",
    "unzip",
    "zip",
    "diff",
    "patch",
    "echo",
    "touch",
    "mkdir",
    "chmod",
    "chown",
}

SHOULD_NETWORK = {
    "npm",
    "npx",
    "pip",
    "pip3",
    "curl",
    "wget",
    "git",
    "cargo",
    "go",
    "apt",
    "apt-get",
    "brew",
    "yarn",
    "pnpm",
}

MAY_NETWORK = {
    "node",
    "python",
    "python3",
    "bash",
    "sh",
    "zsh",
    "ruby",
    "java",
    "php",
}

SPAWN_ALLOWED: dict[str, set[str]] = {
    "npm": {"node", "sh", "bash", "git", "npx", "npm", "esbuild", "tsc", "webpack", "vite", "rollup", "jest", "eslint", "prettier"},
    "npx": {"node", "sh", "bash", "npm"},
    "node": {"sh", "bash", "node"},
    "pip": {"python", "python3", "sh", "bash"},
    "pip3": {"python", "python3", "sh", "bash"},
    "python": {"python", "python3", "sh", "bash"},
    "python3": {"python", "python3", "sh", "bash"},
    "git": {"sh", "bash", "ssh", "gpg", "diff", "less", "vi", "vim", "editor", "git", "git-lfs"},
    "make": {"sh", "bash", "gcc", "clang", "cc", "ld", "ar", "as", "python", "python3", "node", "go", "cargo", "cmake", "ninja"},
    "gcc": {"as", "ld", "cc1", "collect2"},
    "clang": {"as", "ld", "cc1", "collect2"},
    "cc": {"as", "ld", "cc1", "collect2"},
    "cargo": {"rustc", "sh", "bash", "cc", "gcc", "clang", "ar", "linker", "lld"},
    "go": {"sh", "bash", "gcc", "clang", "cc"},
    "bash": {"*"},
    "sh": {"*"},
    "zsh": {"*"},
    "curl": set(),
    "wget": set(),
}

DANGEROUS_CHILDREN = {"nc", "ncat", "netcat", "socat", "curl", "wget", "scp", "rsync"}
DANGEROUS_BUILD_INTERPRETERS = {"python", "python3", "ruby", "perl", "php"}
BUILD_PARENTS = {"make", "npm", "npx", "cargo", "go", "gcc", "clang", "cc"}
SHELL_BINARIES = {"bash", "sh", "zsh", "dash"}


class ToolAnomalyDetector:
    """Evaluate syscall-derived side effects for one tool invocation."""

    def __init__(self, *, skip_unknown_network_binaries: bool = True) -> None:
        self.skip_unknown_network_binaries = bool(skip_unknown_network_binaries)

    def verified_report(self, command: str, root_pid: int | None = None) -> dict[str, Any]:
        return {
            "command": str(command or "").strip(),
            "root_pid": int(root_pid or 0),
            "verdict": "CLEAN",
            "verdict_logic": {
                "CLEAN": "no violations across all rule classes",
                "SUSPICIOUS": "only LOW severity violations present",
                "VIOLATION": "at least one MEDIUM or HIGH severity violation",
            },
            "violations": [],
            "summary": "verified tool call",
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "has_anomaly": False,
            "unsupported_checks": [
                "sensitive_env_var_reads_not_captured",
                "chmod_chown_outside_scope_not_captured",
            ],
        }

    def analyze(
        self,
        command_string: str,
        process_events: list[dict[str, Any]],
        process_parent: dict[int, int],
        *,
        root_pid: int | None = None,
        project_root: Path | None = None,
    ) -> dict[str, Any]:
        ordered_events = sorted(process_events or [], key=lambda e: int(e.get("line_no", 0)))
        if not ordered_events:
            return self.verified_report(command_string, root_pid=root_pid)

        proc_map, child_map = self._build_process_map(ordered_events, process_parent)
        resolved_root_pid = self._resolve_root_pid(ordered_events, root_pid)
        root_binary = self._root_binary(command_string, proc_map.get(resolved_root_pid))

        violations: list[dict[str, Any]] = []
        violations.extend(self._check_sensitive_access(proc_map, project_root))
        violations.extend(self._check_unexpected_spawning(proc_map, child_map, resolved_root_pid, root_binary))
        violations.extend(self._check_scope_violations(proc_map, child_map, resolved_root_pid, root_binary, project_root))
        violations.extend(self._check_unexpected_network(proc_map))

        violations = self._apply_severity_escalation(violations)

        if not violations:
            return self.verified_report(command_string, root_pid=resolved_root_pid)

        severity_counts = Counter(str(v.get("severity") or "LOW") for v in violations)
        if any(SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER["MEDIUM"] for sev in severity_counts):
            verdict = "VIOLATION"
        else:
            verdict = "SUSPICIOUS"

        return {
            "command": str(command_string or "").strip(),
            "root_pid": int(resolved_root_pid or 0),
            "verdict": verdict,
            "verdict_logic": {
                "CLEAN": "no violations across all rule classes",
                "SUSPICIOUS": "only LOW severity violations present",
                "VIOLATION": "at least one MEDIUM or HIGH severity violation",
            },
            "violations": violations,
            "summary": self._summary(command_string, violations),
            "severity_counts": {
                "LOW": int(severity_counts.get("LOW", 0)),
                "MEDIUM": int(severity_counts.get("MEDIUM", 0)),
                "HIGH": int(severity_counts.get("HIGH", 0)),
            },
            "has_anomaly": True,
            "unsupported_checks": [
                "sensitive_env_var_reads_not_captured",
                "chmod_chown_outside_scope_not_captured",
            ],
        }

    def _build_process_map(
        self,
        events: list[dict[str, Any]],
        process_parent: dict[int, int],
    ) -> tuple[dict[int, dict[str, Any]], dict[int, set[int]]]:
        proc_map: dict[int, dict[str, Any]] = {}
        child_map: dict[int, set[int]] = defaultdict(set)

        def _ensure_process(pid: int) -> dict[str, Any]:
            bucket = proc_map.get(pid)
            if bucket is not None:
                return bucket
            bucket = {
                "pid": pid,
                "ppid": int(process_parent.get(pid, 0)),
                "binary": "",
                "argv": [],
                "file_events": [],
                "network_events": [],
            }
            proc_map[pid] = bucket
            return bucket

        for event in events:
            pid = int(event.get("pid") or 0)
            if pid <= 0:
                continue
            proc = _ensure_process(pid)
            et = str(event.get("type") or "")

            if et == "command_exec":
                exec_path = str(event.get("exec_path") or "").strip()
                argv = [str(a) for a in (event.get("argv") or []) if str(a).strip()]
                ppid = int(event.get("ppid") or proc.get("ppid") or 0)
                proc["ppid"] = ppid
                proc["binary"] = self._binary_name(exec_path, argv)
                proc["argv"] = argv
                if exec_path:
                    proc["file_events"].append({"path": exec_path, "operation": "exec"})
                if ppid > 0 and ppid != pid:
                    _ensure_process(ppid)
                    child_map[ppid].add(pid)
                continue

            if et == "process_spawn":
                parent_pid = int(event.get("pid") or 0)
                child_pid = int(event.get("child_pid") or 0)
                if parent_pid > 0 and child_pid > 0 and parent_pid != child_pid:
                    _ensure_process(parent_pid)
                    child_proc = _ensure_process(child_pid)
                    child_proc["ppid"] = int(child_proc.get("ppid") or parent_pid)
                    child_map[parent_pid].add(child_pid)
                continue

            if et in {"file_read", "file_write", "file_delete", "file_rename"}:
                op = {
                    "file_read": "read",
                    "file_write": "write",
                    "file_delete": "unlink",
                    "file_rename": "rename",
                }.get(et, "read")
                path = str(event.get("path") or "").strip()
                if path:
                    proc["file_events"].append({"path": path, "operation": op})
                src = str(event.get("src") or "").strip()
                if src:
                    proc["file_events"].append({"path": src, "operation": "rename_src"})
                continue

            if et in {"net_connect", "net_send", "net_recv"}:
                direction = "inbound" if et == "net_recv" else "outbound"
                dest_host, dest_port = self._parse_dest(str(event.get("dest") or ""))
                proc["network_events"].append(
                    {
                        "direction": direction,
                        "dest_ip": dest_host,
                        "dest_port": dest_port,
                        "protocol": str(event.get("transport") or "").lower() or "tcp",
                        "raw_dest": str(event.get("dest") or ""),
                    }
                )
                continue

            ppid = int(event.get("ppid") or 0)
            if ppid > 0 and ppid != pid:
                proc["ppid"] = ppid
                _ensure_process(ppid)
                child_map[ppid].add(pid)

        for pid, proc in proc_map.items():
            ppid = int(proc.get("ppid") or process_parent.get(pid, 0) or 0)
            if ppid > 0 and ppid != pid:
                child_map[ppid].add(pid)
                _ensure_process(ppid)

        return proc_map, child_map

    def _resolve_root_pid(self, events: list[dict[str, Any]], root_pid: int | None) -> int:
        candidate = int(root_pid or 0)
        if candidate > 0:
            return candidate
        for event in events:
            if str(event.get("type") or "") == "command_exec":
                pid = int(event.get("pid") or 0)
                if pid > 0:
                    return pid
        for event in events:
            pid = int(event.get("pid") or 0)
            if pid > 0:
                return pid
        return 0

    def _root_binary(self, command_string: str, root_proc: dict[str, Any] | None) -> str:
        command_binary = self._command_binary(command_string)
        if command_binary:
            return command_binary
        if root_proc and str(root_proc.get("binary") or "").strip():
            return str(root_proc.get("binary") or "").strip().lower()
        return ""

    def _command_binary(self, command_string: str) -> str:
        text = str(command_string or "").strip()
        if not text:
            return ""
        try:
            parts = shlex.split(text)
        except Exception:
            parts = text.split()
        if not parts:
            return ""
        return Path(parts[0]).name.lower()

    def _binary_name(self, exec_path: str, argv: list[str]) -> str:
        if exec_path:
            return Path(exec_path).name.lower()
        if argv:
            return Path(str(argv[0])).name.lower()
        return ""

    def _check_scope_violations(
        self,
        proc_map: dict[int, dict[str, Any]],
        child_map: dict[int, set[int]],
        root_pid: int,
        root_binary: str,
        project_root: Path | None,
    ) -> list[dict[str, Any]]:
        if not root_binary:
            return []

        root_groups: list[tuple[str, set[int]]] = []
        if root_binary in SHELL_BINARIES and root_pid > 0:
            for child_pid in sorted(child_map.get(root_pid, set())):
                child = proc_map.get(child_pid)
                if not child:
                    continue
                child_binary = str(child.get("binary") or "").strip().lower()
                if not child_binary:
                    continue
                root_groups.append((child_binary, self._descendants(child_map, child_pid)))
        else:
            root_groups.append((root_binary, self._descendants(child_map, root_pid)))

        violations: list[dict[str, Any]] = []
        for group_binary, pid_scope in root_groups:
            allowed = SCOPE_ALLOWED_LABELS.get(group_binary)
            if not allowed:
                continue
            if "*" in allowed:
                continue

            for pid in sorted(pid_scope):
                proc = proc_map.get(pid)
                if not proc:
                    continue
                process_binary = str(proc.get("binary") or "unknown")
                for file_event in proc.get("file_events") or []:
                    path = str(file_event.get("path") or "").strip()
                    if not path:
                        continue
                    label = self._canonicalize(path, project_root)
                    if label in allowed:
                        continue
                    severity = "HIGH" if label in SCOPE_HIGH_LABELS else "MEDIUM"
                    violations.append(
                        {
                            "rule": "SCOPE_VIOLATION",
                            "severity": severity,
                            "process_binary": process_binary,
                            "pid": int(pid),
                            "path": path,
                            "canonical_label": label,
                            "operation": str(file_event.get("operation") or "read"),
                        }
                    )

        return violations

    def _check_unexpected_network(self, proc_map: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
        violations: list[dict[str, Any]] = []
        for pid, proc in sorted(proc_map.items(), key=lambda item: item[0]):
            binary = str(proc.get("binary") or "").strip().lower()
            if not binary:
                continue
            for event in proc.get("network_events") or []:
                if str(event.get("direction") or "") != "outbound":
                    continue

                reason = ""
                severity = ""
                if binary in SHOULD_NETWORK:
                    continue
                if binary in MUST_NOT_NETWORK:
                    reason = "binary is in MUST_NOT_NETWORK class"
                    severity = "HIGH"
                elif binary in MAY_NETWORK:
                    reason = "binary is in MAY_NETWORK class"
                    severity = "LOW"
                elif self.skip_unknown_network_binaries:
                    continue
                else:
                    reason = "binary is in MAY_NETWORK class"
                    severity = "LOW"

                violations.append(
                    {
                        "rule": "UNEXPECTED_NETWORK",
                        "severity": severity,
                        "process_binary": binary,
                        "pid": int(pid),
                        "dest_ip": str(event.get("dest_ip") or ""),
                        "dest_port": int(event.get("dest_port") or 0),
                        "reason": reason,
                    }
                )
        return violations

    def _check_unexpected_spawning(
        self,
        proc_map: dict[int, dict[str, Any]],
        child_map: dict[int, set[int]],
        root_pid: int,
        root_binary: str,
    ) -> list[dict[str, Any]]:
        edges: set[tuple[int, int]] = set()
        for parent_pid, children in child_map.items():
            for child_pid in children:
                if parent_pid > 0 and child_pid > 0 and parent_pid != child_pid:
                    edges.add((int(parent_pid), int(child_pid)))

        violations: list[dict[str, Any]] = []
        for parent_pid, child_pid in sorted(edges):
            if root_binary in SHELL_BINARIES and parent_pid == root_pid:
                # Shell roots are treated as wrappers; evaluate descendants instead.
                continue

            parent_bin = str((proc_map.get(parent_pid) or {}).get("binary") or "").strip().lower()
            child = proc_map.get(child_pid) or {}
            child_bin = str(child.get("binary") or "unknown").strip().lower()
            child_argv = [str(a) for a in (child.get("argv") or [])]

            if not parent_bin:
                continue
            allowed_children = SPAWN_ALLOWED.get(parent_bin)
            if allowed_children is None:
                continue
            if "*" in allowed_children:
                continue

            allowed = child_bin in allowed_children
            dangerous_argv = self._dangerous_child_argv(child_bin, child_argv)
            if allowed and not dangerous_argv:
                continue

            severity = "MEDIUM"
            if dangerous_argv or self._is_dangerous_spawn(parent_bin, child_bin):
                severity = "HIGH"

            violations.append(
                {
                    "rule": "UNEXPECTED_SPAWN",
                    "severity": severity,
                    "parent_binary": parent_bin,
                    "parent_pid": int(parent_pid),
                    "child_binary": child_bin,
                    "child_pid": int(child_pid),
                    "child_argv": child_argv,
                }
            )

        return violations

    def _check_sensitive_access(
        self,
        proc_map: dict[int, dict[str, Any]],
        project_root: Path | None,
    ) -> list[dict[str, Any]]:
        violations: list[dict[str, Any]] = []
        for pid, proc in sorted(proc_map.items(), key=lambda item: item[0]):
            process_binary = str(proc.get("binary") or "unknown")
            for file_event in proc.get("file_events") or []:
                path = str(file_event.get("path") or "").strip()
                if not path:
                    continue
                operation = str(file_event.get("operation") or "read")
                label = self._canonicalize(path, project_root)

                if label in {"SSH_DIR", "CLOUD_CREDS", "GPG_DIR", "SYSTEM_AUTH"}:
                    violations.append(
                        {
                            "rule": "SENSITIVE_ACCESS",
                            "severity": "HIGH",
                            "process_binary": process_binary,
                            "pid": int(pid),
                            "access_type": "file",
                            "resource": path,
                            "operation": operation,
                        }
                    )
                    continue

                if label == "SHELL_HISTORY" and operation in {"write", "unlink", "rename", "rename_src"}:
                    violations.append(
                        {
                            "rule": "SENSITIVE_ACCESS",
                            "severity": "HIGH",
                            "process_binary": process_binary,
                            "pid": int(pid),
                            "access_type": "file",
                            "resource": path,
                            "operation": operation,
                        }
                    )
                    continue

                if label == "SYSTEM_CONFIG" and operation in {"write", "unlink", "rename", "rename_src"}:
                    violations.append(
                        {
                            "rule": "SENSITIVE_ACCESS",
                            "severity": "MEDIUM",
                            "process_binary": process_binary,
                            "pid": int(pid),
                            "access_type": "file",
                            "resource": path,
                            "operation": operation,
                        }
                    )
                    continue

                if label == "SYSTEM_BIN" and operation == "write":
                    violations.append(
                        {
                            "rule": "SENSITIVE_ACCESS",
                            "severity": "MEDIUM",
                            "process_binary": process_binary,
                            "pid": int(pid),
                            "access_type": "file",
                            "resource": path,
                            "operation": operation,
                        }
                    )

        return violations

    def _canonicalize(self, path: str, project_root: Path | None) -> str:
        raw = str(path or "").strip()
        if not raw:
            return "OTHER"

        home = str(Path.home())
        expanded = os.path.expanduser(raw)
        if not os.path.isabs(expanded) and project_root is not None:
            expanded = os.path.join(str(project_root), expanded)
        expanded = os.path.normpath(expanded)

        if project_root is not None and self._is_subpath(expanded, str(project_root)):
            return "PROJECT"

        if expanded == "/tmp" or expanded.startswith("/tmp/") or expanded == "/var/tmp" or expanded.startswith("/var/tmp/"):
            return "TEMP"

        if expanded.startswith("/usr/lib/") or expanded.startswith("/usr/share/") or expanded.startswith("/lib/"):
            return "SYSTEM_LIB"

        if expanded.startswith("/usr/bin/") or expanded.startswith("/usr/local/bin/") or expanded.startswith("/bin/"):
            return "SYSTEM_BIN"

        if self._is_subpath(expanded, os.path.join(home, ".npm")) or self._is_subpath(expanded, os.path.join(home, ".cache", "npm")):
            return "NPM_CACHE"

        if self._is_subpath(expanded, os.path.join(home, ".cache", "pip")):
            return "PY_CACHE"
        if re.match(rf"^{re.escape(os.path.join(home, '.local', 'lib'))}/python[^/]+/", expanded):
            return "PY_CACHE"

        if self._is_subpath(expanded, os.path.join(home, ".cache")):
            return "USER_CACHE"

        if self._is_subpath(expanded, os.path.join(home, ".config")):
            return "USER_CONFIG"

        if self._is_subpath(expanded, os.path.join(home, ".ssh")):
            return "SSH_DIR"

        if self._is_subpath(expanded, os.path.join(home, ".aws")) or self._is_subpath(expanded, os.path.join(home, ".gcp")) or self._is_subpath(expanded, os.path.join(home, ".azure")):
            return "CLOUD_CREDS"

        if self._is_subpath(expanded, os.path.join(home, ".gnupg")):
            return "GPG_DIR"

        shell_history = {
            os.path.join(home, ".bash_history"),
            os.path.join(home, ".zsh_history"),
            os.path.join(home, ".sh_history"),
        }
        if expanded in shell_history:
            return "SHELL_HISTORY"

        if expanded in {"/etc/passwd", "/etc/shadow"} or expanded.startswith("/etc/sudoers"):
            return "SYSTEM_AUTH"

        if expanded == "/etc" or expanded.startswith("/etc/"):
            return "SYSTEM_CONFIG"

        if expanded == "/proc" or expanded.startswith("/proc/"):
            return "PROC_FS"

        if expanded == "/dev" or expanded.startswith("/dev/"):
            return "DEV_FS"

        if self._is_subpath(expanded, home):
            return "HOME"

        return "OTHER"

    def _is_subpath(self, child: str, parent: str) -> bool:
        try:
            return os.path.commonpath([os.path.normpath(child), os.path.normpath(parent)]) == os.path.normpath(parent)
        except Exception:
            return False

    def _descendants(self, child_map: dict[int, set[int]], start_pid: int) -> set[int]:
        if start_pid <= 0:
            return set()
        out: set[int] = set()
        stack = [int(start_pid)]
        while stack:
            current = stack.pop()
            if current in out:
                continue
            out.add(current)
            for child in child_map.get(current, set()):
                if child not in out:
                    stack.append(int(child))
        return out

    def _parse_dest(self, raw_dest: str) -> tuple[str, int]:
        text = str(raw_dest or "").strip()
        if not text:
            return ("", 0)
        if text.startswith("[") and "]" in text:
            host, _, rest = text.partition("]")
            host = host.lstrip("[")
            if rest.startswith(":"):
                port_text = rest[1:]
                return (host, int(port_text) if port_text.isdigit() else 0)
            return (host, 0)
        host, sep, port_text = text.rpartition(":")
        if sep and port_text.isdigit() and host:
            return (host, int(port_text))
        return (text, 0)

    def _dangerous_child_argv(self, child_binary: str, argv: list[str]) -> bool:
        if child_binary not in SHELL_BINARIES:
            return False
        text = " ".join(argv).lower()
        if not text:
            return False
        return bool(re.search(r"\b(curl|wget|nc|ncat|netcat|socat|scp|rsync|ssh)\b", text))

    def _is_dangerous_spawn(self, parent_binary: str, child_binary: str) -> bool:
        if child_binary in DANGEROUS_CHILDREN:
            return True
        if child_binary == "ssh" and parent_binary != "git":
            return True
        if parent_binary in BUILD_PARENTS and child_binary in DANGEROUS_BUILD_INTERPRETERS:
            return True
        return False

    def _apply_severity_escalation(self, violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not violations:
            return []

        resource_to_rules: dict[str, set[str]] = defaultdict(set)
        for violation in violations:
            resource = self._resource_key(violation)
            if resource:
                resource_to_rules[resource].add(str(violation.get("rule") or ""))

        out: list[dict[str, Any]] = []
        for violation in violations:
            item = dict(violation)
            resource = self._resource_key(item)
            if resource and len(resource_to_rules.get(resource, set())) >= 2:
                item["severity"] = self._escalate_once(str(item.get("severity") or "LOW"))
            out.append(item)

        out.sort(key=lambda v: (-SEVERITY_ORDER.get(str(v.get("severity") or "LOW"), 0), str(v.get("rule") or "")))
        return out

    def _resource_key(self, violation: dict[str, Any]) -> str:
        rule = str(violation.get("rule") or "")
        if rule == "SCOPE_VIOLATION":
            return str(violation.get("path") or "")
        if rule == "SENSITIVE_ACCESS":
            return str(violation.get("resource") or "")
        if rule == "UNEXPECTED_NETWORK":
            host = str(violation.get("dest_ip") or "")
            port = str(violation.get("dest_port") or "")
            return f"{host}:{port}".strip(":")
        if rule == "UNEXPECTED_SPAWN":
            parent = str(violation.get("parent_pid") or "")
            child = str(violation.get("child_pid") or "")
            return f"{parent}->{child}" if parent or child else ""
        return ""

    def _escalate_once(self, severity: str) -> str:
        level = str(severity or "LOW").upper()
        if level == "LOW":
            return "MEDIUM"
        if level == "MEDIUM":
            return "HIGH"
        return "HIGH"

    def _summary(self, command_string: str, violations: list[dict[str, Any]]) -> str:
        if not violations:
            return "verified tool call"

        cmd = str(command_string or "tool call").strip() or "tool call"
        top = violations[0]
        rule = str(top.get("rule") or "")
        if rule == "SCOPE_VIOLATION":
            return f"{cmd} accessed {top.get('path') or 'a path'} outside expected scope"
        if rule == "UNEXPECTED_NETWORK":
            return f"{cmd} made unexpected outbound network activity to {top.get('dest_ip') or 'unknown'}:{top.get('dest_port') or 0}"
        if rule == "UNEXPECTED_SPAWN":
            return f"{cmd} spawned unexpected child process {top.get('child_binary') or 'unknown'}"
        if rule == "SENSITIVE_ACCESS":
            return f"{cmd} accessed sensitive resource {top.get('resource') or 'unknown'}"
        return f"{cmd} triggered anomaly checks"


def aggregate_tool_anomaly_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [r for r in reports if isinstance(r, dict)]
    if not valid:
        return {
            "verdict": "CLEAN",
            "has_anomaly": False,
            "summary": "verified tool call",
            "total_violations": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        }

    severity_counts = Counter()
    total_violations = 0
    for report in valid:
        violations = report.get("violations") if isinstance(report.get("violations"), list) else []
        total_violations += len(violations)
        for violation in violations:
            severity_counts[str(violation.get("severity") or "LOW").upper()] += 1

    verdict = "CLEAN"
    if severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) > 0:
        verdict = "VIOLATION"
    elif severity_counts.get("LOW", 0) > 0:
        verdict = "SUSPICIOUS"

    summary = "verified tool call"
    if verdict != "CLEAN":
        first = next((r for r in valid if isinstance(r.get("summary"), str) and str(r.get("summary")) and str(r.get("summary")) != "verified tool call"), None)
        if first is not None:
            summary = str(first.get("summary") or summary)
        else:
            summary = "anomaly detected"

    return {
        "verdict": verdict,
        "has_anomaly": verdict != "CLEAN",
        "summary": summary,
        "total_violations": int(total_violations),
        "severity_counts": {
            "LOW": int(severity_counts.get("LOW", 0)),
            "MEDIUM": int(severity_counts.get("MEDIUM", 0)),
            "HIGH": int(severity_counts.get("HIGH", 0)),
        },
    }
