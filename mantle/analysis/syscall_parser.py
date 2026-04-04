"""Syscall parsing helper functions used by the dashboard TraceStore."""

from __future__ import annotations

import re
from typing import Any


def extract_quoted(text: str) -> list[str]:
    """Extract quoted strings from an strace syscall argument string."""
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)


def is_noisy_path(path: str, noisy_prefixes: tuple[str, ...], noisy_suffixes: tuple[str, ...]) -> bool:
    """Return True for system/noise paths that should be filtered from UX views."""
    if any(path.startswith(prefix) for prefix in noisy_prefixes):
        return True
    if any(part in path for part in noisy_suffixes):
        return True
    if "site-packages" in path and "mantle" not in path:
        return True
    return False


def is_user_visible_path(path: str, system_prefixes: tuple[str, ...]) -> bool:
    """Return True if a path is likely user/workspace relevant."""
    if not path:
        return False

    if path.startswith(("pipe:", "socket:", "anon_inode:")):
        return False

    if any(path.startswith(prefix) for prefix in system_prefixes):
        return False

    if "/.venv/" in path or "/site-packages/" in path or "__pycache__" in path:
        return False

    if path.startswith("/home/"):
        return True
    if path.startswith("/Users/"):
        return True

    if not path.startswith("/"):
        return "/" in path or "." in path

    if "/workspace/" in path or "/mantle/" in path:
        return True
    if path.startswith("/tmp/"):
        return True

    return False


def parse_open_mode(args: str) -> str:
    """Infer read/write classification from open/openat flags."""
    if "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args or "O_TRUNC" in args:
        return "file_write"
    return "file_read"


def extract_fd(args: str) -> int:
    """Parse first positional fd from syscall arguments."""
    fd_match = re.match(r"(\d+)", args.strip())
    return int(fd_match.group(1)) if fd_match else -1


def socket_family(args: str) -> str:
    """Infer socket family from syscall argument text."""
    if "AF_INET6" in args:
        return "AF_INET6"
    if "AF_INET" in args:
        return "AF_INET"
    if "AF_UNIX" in args:
        return "AF_UNIX"
    return "other"


def socket_transport(args: str) -> str:
    """Infer socket transport protocol from syscall argument text."""
    if "SOCK_DGRAM" in args:
        return "udp"
    if "SOCK_STREAM" in args:
        return "tcp"
    return "other"


def parse_socket_address(args: str) -> dict[str, str]:
    """Extract human-readable endpoint details from connect/send/recv args."""
    addr_match = re.search(r"sin6?_addr=inet_pton\([^,]+,\s*\"([^\"]+)\"\)", args)
    if not addr_match:
        addr_match = re.search(r"sin_addr=inet_addr\(\"([^\"]+)\"\)", args)
    port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)

    if addr_match:
        addr = addr_match.group(1)
        port = port_match.group(1) if port_match else "?"
        return {"host": addr, "port": port, "endpoint": f"{addr}:{port}"}

    unix_match = re.search(r"sun_path=\"([^\"]+)\"", args)
    if unix_match:
        path = unix_match.group(1)
        return {"host": "unix", "port": "", "endpoint": f"unix:{path}"}

    return {"host": "unknown", "port": "", "endpoint": "unknown"}


def parse_ret_status(ret: str) -> dict[str, Any]:
    """Parse syscall return field into success/error/value metadata."""
    raw = ret.strip()
    if raw.startswith("-1"):
        err_match = re.search(r"\b([A-Z][A-Z0-9_]+)\b", raw)
        err_code = err_match.group(1) if err_match else "ERROR"
        return {"ok": False, "error": err_code, "raw": raw}

    n_match = re.match(r"(\d+)", raw)
    return {"ok": True, "value": int(n_match.group(1)) if n_match else 0, "raw": raw}


def command_network_targets(command: str) -> list[str]:
    """Extract endpoint targets from command text (URL and git@host forms)."""
    targets: list[str] = []
    if not command:
        return targets

    for m in re.finditer(r"https?://([^\s/:]+)(?::(\d+))?", command):
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else (443 if command[m.start():].startswith("https://") else 80)
        targets.append(f"{host}:{port}")

    for m in re.finditer(r"git@([^\s:]+):", command):
        host = m.group(1)
        targets.append(f"{host}:22")

    seen: set[str] = set()
    uniq: list[str] = []
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        uniq.append(target)
    return uniq
