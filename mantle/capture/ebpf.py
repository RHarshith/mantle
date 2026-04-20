#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


MAX_SNAPSHOT_BYTES = 512 * 1024



def _read_cmdline(pid: int) -> str:
    path = Path(f"/proc/{pid}/cmdline")
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if not data:
        return ""
    parts = [p for p in data.decode("utf-8", errors="replace").split("\x00") if p]
    return " ".join(parts)


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decode_ipv4(hex_addr: str) -> str:
    try:
        packed = struct.pack("<I", int(hex_addr, 16))
        return socket.inet_ntop(socket.AF_INET, packed)
    except Exception:
        return "unknown"


def _decode_ipv6(hex_addr: str) -> str:
    try:
        raw = bytes.fromhex(hex_addr)
        # /proc/net/tcp6 stores each 32-bit word in little-endian order.
        w0, w1, w2, w3 = struct.unpack("<IIII", raw)
        packed = struct.pack(">IIII", w0, w1, w2, w3)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "unknown"


def _bswap_u16(value: int) -> int:
    v = int(value) & 0xFFFF
    return ((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8)


def _bswap_u32(value: int) -> int:
    v = int(value) & 0xFFFFFFFF
    return ((v & 0x000000FF) << 24) | ((v & 0x0000FF00) << 8) | ((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24)


def _decode_ipv4_kernel_u32(value: int) -> str:
    try:
        packed = struct.pack("<I", int(value) & 0xFFFFFFFF)
        return socket.inet_ntop(socket.AF_INET, packed)
    except Exception:
        return "unknown"


def _decode_ipv6_kernel_words(words: tuple[int, int, int, int]) -> str:
    try:
        w0, w1, w2, w3 = words
        packed = struct.pack(
            ">IIII",
            _bswap_u32(w0),
            _bswap_u32(w1),
            _bswap_u32(w2),
            _bswap_u32(w3),
        )
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return "unknown"


def _socket_inode_for_fd(pid: int, fd: int) -> int | None:
    try:
        link = os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return None
    if not link.startswith("socket:[") or not link.endswith("]"):
        return None
    try:
        return int(link[len("socket:[") : -1])
    except ValueError:
        return None


def _read_proc_net(protocol: str, pid: int | None = None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if pid is not None and pid > 0:
        path = Path(f"/proc/{pid}/net/{protocol}")
    else:
        path = Path(f"/proc/net/{protocol}")
    if not path.exists():
        return entries

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return entries

    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 10:
            continue

        local = cols[1]
        remote = cols[2]
        state = cols[3]
        inode_str = cols[9]

        try:
            inode = int(inode_str)
        except ValueError:
            continue

        try:
            local_addr_hex, local_port_hex = local.split(":", 1)
            remote_addr_hex, remote_port_hex = remote.split(":", 1)
            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)
        except Exception:
            continue

        if protocol.endswith("6"):
            family = "AF_INET6"
            local_host = _decode_ipv6(local_addr_hex)
            remote_host = _decode_ipv6(remote_addr_hex)
        else:
            family = "AF_INET"
            local_host = _decode_ipv4(local_addr_hex)
            remote_host = _decode_ipv4(remote_addr_hex)

        transport = "tcp" if protocol.startswith("tcp") else "udp"
        entries.append(
            {
                "inode": inode,
                "transport": transport,
                "family": family,
                "local_host": local_host,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "state": state,
            }
        )

    return entries


def _resolve_socket_endpoint(pid: int, fd: int, retries: int = 4, delay_s: float = 0.002) -> dict[str, Any] | None:
    inode = _socket_inode_for_fd(pid, fd)
    if inode is None:
        return None

    attempts = max(1, int(retries))
    for attempt in range(attempts):
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            # Prefer the traced process namespace view for socket tables.
            entries = _read_proc_net(proto, pid=pid) or _read_proc_net(proto)
            for entry in entries:
                if entry["inode"] != inode:
                    continue

                remote_host = entry.get("remote_host", "unknown")
                remote_port = int(entry.get("remote_port") or 0)
                if remote_port <= 0 or remote_host == "unknown":
                    continue

                return {
                    "dest": f"{remote_host}:{remote_port}",
                    "transport": entry.get("transport", "other"),
                    "family": entry.get("family", "other"),
                }

        if attempt < attempts - 1:
            time.sleep(max(0.0, float(delay_s)))

    return None



def _event_from_line(
    raw: str,
    seq: int,
    cmdline_cache: dict[int, str],
    socket_cache: dict[tuple[int, int], dict[str, Any]],
    time_offset: float,
) -> dict[str, Any] | None:
    line = raw.strip()
    if not line.startswith("EVT|"):
        return None

    parts = line.split("|")
    if len(parts) < 4:
        return None

    ns = _safe_int(parts[1])
    kind = parts[2]
    ts = (ns / 1_000_000_000) + time_offset if ns else 0.0

    if kind == "fork":
        if len(parts) < 5:
            return None
        ppid = _safe_int(parts[3])
        child = _safe_int(parts[4])
        return {
            "ts": ts,
            "line_no": seq,
            "type": "process_spawn",
            "pid": ppid,
            "child_pid": child,
            "label": f"spawn pid {child}",
        }

    if kind == "exec":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        ppid = _safe_int(parts[4])
        exec_path = parts[6] if len(parts) > 6 else parts[5]

        cmdline = cmdline_cache.get(pid)
        if not cmdline:
            cmdline = _read_cmdline(pid)
            if cmdline:
                cmdline_cache[pid] = cmdline

        command = cmdline or exec_path or "exec"
        if cmdline:
            try:
                argv = shlex.split(cmdline)
            except ValueError:
                # Fallback if there are unmatched quotes in the command line
                argv = [cmdline]
        else:
            argv = [exec_path]

        return {
            "ts": ts,
            "line_no": seq,
            "type": "command_exec",
            "pid": pid,
            "ppid": ppid,
            "exec_path": exec_path,
            "argv": argv,
            "command": command,
            "label": f"exec {command[:120]}",
        }

    if kind == "exit":
        if len(parts) < 4:
            return None
        pid = _safe_int(parts[3])
        return {
            "ts": ts,
            "line_no": seq,
            "type": "process_exit",
            "pid": pid,
            "label": f"pid {pid} exited",
        }

    if kind == "openat":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        path = parts[4]
        flags = _safe_int(parts[5]) if len(parts) > 5 else 0
        action_type = "file_write" if (flags & (0x1 | 0x2 | 0x40 | 0x200)) else "file_read"
        return {
            "ts": ts,
            "line_no": seq,
            "type": action_type,
            "pid": pid,
            "path": path,
            "flags": flags,
            "label": f"{action_type.replace('_', ' ')} {path}",
        }

    if kind == "openat_ret":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "fd_open",
            "pid": pid,
            "fd": fd,
            "label": f"fd open {fd}",
        }

    if kind == "unlinkat":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        path = parts[4]
        return {
            "ts": ts,
            "line_no": seq,
            "type": "file_delete",
            "pid": pid,
            "path": path,
            "label": f"delete {path}",
        }

    if kind in {"renameat", "renameat2"}:
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        src = parts[4]
        dst = parts[5]
        return {
            "ts": ts,
            "line_no": seq,
            "type": "file_rename",
            "pid": pid,
            "path": dst,
            "src": src,
            "label": f"rename {src} -> {dst}",
        }

    if kind in {"renameat_ret", "renameat2_ret"}:
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        ret = _safe_int(parts[4], -1)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "file_rename_ret",
            "pid": pid,
            "ok": ret == 0,
            "ret": ret,
            "label": f"rename ret={ret}",
        }

    if kind == "connect4":
        if len(parts) < 7:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        addr_raw = _safe_int(parts[5], 0)
        port_raw = _safe_int(parts[6], 0)
        dest = f"{_decode_ipv4_kernel_u32(addr_raw)}:{_bswap_u16(port_raw)}"
        cached = {
            "dest": dest,
            "transport": "tcp",
            "family": "AF_INET",
            "source": "connect_sockaddr",
        }
        socket_cache[(pid, fd)] = cached
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_connect",
            "pid": pid,
            "fd": fd,
            "dest": cached["dest"],
            "transport": cached["transport"],
            "family": cached["family"],
            "ok": True,
            "endpoint_source": cached["source"],
            "label": f"connect {cached['dest']}",
        }

    if kind == "connect6":
        if len(parts) < 10:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        words = (
            _safe_int(parts[5], 0),
            _safe_int(parts[6], 0),
            _safe_int(parts[7], 0),
            _safe_int(parts[8], 0),
        )
        port_raw = _safe_int(parts[9], 0)
        dest = f"{_decode_ipv6_kernel_words(words)}:{_bswap_u16(port_raw)}"
        cached = {
            "dest": dest,
            "transport": "tcp",
            "family": "AF_INET6",
            "source": "connect_sockaddr",
        }
        socket_cache[(pid, fd)] = cached
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_connect",
            "pid": pid,
            "fd": fd,
            "dest": cached["dest"],
            "transport": cached["transport"],
            "family": cached["family"],
            "ok": True,
            "endpoint_source": cached["source"],
            "label": f"connect {cached['dest']}",
        }

    if kind == "connect":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        resolved = _resolve_socket_endpoint(pid, fd, retries=6, delay_s=0.002)
        if resolved is not None:
            socket_cache[(pid, fd)] = resolved
        cached = socket_cache.get((pid, fd), {})
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_connect",
            "pid": pid,
            "fd": fd,
            "dest": cached.get("dest", f"fd={fd}"),
            "transport": cached.get("transport", "other"),
            "family": cached.get("family", "other"),
            "ok": True,
            "label": f"connect {cached.get('dest', f'fd={fd}')}",
        }

    if kind == "sendto":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        size = _safe_int(parts[5], 0)
        cached = socket_cache.get((pid, fd))
        if cached is None:
            resolved = _resolve_socket_endpoint(pid, fd, retries=4, delay_s=0.002)
            if resolved is not None:
                socket_cache[(pid, fd)] = resolved
            cached = socket_cache.get((pid, fd), {})
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_send",
            "pid": pid,
            "fd": fd,
            "dest": cached.get("dest", f"fd={fd}"),
            "bytes": size,
            "transport": cached.get("transport", "other"),
            "family": cached.get("family", "other"),
            "ok": True,
            "label": f"send {size}B -> {cached.get('dest', f'fd={fd}')}",
        }

    if kind == "recvfrom":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        size = _safe_int(parts[5], 0)
        cached = socket_cache.get((pid, fd))
        if cached is None:
            resolved = _resolve_socket_endpoint(pid, fd, retries=4, delay_s=0.002)
            if resolved is not None:
                socket_cache[(pid, fd)] = resolved
            cached = socket_cache.get((pid, fd), {})
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_recv",
            "pid": pid,
            "fd": fd,
            "dest": cached.get("dest", f"fd={fd}"),
            "bytes": size,
            "transport": cached.get("transport", "other"),
            "family": cached.get("family", "other"),
            "ok": True,
            "label": f"recv {size}B <- {cached.get('dest', f'fd={fd}')}",
        }

    if kind == "write":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        req = _safe_int(parts[5], 0)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "fd_write",
            "pid": pid,
            "fd": fd,
            "requested_bytes": req,
            "label": f"write fd={fd} req={req}",
        }

    if kind == "write_ret":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        ret = _safe_int(parts[4], -1)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "fd_write_ret",
            "pid": pid,
            "written_bytes": ret,
            "ok": ret >= 0,
            "label": f"write ret={ret}",
        }

    if kind == "close":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "fd_close",
            "pid": pid,
            "fd": fd,
            "label": f"close fd={fd}",
        }

    return None


def run_capture(
    output_file: Path,
    cgroup_id: int,
    *,
    agent_executable: str | None = None,
    on_bpf_started: Callable[[subprocess.Popen], None] | None = None,
) -> int:
    """Run bpftrace-based eBPF capture for all processes in the given cgroup.

    Args:
        output_file: Path to write the .ebpf.jsonl trace output.
        cgroup_id: Kernel cgroup ID (inode number) to filter on.
        agent_executable: Optional agent binary name for filtering bootstrap
            noise.  If provided, events are suppressed until the first exec
            of this binary.  If None, all events are captured immediately.
        on_bpf_started: Optional callback invoked with the bpftrace Popen
            object right after launch, allowing the caller to store a
            reference for external termination.

    Returns:
        The bpftrace process exit code.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    bt_script = Path(__file__).parent / "mantle_trace.bt"
    if not bt_script.exists():
        print(f"Error: bpftrace script not found: {bt_script}", file=sys.stderr)
        return 1

    # Calculate offset between bpf_ktime_get_ns() (CLOCK_MONOTONIC) and Epoch (time.time())
    time_offset = time.time() - time.clock_gettime(time.CLOCK_MONOTONIC)

    cmdline_cache: dict[int, str] = {}
    socket_cache: dict[tuple[int, int], dict[str, Any]] = {}
    pending_open: dict[int, dict[str, Any]] = {}
    fd_paths: dict[tuple[int, int], dict[str, Any]] = {}
    pending_write_fd: dict[int, int] = {}
    path_before_snapshot: dict[str, dict[str, Any]] = {}
    pending_rename: dict[int, dict[str, str]] = {}
    seq = 0
    if agent_executable is not None:
        capture_started = False
        expected_exec_basename = Path(agent_executable).name
    else:
        capture_started = True
        expected_exec_basename = ""

    # Increase bpftrace str() buffer size to avoid path truncation.
    # Default is 64 bytes which truncates most real filesystem paths.
    bpf_env = os.environ.copy()
    bpf_env.setdefault("BPFTRACE_STR_LEN", "200")

    proc = subprocess.Popen(
        ["bpftrace", "-q", str(bt_script), str(cgroup_id)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=bpf_env,
    )

    if on_bpf_started is not None:
        on_bpf_started(proc)

    try:
        def _resolve_path_for_pid(pid: int, raw_path: str) -> str:
            path_txt = str(raw_path or "").strip()
            if not path_txt:
                return ""
            if path_txt.startswith("/"):
                return path_txt
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
                return str((Path(cwd) / path_txt).resolve())
            except OSError:
                return path_txt

        def _capture_snapshot(path: str) -> dict[str, Any]:
            out: dict[str, Any] = {
                "path": path,
                "exists": False,
                "size": 0,
                "truncated": False,
                "binary": False,
                "content": "",
            }
            if not path:
                return out

            p = Path(path)
            if not p.exists() or not p.is_file():
                return out

            try:
                size = p.stat().st_size
                out["exists"] = True
                out["size"] = int(size)
                read_size = min(int(size), MAX_SNAPSHOT_BYTES)
                data = p.read_bytes()[:read_size]
            except OSError:
                return out

            if b"\x00" in data:
                out["binary"] = True
                return out

            out["content"] = data.decode("utf-8", errors="replace")
            out["truncated"] = int(out["size"]) > MAX_SNAPSHOT_BYTES
            return out

        def _emit_snapshot(
            out_fh: Any,
            *,
            ts: float,
            pid: int,
            path: str,
            phase: str,
            trigger: str,
        ) -> None:
            nonlocal seq
            if not path:
                return
            snap = _capture_snapshot(path)
            seq += 1
            event = {
                "ts": ts,
                "line_no": seq,
                "type": "file_snapshot",
                "pid": int(pid),
                "path": path,
                "snapshot_phase": phase,
                "trigger": trigger,
                "exists": bool(snap.get("exists")),
                "size": int(snap.get("size") or 0),
                "truncated": bool(snap.get("truncated")),
                "binary": bool(snap.get("binary")),
                "content": snap.get("content") or "",
                "label": f"snapshot {phase} {path}",
            }
            out_fh.write(json.dumps(event, ensure_ascii=False) + "\n")

        with output_file.open("w", encoding="utf-8") as out_fh:
            assert proc.stdout is not None
            for line in proc.stdout:
                seq += 1
                event = _event_from_line(line, seq, cmdline_cache, socket_cache, time_offset)
                if event is None:
                    if line.lstrip().startswith("EVT|"):
                        continue
                    # Preserve target command stdout/stderr-like logs (for example,
                    # agent --verbose output) that are multiplexed on bpftrace stdout.
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    continue

                if not capture_started:
                    # Drop bootstrap noise from command launch wrappers until
                    # the first exec of the target runtime is observed.
                    if event.get("type") == "command_exec":
                        exec_path = str(event.get("exec_path") or "")
                        if Path(exec_path).name == expected_exec_basename:
                            capture_started = True
                    if not capture_started:
                        continue

                et = str(event.get("type") or "")
                pid = int(event.get("pid") or 0)

                if et == "file_write":
                    path = _resolve_path_for_pid(pid, str(event.get("path") or ""))
                    event["path"] = path
                    flags = int(event.get("flags") or 0)
                    if pid > 0 and path:
                        pending_open[pid] = {"path": path, "flags": flags, "ts": float(event.get("ts") or 0.0)}
                        # Fallback: capture an immediate baseline snapshot from
                        # openat(write) path even if later fd correlation fails.
                        if path not in path_before_snapshot:
                            path_before_snapshot[path] = _capture_snapshot(path)
                            _emit_snapshot(
                                out_fh,
                                ts=float(event.get("ts") or 0.0),
                                pid=pid,
                                path=path,
                                phase="before",
                                trigger="file_write_open",
                            )

                elif et == "fd_open":
                    fd = int(event.get("fd") or -1)
                    open_info = pending_open.pop(pid, None)
                    if fd >= 0 and open_info:
                        fd_paths[(pid, fd)] = {
                            "path": str(open_info.get("path") or ""),
                            "flags": int(open_info.get("flags") or 0),
                        }
                        event["path"] = str(open_info.get("path") or "")

                elif et == "fd_write":
                    fd = int(event.get("fd") or -1)
                    pending_write_fd[pid] = fd
                    info = fd_paths.get((pid, fd))
                    if info:
                        path = str(info.get("path") or "")
                        if path:
                            event["path"] = path
                            if path not in path_before_snapshot:
                                pre = _capture_snapshot(path)
                                path_before_snapshot[path] = pre
                                _emit_snapshot(
                                    out_fh,
                                    ts=float(event.get("ts") or 0.0),
                                    pid=pid,
                                    path=path,
                                    phase="before",
                                    trigger="fd_write",
                                )

                elif et == "fd_write_ret":
                    fd = int(pending_write_fd.pop(pid, -1))
                    written = int(event.get("written_bytes") or -1)
                    info = fd_paths.get((pid, fd)) if fd >= 0 else None
                    if info:
                        path = str(info.get("path") or "")
                        if path:
                            event["path"] = path
                            if written > 0:
                                _emit_snapshot(
                                    out_fh,
                                    ts=float(event.get("ts") or 0.0),
                                    pid=pid,
                                    path=path,
                                    phase="after",
                                    trigger="fd_write_ret",
                                )
                    elif written > 0:
                        # Fallback: if fd mapping is unavailable, try the most
                        # recent openat(write) path for this pid.
                        open_info = pending_open.get(pid)
                        fallback_path = str((open_info or {}).get("path") or "")
                        if fallback_path:
                            _emit_snapshot(
                                out_fh,
                                ts=float(event.get("ts") or 0.0),
                                pid=pid,
                                path=fallback_path,
                                phase="after",
                                trigger="fd_write_ret_fallback",
                            )

                elif et == "fd_close":
                    fd = int(event.get("fd") or -1)
                    if fd >= 0:
                        fd_paths.pop((pid, fd), None)

                elif et == "file_rename":
                    src = _resolve_path_for_pid(pid, str(event.get("src") or ""))
                    dst = _resolve_path_for_pid(pid, str(event.get("path") or ""))
                    event["src"] = src
                    event["path"] = dst
                    if pid > 0 and dst:
                        pending_rename[pid] = {"src": src, "dst": dst}
                        _emit_snapshot(
                            out_fh,
                            ts=float(event.get("ts") or 0.0),
                            pid=pid,
                            path=dst,
                            phase="before",
                            trigger="file_rename",
                        )

                elif et == "file_rename_ret":
                    info = pending_rename.pop(pid, None)
                    if info and bool(event.get("ok")):
                        dst = str(info.get("dst") or "")
                        if dst:
                            _emit_snapshot(
                                out_fh,
                                ts=float(event.get("ts") or 0.0),
                                pid=pid,
                                path=dst,
                                phase="after",
                                trigger="file_rename_ret",
                            )

                out_fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    finally:
        pass

    stderr = ""
    if proc.stderr is not None:
        stderr = proc.stderr.read().strip()
    return_code = proc.wait()

    if stderr:
        print(stderr, file=sys.stderr)

    return return_code


def main() -> int:
    parser = argparse.ArgumentParser(description="eBPF capture for cgroup-based agent tracing.")
    parser.add_argument("--output", required=True, help="Path to output .ebpf.jsonl file")
    parser.add_argument("--cgroup-id", required=True, type=int, help="Kernel cgroup ID (inode number) to trace")
    parser.add_argument("--agent-executable", default=None, help="Agent binary name for capture start filtering")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ebpf capture requires root privileges", file=sys.stderr)
        return 1

    return run_capture(
        Path(args.output),
        args.cgroup_id,
        agent_executable=args.agent_executable,
    )


if __name__ == "__main__":
    raise SystemExit(main())
