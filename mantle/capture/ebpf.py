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
import tempfile
import time
from pathlib import Path
from typing import Any


MAX_SNAPSHOT_BYTES = 512 * 1024

BPFTRACE_PROGRAM = r'''
BEGIN
{
  @tracked[cpid] = 1;
  @parent[cpid] = 0;
  printf("EVT|%llu|root|%d|0|start\n", nsecs, cpid);
}

tracepoint:sched:sched_process_fork
/@tracked[args->parent_pid]/
{
  @tracked[args->child_pid] = 1;
  @parent[args->child_pid] = args->parent_pid;
  printf("EVT|%llu|fork|%d|%d|%s\n", nsecs, args->parent_pid, args->child_pid, comm);
}

tracepoint:sched:sched_process_exec
/@tracked[pid]/
{
  $ppid = @parent[pid];
  printf("EVT|%llu|exec|%d|%d|%s|%s\n", nsecs, pid, $ppid, comm, str(args->filename));
}

tracepoint:sched:sched_process_exit
/@tracked[pid]/
{
  $ppid = @parent[pid];
  printf("EVT|%llu|exit|%d|%d|%s\n", nsecs, pid, $ppid, comm);
  delete(@tracked[pid]);
  delete(@parent[pid]);
}

tracepoint:syscalls:sys_enter_openat
/@tracked[pid]/
{
  printf("EVT|%llu|openat|%d|%s|%d\n", nsecs, pid, str(args->filename), args->flags);
}

tracepoint:syscalls:sys_exit_openat
/@tracked[pid]/
{
    printf("EVT|%llu|openat_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_unlinkat
/@tracked[pid]/
{
  printf("EVT|%llu|unlinkat|%d|%s\n", nsecs, pid, str(args->pathname));
}

tracepoint:syscalls:sys_enter_renameat
/@tracked[pid]/
{
  printf("EVT|%llu|renameat|%d|%s|%s\n", nsecs, pid, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_exit_renameat
/@tracked[pid]/
{
    printf("EVT|%llu|renameat_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_renameat2
/@tracked[pid]/
{
  printf("EVT|%llu|renameat2|%d|%s|%s\n", nsecs, pid, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_exit_renameat2
/@tracked[pid]/
{
    printf("EVT|%llu|renameat2_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_connect
/@tracked[pid]/
{
  printf("EVT|%llu|connect|%d|%d\n", nsecs, pid, args->fd);
}

tracepoint:syscalls:sys_enter_sendto
/@tracked[pid]/
{
  printf("EVT|%llu|sendto|%d|%d|%d\n", nsecs, pid, args->fd, args->len);
}

tracepoint:syscalls:sys_enter_recvfrom
/@tracked[pid]/
{
  printf("EVT|%llu|recvfrom|%d|%d|%d\n", nsecs, pid, args->fd, args->size);
}

tracepoint:syscalls:sys_enter_write
/@tracked[pid]/
{
    printf("EVT|%llu|write|%d|%d|%d\n", nsecs, pid, args->fd, args->count);
}

tracepoint:syscalls:sys_exit_write
/@tracked[pid]/
{
    printf("EVT|%llu|write_ret|%d|%d\n", nsecs, pid, args->ret);
}

tracepoint:syscalls:sys_enter_close
/@tracked[pid]/
{
    printf("EVT|%llu|close|%d|%d\n", nsecs, pid, args->fd);
}
'''


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


def _command_for_bpftrace(command: list[str]) -> list[str]:
    """Normalize command argv for bpftrace -c.

    Some bpftrace builds fail to launch script entrypoints directly (for example,
    a Node CLI script with a shebang). If argv[0] is a shebang script, run it via
    its declared interpreter so child process launch is reliable.
    """
    if not command:
        return command

    exe = Path(command[0])
    if not exe.exists() or not exe.is_file():
        return command

    try:
        with exe.open("rb") as fh:
            header = fh.read(4)
            fh.seek(0)
            first_line = fh.readline().decode("utf-8", errors="replace").strip()
    except OSError:
        return command

    # Native binaries should run as-is.
    if header == b"\x7fELF":
        return command

    if not first_line.startswith("#!"):
        return command

    shebang = first_line[2:].strip()
    if not shebang:
        return command

    try:
        interpreter_argv = shlex.split(shebang)
    except ValueError:
        return command

    if not interpreter_argv:
        return command

    return interpreter_argv + [str(exe)] + command[1:]


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


def run_capture(output_file: Path, command: list[str]) -> int:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as script_file:
        script_file.write(BPFTRACE_PROGRAM)
        script_path = Path(script_file.name)

    launch_argv = _command_for_bpftrace(command)
    # Run the target command through a tiny wrapper script so argv is preserved
    # exactly, including arguments that contain spaces (for example --task text).
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as launch_file:
        launch_file.write("#!/usr/bin/env bash\n")
        launch_file.write("set -euo pipefail\n")
        launch_file.write(f"exec {shlex.join(launch_argv)}\n")
        launch_script = Path(launch_file.name)
    launch_script.chmod(0o700)
    launch_cmd = f"/bin/bash {shlex.quote(str(launch_script))}"

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
    expected_exec_basename = Path(launch_argv[0]).name
    capture_started = False

    # Increase bpftrace str() buffer size to avoid path truncation.
    # Default is 64 bytes which truncates most real filesystem paths.
    bpf_env = os.environ.copy()
    bpf_env.setdefault("BPFTRACE_STR_LEN", "200")

    proc = subprocess.Popen(
        ["bpftrace", "-q", "-c", launch_cmd, str(script_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=bpf_env,
    )

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
        script_path.unlink(missing_ok=True)
        launch_script.unlink(missing_ok=True)

    stderr = ""
    if proc.stderr is not None:
        stderr = proc.stderr.read().strip()
    return_code = proc.wait()

    if stderr:
        print(stderr, file=sys.stderr)

    return return_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Prototype eBPF capture wrapper for command execution.")
    parser.add_argument("--output", required=True, help="Path to output .ebpf.jsonl file")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute (prefix with --)")
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("No command provided for eBPF capture", file=sys.stderr)
        return 2

    output_file = Path(args.output)
    if os.geteuid() != 0:
        print("ebpf_capture.py requires root privileges", file=sys.stderr)
        return 1

    return run_capture(output_file, command)


if __name__ == "__main__":
    raise SystemExit(main())
