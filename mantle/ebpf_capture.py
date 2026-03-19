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

tracepoint:syscalls:sys_enter_renameat2
/@tracked[pid]/
{
  printf("EVT|%llu|renameat2|%d|%s|%s\n", nsecs, pid, str(args->oldname), str(args->newname));
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


def _read_proc_net(protocol: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
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


def _resolve_socket_endpoint(pid: int, fd: int) -> dict[str, Any] | None:
    inode = _socket_inode_for_fd(pid, fd)
    if inode is None:
        return None

    for proto in ("tcp", "tcp6", "udp", "udp6"):
        for entry in _read_proc_net(proto):
            if entry["inode"] != inode:
                continue

            remote_host = entry.get("remote_host", "unknown")
            remote_port = int(entry.get("remote_port") or 0)
            dest = (
                f"{remote_host}:{remote_port}"
                if remote_port > 0 and remote_host != "unknown"
                else f"fd={fd}"
            )

            return {
                "dest": dest,
                "transport": entry.get("transport", "other"),
                "family": entry.get("family", "other"),
            }

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
        argv = shlex.split(cmdline) if cmdline else [exec_path]

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
            "label": f"{action_type.replace('_', ' ')} {path}",
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

    if kind == "connect":
        if len(parts) < 5:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        resolved = _resolve_socket_endpoint(pid, fd)
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
            resolved = _resolve_socket_endpoint(pid, fd)
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
            resolved = _resolve_socket_endpoint(pid, fd)
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
