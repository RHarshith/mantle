#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
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


def _event_from_line(raw: str, seq: int, cmdline_cache: dict[int, str]) -> dict[str, Any] | None:
    line = raw.strip()
    if not line.startswith("EVT|"):
        return None

    parts = line.split("|")
    if len(parts) < 4:
        return None

    ns = _safe_int(parts[1])
    kind = parts[2]
    ts = ns / 1_000_000_000 if ns else 0.0

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
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_connect",
            "pid": pid,
            "fd": fd,
            "dest": f"fd={fd}",
            "transport": "other",
            "family": "other",
            "ok": True,
            "label": f"connect fd={fd}",
        }

    if kind == "sendto":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        size = _safe_int(parts[5], 0)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_send",
            "pid": pid,
            "fd": fd,
            "dest": f"fd={fd}",
            "bytes": size,
            "transport": "other",
            "family": "other",
            "ok": True,
            "label": f"send {size}B -> fd={fd}",
        }

    if kind == "recvfrom":
        if len(parts) < 6:
            return None
        pid = _safe_int(parts[3])
        fd = _safe_int(parts[4], -1)
        size = _safe_int(parts[5], 0)
        return {
            "ts": ts,
            "line_no": seq,
            "type": "net_recv",
            "pid": pid,
            "fd": fd,
            "dest": f"fd={fd}",
            "bytes": size,
            "transport": "other",
            "family": "other",
            "ok": True,
            "label": f"recv {size}B <- fd={fd}",
        }

    return None


def run_capture(output_file: Path, command: list[str]) -> int:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as script_file:
        script_file.write(BPFTRACE_PROGRAM)
        script_path = Path(script_file.name)

    launch_argv = _command_for_bpftrace(command)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as runner_file:
        runner_file.write("#!/usr/bin/env bash\n")
        runner_file.write("set -euo pipefail\n")
        runner_file.write(f"exec {shlex.join(launch_argv)}\n")
        runner_path = Path(runner_file.name)
    runner_path.chmod(0o700)

    cmdline_cache: dict[int, str] = {}
    seq = 0

    shell_cmd = f"/bin/bash {runner_path}"
    proc = subprocess.Popen(
        ["bpftrace", "-q", "-c", shell_cmd, str(script_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        with output_file.open("w", encoding="utf-8") as out_fh:
            assert proc.stdout is not None
            for line in proc.stdout:
                seq += 1
                event = _event_from_line(line, seq, cmdline_cache)
                if event is None:
                    continue
                out_fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    finally:
        script_path.unlink(missing_ok=True)
        runner_path.unlink(missing_ok=True)

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
