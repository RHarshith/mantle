"""Client library and CLI for communicating with the Mantle eBPF daemon."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path


SOCKET_PATH = "/var/run/mantle/mantle.sock"


def _send_command(cmd: dict) -> dict:
    """Send a JSON command to the daemon and return the parsed response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(SOCKET_PATH)
        sock.sendall((json.dumps(cmd) + "\n").encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        return json.loads(data.decode())
    finally:
        sock.close()


def trace_start(
    cgroup_path: str,
    trace_id: str,
    output_file: str,
    agent_executable: str | None = None,
) -> dict:
    """Ask the daemon to start tracing a cgroup."""
    cmd: dict = {
        "cmd": "trace_start",
        "cgroup_path": cgroup_path,
        "trace_id": trace_id,
        "output_file": output_file,
    }
    if agent_executable:
        cmd["agent_executable"] = agent_executable
    return _send_command(cmd)


def trace_stop(trace_id: str) -> dict:
    """Ask the daemon to stop tracing and flush output."""
    return _send_command({"cmd": "trace_stop", "trace_id": trace_id})


def status() -> dict:
    """Query daemon health and active traces."""
    return _send_command({"cmd": "status"})


def shutdown() -> dict:
    """Ask the daemon to shut down gracefully."""
    return _send_command({"cmd": "shutdown"})


def is_daemon_running() -> bool:
    """Return True if the daemon is reachable and healthy."""
    try:
        resp = status()
        return resp.get("status") == "ok"
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False


# ---------------------------------------------------------------------------
# CLI entrypoint: python -m mantle.daemon.client <action> [args]
# ---------------------------------------------------------------------------

def _cli_trace_start(argv: list[str]) -> None:
    p = argparse.ArgumentParser(prog="mantle.daemon.client trace-start")
    p.add_argument("--cgroup-path", required=True)
    p.add_argument("--trace-id", required=True)
    p.add_argument("--output-file", required=True)
    p.add_argument("--agent-executable", default=None)
    args = p.parse_args(argv)

    resp = trace_start(
        args.cgroup_path,
        args.trace_id,
        args.output_file,
        agent_executable=args.agent_executable,
    )
    if resp.get("status") != "ok":
        print(f"Error: {resp.get('message', 'unknown error')}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(resp))


def _cli_trace_stop(argv: list[str]) -> None:
    p = argparse.ArgumentParser(prog="mantle.daemon.client trace-stop")
    p.add_argument("--trace-id", required=True)
    args = p.parse_args(argv)

    resp = trace_stop(args.trace_id)
    print(json.dumps(resp))


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m mantle.daemon.client <trace-start|trace-stop|status|shutdown>", file=sys.stderr)
        raise SystemExit(1)

    action = sys.argv[1]

    if action == "trace-start":
        _cli_trace_start(sys.argv[2:])
    elif action == "trace-stop":
        _cli_trace_stop(sys.argv[2:])
    elif action == "status":
        resp = status()
        print(json.dumps(resp, indent=2))
    elif action == "shutdown":
        resp = shutdown()
        print(json.dumps(resp))
    else:
        print(f"Unknown command: {action}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
