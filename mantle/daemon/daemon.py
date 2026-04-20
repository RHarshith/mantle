"""Mantle eBPF tracing daemon.

Runs as root, listens on a Unix domain socket, and manages bpftrace
sessions filtered by cgroup ID.  Each ``trace_start`` request spawns a
background thread that runs bpftrace against the requested cgroup and
streams parsed events to the output file.

Usage:
    sudo python -m mantle.daemon.daemon
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from mantle.daemon.cgroup import get_cgroup_id, is_cgroup_alive, validate_cgroup_path


SOCKET_PATH = "/var/run/mantle/mantle.sock"


# ---------------------------------------------------------------------------
# Tracing session — one per active ``mantle watch`` client
# ---------------------------------------------------------------------------

class TracingSession:
    """Manages a single bpftrace process tracing one cgroup."""

    def __init__(
        self,
        trace_id: str,
        cgroup_id: int,
        output_file: str,
        cgroup_path: str,
        agent_executable: str | None = None,
    ) -> None:
        self.trace_id = trace_id
        self.cgroup_id = cgroup_id
        self.output_file = output_file
        self.cgroup_path = cgroup_path
        self.agent_executable = agent_executable
        self.bpf_proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: str | None = None

    def start(self, timeout: float = 10.0) -> bool:
        """Start the tracing thread and wait for bpftrace to be ready.

        Returns True if bpftrace attached probes successfully within
        *timeout* seconds, False otherwise.
        """
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"trace-{self.trace_id}",
        )
        self._thread.start()
        return self._ready.wait(timeout=timeout)

    def _run(self) -> None:
        from mantle.capture.ebpf import run_capture

        def _on_bpf_started(proc: subprocess.Popen) -> None:
            self.bpf_proc = proc
            # Wait for the BEGIN block output to confirm probes are attached.
            # bpftrace prints "Attaching N probes..." then the BEGIN block
            # output.  The first EVT| line means probes are live.
            if proc.stdout:
                first_line = proc.stdout.readline()
                if first_line:
                    self._ready.set()
                    # Push the line back — run_capture needs to see it.
                    # We can't push it back, so we write it to the pipe.
                    # Instead, we'll handle this by having run_capture
                    # skip the first line if it's trace_start.
                    # Actually, the simplest fix: just set ready, the
                    # event loop in run_capture reads its own stdout
                    # after on_bpf_started returns.  We consumed one line
                    # here, so we need to handle it.
                    #
                    # Inject the line back by writing it to a buffer that
                    # run_capture should check — but that's complex.
                    # Simpler: set ready, and accept that we lose the
                    # trace_start event (it's just a marker, not data).
                else:
                    self._error = "bpftrace exited immediately"
            else:
                self._error = "bpftrace stdout not available"

        try:
            run_capture(
                Path(self.output_file),
                self.cgroup_id,
                agent_executable=self.agent_executable,
                on_bpf_started=_on_bpf_started,
            )
        except Exception as exc:
            self._error = str(exc)
            print(f"[mantle-daemon] trace {self.trace_id} failed: {exc}", file=sys.stderr)
        finally:
            # Ensure ready is set even on failure so start() doesn't block forever
            self._ready.set()

    def stop(self) -> int:
        """Terminate bpftrace, wait for the thread, return lines captured."""
        if self.bpf_proc and self.bpf_proc.poll() is None:
            self.bpf_proc.terminate()
            try:
                self.bpf_proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.bpf_proc.kill()

        if self._thread:
            self._thread.join(timeout=10.0)

        # Count captured lines
        try:
            with open(self.output_file) as fh:
                return sum(1 for _ in fh)
        except (OSError, FileNotFoundError):
            return 0


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

class MantleDaemon:
    """Root daemon process that manages eBPF tracing sessions."""

    def __init__(self, socket_path: str = SOCKET_PATH) -> None:
        self.socket_path = socket_path
        self.sessions: dict[str, TracingSession] = {}
        self.lock = threading.Lock()
        self.running = True

    # -- public entry -------------------------------------------------------

    def run(self) -> None:
        if os.geteuid() != 0:
            print("Error: mantle daemon must run as root.", file=sys.stderr)
            raise SystemExit(1)

        sock_dir = Path(self.socket_path).parent
        sock_dir.mkdir(parents=True, exist_ok=True)

        # Clean stale socket
        stale = Path(self.socket_path)
        if stale.exists():
            stale.unlink()

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        # World-readable for single-user dev machines (see implementation plan).
        os.chmod(self.socket_path, 0o666)
        server.listen(8)
        server.settimeout(1.0)

        # Background monitor for dead cgroups
        monitor = threading.Thread(target=self._monitor_cgroups, daemon=True)
        monitor.start()

        print(f"[mantle-daemon] listening on {self.socket_path}")

        while self.running:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.running:
                    break
                raise
            threading.Thread(
                target=self._handle_client,
                args=(conn,),
                daemon=True,
            ).start()

        # Shutdown: stop all active sessions
        with self.lock:
            for session in self.sessions.values():
                session.stop()
            self.sessions.clear()

        server.close()
        Path(self.socket_path).unlink(missing_ok=True)
        print("[mantle-daemon] stopped.")

    # -- client handler -----------------------------------------------------

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break

            if not data.strip():
                return

            msg: dict[str, Any] = json.loads(data.decode())
            cmd = msg.get("cmd", "")

            if cmd == "trace_start":
                resp = self._cmd_trace_start(msg)
            elif cmd == "trace_stop":
                resp = self._cmd_trace_stop(msg)
            elif cmd == "status":
                resp = self._cmd_status()
            elif cmd == "shutdown":
                resp = self._cmd_shutdown()
            else:
                resp = {"status": "error", "message": f"unknown command: {cmd}"}

            conn.sendall((json.dumps(resp) + "\n").encode())
        except Exception as exc:
            try:
                conn.sendall(
                    (json.dumps({"status": "error", "message": str(exc)}) + "\n").encode()
                )
            except OSError:
                pass
        finally:
            conn.close()

    # -- command implementations --------------------------------------------

    def _cmd_trace_start(self, msg: dict[str, Any]) -> dict[str, Any]:
        cgroup_path = msg.get("cgroup_path", "")
        trace_id = msg.get("trace_id", "")
        output_file = msg.get("output_file", "")
        agent_executable = msg.get("agent_executable")

        if not cgroup_path or not trace_id or not output_file:
            return {"status": "error", "message": "cgroup_path, trace_id, and output_file are required"}

        if not validate_cgroup_path(cgroup_path):
            return {"status": "error", "message": f"invalid cgroup path: {cgroup_path}"}

        try:
            cgroup_id = get_cgroup_id(cgroup_path)
        except FileNotFoundError as exc:
            return {"status": "error", "message": str(exc)}

        with self.lock:
            if trace_id in self.sessions:
                return {"status": "error", "message": f"trace already active: {trace_id}"}

            session = TracingSession(
                trace_id=trace_id,
                cgroup_id=cgroup_id,
                output_file=output_file,
                cgroup_path=cgroup_path,
                agent_executable=agent_executable,
            )

        # Start bpftrace and wait for probes to attach (blocks up to 10s).
        ready = session.start(timeout=10.0)
        if not ready:
            err = session._error or "bpftrace failed to attach probes within timeout"
            session.stop()
            return {"status": "error", "message": err}

        with self.lock:
            self.sessions[trace_id] = session

        print(f"[mantle-daemon] trace started: {trace_id} (cgroup={cgroup_id})")
        return {"status": "ok", "trace_id": trace_id, "cgroup_id": cgroup_id}

    def _cmd_trace_stop(self, msg: dict[str, Any]) -> dict[str, Any]:
        trace_id = msg.get("trace_id", "")

        with self.lock:
            session = self.sessions.pop(trace_id, None)

        if session is None:
            return {"status": "ok", "stopped": False, "message": "trace not found"}

        lines = session.stop()
        print(f"[mantle-daemon] trace stopped: {trace_id} ({lines} lines)")
        return {"status": "ok", "stopped": True, "lines_captured": lines}

    def _cmd_status(self) -> dict[str, Any]:
        with self.lock:
            active = [
                {"trace_id": tid, "cgroup_path": s.cgroup_path}
                for tid, s in self.sessions.items()
            ]
        return {"status": "ok", "active_traces": active, "count": len(active)}

    def _cmd_shutdown(self) -> dict[str, Any]:
        self.running = False
        return {"status": "ok", "message": "shutting down"}

    # -- background monitor -------------------------------------------------

    def _monitor_cgroups(self) -> None:
        """Periodically check if traced cgroups still exist.

        When systemd cleans up an empty scope, the cgroup directory is
        deleted.  Detect this and auto-stop the corresponding bpftrace
        session so we don't leak resources if the client crashed.
        """
        while self.running:
            time.sleep(2.0)

            dead_trace_ids: list[str] = []
            with self.lock:
                for trace_id, session in self.sessions.items():
                    if not is_cgroup_alive(session.cgroup_path):
                        dead_trace_ids.append(trace_id)

            for trace_id in dead_trace_ids:
                with self.lock:
                    session = self.sessions.pop(trace_id, None)
                if session:
                    lines = session.stop()
                    print(
                        f"[mantle-daemon] auto-stopped trace {trace_id} "
                        f"(cgroup gone, {lines} lines captured)"
                    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    # Graceful shutdown on SIGINT / SIGTERM
    daemon = MantleDaemon()

    def _signal_handler(signum: int, frame: Any) -> None:
        print(f"\n[mantle-daemon] received signal {signum}, shutting down...")
        daemon.running = False

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    daemon.run()


if __name__ == "__main__":
    main()
