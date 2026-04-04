"""
mitmproxy addon: capture HTTP(S) requests/responses for an agent process tree.

Usage:
    mitmdump -s mantle/mitm_capture.py --set capture_file=/path/to/output.mitm.jsonl

If `MANTLE_AGENT_ROOT_PID` or `MANTLE_AGENT_ROOT_PID_FILE` is set, this addon records
only traffic whose owning PID is equal to, or a descendant of, that root PID.

Each captured flow is written as JSONL records containing request/response metadata,
payloads (best effort JSON parse), timing, and resolved PID.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from mitmproxy import http, ctx

# Track in-flight requests for timing
_request_times: dict[str, float] = {}


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _read_proc_net_tcp() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for line in lines[1:]:
            cols = line.split()
            if len(cols) < 10:
                continue
            local = cols[1]
            remote = cols[2]
            state = cols[3]
            inode = _safe_int(cols[9], -1)
            if inode <= 0:
                continue
            try:
                _laddr, lport_hex = local.split(":", 1)
                _raddr, rport_hex = remote.split(":", 1)
                lport = int(lport_hex, 16)
                rport = int(rport_hex, 16)
            except Exception:
                continue
            entries.append(
                {
                    "local_port": lport,
                    "remote_port": rport,
                    "state": state,
                    "inode": inode,
                }
            )
    return entries


def _pid_for_inode(inode: int) -> int | None:
    needle = f"socket:[{inode}]"
    proc_root = Path("/proc")
    for proc_dir in proc_root.iterdir():
        if not proc_dir.name.isdigit():
            continue
        pid = _safe_int(proc_dir.name, -1)
        if pid <= 0:
            continue
        fd_dir = proc_dir / "fd"
        if not fd_dir.exists():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    link = os.readlink(str(fd))
                except OSError:
                    continue
                if link == needle:
                    return pid
        except OSError:
            continue
    return None


def _parent_pid(pid: int) -> int:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        end = stat.rfind(")")
        if end < 0:
            return 0
        tail = stat[end + 2 :].split()
        if len(tail) < 2:
            return 0
        return _safe_int(tail[1], 0)
    except OSError:
        return 0


def _is_descendant_or_same(pid: int, root_pid: int) -> bool:
    cur = int(pid)
    seen: set[int] = set()
    while cur > 0 and cur not in seen:
        if cur == root_pid:
            return True
        seen.add(cur)
        cur = _parent_pid(cur)
    return False


def _read_agent_root_pid() -> int | None:
    direct = os.environ.get("MANTLE_AGENT_ROOT_PID")
    if direct:
        pid = _safe_int(direct, 0)
        if pid > 0:
            return pid

    pid_file = os.environ.get("MANTLE_AGENT_ROOT_PID_FILE", "")
    if not pid_file:
        return None
    try:
        raw = Path(pid_file).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    pid = _safe_int(raw, 0)
    return pid if pid > 0 else None


def _pid_for_flow(flow: http.HTTPFlow) -> int | None:
    peer = getattr(flow.client_conn, "peername", None)
    sock = getattr(flow.client_conn, "sockname", None)
    if not peer:
        return None
    try:
        src_port = int(peer[1])
    except Exception:
        return None

    dst_port = 0
    try:
        if sock:
            dst_port = int(sock[1])
    except Exception:
        dst_port = 0

    inode: int | None = None
    for entry in _read_proc_net_tcp():
        if entry.get("local_port") != src_port:
            continue
        if dst_port > 0 and entry.get("remote_port") != dst_port:
            continue
        inode = int(entry.get("inode") or 0)
        if inode > 0:
            break
    if not inode:
        return None
    return _pid_for_inode(inode)


def _get_capture_file() -> Path:
    path = os.environ.get("MITM_CAPTURE_FILE", "")
    if not path:
        try:
            path = ctx.options.capture_file
        except AttributeError:
            path = "/tmp/mitm_capture.jsonl"
    return Path(path)


def _write_record(record: dict):
    fpath = _get_capture_file()
    fpath.parent.mkdir(parents=True, exist_ok=True)
    with open(fpath, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


class ProcessTreeCapture:
    def load(self, loader):
        loader.add_option(
            name="capture_file",
            typespec=str,
            default="/tmp/mitm_capture.jsonl",
            help="Path to write captured API call JSONL",
        )

    def _debug_log(self, msg: str):
        """Write debug info to a sidecar log file."""
        fpath = _get_capture_file()
        debug_path = fpath.with_suffix(".debug.log")
        debug_path.parent.mkdir(parents=True, exist_ok=True)
        with open(debug_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        root_pid = _read_agent_root_pid()
        req_pid = _pid_for_flow(flow)
        if root_pid is not None:
            if req_pid is None or not _is_descendant_or_same(req_pid, root_pid):
                return

        self._debug_log(
            f"REQ  {flow.request.method} {url} (pid={req_pid}, root={root_pid}, content-type: {flow.request.headers.get('content-type', 'N/A')}, len={len(flow.request.content or b'')})"
        )

        _request_times[flow.id] = time.time()

        # Parse request body
        body = {}
        try:
            raw = flow.request.get_text()
            if raw:
                body = json.loads(raw)
        except Exception:
            body = {"_raw": flow.request.get_text() or ""}

        record = {
            "ts": time.time(),
            "direction": "request",
            "url": url,
            "method": flow.request.method,
            "pid": req_pid,
            "model": body.get("model", ""),
            "request_body": body,
        }
        _write_record(record)

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        root_pid = _read_agent_root_pid()
        req_pid = _pid_for_flow(flow)
        if root_pid is not None:
            if req_pid is None or not _is_descendant_or_same(req_pid, root_pid):
                return

        content_type = flow.response.headers.get("content-type", "N/A") if flow.response else "N/A"
        resp_len = len(flow.response.content or b'') if flow.response else 0
        self._debug_log(
            f"RESP {flow.response.status_code if flow.response else '???'} {url} (pid={req_pid}, root={root_pid}, content-type: {content_type}, len={resp_len})"
        )

        start_time = _request_times.pop(flow.id, None)
        duration_ms = int((time.time() - start_time) * 1000) if start_time else None

        # Parse response body
        body = {}
        try:
            raw = flow.response.get_text()
            if raw:
                body = json.loads(raw)
        except Exception:
            body = {"_raw": flow.response.get_text() or ""}

        # Parse request body too for context
        req_body = {}
        try:
            raw_req = flow.request.get_text()
            if raw_req:
                req_body = json.loads(raw_req)
        except Exception:
            req_body = {"_raw": flow.request.get_text() or ""}

        record = {
            "ts": time.time(),
            "direction": "response",
            "url": url,
            "method": flow.request.method,
            "pid": req_pid,
            "status_code": flow.response.status_code,
            "model": body.get("model", req_body.get("model", "")),
            "duration_ms": duration_ms,
            "request_body": req_body,
            "response_body": body,
        }
        _write_record(record)


addons = [ProcessTreeCapture()]
