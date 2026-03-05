from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

LINE_RE = re.compile(r"^(?P<pid>\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<ret>.+)$")
UNFINISHED_RE = re.compile(r"^(?P<pid>\d+)\s+(?P<syscall>[a-zA-Z0-9_]+)\((?P<args>.*)\s+<unfinished \.\.\.>$")
RESUMED_RE = re.compile(r"^(?P<pid>\d+)\s+<\.\.\.\s+(?P<syscall>[a-zA-Z0-9_]+)\s+resumed>(?P<tail>.*)$")

NOISY_PREFIXES = (
    "/usr/lib/",
    "/lib/",
    "/proc/",
    "/sys/",
    "/etc/ld.so",
)
NOISY_SUFFIXES = (".pyc", ".so", "__pycache__")
SYSTEM_PREFIXES = (
    "/usr/",
    "/lib/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/var/lib/",
    "/var/cache/",
)


@dataclass
class TraceState:
    trace_id: str
    strace_path: Path
    events_path_candidates: list[Path]
    strace_offset: int = 0
    strace_line_no: int = 0
    events_offset: int = 0
    mitm_offset: int = 0
    mitm_path: Path | None = None
    complete: bool = False
    root_pid: int | None = None
    strace_pending: dict[tuple[int, str], str] = field(default_factory=dict)
    process_parent: dict[int, int] = field(default_factory=dict)
    pid_fds: dict[tuple[int, int], dict[str, Any]] = field(default_factory=dict)  # (pid, fd) -> socket info
    sys_events: list[dict[str, Any]] = field(default_factory=list)
    agent_events: list[dict[str, Any]] = field(default_factory=list)


class TraceStore:
    def __init__(self, trace_dir: Path, events_dir: Path, mitm_dir: Path | None = None):
        self.trace_dir = trace_dir
        self.events_dir = events_dir
        self.mitm_dir = mitm_dir
        self.traces: dict[str, TraceState] = {}
        self.version = 0
        self._lock = asyncio.Lock()

    def _trace_to_event_candidates(self, trace_file: Path) -> list[Path]:
        stem = trace_file.name
        no_ext = trace_file.stem
        return [
            self.events_dir / f"{stem}.events.jsonl",
            self.events_dir / f"{no_ext}.events.jsonl",
        ]

    async def poll_once(self) -> None:
        changed = False

        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.events_dir.mkdir(parents=True, exist_ok=True)

        for file_path in sorted(self.trace_dir.glob("*.log")):
            trace_id = file_path.name
            if trace_id not in self.traces:
                mitm_path = self._find_mitm_file(trace_id) if self.mitm_dir else None
                self.traces[trace_id] = TraceState(
                    trace_id=trace_id,
                    strace_path=file_path,
                    events_path_candidates=self._trace_to_event_candidates(file_path),
                    mitm_path=mitm_path,
                )
                changed = True

        for state in self.traces.values():
            if state.strace_path.exists():
                changed = self._tail_strace(state) or changed
            changed = self._tail_events(state) or changed
            # If no native events found, try loading from mitmproxy capture
            if not state.agent_events and state.mitm_path:
                changed = self._tail_mitm_events(state) or changed

        if changed:
            async with self._lock:
                self.version += 1

    def _read_new_lines(self, path: Path, start_offset: int) -> tuple[list[str], int]:
        if not path.exists():
            return [], start_offset

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(start_offset)
            data = fh.read()
            end_offset = fh.tell()

        if not data:
            return [], start_offset

        lines = data.splitlines()
        return lines, end_offset

    def _tail_events(self, state: TraceState) -> bool:
        target = None
        for cand in state.events_path_candidates:
            if cand.exists():
                target = cand
                break
        if target is None:
            return False

        lines, new_offset = self._read_new_lines(target, state.events_offset)
        if not lines:
            return False

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            state.agent_events.append(event)

        state.events_offset = new_offset
        return True

    def _find_mitm_file(self, trace_id: str) -> Path | None:
        """Find a matching .mitm.jsonl file for the given trace_id."""
        if not self.mitm_dir or not self.mitm_dir.exists():
            return None
        stem = trace_id
        no_ext = Path(trace_id).stem  # strip .log
        candidates = [
            self.mitm_dir / f"{stem}.mitm.jsonl",
            self.mitm_dir / f"{no_ext}.mitm.jsonl",
        ]
        # Also strip .strace from e.g. trace_xxx.strace.log
        if no_ext.endswith(".strace"):
            candidates.append(self.mitm_dir / f"{no_ext[:-7]}.mitm.jsonl")
        for cand in candidates:
            if cand.exists():
                return cand
        return None

    def _tail_mitm_events(self, state: TraceState) -> bool:
        """Parse mitmproxy capture JSONL into agent_events format."""
        if not state.mitm_path or not state.mitm_path.exists():
            return False

        lines, new_offset = self._read_new_lines(state.mitm_path, state.mitm_offset)
        if not lines:
            return False

        seq = len(state.agent_events)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            # We only care about 'response' records — they contain both
            # request (in request_body) and response (in response_body)
            if record.get("direction") != "response":
                continue

            req_body = record.get("request_body") or {}
            resp_body = record.get("response_body") or {}
            ts = record.get("ts", 0)
            duration_ms = record.get("duration_ms")
            model = record.get("model", "")

            messages = req_body.get("messages", [])
            choices = resp_body.get("choices", [])

            # Extract the user prompt from request messages if this is the
            # first call (seq == 0) — emit a user_prompt event
            if seq == 0 and messages:
                for msg in messages:
                    if msg.get("role") == "user":
                        seq += 1
                        state.agent_events.append({
                            "ts": ts,
                            "seq": seq,
                            "event_type": "user_prompt",
                            "payload": {
                                "content": msg.get("content", ""),
                            },
                            "_source": "mitm",
                        })
                        break

            # Process the model's response choices
            for choice in choices:
                msg = choice.get("message") or {}
                tool_calls = msg.get("tool_calls") or []

                if tool_calls:
                    # Emit tool_call events
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        tool_name = func.get("name", "unknown")
                        tool_call_id = tc.get("id", f"mitm_tc_{seq}")
                        args_raw = func.get("arguments", "{}")
                        try:
                            args = json.loads(args_raw)
                        except json.JSONDecodeError:
                            args = {"_raw": args_raw}

                        seq += 1
                        state.agent_events.append({
                            "ts": ts,
                            "seq": seq,
                            "event_type": "tool_call_started",
                            "payload": {
                                "tool_call_id": tool_call_id,
                                "tool_name": tool_name,
                                "arguments": args,
                            },
                            "_source": "mitm",
                        })

                    # For mitmproxy, we don't see the tool execution result
                    # directly — but we know the next request will contain it.
                    # Emit a tool_call_finished from the next request's tool
                    # result message if available.
                    # We look at the NEXT response's request_body for tool msgs.
                    # (This is handled naturally by the next iteration.)

                    # Also check if the current request has tool result messages
                    for msg_r in messages:
                        if msg_r.get("role") == "tool":
                            # This is a tool result from a previous call
                            tool_content = msg_r.get("content", "")
                            tool_call_id_r = msg_r.get("tool_call_id", "")
                            try:
                                result = json.loads(tool_content)
                            except (json.JSONDecodeError, TypeError):
                                result = {"output": tool_content}
                            seq += 1
                            state.agent_events.append({
                                "ts": ts,
                                "seq": seq,
                                "event_type": "tool_call_finished",
                                "payload": {
                                    "tool_call_id": tool_call_id_r,
                                    "tool_name": "unknown",
                                    "duration_ms": duration_ms,
                                    "result": result,
                                },
                                "_source": "mitm",
                            })
                elif msg.get("content"):
                    # Pure text response — assistant_response
                    # But first, emit any tool results from the request
                    for msg_r in messages:
                        if msg_r.get("role") == "tool":
                            tool_content = msg_r.get("content", "")
                            tool_call_id_r = msg_r.get("tool_call_id", "")
                            try:
                                result = json.loads(tool_content)
                            except (json.JSONDecodeError, TypeError):
                                result = {"output": tool_content}
                            seq += 1
                            state.agent_events.append({
                                "ts": ts,
                                "seq": seq,
                                "event_type": "tool_call_finished",
                                "payload": {
                                    "tool_call_id": tool_call_id_r,
                                    "tool_name": "unknown",
                                    "duration_ms": duration_ms,
                                    "result": result,
                                },
                                "_source": "mitm",
                            })

                    seq += 1
                    state.agent_events.append({
                        "ts": ts,
                        "seq": seq,
                        "event_type": "assistant_response",
                        "payload": {
                            "content": msg.get("content", ""),
                            "model": model,
                        },
                        "_source": "mitm",
                    })

        state.mitm_offset = new_offset
        return True

    def _tail_strace(self, state: TraceState) -> bool:
        lines, new_offset = self._read_new_lines(state.strace_path, state.strace_offset)
        if not lines:
            return False

        changed = False
        for line in lines:
            state.strace_line_no += 1
            changed = self._ingest_strace_line(state, line, state.strace_line_no) or changed

        state.strace_offset = new_offset
        return changed

    def _extract_quoted(self, text: str) -> list[str]:
        return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)

    def _is_noisy_path(self, path: str) -> bool:
        if any(path.startswith(prefix) for prefix in NOISY_PREFIXES):
            return True
        if any(part in path for part in NOISY_SUFFIXES):
            return True
        if "site-packages" in path and "simple_agent" not in path:
            return True
        return False

    def _is_user_visible_path(self, path: str) -> bool:
        if not path:
            return False

        if path.startswith(("pipe:", "socket:", "anon_inode:")):
            return False

        if any(path.startswith(prefix) for prefix in SYSTEM_PREFIXES):
            return False

        if "/.venv/" in path or "/site-packages/" in path or "__pycache__" in path:
            return False

        if path.startswith("/home/"):
            return True

        # macOS user directories
        if path.startswith("/Users/"):
            return True

        if not path.startswith("/"):
            return "/" in path or "." in path

        if "/workspace/" in path or "/simple_agent/" in path:
            return True

        # Catch-all for tmp and other workspace-like paths
        if path.startswith("/tmp/"):
            return True

        return False

    def _parse_open_mode(self, args: str) -> str:
        if "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args or "O_TRUNC" in args:
            return "file_write"
        return "file_read"

    def _push_sys_event(self, state: TraceState, event: dict[str, Any]) -> None:
        event["ts"] = time.time()
        event["line_no"] = state.strace_line_no
        state.sys_events.append(event)

    def _handle_syscall(self, state: TraceState, pid: int, syscall: str, args: str, ret: str) -> bool:
        if state.root_pid is None and syscall == "execve":
            state.root_pid = pid

        if syscall in {"clone", "clone3", "fork", "vfork"}:
            child = re.search(r"(-?\d+)\s*$", ret)
            if child and int(child.group(1)) > 0:
                child_pid = int(child.group(1))
                state.process_parent[child_pid] = pid
                self._push_sys_event(
                    state,
                    {
                        "type": "process_spawn",
                        "pid": pid,
                        "child_pid": child_pid,
                        "label": f"spawn pid {child_pid}",
                    },
                )
                return True
            return False

        if syscall == "execve" and not ret.startswith("-1"):
            quoted = self._extract_quoted(args)
            exec_path = quoted[0] if quoted else ""
            argv = quoted[1:] if len(quoted) > 1 else []
            cmd = " ".join(argv) if argv else (exec_path or "exec")
            self._push_sys_event(
                state,
                {
                    "type": "command_exec",
                    "pid": pid,
                    "exec_path": exec_path,
                    "argv": argv,
                    "command": cmd,
                    "label": f"exec {cmd[:120]}",
                },
            )
            return True

        if syscall in {"open", "openat"}:
            quoted = self._extract_quoted(args)
            if not quoted:
                return False
            path = quoted[0]
            if self._is_noisy_path(path):
                return False
            if not self._is_user_visible_path(path):
                return False
            action_type = self._parse_open_mode(args)
            self._push_sys_event(
                state,
                {
                    "type": action_type,
                    "pid": pid,
                    "path": path,
                    "label": f"{action_type.replace('_', ' ')} {path}",
                },
            )
            return True

        if syscall in {"unlink", "unlinkat"}:
            quoted = self._extract_quoted(args)
            if not quoted:
                return False
            path = quoted[-1]
            if self._is_noisy_path(path):
                return False
            if not self._is_user_visible_path(path):
                return False
            self._push_sys_event(
                state,
                {
                    "type": "file_delete",
                    "pid": pid,
                    "path": path,
                    "label": f"delete {path}",
                },
            )
            return True

        if syscall in {"rename", "renameat", "renameat2"}:
            quoted = self._extract_quoted(args)
            if len(quoted) < 2:
                return False
            src, dst = quoted[0], quoted[1]
            if self._is_noisy_path(src) and self._is_noisy_path(dst):
                return False
            if not (self._is_user_visible_path(src) or self._is_user_visible_path(dst)):
                return False
            self._push_sys_event(
                state,
                {
                    "type": "file_rename",
                    "pid": pid,
                    "path": dst,
                    "src": src,
                    "label": f"rename {src} -> {dst}",
                },
            )
            return True

        # ── Network syscalls ──────────────────────────────────────
        if syscall == "socket":
            # socket(AF_INET, SOCK_STREAM, ...) = fd
            fd_match = re.search(r"(\d+)\s*$", ret)
            if fd_match and not ret.strip().startswith("-1"):
                fd = int(fd_match.group(1))
                family = "AF_INET" if "AF_INET" in args else ("AF_INET6" if "AF_INET6" in args else "other")
                sock_type = "STREAM" if "SOCK_STREAM" in args else ("DGRAM" if "SOCK_DGRAM" in args else "other")
                state.pid_fds[(pid, fd)] = {"family": family, "sock_type": sock_type}
            return False  # don't emit event for socket() alone

        if syscall == "connect":
            if ret.strip().startswith("-1"):
                return False
            fd_match = re.match(r"(\d+)", args.strip())
            fd = int(fd_match.group(1)) if fd_match else -1
            # Extract address: sin_addr, sin6_addr, or sun_path
            addr_match = re.search(r"sin6?_addr=inet_pton\([^,]+,\s*\"([^\"]+)\"\)", args)
            if not addr_match:
                addr_match = re.search(r"sin6?_addr=htons\(([^)]+)\)", args)
            port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)
            addr = addr_match.group(1) if addr_match else "unknown"
            port = port_match.group(1) if port_match else "?"
            # Skip local/loopback unless it looks like an API call
            if addr in ("127.0.0.1", "::1") and port not in ("80", "443", "8080", "8443"):
                return False
            dest = f"{addr}:{port}"
            sock_info = state.pid_fds.get((pid, fd), {})
            self._push_sys_event(
                state,
                {
                    "type": "net_connect",
                    "pid": pid,
                    "dest": dest,
                    "addr": addr,
                    "port": port,
                    "family": sock_info.get("family", "?"),
                    "label": f"connect {dest}",
                },
            )
            return True

        if syscall in {"sendto", "sendmsg"}:
            if ret.strip().startswith("-1"):
                return False
            fd_match = re.match(r"(\d+)", args.strip())
            fd = int(fd_match.group(1)) if fd_match else -1
            bytes_sent = 0
            ret_bytes = re.match(r"(\d+)", ret.strip())
            if ret_bytes:
                bytes_sent = int(ret_bytes.group(1))
            addr_match = re.search(r"sin6?_addr=inet_pton\([^,]+,\s*\"([^\"]+)\"\)", args)
            port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)
            addr = addr_match.group(1) if addr_match else None
            port = port_match.group(1) if port_match else None
            dest = f"{addr}:{port}" if addr else "fd={fd}"
            if addr and addr in ("127.0.0.1", "::1"):
                return False
            self._push_sys_event(
                state,
                {
                    "type": "net_send",
                    "pid": pid,
                    "dest": dest,
                    "bytes": bytes_sent,
                    "label": f"send {bytes_sent}B -> {dest}",
                },
            )
            return True

        if syscall in {"recvfrom", "recvmsg"}:
            if ret.strip().startswith("-1"):
                return False
            fd_match = re.match(r"(\d+)", args.strip())
            fd = int(fd_match.group(1)) if fd_match else -1
            bytes_recv = 0
            ret_bytes = re.match(r"(\d+)", ret.strip())
            if ret_bytes:
                bytes_recv = int(ret_bytes.group(1))
            addr_match = re.search(r"sin6?_addr=inet_pton\([^,]+,\s*\"([^\"]+)\"\)", args)
            port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)
            addr = addr_match.group(1) if addr_match else None
            port = port_match.group(1) if port_match else None
            src = f"{addr}:{port}" if addr else "fd={fd}"
            if addr and addr in ("127.0.0.1", "::1"):
                return False
            self._push_sys_event(
                state,
                {
                    "type": "net_recv",
                    "pid": pid,
                    "dest": src,
                    "bytes": bytes_recv,
                    "label": f"recv {bytes_recv}B <- {src}",
                },
            )
            return True

        return False

    def _ingest_strace_line(self, state: TraceState, line: str, line_no: int) -> bool:
        m_exit = re.match(r"^(?P<pid>\d+)\s+\+\+\+ exited with", line)
        if m_exit:
            pid = int(m_exit.group("pid"))
            self._push_sys_event(
                state,
                {
                    "type": "process_exit",
                    "pid": pid,
                    "label": f"pid {pid} exited",
                },
            )

        if "+++ exited with" in line and state.root_pid is not None:
            root_prefix = f"{state.root_pid}  +++ exited with"
            if line.startswith(root_prefix):
                state.complete = True
                return True

        m_full = LINE_RE.match(line)
        if m_full:
            return self._handle_syscall(
                state,
                int(m_full.group("pid")),
                m_full.group("syscall"),
                m_full.group("args"),
                m_full.group("ret"),
            )

        m_unfinished = UNFINISHED_RE.match(line)
        if m_unfinished:
            pid = int(m_unfinished.group("pid"))
            syscall = m_unfinished.group("syscall")
            args = m_unfinished.group("args")
            state.strace_pending[(pid, syscall)] = args
            return False

        m_resumed = RESUMED_RE.match(line)
        if m_resumed:
            pid = int(m_resumed.group("pid"))
            syscall = m_resumed.group("syscall")
            tail = m_resumed.group("tail")
            ret_match = re.search(r"=\s*(.+)$", tail)
            if not ret_match:
                return False
            ret = ret_match.group(1).strip()
            args = state.strace_pending.pop((pid, syscall), "")
            return self._handle_syscall(state, pid, syscall, args, ret)

        return False

    def list_traces(self) -> list[dict[str, Any]]:
        out = []
        for trace_id in sorted(self.traces.keys()):
            t = self.traces[trace_id]
            out.append(
                {
                    "trace_id": trace_id,
                    "status": "completed" if t.complete else "active",
                    "sys_event_count": len(t.sys_events),
                    "agent_event_count": len(t.agent_events),
                    "has_trajectory": len(t.agent_events) > 0,
                }
            )
        return out

    def _get_trace(self, trace_id: str) -> TraceState:
        trace = self.traces.get(trace_id)
        if trace is None:
            raise KeyError(trace_id)
        return trace

    def high_level_graph(self, trace_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)

        # ── Fallback: if no agent trajectory, build from strace ────────
        if not t.agent_events and t.sys_events:
            return self._strace_only_graph(t)

        nodes = []
        edges = []
        timeline = []
        prev_id = None

        tool_finish_by_id: dict[str, tuple[int, dict[str, Any]]] = {}
        for i, event in enumerate(t.agent_events):
            if event.get("event_type") not in {"tool_call_finished", "tool_call_denied", "tool_call_invalid_args", "tool_call_unknown"}:
                continue
            payload = event.get("payload") or {}
            tool_call_id = payload.get("tool_call_id")
            if tool_call_id and tool_call_id not in tool_finish_by_id:
                tool_finish_by_id[tool_call_id] = (i, event)

        consumed_finish_indices: set[int] = set()

        for i, event in enumerate(t.agent_events):
            if i in consumed_finish_indices:
                continue

            event_type = event.get("event_type", "unknown")
            payload = event.get("payload") or {}

            if event_type == "user_prompt":
                label = "Prompt"
                kind = "prompt"
                metadata = {"content": payload.get("content", "")}
            elif event_type == "tool_call_started":
                tool_call_id = payload.get("tool_call_id")
                finish_tuple = tool_finish_by_id.get(str(tool_call_id)) if tool_call_id else None
                finish_event = finish_tuple[1] if finish_tuple else None
                if finish_tuple:
                    consumed_finish_indices.add(finish_tuple[0])

                finish_payload = (finish_event or {}).get("payload") or {}
                status = "ok"
                result = finish_payload.get("result")
                if isinstance(result, dict) and result.get("ok") is False:
                    status = "error"
                elif finish_event and finish_event.get("event_type") != "tool_call_finished":
                    status = "error"

                label = f"Tool: {payload.get('tool_name', 'unknown')} ({status})"
                kind = "tool_step"
                metadata = {
                    "tool_call_id": tool_call_id,
                    "tool_name": payload.get("tool_name"),
                    "arguments": payload.get("arguments", {}),
                    "status": status,
                    "result": result,
                    "duration_ms": finish_payload.get("duration_ms"),
                }
            elif event_type == "assistant_response":
                label = "Agent Response"
                kind = "assistant_response"
                metadata = {"content": payload.get("content", "")}
            else:
                continue

            node_id = f"hl_{len(nodes)}"
            node = {
                "id": node_id,
                "label": label,
                "kind": kind,
                "metadata": metadata,
                "ts": event.get("ts"),
            }
            nodes.append(node)
            timeline.append(node)

            if prev_id is not None:
                edges.append({"source": prev_id, "target": node_id, "label": "next"})
            prev_id = node_id

        summary = {
            "prompts": sum(1 for n in nodes if n["kind"] == "prompt"),
            "tool_steps": sum(1 for n in nodes if n["kind"] == "tool_step"),
            "responses": sum(1 for n in nodes if n["kind"] == "assistant_response"),
            "trace_status": "completed" if t.complete else "active",
        }

        return {"nodes": nodes, "edges": edges, "timeline": timeline, "summary": summary}

    def _strace_only_graph(self, t: TraceState) -> dict[str, Any]:
        """Build a high-level graph from sys_events when no agent trajectory is available."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        # ── Gather command_exec events ─────────────────────────────────
        command_events = [
            e for e in t.sys_events if e.get("type") == "command_exec"
        ]

        # Filter to user-visible commands (skip runtime plumbing)
        visible_commands: list[dict[str, Any]] = []
        for cmd in command_events:
            exec_path = str(cmd.get("exec_path") or "")
            # Keep the command if it touches user-visible paths or is a
            # recognisable tool (git, python, node, etc.)
            base = Path(exec_path).name.lower() if exec_path else ""
            if base in {
                "sh", "bash", "zsh", "dash",
                "python", "python3", "node", "git",
                "cat", "ls", "grep", "find", "sed", "awk",
                "cp", "mv", "rm", "mkdir", "touch", "chmod",
                "curl", "wget",
                "npm", "npx", "pip", "pip3",
                "codex", "codex-linux-sandbox",
            }:
                visible_commands.append(cmd)
            elif self._is_user_visible_path(exec_path):
                visible_commands.append(cmd)

        # If nothing matched the allowlist, fall back to all commands
        if not visible_commands:
            visible_commands = command_events

        # ── Build per-command file & net aggregation ───────────────────
        # Sort by line_no so we can attribute file/net events to commands
        cmd_sorted = sorted(visible_commands, key=lambda e: int(e.get("line_no", 0)))
        cmd_line_nos = [int(c.get("line_no", 0)) for c in cmd_sorted]

        file_events = [
            e for e in t.sys_events
            if e.get("type") in {"file_read", "file_write", "file_delete", "file_rename"}
            and isinstance(e.get("path"), str)
            and self._is_user_visible_path(str(e.get("path")))
        ]
        net_events = [
            e for e in t.sys_events
            if e.get("type") in {"net_connect", "net_send", "net_recv"}
        ]

        def _find_owning_cmd_idx(line_no: int) -> int | None:
            """Binary-search for the latest command at or before line_no."""
            lo, hi = 0, len(cmd_line_nos) - 1
            result = -1
            while lo <= hi:
                mid = (lo + hi) // 2
                if cmd_line_nos[mid] <= line_no:
                    result = mid
                    lo = mid + 1
                else:
                    hi = mid - 1
            return result if result >= 0 else None

        cmd_files: dict[int, list[str]] = defaultdict(list)
        cmd_files_set: dict[int, set[str]] = defaultdict(set)
        for fe in file_events:
            idx = _find_owning_cmd_idx(int(fe.get("line_no", 0)))
            if idx is not None:
                path = str(fe.get("path"))
                if path not in cmd_files_set[idx]:
                    cmd_files_set[idx].add(path)
                    cmd_files[idx].append(path)

        cmd_net: dict[int, set[str]] = defaultdict(set)
        for ne in net_events:
            idx = _find_owning_cmd_idx(int(ne.get("line_no", 0)))
            if idx is not None:
                cmd_net[idx].add(str(ne.get("dest") or "unknown"))

        # ── Collapse consecutive similar commands ──────────────────────
        # e.g. many git rev-parse calls → single node
        collapsed: list[dict[str, Any]] = []
        MAX_NODES = 60

        for i, cmd in enumerate(cmd_sorted):
            label = self._short_command_label(cmd)
            pid = int(cmd.get("pid", 0))
            files_touched = cmd_files.get(i, [])
            net_dests = sorted(cmd_net.get(i, set()))

            # Try to merge with previous if same base command and no files/net
            if collapsed and not files_touched and not net_dests:
                prev = collapsed[-1]
                if prev["_base_label"] == label and not prev.get("metadata", {}).get("files") and not prev.get("metadata", {}).get("network"):
                    prev["_count"] += 1
                    prev["label"] = f"{label} (×{prev['_count']})"
                    continue

            node_data = {
                "_base_label": label,
                "_count": 1,
                "label": label,
                "kind": "sys_command",
                "metadata": {
                    "pid": pid,
                    "line_no": cmd.get("line_no"),
                    "exec_path": cmd.get("exec_path"),
                    "argv": cmd.get("argv", []),
                    "command": cmd.get("command"),
                    "files": files_touched[:20],
                    "file_count": len(files_touched),
                    "network": net_dests[:10],
                    "net_count": len(net_dests),
                },
            }
            collapsed.append(node_data)

        # Trim to MAX_NODES, keeping first few and last few
        if len(collapsed) > MAX_NODES:
            head = collapsed[: MAX_NODES // 2]
            tail = collapsed[-(MAX_NODES // 2):]
            hidden = len(collapsed) - len(head) - len(tail)
            collapsed = head + [{
                "_base_label": "",
                "_count": 0,
                "label": f"… {hidden} commands hidden …",
                "kind": "placeholder",
                "metadata": {"hidden_commands": hidden},
            }] + tail

        # ── Emit nodes and edges ───────────────────────────────────────
        prev_id: str | None = None
        for i, item in enumerate(collapsed):
            node_id = f"sys_{i}"
            node = {
                "id": node_id,
                "label": item["label"],
                "kind": item["kind"],
                "metadata": item.get("metadata", {}),
            }
            nodes.append(node)

            if prev_id is not None:
                edges.append({"source": prev_id, "target": node_id, "label": "next"})
            prev_id = node_id

        # ── Collect unique files and network endpoints for summary ─────
        all_files: set[str] = set()
        all_net: set[str] = set()
        for fe in file_events:
            all_files.add(str(fe.get("path")))
        for ne in net_events:
            all_net.add(str(ne.get("dest") or "unknown"))

        summary = {
            "commands": len(visible_commands),
            "files_touched": len(all_files),
            "net_endpoints": len(all_net),
            "strace_events": len(t.sys_events),
            "trace_status": "completed" if t.complete else "active",
        }

        return {
            "mode": "strace_only",
            "nodes": nodes,
            "edges": edges,
            "timeline": nodes,
            "summary": summary,
        }

    def _tool_start_events(self, trace: TraceState) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for event in trace.agent_events:
            if event.get("event_type") == "tool_call_started":
                payload = event.get("payload") or {}
                if payload.get("tool_call_id"):
                    out.append(event)
        return out

    def _tool_line_ranges(self, trace: TraceState) -> dict[str, tuple[int, int | None]]:
        starts = self._tool_start_events(trace)
        exec_events = sorted(
            [e for e in trace.sys_events if e.get("type") == "command_exec"],
            key=lambda x: int(x.get("line_no", 0)),
        )
        if not starts or not exec_events:
            return {}

        assigned_starts: dict[str, int] = {}
        used_indices: set[int] = set()
        cursor = 0

        def norm(text: str) -> str:
            text = re.sub(r"\s+", " ", text.strip().lower())
            return text

        def command_match_score(tool_cmd: str, exec_cmd: str) -> int:
            if not tool_cmd or not exec_cmd:
                return 0
            tool_n = norm(tool_cmd)
            exec_n = norm(exec_cmd)
            if not tool_n or not exec_n:
                return 0
            if tool_n in exec_n:
                return len(tool_n)
            tokens = [tok for tok in re.split(r"\s+", tool_n) if len(tok) >= 3]
            return sum(1 for tok in tokens if tok in exec_n)

        for start in starts:
            payload = start.get("payload") or {}
            tool_call_id = payload.get("tool_call_id")
            if not tool_call_id:
                continue

            tool_name = payload.get("tool_name")
            tool_args = payload.get("arguments") or {}
            tool_cmd = str(tool_args.get("command") or "") if tool_name == "command_exec" else ""

            chosen_idx = None

            if tool_cmd:
                best_score = 0
                for idx in range(cursor, len(exec_events)):
                    if idx in used_indices:
                        continue
                    score = command_match_score(tool_cmd, str(exec_events[idx].get("command") or ""))
                    if score > best_score:
                        best_score = score
                        chosen_idx = idx

            if chosen_idx is None:
                for idx in range(cursor, len(exec_events)):
                    if idx not in used_indices:
                        chosen_idx = idx
                        break

            if chosen_idx is None:
                continue

            used_indices.add(chosen_idx)
            cursor = min(chosen_idx + 1, len(exec_events))
            assigned_starts[tool_call_id] = int(exec_events[chosen_idx].get("line_no", 0))

        ordered_ids = [
            (event.get("payload") or {}).get("tool_call_id")
            for event in starts
            if (event.get("payload") or {}).get("tool_call_id") in assigned_starts
        ]

        ranges: dict[str, tuple[int, int | None]] = {}
        for i, call_id in enumerate(ordered_ids):
            start_line = assigned_starts[call_id]
            end_line = None
            if i + 1 < len(ordered_ids):
                next_start = assigned_starts[ordered_ids[i + 1]]
                end_line = next_start - 1
            ranges[call_id] = (start_line, end_line)

        return ranges

    def _compress_sys_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not events:
            return []

        ordered = sorted(events, key=lambda e: int(e.get("line_no", 0)))
        compressed: list[dict[str, Any]] = []

        for event in ordered:
            key = (
                event.get("type"),
                event.get("pid"),
                event.get("path"),
                event.get("command"),
                event.get("child_pid"),
                event.get("src"),
            )

            if compressed and compressed[-1].get("_key") == key:
                compressed[-1]["count"] += 1
                compressed[-1]["last_line_no"] = event.get("line_no")
                continue

            entry = dict(event)
            entry["count"] = 1
            entry["first_line_no"] = event.get("line_no")
            entry["last_line_no"] = event.get("line_no")
            entry["_key"] = key
            compressed.append(entry)

        for item in compressed:
            item.pop("_key", None)

        return compressed

    def _short_command_label(self, event: dict[str, Any]) -> str:
        argv = event.get("argv") or []
        if isinstance(argv, list) and argv:
            return " ".join(argv[:4])[:140]

        command = str(event.get("command") or "exec")
        return command[:140]

    def _find_tool_events(self, trace: TraceState, tool_call_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        start_event = None
        end_event = None

        for event in trace.agent_events:
            payload = event.get("payload") or {}
            if event.get("event_type") == "tool_call_started" and payload.get("tool_call_id") == tool_call_id:
                start_event = event
            if event.get("event_type") in {"tool_call_finished", "tool_call_denied", "tool_call_invalid_args", "tool_call_unknown"} and payload.get("tool_call_id") == tool_call_id:
                end_event = event
                break

        return start_event, end_event

    def _related_sys_events_for_tool(self, trace: TraceState, tool_call_id: str, start_event: dict[str, Any], end_event: dict[str, Any] | None) -> list[dict[str, Any]]:
        start_ts = float(start_event.get("ts") or 0)
        end_ts = float((end_event or {}).get("ts") or (start_ts + 5.0))
        if end_ts < start_ts:
            end_ts = start_ts + 5.0

        related: list[dict[str, Any]] = []
        tool_ranges = self._tool_line_ranges(trace)
        line_range = tool_ranges.get(tool_call_id)

        if line_range is not None:
            start_line, end_line = line_range
            related = [
                e
                for e in trace.sys_events
                if int(e.get("line_no", 0)) >= start_line
                and (end_line is None or int(e.get("line_no", 0)) <= end_line)
            ]

        if not related:
            related = [e for e in trace.sys_events if start_ts <= float(e.get("ts", 0)) <= (end_ts + 0.25)]

        return sorted(related, key=lambda x: int(x.get("line_no", 0)))

    def _collapse_files_into_folders(
        self,
        file_items: list[dict[str, Any]],
        source_ids: dict[str, set[str]],
        start_index: int,
        max_nodes: int = 8,
    ) -> dict[str, Any]:
        """Collapse file items into an OS-like folder hierarchy.

        Simple algorithm like a file manager:
        1.  Find the longest common prefix of all paths.
        2.  Group by the *next* path segment after the common prefix.
        3.  If a group has ≤ 2 items → emit individually.
            Otherwise → emit a single folder_group node.
        4.  If total emitted nodes > max_nodes, repeat at a higher
            (shorter prefix) level until it fits.
        5.  Children inside each folder_group are themselves grouped
            the same way so the frontend can drill down recursively.

        Returns {"nodes": [...], "edges": [...], "next_index": int}.
        """

        idx = start_index
        nodes_out: list[dict[str, Any]] = []
        edges_out: list[dict[str, Any]] = []

        if not file_items:
            return {"nodes": nodes_out, "edges": edges_out, "next_index": idx}

        paths = [item["path"] for item in file_items]
        item_by_path: dict[str, dict[str, Any]] = {it["path"]: it for it in file_items}

        # ── Find longest common directory prefix ───────────────────
        def _common_prefix(ps: list[str]) -> str:
            if not ps:
                return ""
            parts0 = ps[0].split("/")
            prefix_len = len(parts0)
            for p in ps[1:]:
                parts = p.split("/")
                prefix_len = min(prefix_len, len(parts))
                for i in range(prefix_len):
                    if parts[i] != parts0[i]:
                        prefix_len = i
                        break
            # We want directory prefix, not filename
            # Remove the last segment if it's not shared by all
            return "/".join(parts0[:prefix_len])

        def _build_children(sub_paths: list[str], depth: int = 0) -> list[dict[str, Any]]:
            """Recursively build hierarchical children list."""
            if len(sub_paths) <= 3 or depth > 10:
                # Leaf: return individual file entries
                result = []
                for p in sorted(sub_paths):
                    it = item_by_path.get(p, {})
                    result.append({
                        "kind": "resource",
                        "label": p,
                        "path": p,
                        "ops": sorted(t.replace("file_", "") for t in it.get("types", set())),
                        "count": it.get("count", 1),
                        "metadata": {"path": p},
                    })
                return result

            # Group by next path segment
            prefix = _common_prefix(sub_paths)
            prefix_parts = prefix.split("/") if prefix else []
            prefix_depth = len(prefix_parts) if prefix_parts != [""] else 0
            groups: dict[str, list[str]] = defaultdict(list)
            for p in sub_paths:
                parts = p.split("/")
                if len(parts) > prefix_depth + 1:
                    key = "/".join(parts[: prefix_depth + 1])
                else:
                    # File is at or above this depth
                    if prefix_depth > 0 and len(parts) > 1:
                        key = "/".join(parts[:prefix_depth])
                    else:
                        key = "."
                groups[key].append(p)

            # If grouping didn't help (everything in one group), try deeper
            if len(groups) <= 1 and depth < 10:
                return _build_children(sub_paths, depth + 1)

            children = []
            for gkey in sorted(groups.keys()):
                gpaths = groups[gkey]
                if len(gpaths) == 1:
                    p = gpaths[0]
                    it = item_by_path.get(p, {})
                    children.append({
                        "kind": "resource",
                        "label": p,
                        "path": p,
                        "ops": sorted(t.replace("file_", "") for t in it.get("types", set())),
                        "count": it.get("count", 1),
                        "metadata": {"path": p},
                    })
                else:
                    display = gkey if len(gkey) <= 50 else ("…" + gkey[-45:])
                    sub_children = _build_children(gpaths, depth + 1)
                    children.append({
                        "kind": "folder_group",
                        "label": f"📁 {display}/ ({len(gpaths)} files)",
                        "path": gkey,
                        "metadata": {
                            "folder": gkey,
                            "file_count": len(gpaths),
                            "children": sub_children,
                        },
                    })
            return children

        def _emit_groups(all_paths: list[str]) -> None:
            """Group paths and emit nodes + edges."""
            nonlocal idx

            if len(all_paths) <= 3:
                for p in sorted(all_paths):
                    it = item_by_path.get(p, {})
                    rid = f"res_{idx}"; idx += 1
                    nodes_out.append({
                        "id": rid, "label": p, "kind": "resource",
                        "metadata": {"path": p},
                    })
                    types = sorted(it.get("types", set()))
                    lbl = "/".join(t.replace("file_", "") for t in types)
                    if it.get("count", 1) > 1:
                        lbl += f" x{it['count']}"
                    for src in source_ids.get(p, set()):
                        edges_out.append({"source": src, "target": rid, "label": lbl})
                return

            # Build groups at increasing depth until we're under max_nodes
            prefix = _common_prefix(all_paths)
            prefix_parts = prefix.split("/") if prefix else []
            prefix_depth = len(prefix_parts) if prefix_parts != [""] else 0

            for level in range(12):
                seg_depth = prefix_depth + level
                groups: dict[str, list[str]] = defaultdict(list)
                for p in all_paths:
                    parts = p.split("/")
                    if len(parts) > seg_depth + 1:
                        # Has a directory component at this depth
                        key = "/".join(parts[: seg_depth + 1])
                    else:
                        # File is at or above this depth — group under
                        # parent dir, or "." if at root
                        if seg_depth > 0 and len(parts) > 1:
                            key = "/".join(parts[:seg_depth])
                        else:
                            key = "."
                    groups[key].append(p)

                if len(groups) <= max_nodes or level >= 11:
                    break

            # Emit one node per group
            all_src: set[str] = set()
            for p in all_paths:
                all_src |= source_ids.get(p, set())

            for gkey in sorted(groups.keys()):
                gpaths = groups[gkey]
                if len(gpaths) == 1:
                    p = gpaths[0]
                    it = item_by_path.get(p, {})
                    rid = f"res_{idx}"; idx += 1
                    nodes_out.append({
                        "id": rid, "label": p, "kind": "resource",
                        "metadata": {"path": p},
                    })
                    for src in source_ids.get(p, set()) or all_src:
                        edges_out.append({"source": src, "target": rid, "label": ""})
                else:
                    display = gkey if len(gkey) <= 50 else ("…" + gkey[-45:])
                    sub_children = _build_children(gpaths)
                    fid = f"folder_{idx}"; idx += 1
                    nodes_out.append({
                        "id": fid,
                        "label": f"📁 {display}/ ({len(gpaths)} files)",
                        "kind": "folder_group",
                        "metadata": {
                            "folder": gkey,
                            "file_count": len(gpaths),
                            "children": sub_children,
                        },
                    })
                    # Connect from all source commands
                    grp_srcs: set[str] = set()
                    for p in gpaths:
                        grp_srcs |= source_ids.get(p, set())
                    if not grp_srcs:
                        grp_srcs = all_src
                    for src in grp_srcs:
                        edges_out.append({
                            "source": src,
                            "target": fid,
                            "label": f"{len(gpaths)} files",
                        })

        _emit_groups(paths)
        return {"nodes": nodes_out, "edges": edges_out, "next_index": idx}

    def tool_graph(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)

        start_event, end_event = self._find_tool_events(t, tool_call_id)

        if start_event is None:
            raise KeyError(tool_call_id)

        tool_ranges = self._tool_line_ranges(t)
        line_range = tool_ranges.get(tool_call_id)
        related = self._related_sys_events_for_tool(t, tool_call_id, start_event, end_event)

        nodes = [
            {
                "id": "tool",
                "label": f"{(start_event.get('payload') or {}).get('tool_name', 'tool')}\n{tool_call_id}",
                "kind": "tool_call",
                "metadata": start_event.get("payload") or {},
            }
        ]
        edges = []

        if not related:
            nodes.append(
                {
                    "id": "no_data",
                    "label": "No low-level events correlated yet",
                    "kind": "placeholder",
                    "metadata": {},
                }
            )
            edges.append({"source": "tool", "target": "no_data", "label": "info"})
            return {"nodes": nodes, "edges": edges, "events": []}

        related_sorted = related
        command_events = [e for e in related_sorted if e.get("type") == "command_exec"]

        if not command_events:
            nodes.append(
                {
                    "id": "no_commands",
                    "label": "No command-level events found",
                    "kind": "placeholder",
                    "metadata": {},
                }
            )
            edges.append({"source": "tool", "target": "no_commands", "label": "info"})
            return {"nodes": nodes, "edges": edges, "events": []}

        root_pid = int(command_events[0].get("pid", 0))

        if line_range is not None and line_range[1] is None:
            start_line = line_range[0]
            exit_lines = [
                int(e.get("line_no", 0))
                for e in t.sys_events
                if e.get("type") == "process_exit"
                and int(e.get("pid", 0)) == root_pid
                and int(e.get("line_no", 0)) >= start_line
            ]
            if exit_lines:
                bounded_end = min(exit_lines)
                related_sorted = [e for e in related_sorted if int(e.get("line_no", 0)) <= bounded_end]
                command_events = [e for e in command_events if int(e.get("line_no", 0)) <= bounded_end]

        def is_descendant_or_same(pid: int, ancestor: int) -> bool:
            current = pid
            seen = set()
            while current and current not in seen:
                if current == ancestor:
                    return True
                seen.add(current)
                current = int(t.process_parent.get(current, 0))
            return False

        command_events = [
            e for e in command_events if is_descendant_or_same(int(e.get("pid", 0)), root_pid)
        ] or command_events

        max_commands = 80
        command_overflow = 0
        if len(command_events) > max_commands:
            command_overflow = len(command_events) - max_commands
            command_events = command_events[:max_commands]

        command_nodes: list[dict[str, Any]] = []
        command_ids_by_pid: dict[int, list[tuple[int, str]]] = defaultdict(list)
        command_event_by_id: dict[str, dict[str, Any]] = {}

        for i, cmd in enumerate(command_events):
            cmd_id = f"cmd_{i}"
            pid = int(cmd.get("pid", 0))
            command_ids_by_pid[pid].append((int(cmd.get("line_no", 0)), cmd_id))
            cmd_label = self._short_command_label(cmd)

            node = {
                "id": cmd_id,
                "label": cmd_label,
                "kind": "action",
                "metadata": {
                    "pid": pid,
                    "line_no": cmd.get("line_no"),
                    "exec_path": cmd.get("exec_path"),
                    "argv": cmd.get("argv", []),
                    "command": cmd.get("command"),
                },
            }
            command_nodes.append(node)
            command_event_by_id[cmd_id] = cmd

        file_events = [
            e
            for e in related_sorted
            if e.get("type") in {"file_read", "file_write", "file_delete", "file_rename"}
            and isinstance(e.get("path"), str)
            and self._is_user_visible_path(str(e.get("path")))
        ]

        # Collect network events
        net_events = [
            e
            for e in related_sorted
            if e.get("type") in {"net_connect", "net_send", "net_recv"}
        ]

        resource_nodes: dict[str, str] = {}
        resource_index = 0

        command_lookup = sorted(
            [(int(n["metadata"]["line_no"] or 0), n["metadata"]["pid"], n["id"]) for n in command_nodes],
            key=lambda x: x[0],
        )

        def match_command_for_event(event: dict[str, Any]) -> str | None:
            line = int(event.get("line_no", 0))
            pid = int(event.get("pid", 0))

            candidates = command_ids_by_pid.get(pid, [])
            best_id = None
            best_line = -1
            for cmd_line, cmd_id in candidates:
                if cmd_line <= line and cmd_line >= best_line:
                    best_line = cmd_line
                    best_id = cmd_id

            if best_id is not None:
                return best_id

            for cmd_line, _cmd_pid, cmd_id in command_lookup:
                if cmd_line <= line:
                    best_id = cmd_id
                else:
                    break
            return best_id

        file_agg: dict[tuple[str, str], dict[str, Any]] = {}
        for fe in file_events:
            cmd_id = match_command_for_event(fe)
            if cmd_id is None:
                continue
            path = str(fe.get("path"))
            key = (cmd_id, path)
            bucket = file_agg.setdefault(
                key,
                {
                    "cmd_id": cmd_id,
                    "path": path,
                    "types": set(),
                    "count": 0,
                    "line_min": int(fe.get("line_no", 0)),
                    "line_max": int(fe.get("line_no", 0)),
                },
            )
            bucket["types"].add(str(fe.get("type")))
            bucket["count"] += 1
            bucket["line_min"] = min(bucket["line_min"], int(fe.get("line_no", 0)))
            bucket["line_max"] = max(bucket["line_max"], int(fe.get("line_no", 0)))

        command_ids_with_files = {b["cmd_id"] for b in file_agg.values()}

        # Aggregate network events per command
        net_agg: dict[tuple[str, str], dict[str, Any]] = {}
        for ne in net_events:
            cmd_id = match_command_for_event(ne)
            if cmd_id is None:
                continue
            dest = str(ne.get("dest") or "unknown")
            key = (cmd_id, dest)
            bucket = net_agg.setdefault(
                key,
                {
                    "cmd_id": cmd_id,
                    "dest": dest,
                    "types": set(),
                    "bytes_total": 0,
                    "count": 0,
                },
            )
            bucket["types"].add(str(ne.get("type")))
            bucket["bytes_total"] += int(ne.get("bytes", 0))
            bucket["count"] += 1

        command_ids_with_net = {b["cmd_id"] for b in net_agg.values()}
        command_ids_with_resources = command_ids_with_files | command_ids_with_net

        tool_payload = start_event.get("payload") or {}
        tool_cmd_text = ""
        if (tool_payload.get("tool_name") or "") == "command_exec":
            tool_cmd_text = str((tool_payload.get("arguments") or {}).get("command") or "")
        tool_tokens = {tok for tok in re.findall(r"[A-Za-z0-9_./-]+", tool_cmd_text.lower()) if len(tok) >= 2}

        def command_is_relevant(node: dict[str, Any], idx: int) -> bool:
            cmd_id = node["id"]
            if idx == 0:
                return True
            if cmd_id in command_ids_with_resources:
                return True

            meta = node.get("metadata") or {}
            exec_path = str(meta.get("exec_path") or "")
            base = Path(exec_path).name.lower() if exec_path else ""

            if base and base in tool_tokens:
                return True
            if base in {"sh", "bash"}:
                return True
            return False

        filtered_nodes: list[dict[str, Any]] = []
        hidden_count = 0
        for idx, node in enumerate(command_nodes):
            if command_is_relevant(node, idx):
                if hidden_count > 0:
                    filtered_nodes.append(
                        {
                            "id": f"hidden_{idx}",
                            "label": f"runtime/setup commands hidden ({hidden_count})",
                            "kind": "placeholder",
                            "metadata": {"hidden_commands": hidden_count},
                        }
                    )
                    hidden_count = 0
                filtered_nodes.append(node)
            else:
                hidden_count += 1

        if hidden_count > 0:
            filtered_nodes.append(
                {
                    "id": "hidden_tail",
                    "label": f"runtime/setup commands hidden ({hidden_count})",
                    "kind": "placeholder",
                    "metadata": {"hidden_commands": hidden_count},
                }
            )

        prev_cmd_id: str | None = None
        visible_command_ids = {n["id"] for n in filtered_nodes if n.get("kind") == "action"}
        for node in filtered_nodes:
            nodes.append(node)
            nid = node["id"]
            if prev_cmd_id is None:
                edges.append({"source": "tool", "target": nid, "label": "start"})
            else:
                edges.append({"source": prev_cmd_id, "target": nid, "label": "next"})
            prev_cmd_id = nid

        # ── Collapse file nodes into folder hierarchy ─────────────────
        # Gather all file buckets across all visible commands,
        # then collapse them in one pass like an OS folder tree.
        all_file_items: list[dict[str, Any]] = []
        file_source_ids: dict[str, set[str]] = defaultdict(set)  # path → set of cmd_ids
        for bucket in sorted(file_agg.values(), key=lambda b: (b["line_min"], b["path"])):
            if bucket["cmd_id"] not in visible_command_ids:
                continue
            all_file_items.append(bucket)
            file_source_ids[bucket["path"]].add(bucket["cmd_id"])

        collapsed = self._collapse_files_into_folders(
            all_file_items, file_source_ids, resource_index, max_nodes=8,
        )
        nodes.extend(collapsed["nodes"])
        edges.extend(collapsed["edges"])
        resource_index = collapsed["next_index"]

        # ── Network resource nodes ─────────────────────────────────────
        net_node_ids: dict[str, str] = {}
        net_index = 0
        for bucket in sorted(net_agg.values(), key=lambda b: b["dest"]):
            if bucket["cmd_id"] not in visible_command_ids:
                continue
            dest = bucket["dest"]
            if dest not in net_node_ids:
                nid = f"net_{net_index}"
                net_index += 1
                net_node_ids[dest] = nid
                nodes.append({
                    "id": nid,
                    "label": dest,
                    "kind": "network",
                    "metadata": {"dest": dest},
                })
            types = sorted(bucket["types"])
            label = "/".join(t.replace("net_", "") for t in types)
            if bucket["bytes_total"] > 0:
                if bucket["bytes_total"] > 1024 * 1024:
                    label += f" {bucket['bytes_total'] / (1024*1024):.1f}MB"
                elif bucket["bytes_total"] > 1024:
                    label += f" {bucket['bytes_total'] / 1024:.1f}KB"
                else:
                    label += f" {bucket['bytes_total']}B"
            if bucket["count"] > 1:
                label += f" x{bucket['count']}"
            edges.append({"source": bucket["cmd_id"], "target": net_node_ids[dest], "label": label})

        if command_overflow > 0 and prev_cmd_id is not None:
            nodes.append(
                {
                    "id": "overflow",
                    "label": f"{command_overflow} additional command nodes hidden",
                    "kind": "placeholder",
                    "metadata": {"overflow": command_overflow},
                }
            )
            edges.append({"source": prev_cmd_id, "target": "overflow", "label": "next"})

        events_out = [
            {
                "type": "command_exec",
                "line_no": n["metadata"].get("line_no"),
                "pid": n["metadata"].get("pid"),
                "command": n["metadata"].get("command"),
                "exec_path": n["metadata"].get("exec_path"),
            }
            for n in command_nodes
        ]

        return {"nodes": nodes, "edges": edges, "events": events_out}

    def trace_summary(self, trace_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)

        file_agg: dict[str, dict[str, Any]] = {}
        for event in t.sys_events:
            event_type = str(event.get("type") or "")
            if event_type not in {"file_read", "file_write", "file_delete", "file_rename", "command_exec"}:
                continue

            if event_type == "command_exec":
                path = str(event.get("exec_path") or "")
                if not self._is_user_visible_path(path):
                    continue
                op = "execute"
            else:
                path = str(event.get("path") or "")
                if not self._is_user_visible_path(path):
                    continue
                op = event_type.replace("file_", "")

            if not path:
                continue

            bucket = file_agg.setdefault(path, {"path": path, "ops": set(), "count": 0})
            bucket["ops"].add(op)
            bucket["count"] += 1

        files = [{"path": v["path"], "ops": sorted(v["ops"]), "count": v["count"]} for v in file_agg.values()]
        files.sort(key=lambda x: (-x["count"], x["path"]))

        # Collect network endpoints
        net_agg: dict[str, dict[str, Any]] = {}
        for event in t.sys_events:
            event_type = str(event.get("type") or "")
            if event_type not in {"net_connect", "net_send", "net_recv"}:
                continue
            dest = str(event.get("dest") or "unknown")
            bucket = net_agg.setdefault(dest, {"dest": dest, "ops": set(), "bytes": 0, "count": 0})
            bucket["ops"].add(event_type.replace("net_", ""))
            bucket["bytes"] += int(event.get("bytes", 0))
            bucket["count"] += 1
        net_endpoints = [
            {"dest": v["dest"], "ops": sorted(v["ops"]), "bytes": v["bytes"], "count": v["count"]}
            for v in net_agg.values()
        ]
        net_endpoints.sort(key=lambda x: (-x["count"], x["dest"]))

        return {
            "trace_id": trace_id,
            "status": "completed" if t.complete else "active",
            "files": files[:250],
            "network": net_endpoints[:100],
            "totals": {
                "unique_files": len(files),
                "network_endpoints": len(net_endpoints),
                "events": len(t.sys_events),
                "agent_events": len(t.agent_events),
            },
        }

    def tool_summary(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        start_event, end_event = self._find_tool_events(t, tool_call_id)
        if start_event is None:
            raise KeyError(tool_call_id)

        related = self._related_sys_events_for_tool(t, tool_call_id, start_event, end_event)

        # If line-range / timestamp correlation found no events, try a wider
        # window as a last resort (±10s around the start timestamp).
        if not related:
            start_ts = float(start_event.get("ts") or 0)
            end_ts = float((end_event or {}).get("ts") or (start_ts + 10.0))
            related = [
                e for e in t.sys_events
                if start_ts - 1.0 <= float(e.get("ts", 0)) <= end_ts + 2.0
            ]

        file_agg: dict[str, dict[str, Any]] = {}
        for event in related:
            event_type = str(event.get("type") or "")
            if event_type not in {"file_read", "file_write", "file_delete", "file_rename", "command_exec"}:
                continue

            if event_type == "command_exec":
                path = str(event.get("exec_path") or "")
                op = "execute"
            else:
                path = str(event.get("path") or "")
                op = event_type.replace("file_", "")

            if not self._is_user_visible_path(path):
                continue

            bucket = file_agg.setdefault(path, {"path": path, "ops": set(), "count": 0})
            bucket["ops"].add(op)
            bucket["count"] += 1

        files = [{"path": v["path"], "ops": sorted(v["ops"]), "count": v["count"]} for v in file_agg.values()]
        files.sort(key=lambda x: (-x["count"], x["path"]))

        # Network endpoints for this tool
        net_agg: dict[str, dict[str, Any]] = {}
        for event in related:
            event_type = str(event.get("type") or "")
            if event_type not in {"net_connect", "net_send", "net_recv"}:
                continue
            dest = str(event.get("dest") or "unknown")
            bucket = net_agg.setdefault(dest, {"dest": dest, "ops": set(), "bytes": 0, "count": 0})
            bucket["ops"].add(event_type.replace("net_", ""))
            bucket["bytes"] += int(event.get("bytes", 0))
            bucket["count"] += 1
        net_endpoints = [
            {"dest": v["dest"], "ops": sorted(v["ops"]), "bytes": v["bytes"], "count": v["count"]}
            for v in net_agg.values()
        ]
        net_endpoints.sort(key=lambda x: (-x["count"], x["dest"]))

        return {
            "tool_call_id": tool_call_id,
            "files": files,
            "network": net_endpoints,
            "totals": {"unique_files": len(files), "network_endpoints": len(net_endpoints), "events": len(related)},
        }


app = FastAPI(title="Agent System Observability Dashboard")


def _resolve_paths() -> tuple[Path, Path]:
    env_trace = os.getenv("OBS_TRACE_DIR")
    env_events = os.getenv("OBS_EVENTS_DIR")
    if env_trace and env_events:
        return Path(env_trace).expanduser(), Path(env_events).expanduser()

    repo_root = Path(__file__).resolve().parent.parent

    candidate_pairs = [
        (
            Path("~/shared/simple_agent/obs/traces").expanduser(),
            Path("~/shared/simple_agent/obs/events").expanduser(),
        ),
        (
            Path("~/ubuntu_shared/simple_agent/obs/traces").expanduser(),
            Path("~/ubuntu_shared/simple_agent/obs/events").expanduser(),
        ),
        (repo_root / "obs" / "traces", repo_root / "obs" / "events"),
    ]

    best_pair = candidate_pairs[-1]
    best_score = -1

    for trace_dir, events_dir in candidate_pairs:
        trace_logs = len(list(trace_dir.glob("*.log"))) if trace_dir.exists() else 0
        event_logs = len(list(events_dir.glob("*.events.jsonl"))) if events_dir.exists() else 0
        score = trace_logs + event_logs

        if score > best_score:
            best_score = score
            best_pair = (trace_dir, events_dir)

    if best_score > 0:
        return best_pair

    for trace_dir, events_dir in candidate_pairs:
        if trace_dir.exists() or events_dir.exists():
            return trace_dir, events_dir

    return best_pair


WATCH_DIR, EVENTS_DIR = _resolve_paths()
MITM_DIR = WATCH_DIR.parent / "mitm" if WATCH_DIR else None

store = TraceStore(trace_dir=WATCH_DIR, events_dir=EVENTS_DIR, mitm_dir=MITM_DIR)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
async def startup() -> None:
    async def _poll_loop() -> None:
        while True:
            try:
                await store.poll_once()
            except Exception:
                pass
            await asyncio.sleep(1.0)

    asyncio.create_task(_poll_loop())


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/traces")
def list_traces() -> dict[str, Any]:
    return {"traces": store.list_traces(), "version": store.version}


@app.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "watch_dir": str(WATCH_DIR),
        "events_dir": str(EVENTS_DIR),
        "trace_count": len(store.traces),
    }


@app.get("/api/traces/{trace_id}/high-level-graph")
def high_level_graph(trace_id: str) -> dict[str, Any]:
    try:
        return store.high_level_graph(trace_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/tool-graph/{tool_call_id}")
def tool_graph(trace_id: str, tool_call_id: str) -> dict[str, Any]:
    try:
        return store.tool_graph(trace_id, tool_call_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Trace or tool call not found")


@app.get("/api/traces/{trace_id}/summary")
def trace_summary(trace_id: str) -> dict[str, Any]:
    try:
        return store.trace_summary(trace_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/tool-summary/{tool_call_id}")
def tool_summary(trace_id: str, tool_call_id: str) -> dict[str, Any]:
    try:
        return store.tool_summary(trace_id, tool_call_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Trace or tool call not found")


@app.websocket("/ws")
async def ws_updates(websocket: WebSocket) -> None:
    await websocket.accept()
    last_version = -1
    try:
        while True:
            version = store.version
            if version != last_version:
                await websocket.send_json({"type": "version", "version": version})
                last_version = version
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
