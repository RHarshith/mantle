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


@dataclass
class TraceState:
    trace_id: str
    strace_path: Path
    events_path_candidates: list[Path]
    strace_offset: int = 0
    strace_line_no: int = 0
    events_offset: int = 0
    complete: bool = False
    root_pid: int | None = None
    strace_pending: dict[tuple[int, str], str] = field(default_factory=dict)
    process_parent: dict[int, int] = field(default_factory=dict)
    sys_events: list[dict[str, Any]] = field(default_factory=list)
    agent_events: list[dict[str, Any]] = field(default_factory=list)


class TraceStore:
    def __init__(self, trace_dir: Path, events_dir: Path):
        self.trace_dir = trace_dir
        self.events_dir = events_dir
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
                self.traces[trace_id] = TraceState(
                    trace_id=trace_id,
                    strace_path=file_path,
                    events_path_candidates=self._trace_to_event_candidates(file_path),
                )
                changed = True

        for state in self.traces.values():
            if state.strace_path.exists():
                changed = self._tail_strace(state) or changed
            changed = self._tail_events(state) or changed

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
            cmd = " ".join(quoted[1:]) if len(quoted) > 1 else (quoted[0] if quoted else "exec")
            self._push_sys_event(
                state,
                {
                    "type": "command_exec",
                    "pid": pid,
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

        return False

    def _ingest_strace_line(self, state: TraceState, line: str, line_no: int) -> bool:
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

        nodes = []
        edges = []
        timeline = []
        prev_id = None

        for i, event in enumerate(t.agent_events):
            event_type = event.get("event_type", "unknown")
            payload = event.get("payload") or {}

            if event_type == "user_prompt":
                label = "Prompt"
                kind = "prompt"
                metadata = {"content": payload.get("content", "")}
            elif event_type == "tool_call_started":
                label = f"Tool: {payload.get('tool_name', 'unknown')}"
                kind = "tool_call"
                metadata = {
                    "tool_call_id": payload.get("tool_call_id"),
                    "tool_name": payload.get("tool_name"),
                    "arguments": payload.get("arguments", {}),
                }
            elif event_type in {"tool_call_finished", "tool_call_denied", "tool_call_invalid_args", "tool_call_unknown"}:
                label = "Tool Response"
                kind = "tool_response"
                metadata = payload
            elif event_type == "assistant_response":
                label = "Agent Response"
                kind = "assistant_response"
                metadata = {"content": payload.get("content", "")}
            else:
                continue

            node_id = f"hl_{i}"
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

        return {"nodes": nodes, "edges": edges, "timeline": timeline}

    def tool_graph(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)

        start_event = None
        end_event = None

        for event in t.agent_events:
            if event.get("event_type") == "tool_call_started":
                payload = event.get("payload") or {}
                if payload.get("tool_call_id") == tool_call_id:
                    start_event = event
            if event.get("event_type") == "tool_call_finished":
                payload = event.get("payload") or {}
                if payload.get("tool_call_id") == tool_call_id:
                    end_event = event
                    break

        if start_event is None:
            raise KeyError(tool_call_id)

        start_ts = float(start_event.get("ts") or 0)
        end_ts = float((end_event or {}).get("ts") or (start_ts + 5.0))
        if end_ts < start_ts:
            end_ts = start_ts + 5.0

        related = [e for e in t.sys_events if start_ts <= float(e.get("ts", 0)) <= (end_ts + 0.25)]

        nodes = [
            {
                "id": "tool",
                "label": f"{(start_event.get('payload') or {}).get('tool_name', 'tool')}\n{tool_call_id}",
                "kind": "tool_call",
                "metadata": start_event.get("payload") or {},
            }
        ]
        edges = []

        action_agg: dict[tuple, dict[str, Any]] = {}
        for event in related:
            event_type = event.get("type")
            key = (event_type, event.get("command"), event.get("path"), event.get("child_pid"))
            entry = action_agg.get(key)
            if entry is None:
                entry = {"event": event, "count": 0}
                action_agg[key] = entry
            entry["count"] += 1

        if not action_agg:
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

        action_index = 0
        resource_index = 0
        resource_nodes: dict[str, str] = {}
        flat_events = []

        for aggregated in action_agg.values():
            event = aggregated["event"]
            count = aggregated["count"]
            action_id = f"act_{action_index}"
            action_index += 1
            action_label = event.get("label", event.get("type", "action"))

            nodes.append(
                {
                    "id": action_id,
                    "label": action_label,
                    "kind": "action",
                    "metadata": {"count": count, **event},
                }
            )
            edges.append({"source": "tool", "target": action_id, "label": f"x{count}"})

            path = event.get("path")
            if isinstance(path, str) and path:
                if path not in resource_nodes:
                    res_id = f"res_{resource_index}"
                    resource_index += 1
                    resource_nodes[path] = res_id
                    nodes.append(
                        {
                            "id": res_id,
                            "label": path,
                            "kind": "resource",
                            "metadata": {"path": path},
                        }
                    )
                edges.append({"source": action_id, "target": resource_nodes[path], "label": "touches"})

            flat_events.append({"count": count, **event})

        flat_events.sort(key=lambda x: x.get("line_no", 0))
        return {"nodes": nodes, "edges": edges, "events": flat_events}


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

store = TraceStore(trace_dir=WATCH_DIR, events_dir=EVENTS_DIR)

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
