from __future__ import annotations

import asyncio
import bisect
import heapq
import json
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from mantle.taint_engine import run_taint_analysis
from mantle.taint_rules import TrustPolicy

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

KNOWN_LLM_HOSTS = {
    "api.openai.com",
    "chat-api.tamu.ai",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
    "api.deepseek.com",
}


@dataclass
class TraceState:
    trace_id: str
    trace_path: Path
    events_path_candidates: list[Path]
    trace_format: str = "ebpf"
    trace_offset: int = 0
    trace_line_no: int = 0
    events_offset: int = 0
    mitm_offset: int = 0
    mitm_path: Path | None = None
    complete: bool = False
    root_pid: int | None = None
    pending_syscalls: dict[tuple[int, str], str] = field(default_factory=dict)
    process_parent: dict[int, int] = field(default_factory=dict)
    pid_fds: dict[tuple[int, int], dict[str, Any]] = field(default_factory=dict)  # (pid, fd) -> socket info
    mitm_endpoints: set[str] = field(default_factory=set)
    mitm_intervals: list[tuple[float, float, str]] = field(default_factory=list)  # (start_ts, end_ts, host:port) sorted by start_ts
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
        name = trace_file.name
        no_ext = trace_file.stem
        candidates = [
            self.events_dir / f"{name}.events.jsonl",
            self.events_dir / f"{no_ext}.events.jsonl",
        ]

        # Preferred naming for traces generated as <id>.ebpf.jsonl is <id>.events.jsonl.
        if name.endswith(".ebpf.jsonl"):
            base = name[: -len(".ebpf.jsonl")]
            candidates.append(self.events_dir / f"{base}.events.jsonl")

        # De-duplicate while preserving order.
        seen: set[Path] = set()
        unique: list[Path] = []
        for cand in candidates:
            if cand in seen:
                continue
            seen.add(cand)
            unique.append(cand)
        return unique

    async def poll_once(self) -> None:
        changed = False

        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.events_dir.mkdir(parents=True, exist_ok=True)

        trace_files = sorted(self.trace_dir.glob("*.ebpf.jsonl"))
        for file_path in trace_files:
            trace_id = file_path.name
            if trace_id not in self.traces:
                mitm_path = self._find_mitm_file(trace_id) if self.mitm_dir else None
                self.traces[trace_id] = TraceState(
                    trace_id=trace_id,
                    trace_path=file_path,
                    events_path_candidates=self._trace_to_event_candidates(file_path),
                    mitm_path=mitm_path,
                )
                changed = True

        for state in self.traces.values():
            if not state.mitm_path and self.mitm_dir:
                state.mitm_path = self._find_mitm_file(state.trace_id)

            if state.trace_path.exists():
                changed = self._tail_ebpf_events(state) or changed
            has_native = self._tail_events(state)
            changed = has_native or changed
            # If no native events FILE exists, continuously tail mitmproxy capture
            # (don't check `state.agent_events` — that becomes non-empty after the
            #  first MITM read and would block all subsequent reads)
            if state.mitm_path:
                native_file_exists = any(
                    c.exists() for c in state.events_path_candidates
                )
                if native_file_exists:
                    # Native events provide agent events; only extract
                    # network interval data from MITM for proxy resolution.
                    changed = self._tail_mitm_events(state, intervals_only=True) or changed
                else:
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
        no_ext = Path(trace_id).stem
        candidates = [
            self.mitm_dir / f"{stem}.mitm.jsonl",
            self.mitm_dir / f"{no_ext}.mitm.jsonl",
        ]
        if trace_id.endswith(".ebpf.jsonl"):
            base = trace_id[: -len(".ebpf.jsonl")]
            candidates.append(self.mitm_dir / f"{base}.mitm.jsonl")
        for cand in candidates:
            if cand.exists():
                return cand
        return None

    def _tail_mitm_events(self, state: TraceState, intervals_only: bool = False) -> bool:
        """Parse mitmproxy capture JSONL into agent_events format.
        
        When intervals_only=True, only extract network endpoint / interval
        data (for proxy resolution) without appending agent events (which
        would duplicate events already provided by native event files).
        """
        if not state.mitm_path or not state.mitm_path.exists():
            return False

        lines, new_offset = self._read_new_lines(state.mitm_path, state.mitm_offset)
        if not lines:
            return False

        seq = len(state.agent_events)

        def _get_string_content(content: Any) -> str:
            if content is None:
                return ""
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                texts: list[str] = []
                for item in content:
                    if isinstance(item, str):
                        texts.append(item)
                        continue
                    if not isinstance(item, dict):
                        continue
                    text_value = item.get("text")
                    if isinstance(text_value, str):
                        texts.append(text_value)
                        continue
                    text_value = item.get("output_text")
                    if isinstance(text_value, str):
                        texts.append(text_value)
                        continue
                    if item.get("type") in {"input_text", "output_text", "summary_text"}:
                        maybe_text = item.get("text")
                        if isinstance(maybe_text, str):
                            texts.append(maybe_text)
                return "\n".join([t for t in texts if t])
            if isinstance(content, dict):
                if isinstance(content.get("text"), str):
                    return str(content.get("text"))
                if isinstance(content.get("output_text"), str):
                    return str(content.get("output_text"))
                if isinstance(content.get("content"), (str, list, dict)):
                    return _get_string_content(content.get("content"))
                return json.dumps(content, ensure_ascii=False)
            return str(content)

        def _extract_user_prompts(messages: list[dict[str, Any]]) -> list[str]:
            prompts: list[str] = []
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                role = msg.get("role")
                if role == "user":
                    text = _get_string_content(msg.get("content"))
                    if text:
                        prompts.append(text)
                    continue

                msg_type = msg.get("type")
                if msg_type == "message" and msg.get("role") == "user":
                    text = _get_string_content(msg.get("content"))
                    if text:
                        prompts.append(text)
            return prompts

        def _extract_available_tools(req: dict[str, Any]) -> list[str]:
            tools = req.get("tools")
            if not isinstance(tools, list):
                return []

            out: list[str] = []
            for item in tools:
                if not isinstance(item, dict):
                    continue

                # Responses API function tools usually carry `name`.
                if isinstance(item.get("name"), str) and item.get("name"):
                    out.append(str(item.get("name")))
                    continue

                # Some formats embed function metadata.
                fn = item.get("function")
                if isinstance(fn, dict) and isinstance(fn.get("name"), str) and fn.get("name"):
                    out.append(str(fn.get("name")))
                    continue

                t = item.get("type")
                if isinstance(t, str) and t:
                    out.append(t)

            # Preserve order while de-duplicating.
            seen: set[str] = set()
            uniq: list[str] = []
            for name in out:
                if name in seen:
                    continue
                seen.add(name)
                uniq.append(name)
            return uniq

        def _parse_responses_sse(raw: str) -> dict[str, Any]:
            parsed: dict[str, Any] = {
                "assistant_messages": [],
                "tool_calls": [],
                "reasoning_summary": "",
            }
            if not raw:
                return parsed

            message_by_item: dict[str, dict[str, Any]] = {}
            tool_by_item: dict[str, dict[str, Any]] = {}
            reasoning_parts: dict[tuple[str, int], str] = {}

            for line in raw.splitlines():
                if not line.startswith("data: "):
                    continue
                payload = line[6:].strip()
                if not payload or payload == "[DONE]":
                    continue
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue

                dtype = data.get("type", "")
                if dtype == "response.output_item.added":
                    item = data.get("item") or {}
                    item_id = str(item.get("id") or "")
                    item_type = item.get("type")
                    if item_type == "message":
                        message_by_item[item_id] = {
                            "id": item_id,
                            "role": item.get("role"),
                            "phase": item.get("phase"),
                            "parts": [],
                        }
                    elif item_type == "function_call":
                        tool_by_item[item_id] = {
                            "id": item_id,
                            "tool_call_id": item.get("call_id") or item_id,
                            "tool_name": item.get("name") or "unknown",
                            "arguments": item.get("arguments") or "",
                        }
                    continue

                if dtype in {"response.output_text.delta", "response.text.delta"}:
                    item_id = str(data.get("item_id") or "")
                    if item_id in message_by_item:
                        message_by_item[item_id]["parts"].append(str(data.get("delta", "")))
                    continue

                if dtype == "response.output_item.done":
                    item = data.get("item") or {}
                    item_id = str(item.get("id") or "")
                    item_type = item.get("type")
                    if item_type == "message":
                        entry = message_by_item.setdefault(
                            item_id,
                            {
                                "id": item_id,
                                "role": item.get("role"),
                                "phase": item.get("phase"),
                                "parts": [],
                            },
                        )
                        text = _get_string_content(item.get("content"))
                        if text:
                            entry["parts"] = [text]
                    elif item_type == "function_call":
                        entry = tool_by_item.setdefault(
                            item_id,
                            {
                                "id": item_id,
                                "tool_call_id": item.get("call_id") or item_id,
                                "tool_name": item.get("name") or "unknown",
                                "arguments": "",
                            },
                        )
                        entry["arguments"] = item.get("arguments") or entry.get("arguments") or ""
                    continue

                if dtype == "response.function_call_arguments.delta":
                    item_id = str(data.get("item_id") or "")
                    if item_id in tool_by_item:
                        tool_by_item[item_id]["arguments"] = str(tool_by_item[item_id].get("arguments") or "") + str(data.get("delta", ""))
                    continue

                if dtype == "response.reasoning_summary_text.delta":
                    key = (str(data.get("item_id") or ""), int(data.get("summary_index") or 0))
                    reasoning_parts[key] = reasoning_parts.get(key, "") + str(data.get("delta", ""))
                    continue

                if dtype == "response.reasoning_summary_text.done":
                    key = (str(data.get("item_id") or ""), int(data.get("summary_index") or 0))
                    reasoning_parts[key] = str(data.get("text") or "")

            parsed["assistant_messages"] = [
                {
                    "role": msg.get("role") or "assistant",
                    "phase": msg.get("phase") or "final",
                    "content": "".join(msg.get("parts") or []).strip(),
                }
                for msg in message_by_item.values()
                if "".join(msg.get("parts") or []).strip()
            ]

            tool_calls: list[dict[str, Any]] = []
            for tc in tool_by_item.values():
                raw_args = str(tc.get("arguments") or "")
                args_obj: Any
                try:
                    args_obj = json.loads(raw_args) if raw_args else {}
                except json.JSONDecodeError:
                    args_obj = {"_raw": raw_args}
                tool_calls.append(
                    {
                        "tool_call_id": tc.get("tool_call_id"),
                        "tool_name": tc.get("tool_name") or "unknown",
                        "arguments": args_obj,
                    }
                )
            parsed["tool_calls"] = tool_calls

            if reasoning_parts:
                keys = sorted(reasoning_parts.keys(), key=lambda x: (x[0], x[1]))
                parsed["reasoning_summary"] = "\n".join([reasoning_parts[k] for k in keys if reasoning_parts[k]]).strip()

            return parsed

        def _parse_chat_completion_response(resp: dict[str, Any]) -> dict[str, Any]:
            parsed: dict[str, Any] = {"assistant_messages": [], "tool_calls": []}
            choices = resp.get("choices")
            if not isinstance(choices, list):
                return parsed

            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message") or {}
                if not isinstance(message, dict):
                    continue

                content = _get_string_content(message.get("content"))
                if content.strip():
                    parsed["assistant_messages"].append(
                        {
                            "role": message.get("role") or "assistant",
                            "phase": "final",
                            "content": content.strip(),
                        }
                    )

                tool_calls = message.get("tool_calls")
                if not isinstance(tool_calls, list):
                    continue
                for tool in tool_calls:
                    if not isinstance(tool, dict):
                        continue
                    fn = tool.get("function") or {}
                    raw_args = fn.get("arguments") if isinstance(fn, dict) else ""
                    args_obj: Any = {}
                    if isinstance(raw_args, str) and raw_args:
                        try:
                            args_obj = json.loads(raw_args)
                        except json.JSONDecodeError:
                            args_obj = {"_raw": raw_args}
                    parsed["tool_calls"].append(
                        {
                            "tool_call_id": tool.get("id") or tool.get("call_id") or "",
                            "tool_name": fn.get("name") if isinstance(fn, dict) else "unknown",
                            "arguments": args_obj,
                        }
                    )
            return parsed

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
            model = record.get("model") or req_body.get("model") or ""
            endpoint = record.get("url") or ""
            status_code = record.get("status_code")

            if endpoint:
                try:
                    parsed_url = urlparse(str(endpoint))
                    host = parsed_url.hostname or ""
                    if host:
                        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                        state.mitm_endpoints.add(f"{host}:{port}")
                except Exception:
                    pass

            messages = req_body.get("messages", [])
            if not messages and "input" in req_body:
                messages = req_body.get("input") or []
            if not isinstance(messages, list):
                messages = []

            tool_results_for_turn: list[dict[str, Any]] = []
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                is_tool_chat = msg.get("role") == "tool"
                is_tool_resp = msg.get("type") == "function_call_output"
                if not (is_tool_chat or is_tool_resp):
                    continue
                tid = msg.get("tool_call_id") or msg.get("call_id", "")
                raw_content = msg.get("content", msg.get("output", ""))
                text = _get_string_content(raw_content)
                parsed_result: Any
                try:
                    parsed_result = json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    parsed_result = {"output": text}
                tool_results_for_turn.append(
                    {
                        "tool_call_id": tid,
                        "result": parsed_result,
                    }
                )

            sse_parsed = _parse_responses_sse(str(resp_body.get("_raw") or ""))
            chat_fallback = _parse_chat_completion_response(resp_body)
            if not sse_parsed.get("assistant_messages") and chat_fallback.get("assistant_messages"):
                sse_parsed["assistant_messages"] = chat_fallback["assistant_messages"]
            if not sse_parsed.get("tool_calls") and chat_fallback.get("tool_calls"):
                sse_parsed["tool_calls"] = chat_fallback["tool_calls"]
            available_tools = _extract_available_tools(req_body)

            if not intervals_only:
                seq += 1
                state.agent_events.append(
                    {
                        "ts": ts,
                        "seq": seq,
                        "event_type": "api_call",
                        "payload": {
                            "endpoint": endpoint,
                            "method": record.get("method", "POST"),
                            "model": model,
                            "duration_ms": duration_ms,
                            "status_code": status_code,
                            "reasoning": (req_body.get("reasoning") or {}).get("effort"),
                            "available_tools": available_tools,
                        },
                        "_source": "mitm",
                    }
                )

            # Build interval mapping: BPF traffic for this MITM call occurred
            # between [response_ts - duration, response_ts].  We store these
            # sorted intervals so _with_inferred_net_dest can binary-search.
            if endpoint and ts > 0:
                try:
                    pu = urlparse(str(endpoint))
                    ihost = pu.hostname or ""
                    if ihost:
                        iport = pu.port or (443 if pu.scheme == "https" else 80)
                        dest_label = f"{ihost}:{iport}"
                        dur_s = (float(duration_ms) / 1000.0) if duration_ms else 5.0
                        start_ts = ts - dur_s
                        state.mitm_intervals.append((start_ts, ts, dest_label))
                except Exception:
                    pass

            if not intervals_only:
                instructions = req_body.get("instructions")
                if isinstance(instructions, str) and instructions.strip():
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "system_instruction",
                            "payload": {
                                "content": instructions,
                            },
                            "_source": "mitm",
                        }
                    )

                user_prompts = _extract_user_prompts(messages)
                if user_prompts:
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "user_prompt_batch",
                            "payload": {
                                "prompts": user_prompts,
                                "count": len(user_prompts),
                            },
                            "_source": "mitm",
                        }
                    )

                if sse_parsed.get("reasoning_summary"):
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "reasoning_summary",
                            "payload": {
                                "content": sse_parsed.get("reasoning_summary", ""),
                            },
                            "_source": "mitm",
                        }
                    )

                # Some turns return tool_calls with empty assistant content.
                # Emit one assistant_response node so the first tool-calling response
                # is visible in the high-level graph without duplicating nodes.
                if not sse_parsed.get("assistant_messages") and sse_parsed.get("tool_calls"):
                    calls = sse_parsed.get("tool_calls") or []
                    names = [str(c.get("tool_name") or "tool") for c in calls if c.get("tool_name")]
                    preview = ", ".join(names[:3]) if names else "tool"
                    if len(names) > 3:
                        preview = f"{preview}, +{len(names) - 3} more"
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "assistant_response",
                            "payload": {
                                "content": f"Calling tool: {preview}",
                                "phase": "tool_call",
                                "model": model,
                                "tool_calls": calls,
                                "tool_results": [],
                            },
                            "_source": "mitm",
                        }
                    )

                for tool_start in sse_parsed.get("tool_calls", []):
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "tool_call_started",
                            "payload": {
                                "tool_call_id": tool_start.get("tool_call_id") or f"mitm_tc_{seq}",
                                "tool_name": tool_start.get("tool_name") or "unknown",
                                "arguments": tool_start.get("arguments") or {},
                            },
                            "_source": "mitm",
                        }
                    )

                # Deduplicate and emit tool results from previous turns
                # Supports both Chat Completions API (role=tool) and
                # Responses API (type=function_call_output)
                emitted_tool_results = {e["payload"]["tool_call_id"] for e in state.agent_events if e.get("event_type") == "tool_call_finished"}
                for msg in messages:
                    # Chat Completions format: role=tool, tool_call_id, content
                    is_tool_chat = msg.get("role") == "tool"
                    # Responses API format: type=function_call_output, call_id, output
                    is_tool_resp = msg.get("type") == "function_call_output"

                    if not (is_tool_chat or is_tool_resp):
                        continue

                    tid = msg.get("tool_call_id") or msg.get("call_id", "")
                    if not tid or tid in emitted_tool_results:
                        continue

                    emitted_tool_results.add(tid)
                    raw_content = msg.get("content", msg.get("output", ""))
                    tool_content = _get_string_content(raw_content)
                    try:
                        result = json.loads(tool_content)
                    except (json.JSONDecodeError, TypeError):
                        result = {"output": tool_content}

                    # Try to find the tool name from a matching function_call item
                    tool_name = "unknown"
                    for m2 in messages:
                        if m2.get("type") == "function_call" and m2.get("call_id") == tid:
                            tool_name = m2.get("name", "unknown")
                            break

                    seq += 1
                    state.agent_events.append({
                        "ts": ts,
                        "seq": seq,
                        "event_type": "tool_call_finished",
                        "payload": {
                            "tool_call_id": tid,
                            "tool_name": tool_name,
                            "duration_ms": duration_ms,
                            "result": result,
                        },
                        "_source": "mitm",
                    })

                for assistant_msg in sse_parsed.get("assistant_messages", []):
                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": ts,
                            "seq": seq,
                            "event_type": "assistant_response",
                            "payload": {
                                "content": assistant_msg.get("content", ""),
                                "phase": assistant_msg.get("phase"),
                                "model": model,
                                "tool_calls": sse_parsed.get("tool_calls") or [],
                                "tool_results": tool_results_for_turn,
                            },
                            "_source": "mitm",
                        }
                    )

        state.mitm_offset = new_offset
        return True

    def _tail_trace_log(self, state: TraceState) -> bool:
        lines, new_offset = self._read_new_lines(state.trace_path, state.trace_offset)
        if not lines:
            return False

        changed = False
        for line in lines:
            state.trace_line_no += 1
            changed = self._ingest_trace_line(state, line, state.trace_line_no) or changed

        state.trace_offset = new_offset
        return changed

    def _tail_ebpf_events(self, state: TraceState) -> bool:
        lines, new_offset = self._read_new_lines(state.trace_path, state.trace_offset)
        if not lines:
            return False

        changed = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            state.trace_line_no += 1
            event_type = str(event.get("type") or "")

            normalized = dict(event)
            normalized["line_no"] = int(normalized.get("line_no") or state.trace_line_no)
            normalized["ts"] = float(normalized.get("ts") or time.time())
            state.sys_events.append(normalized)
            changed = True

            if event_type == "command_exec" and state.root_pid is None:
                state.root_pid = int(normalized.get("pid", 0)) or None

            if event_type == "process_spawn":
                parent_pid = int(normalized.get("pid", 0))
                child_pid = int(normalized.get("child_pid", 0))
                if parent_pid > 0 and child_pid > 0:
                    state.process_parent[child_pid] = parent_pid

            if event_type == "process_exit" and state.root_pid is not None:
                pid = int(normalized.get("pid", 0))
                if pid == state.root_pid:
                    state.complete = True

        state.trace_offset = new_offset
        return changed

    def _extract_quoted(self, text: str) -> list[str]:
        return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)

    def _is_noisy_path(self, path: str) -> bool:
        if any(path.startswith(prefix) for prefix in NOISY_PREFIXES):
            return True
        if any(part in path for part in NOISY_SUFFIXES):
            return True
        if "site-packages" in path and "mantle" not in path:
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

        if "/workspace/" in path or "/mantle/" in path:
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
        event["line_no"] = state.trace_line_no
        state.sys_events.append(event)

    def _extract_fd(self, args: str) -> int:
        fd_match = re.match(r"(\d+)", args.strip())
        return int(fd_match.group(1)) if fd_match else -1

    def _socket_family(self, args: str) -> str:
        if "AF_INET6" in args:
            return "AF_INET6"
        if "AF_INET" in args:
            return "AF_INET"
        if "AF_UNIX" in args:
            return "AF_UNIX"
        return "other"

    def _socket_transport(self, args: str) -> str:
        if "SOCK_DGRAM" in args:
            return "udp"
        if "SOCK_STREAM" in args:
            return "tcp"
        return "other"

    def _parse_socket_address(self, args: str) -> dict[str, str]:
        # AF_INET/AF_INET6: prefer inet_pton output when available.
        addr_match = re.search(r"sin6?_addr=inet_pton\([^,]+,\s*\"([^\"]+)\"\)", args)
        if not addr_match:
            # Some traces contain inet_addr("x.x.x.x") style output.
            addr_match = re.search(r"sin_addr=inet_addr\(\"([^\"]+)\"\)", args)
        port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)

        if addr_match:
            addr = addr_match.group(1)
            port = port_match.group(1) if port_match else "?"
            return {
                "host": addr,
                "port": port,
                "endpoint": f"{addr}:{port}",
            }

        # AF_UNIX
        unix_match = re.search(r"sun_path=\"([^\"]+)\"", args)
        if unix_match:
            path = unix_match.group(1)
            return {
                "host": "unix",
                "port": "",
                "endpoint": f"unix:{path}",
            }

        return {"host": "unknown", "port": "", "endpoint": "unknown"}

    def _parse_ret_status(self, ret: str) -> dict[str, Any]:
        raw = ret.strip()
        if raw.startswith("-1"):
            err_match = re.search(r"\b([A-Z][A-Z0-9_]+)\b", raw)
            err_code = err_match.group(1) if err_match else "ERROR"
            return {"ok": False, "error": err_code, "raw": raw}

        n_match = re.match(r"(\d+)", raw)
        return {
            "ok": True,
            "value": int(n_match.group(1)) if n_match else 0,
            "raw": raw,
        }

    def _network_display_label(self, event: dict[str, Any]) -> str:
        dest = str(event.get("dest") or "unknown")
        transport = str(event.get("transport") or "").strip()
        family = str(event.get("family") or "").strip()
        inferred = str(event.get("inferred_dest") or "").strip()

        if inferred:
            # Show only the resolved destination — the proxy address
            # (e.g. 127.0.0.1:8899) is an implementation detail.
            base = inferred
            if transport and transport != "other":
                return f"{transport} {base}"
            return base

        if dest.startswith("fd="):
            if transport:
                return f"{transport} unresolved ({dest})"
            if family:
                return f"{family} unresolved ({dest})"
            return f"unresolved ({dest})"

        if transport and transport != "other":
            return f"{transport} {dest}"
        if family and family != "other":
            return f"{family} {dest}"
        return dest

    def _with_inferred_net_dest(self, trace: TraceState, event: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(event)
        dest = str(enriched.get("dest") or "")
        if not trace.mitm_endpoints or enriched.get("inferred_dest"):
            return enriched

        def _best_endpoint_for_event_ts(ts: float) -> str:
            """Map a BPF timestamp to the MITM call whose active interval
            contains it.  Falls back to nearest interval within 2 s, then
            to global MITM endpoints."""
            if ts <= 0:
                # No usable timestamp — fall back to global endpoints
                non_llm = sorted(
                    ep for ep in trace.mitm_endpoints if ep.split(":", 1)[0] not in KNOWN_LLM_HOSTS
                )
                return non_llm[0] if non_llm else sorted(trace.mitm_endpoints)[0]

            intervals = trace.mitm_intervals
            if not intervals:
                # No interval data yet — fall back to global endpoints
                non_llm = sorted(
                    ep for ep in trace.mitm_endpoints if ep.split(":", 1)[0] not in KNOWN_LLM_HOSTS
                )
                return non_llm[0] if non_llm else sorted(trace.mitm_endpoints)[0]

            # Ensure intervals are sorted by start_ts for binary search
            # (they are appended in chronological order during ingestion,
            #  but sort defensively on first use).
            if not hasattr(trace, '_mitm_intervals_sorted'):
                trace.mitm_intervals.sort(key=lambda x: x[0])
                trace._mitm_intervals_sorted = True  # type: ignore[attr-defined]

            # Binary search: find intervals that could contain `ts`.
            # An interval (s, e, label) contains ts if s <= ts <= e.
            # Use bisect on start_ts to narrow the search window.
            start_keys = [iv[0] for iv in intervals]
            # All intervals starting at or before ts could contain it
            right = bisect.bisect_right(start_keys, ts)

            best_match: str | None = None
            best_dist = float("inf")

            # Check a small window of intervals around the insertion point
            # that could overlap with ts.  We look back further because an
            # interval starting well before `ts` may still contain it if it
            # has a long duration.
            search_range = range(max(0, right - 5), min(len(intervals), right + 2))
            for i in search_range:
                s, e, label = intervals[i]
                if s <= ts <= e:
                    # Exact containment — prefer this
                    if best_match is None or (label.split(":", 1)[0] not in KNOWN_LLM_HOSTS):
                        best_match = label
                        best_dist = 0
                else:
                    # Near miss — track closest within 2s tolerance
                    d = min(abs(ts - s), abs(ts - e))
                    if d < best_dist and d <= 2.0:
                        best_dist = d
                        best_match = label

            if best_match:
                return best_match

            # Nothing within 2s — fall back to global MITM endpoints
            non_llm = sorted(
                ep for ep in trace.mitm_endpoints if ep.split(":", 1)[0] not in KNOWN_LLM_HOSTS
            )
            if non_llm:
                return non_llm[0]
            return sorted(trace.mitm_endpoints)[0]

        # Map proxy-local traffic to known MITM upstream endpoints so users can
        # see where traffic really went (for example git clone -> github.com:443).
        proxy_dests = {"127.0.0.1:8899", "127.0.0.1:8898", "localhost:8899", "localhost:8898"}
        if dest.startswith("fd=") or dest in proxy_dests:
            enriched["inferred_dest"] = _best_endpoint_for_event_ts(float(event.get("ts") or 0.0))
        return enriched

    def _command_network_targets(self, command: str) -> list[str]:
        targets: list[str] = []
        if not command:
            return targets

        # URLs like https://github.com/org/repo.git
        for m in re.finditer(r"https?://([^\s/:]+)(?::(\d+))?", command):
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else (443 if command[m.start():].startswith("https://") else 80)
            targets.append(f"{host}:{port}")

        # SSH-style git remotes: git@github.com:org/repo.git
        for m in re.finditer(r"git@([^\s:]+):", command):
            host = m.group(1)
            targets.append(f"{host}:22")

        # Keep order while de-duplicating.
        seen: set[str] = set()
        uniq: list[str] = []
        for t in targets:
            if t in seen:
                continue
            seen.add(t)
            uniq.append(t)
        return uniq

    def _handle_syscall(self, state: TraceState, pid: int, syscall: str, args: str, ret: str) -> bool:
        if state.root_pid is None and syscall == "execve":
            state.root_pid = pid

        if syscall in {"clone", "clone3", "fork", "vfork"}:
            child = re.search(r"(-?\d+)\s*$", ret)
            if child and int(child.group(1)) > 0:
                child_pid = int(child.group(1))
                state.process_parent[child_pid] = pid
                # Child inherits open fds from parent; keep socket destinations.
                for (ppid, fd), info in list(state.pid_fds.items()):
                    if ppid != pid:
                        continue
                    state.pid_fds[(child_pid, fd)] = dict(info)
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
                state.pid_fds[(pid, fd)] = {
                    "family": self._socket_family(args),
                    "transport": self._socket_transport(args),
                }
            return False  # don't emit event for socket() alone

        if syscall == "close":
            fd = self._extract_fd(args)
            if fd >= 0:
                state.pid_fds.pop((pid, fd), None)
            return False

        if syscall == "connect":
            fd = self._extract_fd(args)
            status = self._parse_ret_status(ret)
            parsed_addr = self._parse_socket_address(args)
            dest = parsed_addr["endpoint"]
            sock_info = state.pid_fds.get((pid, fd), {})
            if fd >= 0 and status.get("ok"):
                sock_info["dest"] = dest
                state.pid_fds[(pid, fd)] = sock_info
            transport = str(sock_info.get("transport") or self._socket_transport(args))
            family = str(sock_info.get("family") or self._socket_family(args))
            label_status = "ok" if status.get("ok") else f"failed ({status.get('error')})"
            self._push_sys_event(
                state,
                {
                    "type": "net_connect",
                    "pid": pid,
                    "fd": fd,
                    "dest": dest,
                    "addr": parsed_addr["host"],
                    "port": parsed_addr["port"],
                    "family": family,
                    "transport": transport,
                    "ok": status.get("ok", False),
                    "error": status.get("error"),
                    "label": f"connect {transport} {dest} [{label_status}]",
                },
            )
            return True

        if syscall in {"sendto", "sendmsg"}:
            fd = self._extract_fd(args)
            status = self._parse_ret_status(ret)
            bytes_sent = int(status.get("value", 0)) if status.get("ok") else 0
            parsed_addr = self._parse_socket_address(args)
            sock_info = state.pid_fds.get((pid, fd), {})
            transport = str(sock_info.get("transport") or "other")
            family = str(sock_info.get("family") or "other")
            dest = parsed_addr["endpoint"] if parsed_addr["endpoint"] != "unknown" else str(sock_info.get("dest") or f"fd={fd}")
            label_status = "ok" if status.get("ok") else f"failed ({status.get('error')})"
            self._push_sys_event(
                state,
                {
                    "type": "net_send",
                    "pid": pid,
                    "fd": fd,
                    "dest": dest,
                    "bytes": bytes_sent,
                    "family": family,
                    "transport": transport,
                    "ok": status.get("ok", False),
                    "error": status.get("error"),
                    "label": f"send {bytes_sent}B -> {dest} [{label_status}]",
                },
            )
            return True

        if syscall in {"recvfrom", "recvmsg"}:
            fd = self._extract_fd(args)
            status = self._parse_ret_status(ret)
            bytes_recv = int(status.get("value", 0)) if status.get("ok") else 0
            parsed_addr = self._parse_socket_address(args)
            sock_info = state.pid_fds.get((pid, fd), {})
            transport = str(sock_info.get("transport") or "other")
            family = str(sock_info.get("family") or "other")
            src = parsed_addr["endpoint"] if parsed_addr["endpoint"] != "unknown" else str(sock_info.get("dest") or f"fd={fd}")
            label_status = "ok" if status.get("ok") else f"failed ({status.get('error')})"
            self._push_sys_event(
                state,
                {
                    "type": "net_recv",
                    "pid": pid,
                    "fd": fd,
                    "dest": src,
                    "bytes": bytes_recv,
                    "family": family,
                    "transport": transport,
                    "ok": status.get("ok", False),
                    "error": status.get("error"),
                    "label": f"recv {bytes_recv}B <- {src} [{label_status}]",
                },
            )
            return True

        return False

    def _ingest_trace_line(self, state: TraceState, line: str, line_no: int) -> bool:
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
            state.pending_syscalls[(pid, syscall)] = args
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
            args = state.pending_syscalls.pop((pid, syscall), "")
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

    def _nearest_line_for_ts(self, sys_events: list[dict[str, Any]], ts: float) -> int:
        if not sys_events:
            return 0
        best_line = int(sys_events[0].get("line_no", 0))
        best_dist = abs(float(sys_events[0].get("ts", 0.0)) - ts)
        for event in sys_events[1:]:
            dist = abs(float(event.get("ts", 0.0)) - ts)
            if dist < best_dist:
                best_dist = dist
                best_line = int(event.get("line_no", 0))
        return best_line

    def _is_relevant_trunk_sys_event(self, event: dict[str, Any]) -> bool:
        et = str(event.get("type") or "")
        if et == "command_exec":
            return True
        if et in {"net_connect", "net_send", "net_recv"}:
            return True
        if et in {"file_write", "file_delete", "file_rename"}:
            return True
        if et == "file_read":
            return True
        return False

    def _agent_event_to_git_node(self, event: dict[str, Any], line_no: int, idx: int) -> dict[str, Any] | None:
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") or {}

        kind = ""
        label = ""
        metadata: dict[str, Any] = dict(payload)

        if event_type == "user_prompt":
            kind = "prompt"
            label = "User Prompt"
        elif event_type == "user_prompt_batch":
            kind = "prompt_batch"
            count = int(payload.get("count") or 0)
            label = f"User Prompts ({count})"
        elif event_type == "assistant_response":
            kind = "assistant_response"
            label = "Assistant Response"
        elif event_type == "api_call":
            kind = "api_call"
            label = "LLM API Request"
        elif event_type == "tool_call_started":
            kind = "tool_call_started"
            tool_name = payload.get("tool_name") or "unknown"
            label = f"Tool: {tool_name}"
        elif event_type == "tool_call_finished":
            kind = "tool_call_finished"
            tool_name = payload.get("tool_name") or "unknown"
            label = f"Tool Result: {tool_name}"
        else:
            return None

        return {
            "id": f"agent_{idx}",
            "line_no": line_no,
            "lane": 0,
            "pid": None,
            "kind": kind,
            "label": label,
            "metadata": metadata,
            "branch_from_lane": None,
            "merge_to_lane": None,
            "source": "agent",
        }

    def _map_agent_event_lines(self, trace: TraceState, sys_events: list[dict[str, Any]]) -> list[float]:
        n = len(trace.agent_events)
        if n == 0:
            return []

        if not sys_events:
            return [float(i + 1) for i in range(n)]

        sys_sorted_by_ts = sorted(sys_events, key=lambda e: float(e.get("ts", 0.0)))

        root_start_line = float(sys_sorted_by_ts[0].get("line_no", 0))

        lines: list[float] = [0.0] * n

        for i, agent_event in enumerate(trace.agent_events):
            try:
                agent_ts = float(agent_event.get("ts", 0.0))
            except (TypeError, ValueError):
                agent_ts = 0.0

            assigned_line = root_start_line - 0.1
            for s in sys_sorted_by_ts:
                try:
                    s_ts = float(s.get("ts", 0.0))
                except (TypeError, ValueError):
                    s_ts = 0.0

                if s_ts > agent_ts:
                    break
                assigned_line = float(s.get("line_no", 0))

            lines[i] = assigned_line + 0.05

        # Guarantee strictly monotonic lines for frontend stability
        for i in range(1, n):
            if lines[i] <= lines[i - 1]:
                lines[i] = lines[i - 1] + 0.001

        return lines

    def _setup_phase_window(self, trace: TraceState, sys_events: list[dict[str, Any]]) -> tuple[int, int] | None:
        if not sys_events:
            return None

        mapped = self._map_agent_event_lines(trace, sys_events)
        first_api_line: float | None = None
        for i, event in enumerate(trace.agent_events):
            if event.get("event_type") == "api_call":
                first_api_line = mapped[i] if i < len(mapped) else None
                break

        if first_api_line is None and mapped:
            first_api_line = float(mapped[0])
        if first_api_line is None:
            return None

        mapped_by_idx = {i: float(mapped[i]) for i in range(min(len(mapped), len(trace.agent_events)))}

        # Cut the internal window at the first next top-level boundary so it does
        # not overlap tool-call branches or later prompt/API sections.
        stop_line = float("inf")
        boundary_types = {"assistant_response", "tool_call_started", "api_call", "user_prompt", "user_prompt_batch"}
        for i, event in enumerate(trace.agent_events):
            line = mapped_by_idx.get(i)
            if line is None or line <= first_api_line:
                continue
            if str(event.get("event_type") or "") in boundary_types:
                stop_line = min(stop_line, line)

        candidates = [
            e for e in sys_events
            if first_api_line <= float(e.get("line_no", 0)) < stop_line
            and str(e.get("type") or "") in {"file_read", "file_write", "file_delete", "file_rename", "net_connect", "net_send", "net_recv", "command_exec"}
        ]

        if not candidates:
            candidates = [
                e for e in sys_events
                if float(e.get("line_no", 0)) < first_api_line
                and str(e.get("type") or "") in {"file_read", "file_write", "file_delete", "file_rename", "net_connect", "net_send", "net_recv", "command_exec"}
            ]
        if not candidates:
            return None

        start_line = int(min(float(e.get("line_no", 0)) for e in candidates))
        end_line = int(max(float(e.get("line_no", 0)) for e in candidates))
        return (start_line, end_line)

    def _git_tree_graph(
        self,
        t: TraceState,
        focus_pid: int | None = None,
        detailed: bool = False,
        scoped_sys_events: list[dict[str, Any]] | None = None,
        include_agent_events: bool = True,
    ) -> dict[str, Any]:
        sys_events = sorted(scoped_sys_events if scoped_sys_events is not None else t.sys_events, key=lambda e: int(e.get("line_no", 0)))
        if not sys_events:
            return {
                "mode": "git_tree",
                "nodes": [],
                "summary": {
                    "prompts": 0,
                    "tool_steps": 0,
                    "responses": 0,
                    "trace_status": "completed" if t.complete else "active",
                },
            }

        command_execs = [e for e in sys_events if str(e.get("type") or "") == "command_exec"]
        if focus_pid is not None and focus_pid > 0:
            root_pid = int(focus_pid)
            focus_exec = [e for e in command_execs if int(e.get("pid", 0)) == root_pid]
            root_start_line = int((focus_exec[0] if focus_exec else sys_events[0]).get("line_no", 0))
        elif command_execs:
            root_pid = int(command_execs[0].get("pid", 0))
            root_start_line = int(command_execs[0].get("line_no", 0))
        else:
            root_pid = int(t.root_pid or 0)
            root_start_line = int(sys_events[0].get("line_no", 0))

        parent_map: dict[int, int] = {int(k): int(v) for k, v in t.process_parent.items()}
        spawn_event_by_pid: dict[int, dict[str, Any]] = {}
        exit_event_by_pid: dict[int, dict[str, Any]] = {}
        first_exec_by_pid: dict[int, dict[str, Any]] = {}

        for event in sys_events:
            et = str(event.get("type") or "")
            if et == "process_spawn":
                child = int(event.get("child_pid", 0))
                if child > 0 and child not in spawn_event_by_pid:
                    spawn_event_by_pid[child] = event
            elif et == "process_exit":
                pid = int(event.get("pid", 0))
                if pid > 0 and pid not in exit_event_by_pid:
                    exit_event_by_pid[pid] = event
            elif et == "command_exec":
                pid = int(event.get("pid", 0))
                if pid > 0 and pid not in first_exec_by_pid:
                    first_exec_by_pid[pid] = event

        children_by_pid: dict[int, list[int]] = defaultdict(list)
        for child, parent in parent_map.items():
            if parent > 0:
                children_by_pid[parent].append(child)

        for parent in list(children_by_pid.keys()):
            children_by_pid[parent].sort(key=lambda p: int((spawn_event_by_pid.get(p) or {}).get("line_no", 10**9)))

        # Render only one subprocess depth per graph: focused/root process + its
        # direct children. Deeper descendants remain available via drilldown.
        direct_children = list(children_by_pid.get(root_pid, []))

        def child_start_line(pid: int) -> int:
            spawn_line = int((spawn_event_by_pid.get(pid) or {}).get("line_no", 10**9))
            exec_line = int((first_exec_by_pid.get(pid) or {}).get("line_no", 10**9))
            return min(spawn_line, exec_line)

        direct_children.sort(key=lambda p: (child_start_line(p), p))

        # Reuse lane columns when earlier children have exited.
        lane_for_pid: dict[int, int] = {root_pid: 0}
        free_lanes: list[int] = []
        active_lanes: list[tuple[int, int]] = []  # (exit_line, lane)
        next_lane = 1

        for child_pid in direct_children:
            spawn_line = child_start_line(child_pid)

            while active_lanes and active_lanes[0][0] <= spawn_line:
                _, released_lane = heapq.heappop(active_lanes)
                heapq.heappush(free_lanes, released_lane)

            if free_lanes:
                lane = heapq.heappop(free_lanes)
            else:
                lane = next_lane
                next_lane += 1

            lane_for_pid[child_pid] = lane

            exit_event = exit_event_by_pid.get(child_pid)
            if exit_event is not None:
                exit_line = int(exit_event.get("line_no", 0))
                if exit_line >= spawn_line:
                    heapq.heappush(active_lanes, (exit_line, lane))

        visible_pids = set(lane_for_pid.keys())
        sys_events = [e for e in sys_events if int(e.get("pid", 0)) in visible_pids or int(e.get("child_pid", 0)) in visible_pids]

        max_lane = max(lane_for_pid.values()) if lane_for_pid else 0

        nodes: list[dict[str, Any]] = []

        for pid, spawn_event in spawn_event_by_pid.items():
            if pid not in lane_for_pid:
                continue
            parent = int(spawn_event.get("pid", 0))
            parent_lane = lane_for_pid.get(parent)
            nodes.append(
                {
                    "id": f"proc_spawn_{pid}_{int(spawn_event.get('line_no', 0))}",
                    "line_no": int(spawn_event.get("line_no", 0)),
                    "lane": lane_for_pid[pid],
                    "pid": pid,
                    "kind": "process_spawn",
                    "label": f"Spawn pid={pid}",
                    "metadata": {"pid": pid, "parent_pid": parent},
                    "branch_from_lane": parent_lane,
                    "merge_to_lane": None,
                    "source": "sys",
                }
            )

        for pid, exec_event in first_exec_by_pid.items():
            if pid not in lane_for_pid:
                continue
            if not detailed and pid != root_pid:
                continue
            nodes.append(
                {
                    "id": f"proc_exec_{pid}_{int(exec_event.get('line_no', 0))}",
                    "line_no": int(exec_event.get("line_no", 0)),
                    "lane": lane_for_pid[pid],
                    "pid": pid,
                    "kind": "process_exec",
                    "label": self._short_command_label(exec_event),
                    "metadata": {
                        "pid": pid,
                        "exec_path": exec_event.get("exec_path"),
                        "command": exec_event.get("command"),
                        "argv": exec_event.get("argv", []),
                    },
                    "branch_from_lane": None,
                    "merge_to_lane": None,
                    "source": "sys",
                }
            )

        if detailed:
            file_run: list[dict[str, Any]] = []

            def flush_file_run() -> None:
                nonlocal file_run
                if not file_run:
                    return

                run_pid = int(file_run[0].get("pid", 0))
                if run_pid <= 0 or run_pid not in lane_for_pid:
                    file_run = []
                    return

                start_line = int(file_run[0].get("line_no", 0))
                end_line = int(file_run[-1].get("line_no", 0))
                unique_files = {
                    str(e.get("path") or "")
                    for e in file_run
                    if str(e.get("path") or "")
                }

                nodes.append(
                    {
                        "id": f"folder_group_{run_pid}_{start_line}_{end_line}",
                        "line_no": float(start_line),
                        "lane": lane_for_pid.get(run_pid, 0),
                        "pid": run_pid,
                        "kind": "folder_group",
                        "label": f"/ ({len(unique_files)} files, {len(file_run)} ops)",
                        "metadata": {
                            "path": "/",
                            "line_start": start_line,
                            "line_end": end_line,
                            "event_count": len(file_run),
                            "file_count": len(unique_files),
                            "folder_tree": self._build_folder_tree(file_run),
                        },
                        "branch_from_lane": None,
                        "merge_to_lane": None,
                        "source": "sys",
                    }
                )
                file_run = []

            for event in sys_events:
                et = str(event.get("type") or "")
                if et in {"process_spawn", "process_exit", "command_exec"}:
                    flush_file_run()
                    continue
                if not self._is_relevant_trunk_sys_event(event):
                    flush_file_run()
                    continue
                pid = int(event.get("pid", 0))
                if pid <= 0 or pid not in lane_for_pid:
                    flush_file_run()
                    continue

                if et in {"file_read", "file_write", "file_delete", "file_rename"}:
                    if file_run and int(file_run[0].get("pid", 0)) != pid:
                        flush_file_run()
                    file_run.append(event)
                    continue

                flush_file_run()
                meta_event = self._with_inferred_net_dest(t, event) if et in {"net_connect", "net_send", "net_recv"} else dict(event)
                label = str(meta_event.get("label") or et)
                if et in {"net_connect", "net_send", "net_recv"}:
                    display = self._network_display_label(meta_event)
                    if et == "net_connect":
                        label = f"connect {display}"
                    elif et == "net_send":
                        label = f"send {int(meta_event.get('bytes', 0))}B -> {display}"
                    else:
                        label = f"recv {int(meta_event.get('bytes', 0))}B <- {display}"
                nodes.append(
                    {
                        "id": f"sys_{et}_{pid}_{int(event.get('line_no', 0))}",
                        "line_no": int(event.get("line_no", 0)),
                        "lane": lane_for_pid.get(pid, 0),
                        "pid": pid,
                        "kind": et,
                        "label": label,
                        "metadata": meta_event,
                        "branch_from_lane": None,
                        "merge_to_lane": None,
                        "source": "sys",
                    }
                )

            flush_file_run()
        else:
            root_relevant_events = [
                e for e in sys_events
                if int(e.get("pid", 0)) == root_pid
                and self._is_relevant_trunk_sys_event(e)
                and str(e.get("type") or "") not in {"process_spawn", "process_exit"}
            ]
            root_relevant_events.sort(key=lambda e: int(e.get("line_no", 0)))
            root_relevant_events = root_relevant_events[:120]

            # Compress root lane syscalls into linear internal segments split by
            # agent anchors and process spawn boundaries.
            split_lines: set[int] = set()
            for event in sys_events:
                if str(event.get("type") or "") == "process_spawn" and int(event.get("pid", 0)) == root_pid:
                    split_lines.add(int(event.get("line_no", 0)))

            if include_agent_events and focus_pid is None:
                mapped_agent_lines = self._map_agent_event_lines(t, sys_events)
                for ln in mapped_agent_lines:
                    split_lines.add(int(float(ln)))

            segments: list[list[dict[str, Any]]] = []
            current: list[dict[str, Any]] = []
            for event in root_relevant_events:
                line_no = int(event.get("line_no", 0))
                if line_no in split_lines and current:
                    segments.append(current)
                    current = []
                current.append(event)
            if current:
                segments.append(current)

            for idx, segment in enumerate(segments):
                if not segment:
                    continue
                start_line = int(segment[0].get("line_no", 0))
                end_line = int(segment[-1].get("line_no", 0))
                nodes.append(
                    {
                        "id": f"internal_{idx}_{start_line}",
                        "line_no": float(start_line) + 0.01,
                        "lane": 0,
                        "pid": root_pid,
                        "kind": "internal",
                        "label": f"Internal ({len(segment)} events)",
                        "metadata": {
                            "tool_call_id": "internal_phase" if focus_pid is None else None,
                            "line_start": start_line,
                            "line_end": end_line,
                            "event_count": len(segment),
                            "events": [dict(e) for e in segment],
                        },
                        "branch_from_lane": None,
                        "merge_to_lane": None,
                        "source": "sys",
                    }
                )

        if include_agent_events:
            mapped_agent_lines = self._map_agent_event_lines(t, sys_events)
            for idx, event in enumerate(t.agent_events):
                if focus_pid is not None and focus_pid > 0:
                    continue
                line_no = mapped_agent_lines[idx] if idx < len(mapped_agent_lines) else float(root_start_line)
                node = self._agent_event_to_git_node(event, line_no, idx)
                if node is not None:
                    nodes.append(node)

        # Merge rule: merge child branch to parent only if child exited and parent
        # continues with at least one later event before parent exit.
        parent_activity_lines: dict[int, list[int]] = defaultdict(list)
        for event in sys_events:
            pid = int(event.get("pid", 0))
            if pid > 0:
                parent_activity_lines[pid].append(int(event.get("line_no", 0)))

        for node in nodes:
            if node.get("kind") != "process_spawn":
                continue
            pid = int(node.get("pid", 0))
            parent_pid = int((node.get("metadata") or {}).get("parent_pid") or 0)
            if pid <= 0 or parent_pid <= 0:
                continue

            child_exit_event = exit_event_by_pid.get(pid)
            if child_exit_event is None:
                continue
            child_exit_line = int(child_exit_event.get("line_no", 0))
            parent_exit_line = int((exit_event_by_pid.get(parent_pid) or {}).get("line_no", 0))

            act_lines = parent_activity_lines.get(parent_pid, [])
            merge_line = None
            for line in act_lines:
                if line <= child_exit_line:
                    continue
                if parent_exit_line and line >= parent_exit_line:
                    continue
                merge_line = line
                break

            if merge_line is None:
                continue

            nodes.append(
                {
                    "id": f"proc_exit_{pid}_{child_exit_line}",
                    "line_no": child_exit_line,
                    "lane": lane_for_pid.get(pid, 0),
                    "pid": pid,
                    "kind": "process_exit",
                    "label": f"Exit pid={pid}",
                    "metadata": {"pid": pid, "parent_pid": parent_pid},
                    "branch_from_lane": None,
                    "merge_to_lane": lane_for_pid.get(parent_pid),
                    "merge_line": merge_line,
                    "source": "sys",
                }
            )

        # Add non-merged child exits so long-running/dangling branches are explicit.
        existing_exit_ids = {
            str(node.get("id"))
            for node in nodes
            if str(node.get("kind")) == "process_exit"
        }
        for pid, exit_event in exit_event_by_pid.items():
            if pid not in lane_for_pid:
                continue
            node_id = f"proc_exit_{pid}_{int(exit_event.get('line_no', 0))}"
            if node_id in existing_exit_ids:
                continue
            nodes.append(
                {
                    "id": node_id,
                    "line_no": int(exit_event.get("line_no", 0)),
                    "lane": lane_for_pid.get(pid, 0),
                    "pid": pid,
                    "kind": "process_exit",
                    "label": f"Exit pid={pid}",
                    "metadata": {"pid": pid, "parent_pid": parent_map.get(pid)},
                    "branch_from_lane": None,
                    "merge_to_lane": None,
                    "source": "sys",
                }
            )

        nodes.sort(key=lambda n: (float(n.get("line_no", 0)), int(n.get("lane", 0)), str(n.get("id"))))

        # Compress all nodes before the first LLM API call into one internal
        # setup node so heavy agent bootstrap activity does not flood the top view.
        if include_agent_events and focus_pid is None and not detailed:
            first_api_line: float | None = None
            for node in nodes:
                if str(node.get("kind") or "") == "api_call" and str(node.get("source") or "") == "agent":
                    first_api_line = float(node.get("line_no", 0))
                    break

            if first_api_line is not None:
                pre_api = [n for n in nodes if float(n.get("line_no", 0)) < first_api_line]
                post_api = [n for n in nodes if float(n.get("line_no", 0)) >= first_api_line]

                if len(pre_api) > 1:
                    start_line = int(min(float(n.get("line_no", 0)) for n in pre_api))
                    end_line = int(max(float(n.get("line_no", 0)) for n in pre_api))
                    compressed = {
                        "id": f"internal_pre_api_{start_line}_{end_line}",
                        "line_no": float(start_line) - 0.01,
                        "lane": 0,
                        "pid": root_pid,
                        "kind": "internal",
                        "label": f"Internal setup ({len(pre_api)} nodes)",
                        "metadata": {
                            "line_start": start_line,
                            "line_end": end_line,
                            "event_count": len(pre_api),
                            "tool_call_id": "internal_phase",
                        },
                        "branch_from_lane": None,
                        "merge_to_lane": None,
                        "source": "sys",
                    }
                    nodes = [compressed] + post_api
                    nodes.sort(key=lambda n: (float(n.get("line_no", 0)), int(n.get("lane", 0)), str(n.get("id"))))

        visible_lanes = sorted({int(n.get("lane", 0)) for n in nodes if n.get("lane") is not None})
        lane_remap = {old_lane: idx for idx, old_lane in enumerate(visible_lanes)}

        # Normalize sparse lane ids (for example 0, 17, 42) into dense lanes
        # so the frontend width is proportional to visible branches only.
        for node in nodes:
            lane_val = node.get("lane")
            if lane_val is not None:
                node["lane"] = lane_remap.get(int(lane_val), 0)

            branch_from = node.get("branch_from_lane")
            if branch_from is not None:
                node["branch_from_lane"] = lane_remap.get(int(branch_from))

            merge_to = node.get("merge_to_lane")
            if merge_to is not None:
                node["merge_to_lane"] = lane_remap.get(int(merge_to))

        max_lane = (len(visible_lanes) - 1) if visible_lanes else 0

        branch_ranges: list[dict[str, Any]] = []
        for pid, lane in lane_for_pid.items():
            if lane not in lane_remap:
                continue
            start_line = root_start_line if pid == root_pid else int((spawn_event_by_pid.get(pid) or {}).get("line_no", root_start_line))
            end_event = exit_event_by_pid.get(pid)
            end_line = int(end_event.get("line_no", 0)) if end_event is not None else None
            branch_ranges.append(
                {
                    "pid": pid,
                    "lane": lane_remap[lane],
                    "parent_pid": parent_map.get(pid),
                    "start_line": start_line,
                    "end_line": end_line,
                }
            )

        summary = {
            "prompts": sum(1 for n in nodes if n.get("kind") in {"prompt", "prompt_batch"}),
            "tool_steps": sum(1 for n in nodes if n.get("kind") == "tool_step"),
            "responses": sum(1 for n in nodes if n.get("kind") == "assistant_response"),
            "trace_status": "completed" if t.complete else "active",
        }

        return {
            "mode": "git_tree",
            "root_pid": root_pid,
            "max_lane": max_lane,
            "nodes": nodes,
            "branch_ranges": sorted(branch_ranges, key=lambda b: int(b.get("lane", 0))),
            "summary": summary,
        }

    def high_level_graph(self, trace_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        return self._git_tree_graph(t)

    def process_graph(self, trace_id: str, pid: int) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        return self._git_tree_graph(t, focus_pid=pid, detailed=True, include_agent_events=False)

    def internal_graph(self, trace_id: str, line_start: int, line_end: int) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        if line_end < line_start:
            line_start, line_end = line_end, line_start

        scoped = [
            e for e in t.sys_events
            if line_start <= int(e.get("line_no", 0)) <= line_end
            and str(e.get("type") or "") != "process_exit"
        ]

        return self._git_tree_graph(
            t,
            detailed=True,
            scoped_sys_events=scoped,
            include_agent_events=False,
        )

    def _syscall_only_graph(self, t: TraceState) -> dict[str, Any]:
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
                cmd_net[idx].add(self._network_display_label(ne))

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
            all_net.add(self._network_display_label(ne))

        summary = {
            "commands": len(visible_commands),
            "files_touched": len(all_files),
            "net_endpoints": len(all_net),
            "syscall_events": len(t.sys_events),
            "trace_status": "completed" if t.complete else "active",
        }

        return {
            "mode": "syscall_only",
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

    def _normalize_command_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", str(text or "").strip().lower())

    def _command_tokens(self, text: str) -> list[str]:
        norm = self._normalize_command_text(text)
        return [tok for tok in re.findall(r"[A-Za-z0-9_./:\-]+", norm) if len(tok) >= 2]

    def _extract_tool_command_text(self, payload: dict[str, Any]) -> str:
        args = payload.get("arguments") or {}
        if isinstance(args, dict):
            for key in ("command", "cmd", "script", "path"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    return value
        return str(payload.get("tool_name") or "")

    def _event_command_text(self, event: dict[str, Any]) -> str:
        command = str(event.get("command") or "")
        argv = event.get("argv") or []
        if isinstance(argv, list) and argv:
            argv_text = " ".join(str(a) for a in argv if isinstance(a, str))
            if len(argv_text) > len(command):
                command = argv_text
        return command

    def _command_match_score(self, tool_cmd: str, event: dict[str, Any]) -> int:
        tool_n = self._normalize_command_text(tool_cmd)
        exec_n = self._normalize_command_text(self._event_command_text(event))
        if not tool_n or not exec_n:
            return 0

        score = 0
        if tool_n in exec_n:
            score += 200 + min(len(tool_n), 80)

        tool_tokens = self._command_tokens(tool_n)
        exec_tokens = self._command_tokens(exec_n)
        exec_set = {t.lower() for t in exec_tokens}
        exec_basenames = {Path(t).name.lower() for t in exec_tokens}

        for tok in tool_tokens:
            t = tok.lower()
            base = Path(t).name.lower()
            if t in exec_n:
                score += 8
            elif t in exec_set:
                score += 6
            elif base in exec_basenames:
                score += 4

        if tool_tokens:
            primary = Path(tool_tokens[0]).name.lower()
            if primary in exec_basenames:
                score += 30

        return score

    def _is_shell_wrapper_command(self, event: dict[str, Any]) -> bool:
        exec_path = str(event.get("exec_path") or "")
        base = Path(exec_path).name.lower() if exec_path else ""
        command = self._normalize_command_text(self._event_command_text(event))
        if base in {"sh", "bash", "zsh", "dash"} and " -c " in f" {command} ":
            return True
        return False

    def _is_agent_internal_command(self, event: dict[str, Any]) -> bool:
        exec_path = str(event.get("exec_path") or "")
        base = Path(exec_path).name.lower() if exec_path else ""
        command = self._normalize_command_text(self._event_command_text(event))

        if base in {"codex", "codex-linux-sandbox", "node"}:
            return True
        if "codex-linux-sandbox" in command or "--sandbox-policy" in command:
            return True
        if "/root/.codex/" in command or "shell_snapsho" in command:
            return True
        if base in {"bash", "sh", "zsh", "dash"} and "/root/.codex/" in command:
            return True
        return False

    def _match_tool_root_commands(self, trace: TraceState) -> dict[str, dict[str, Any]]:
        starts = self._tool_start_events(trace)
        exec_events = [e for e in trace.sys_events if e.get("type") == "command_exec"]
        if not starts or not exec_events:
            return {}

        used_exec_indices: set[int] = set()
        matched: dict[str, dict[str, Any]] = {}

        for start in starts:
            payload = start.get("payload") or {}
            tool_call_id = payload.get("tool_call_id")
            if not tool_call_id:
                continue

            tool_cmd = self._extract_tool_command_text(payload)
            best_idx: int | None = None
            best_score = 0

            for idx, exec_event in enumerate(exec_events):
                if idx in used_exec_indices:
                    continue
                score = self._command_match_score(tool_cmd, exec_event)
                if score > best_score:
                    best_score = score
                    best_idx = idx
                elif score == best_score and score > 0 and best_idx is not None:
                    cur_line = int(exec_event.get("line_no", 0))
                    best_line = int(exec_events[best_idx].get("line_no", 0))
                    if cur_line < best_line:
                        best_idx = idx

            # Weak threshold to still support truncated command strings.
            if best_idx is None or best_score < 12:
                continue

            used_exec_indices.add(best_idx)
            matched[str(tool_call_id)] = exec_events[best_idx]

        return matched

    def _is_descendant_or_same_pid(self, trace: TraceState, pid: int, ancestor: int) -> bool:
        current = int(pid)
        seen: set[int] = set()
        while current and current not in seen:
            if current == ancestor:
                return True
            seen.add(current)
            current = int(trace.process_parent.get(current, 0))
        return False

    def _split_tool_command_events(
        self,
        trace: TraceState,
        tool_payload: dict[str, Any],
        command_events: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not command_events:
            return [], []

        tool_cmd = self._extract_tool_command_text(tool_payload)
        has_tool_cmd = bool(self._normalize_command_text(tool_cmd))
        min_tool_match_score = 8
        non_wrapper_exists = any(not self._is_shell_wrapper_command(cmd) for cmd in command_events)

        relevant: list[dict[str, Any]] = []
        internal: list[dict[str, Any]] = []

        scored: list[tuple[dict[str, Any], int, bool, bool]] = []
        for cmd in command_events:
            score = self._command_match_score(tool_cmd, cmd)
            is_wrapper = self._is_shell_wrapper_command(cmd)
            is_internal = self._is_agent_internal_command(cmd)
            cmd["_tool_match_score"] = score
            scored.append((cmd, score, is_wrapper, is_internal))

        matched_external_exists = any(
            (not is_internal) and score >= min_tool_match_score
            for cmd, score, _is_wrapper, is_internal in scored
        )

        for cmd, score, is_wrapper, is_internal in scored:
            # If we have at least one user-relevant external command, keep the
            # drilldown focused on those and demote internal runtime wrappers.
            if matched_external_exists and is_internal:
                internal.append(cmd)
                continue

            # When tool command text is known, ignore unrelated command noise.
            if has_tool_cmd and score < min_tool_match_score and not is_internal:
                internal.append(cmd)
                continue

            if non_wrapper_exists and is_wrapper:
                internal.append(cmd)
                continue

            if is_internal and score < 12:
                internal.append(cmd)
                continue

            relevant.append(cmd)

        if not relevant:
            best = max(command_events, key=lambda e: self._command_match_score(tool_cmd, e))
            relevant = [best]
            internal = [e for e in command_events if e is not best]

        seen_ids: set[int] = set()
        uniq_relevant: list[dict[str, Any]] = []
        for event in sorted(relevant, key=lambda e: int(e.get("line_no", 0))):
            line_no = int(event.get("line_no", 0))
            if line_no in seen_ids:
                continue
            seen_ids.add(line_no)
            uniq_relevant.append(event)

        uniq_internal: list[dict[str, Any]] = []
        relevant_lines = {int(e.get("line_no", 0)) for e in uniq_relevant}
        for event in sorted(internal, key=lambda e: int(e.get("line_no", 0))):
            if int(event.get("line_no", 0)) in relevant_lines:
                continue
            uniq_internal.append(event)

        return uniq_relevant, uniq_internal

    def _tool_line_ranges(self, trace: TraceState) -> dict[str, tuple[int, int | None]]:
        starts = self._tool_start_events(trace)
        matched = self._match_tool_root_commands(trace)
        if not starts or not matched:
            return {}

        ordered_ids = [
            (event.get("payload") or {}).get("tool_call_id")
            for event in starts
            if (event.get("payload") or {}).get("tool_call_id") in matched
        ]

        ranges: dict[str, tuple[int, int | None]] = {}
        for i, call_id in enumerate(ordered_ids):
            start_line = int((matched[call_id] or {}).get("line_no", 0))
            end_line = None
            if i + 1 < len(ordered_ids):
                next_start = int((matched[ordered_ids[i + 1]] or {}).get("line_no", 0))
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

    def _build_folder_tree(self, file_events: list[dict[str, Any]]) -> dict[str, Any]:
        """Build an OS-like folder tree rooted at '/'."""
        root: dict[str, Any] = {"name": "/", "kind": "folder", "children": {}}

        for event in file_events:
            path = str(event.get("path") or "").strip()
            if not path:
                continue

            parts = [p for p in path.split("/") if p]
            if not parts:
                continue

            raw_type = str(event.get("type") or "")
            op = raw_type.replace("file_", "") if raw_type.startswith("file_") else "read"
            node = root
            for seg in parts[:-1]:
                children = node.setdefault("children", {})
                if seg not in children:
                    children[seg] = {"name": seg, "kind": "folder", "children": {}}
                node = children[seg]

            file_name = parts[-1]
            children = node.setdefault("children", {})
            if file_name not in children:
                full_path = "/" + "/".join(parts)
                children[file_name] = {
                    "name": file_name,
                    "kind": "file",
                    "path": full_path,
                    "ops": set(),
                    "count": 0,
                }

            leaf = children[file_name]
            # Some traces report both a directory path and nested file paths
            # under it; in that case this node may already exist as a folder.
            # Keep metadata fields defensively to avoid crashing drilldowns.
            if "ops" not in leaf or not isinstance(leaf.get("ops"), set):
                leaf["ops"] = set()
            if "count" not in leaf:
                leaf["count"] = 0
            leaf["ops"].add(op)
            leaf["count"] = int(leaf.get("count", 0)) + 1

        def _to_plain(node: dict[str, Any]) -> dict[str, Any]:
            if node.get("kind") == "file":
                return {
                    "name": str(node.get("name") or ""),
                    "kind": "file",
                    "path": str(node.get("path") or ""),
                    "ops": sorted(node.get("ops") or []),
                    "count": int(node.get("count") or 0),
                }

            children_dict = node.get("children") or {}
            children = [_to_plain(child) for child in children_dict.values()]
            children.sort(key=lambda c: (0 if c.get("kind") == "folder" else 1, str(c.get("name") or "").lower()))
            return {
                "name": str(node.get("name") or ""),
                "kind": "folder",
                "children": children,
            }

        return _to_plain(root)

    def _short_command_label(self, event: dict[str, Any]) -> str:
        argv = event.get("argv") or []
        if isinstance(argv, list) and argv:
            return " ".join(argv[:4])[:140]

        command = str(event.get("command") or "exec")
        return command[:140]

    def _extract_shell_steps(self, tool_payload: dict[str, Any]) -> list[str]:
        cmd = self._extract_tool_command_text(tool_payload)
        if not cmd:
            return []

        # Split common shell separators to expose the user-facing sequence.
        raw_steps = [
            part.strip()
            for part in re.split(r"\s*(?:&&|;|\n)\s*", cmd)
            if part and part.strip()
        ]

        steps: list[str] = []
        for step in raw_steps:
            compact = re.sub(r"\s+", " ", step).strip()
            if not compact:
                continue
            if compact in steps:
                continue
            steps.append(compact)

        return steps[:8]

    def _shell_step_needs_synthetic_node(self, step: str, visible_exec_events: list[dict[str, Any]]) -> bool:
        step_norm = self._normalize_command_text(step)
        if not step_norm:
            return False

        exec_texts = [self._normalize_command_text(self._event_command_text(e)) for e in visible_exec_events]
        if any(step_norm in text for text in exec_texts):
            return False

        first_tok = step_norm.split(" ", 1)[0]
        shell_builtins = {
            "cd", "echo", "export", "alias", "set", "unset", "readonly", "local",
            "source", ".", "test", "[", "printf", "read",
        }
        if first_tok in shell_builtins:
            return True

        # Variable assignment / arithmetic steps often do useful work but do not
        # create separate execve events.
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", step.strip()):
            return True

        return False

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
        matched_roots = self._match_tool_root_commands(trace)
        root_event = matched_roots.get(tool_call_id)

        if root_event is not None:
            root_line = int(root_event.get("line_no", 0))
            root_pid = int(root_event.get("pid", 0))

            root_exit_line: int | None = None
            for e in trace.sys_events:
                if e.get("type") != "process_exit":
                    continue
                if int(e.get("pid", 0)) != root_pid:
                    continue
                line_no = int(e.get("line_no", 0))
                if line_no >= root_line:
                    root_exit_line = line_no
                    break

            related = []
            for e in trace.sys_events:
                line_no = int(e.get("line_no", 0))
                if line_no < root_line:
                    continue
                if root_exit_line is not None and line_no > root_exit_line:
                    continue
                pid = int(e.get("pid", 0))
                if pid and self._is_descendant_or_same_pid(trace, pid, root_pid):
                    related.append(e)

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

        if tool_call_id == "internal_phase":
            setup_range = self._setup_phase_window(t, sorted(t.sys_events, key=lambda e: int(e.get("line_no", 0))))
            if setup_range is None:
                setup_events = []
            else:
                s_start, s_end = setup_range
                setup_events = [
                    e for e in t.sys_events
                    if s_start <= int(e.get("line_no", 0)) <= s_end
                ]
            start_event = {
                "ts": setup_events[0].get("ts", 0) if setup_events else 0,
                "payload": {"tool_name": "Internal", "tool_call_id": "internal_phase"}
            }
            end_event = {
                "ts": setup_events[-1].get("ts", 0) if setup_events else 0,
            }
            related = setup_events
            line_range = (int(setup_events[0].get("line_no", 0)), int(setup_events[-1].get("line_no", 0))) if setup_events else None
        else:
            start_event, end_event = self._find_tool_events(t, tool_call_id)
            if start_event is None:
                raise KeyError(tool_call_id)
            tool_ranges = self._tool_line_ranges(t)
            line_range = tool_ranges.get(tool_call_id)
            related = self._related_sys_events_for_tool(t, tool_call_id, start_event, end_event)

        if related:
            root_pid = int(related[0].get("pid", 0))
            for ev in related:
                if str(ev.get("type") or "") == "command_exec":
                    root_pid = int(ev.get("pid", root_pid))
                    break
        else:
            root_pid = int(t.root_pid or 0)

        if root_pid <= 0:
            raise KeyError(tool_call_id)

        return self._git_tree_graph(
            t,
            focus_pid=root_pid,
            detailed=True,
            scoped_sys_events=related,
            include_agent_events=False,
        )

    def trace_summary(self, trace_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)

        tools_set: set[str] = set()
        tool_calls: list[dict[str, str]] = []
        seen_tool_call_ids: set[str] = set()
        for event in t.agent_events:
            payload = event.get("payload") or {}
            if event.get("event_type") == "tool_call_started":
                name = payload.get("tool_name")
                if isinstance(name, str) and name:
                    tools_set.add(name)
                call_id = payload.get("tool_call_id")
                if isinstance(call_id, str) and call_id and call_id not in seen_tool_call_ids:
                    seen_tool_call_ids.add(call_id)
                    tool_calls.append(
                        {
                            "tool_call_id": call_id,
                            "tool_name": str(name or "unknown"),
                        }
                    )
            if event.get("event_type") == "api_call":
                for name in payload.get("available_tools") or []:
                    if isinstance(name, str) and name:
                        tools_set.add(name)

        file_agg: dict[str, dict[str, Any]] = {}
        for event in t.sys_events:
            event_type = str(event.get("type") or "")
            if event_type not in {"file_read", "file_write", "file_delete", "file_rename", "command_exec"}:
                continue

            if event_type == "command_exec":
                path = str(event.get("exec_path") or "")
                op = "execute"
            else:
                path = str(event.get("path") or "")
                op = event_type.replace("file_", "")

            if not path:
                continue

            bucket = file_agg.setdefault(path, {"path": path, "ops": set(), "count": 0})
            bucket["ops"].add(op)
            bucket["count"] += 1

        files = [{"path": v["path"], "ops": sorted(v["ops"]), "count": v["count"]} for v in file_agg.values()]
        files.sort(key=lambda x: (-x["count"], x["path"]))

        # Collect network endpoints
        net_agg: dict[tuple[str, str], dict[str, Any]] = {}
        for event in t.sys_events:
            event_type = str(event.get("type") or "")
            if event_type not in {"net_connect", "net_send", "net_recv"}:
                continue
            net_event = self._with_inferred_net_dest(t, event)
            display = self._network_display_label(net_event)
            transport = str(net_event.get("transport") or "other")
            key = (display, transport)
            bucket = net_agg.setdefault(
                key,
                {
                    "dest": display,
                    "ops": set(),
                    "bytes": 0,
                    "count": 0,
                    "transport": transport,
                    "family": str(net_event.get("family") or "other"),
                    "failed": 0,
                    "errors": set(),
                },
            )
            bucket["ops"].add(event_type.replace("net_", ""))
            bucket["bytes"] += int(net_event.get("bytes", 0))
            bucket["count"] += 1
            if net_event.get("ok") is False:
                bucket["failed"] += 1
                err = str(net_event.get("error") or "")
                if err:
                    bucket["errors"].add(err)

        # Add command-derived network intents (for example git clone URLs) when
        # kernel-level connect destination is masked by local proxy forwarding.
        for event in t.sys_events:
            if str(event.get("type") or "") != "command_exec":
                continue
            command = str(event.get("command") or "")
            for dest in self._command_network_targets(command):
                key = (f"{dest} [cmd]", "command")
                bucket = net_agg.setdefault(
                    key,
                    {
                        "dest": f"{dest} [cmd]",
                        "ops": set(),
                        "bytes": 0,
                        "count": 0,
                        "transport": "command",
                        "family": "inferred",
                        "failed": 0,
                        "errors": set(),
                    },
                )
                bucket["ops"].add("connect")
                bucket["count"] += 1
        net_endpoints = [
            {
                "dest": v["dest"],
                "ops": sorted(v["ops"]),
                "bytes": v["bytes"],
                "count": v["count"],
                "transport": v["transport"],
                "family": v["family"],
                "failed": v["failed"],
                "errors": sorted(v["errors"]),
            }
            for v in net_agg.values()
        ]
        net_endpoints.sort(key=lambda x: (0 if x.get("transport") == "command" else 1, -x["count"], x["dest"]))

        return {
            "trace_id": trace_id,
            "status": "completed" if t.complete else "active",
            "files": files[:250],
            "network": net_endpoints[:100],
            "tools": sorted(tools_set),
            "tool_calls": tool_calls,
            "totals": {
                "unique_files": len(files),
                "network_endpoints": len(net_endpoints),
                "events": len(t.sys_events),
                "agent_events": len(t.agent_events),
            },
        }

    def tool_summary(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        start_event: dict[str, Any] | None = None
        
        if tool_call_id == "internal_phase":
            setup_range = self._setup_phase_window(t, sorted(t.sys_events, key=lambda e: int(e.get("line_no", 0))))
            if setup_range is None:
                related = []
            else:
                s_start, s_end = setup_range
                related = [
                    e for e in t.sys_events
                    if s_start <= int(e.get("line_no", 0)) <= s_end
                ]
        else:
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

        related = sorted(related, key=lambda e: int(e.get("line_no", 0)))
        command_events = [e for e in related if e.get("type") == "command_exec"]

        relevant_pid_roots: set[int] = set()
        relevant_line_min: int | None = None
        relevant_line_max: int | None = None
        if command_events:
            payload = (start_event or {}).get("payload") or {}
            relevant_cmds, _internal_cmds = self._split_tool_command_events(t, payload, command_events)
            for cmd in relevant_cmds:
                pid = int(cmd.get("pid", 0))
                if pid:
                    relevant_pid_roots.add(pid)
            if relevant_cmds:
                line_values = [int(c.get("line_no", 0)) for c in relevant_cmds]
                relevant_line_min = min(line_values)
                relevant_line_max = max(line_values)

        def _event_relevant(event: dict[str, Any]) -> bool:
            pid = int(event.get("pid", 0))
            line_no = int(event.get("line_no", 0))
            if relevant_pid_roots and pid:
                if any(self._is_descendant_or_same_pid(t, pid, root) for root in relevant_pid_roots):
                    return True
            if relevant_line_min is not None and relevant_line_max is not None:
                if relevant_line_min <= line_no <= relevant_line_max:
                    return True
            return not relevant_pid_roots

        file_agg: dict[str, dict[str, Any]] = {}
        for event in related:
            if not _event_relevant(event):
                continue
            event_type = str(event.get("type") or "")
            if event_type not in {"file_read", "file_write", "file_delete", "file_rename", "command_exec"}:
                continue

            if event_type == "command_exec":
                path = str(event.get("exec_path") or "")
                op = "execute"
            else:
                path = str(event.get("path") or "")
                op = event_type.replace("file_", "")

            if not path:
                continue

            bucket = file_agg.setdefault(path, {"path": path, "ops": set(), "count": 0})
            bucket["ops"].add(op)
            bucket["count"] += 1

        files = [{"path": v["path"], "ops": sorted(v["ops"]), "count": v["count"]} for v in file_agg.values()]
        files.sort(key=lambda x: (-x["count"], x["path"]))

        # Network endpoints for this tool
        net_agg: dict[tuple[str, str], dict[str, Any]] = {}
        for event in related:
            if not _event_relevant(event):
                continue
            event_type = str(event.get("type") or "")
            if event_type not in {"net_connect", "net_send", "net_recv"}:
                continue
            net_event = self._with_inferred_net_dest(t, event)
            display = self._network_display_label(net_event)
            transport = str(net_event.get("transport") or "other")
            key = (display, transport)
            bucket = net_agg.setdefault(
                key,
                {
                    "dest": display,
                    "ops": set(),
                    "bytes": 0,
                    "count": 0,
                    "transport": transport,
                    "family": str(net_event.get("family") or "other"),
                    "failed": 0,
                    "errors": set(),
                },
            )
            bucket["ops"].add(event_type.replace("net_", ""))
            bucket["bytes"] += int(net_event.get("bytes", 0))
            bucket["count"] += 1
            if net_event.get("ok") is False:
                bucket["failed"] += 1
                err = str(net_event.get("error") or "")
                if err:
                    bucket["errors"].add(err)

        for event in related:
            if not _event_relevant(event):
                continue
            if str(event.get("type") or "") != "command_exec":
                continue
            command = str(event.get("command") or "")
            for dest in self._command_network_targets(command):
                key = (f"{dest} [cmd]", "command")
                bucket = net_agg.setdefault(
                    key,
                    {
                        "dest": f"{dest} [cmd]",
                        "ops": set(),
                        "bytes": 0,
                        "count": 0,
                        "transport": "command",
                        "family": "inferred",
                        "failed": 0,
                        "errors": set(),
                    },
                )
                bucket["ops"].add("connect")
                bucket["count"] += 1
        net_endpoints = [
            {
                "dest": v["dest"],
                "ops": sorted(v["ops"]),
                "bytes": v["bytes"],
                "count": v["count"],
                "transport": v["transport"],
                "family": v["family"],
                "failed": v["failed"],
                "errors": sorted(v["errors"]),
            }
            for v in net_agg.values()
        ]
        net_endpoints.sort(key=lambda x: (0 if x.get("transport") == "command" else 1, -x["count"], x["dest"]))

        return {
            "tool_call_id": tool_call_id,
            "files": files,
            "network": net_endpoints,
            "totals": {"unique_files": len(files), "network_endpoints": len(net_endpoints), "events": len(related)},
        }

    def taint_analysis(self, trace_id: str, trust_policy: str = "nondeterministic") -> dict[str, Any]:
        t = self._get_trace(trace_id)

        policy = (
            TrustPolicy.TRUST_EXTERNAL_FILES
            if trust_policy == TrustPolicy.TRUST_EXTERNAL_FILES.value
            else TrustPolicy.NONDETERMINISTIC_EXTERNAL_FILES
        )

        report = run_taint_analysis(
            sys_events=t.sys_events,
            agent_events=t.agent_events,
            trust_policy=policy,
            mitm_endpoints=t.mitm_endpoints,
        )
        payload = report.to_dict()
        payload["trace_id"] = trace_id
        return payload

    def _path_bucket(self, path: str) -> str:
        p = str(path or "").strip()
        if not p:
            return "unknown_path"
        lower = p.lower()
        if lower.endswith("/etc/passwd"):
            return "etc_passwd"
        if lower.endswith("/etc/shadow"):
            return "etc_shadow"
        if lower.endswith("/etc/group"):
            return "etc_group"
        if lower.endswith("authorized_keys"):
            return "authorized_keys"
        if lower.endswith("audit.log"):
            return "audit_log"
        if "/etc/ssh/" in lower:
            return "etc_ssh"
        if "/home/" in lower:
            return "home_tree"
        if "/tmp/" in lower:
            return "tmp_tree"
        try:
            return Path(p).name or "unknown_path"
        except Exception:
            return "unknown_path"

    def _command_bucket(self, command: str) -> str:
        cmd = self._normalize_command_text(command)
        if not cmd:
            return "unknown_command"
        tokens = self._command_tokens(cmd)
        first = Path(tokens[0]).name if tokens else Path(cmd.split(" ", 1)[0]).name
        first = first.lower()
        if first in {"useradd", "adduser"}:
            return "create_user"
        if first in {"getent", "grep", "awk", "cut"} and "passwd" in cmd:
            return "check_user_availability"
        if first in {"mkdir", "install"} and ".ssh" in cmd:
            return "prepare_ssh_dir"
        if first in {"tee", "cat", "printf", "echo"} and "authorized_keys" in cmd:
            return "install_authorized_key"
        if first in {"fail2ban-client", "iptables", "nft", "ufw"}:
            return "apply_rate_limit"
        if first in {"logger", "echo", "tee"} and "audit" in cmd:
            return "write_audit_log"
        return first or "unknown_command"

    def _agent_step_signature(self, event: dict[str, Any]) -> tuple[str, str] | None:
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") or {}
        if event_type in {"user_prompt", "user_prompt_batch"}:
            return "phase:user_prompt", "User prompt intake"
        if event_type == "assistant_response":
            return "phase:assistant_response", "Assistant response"
        if event_type == "api_call":
            model = str(payload.get("model") or "llm").strip() or "llm"
            return f"phase:api_call:{model}", f"LLM API call ({model})"
        if event_type == "tool_call_started":
            tool_name = str(payload.get("tool_name") or "unknown").strip() or "unknown"
            return f"tool:{tool_name}", f"Tool call: {tool_name}"
        if event_type == "tool_call_finished":
            tool_name = str(payload.get("tool_name") or "unknown").strip() or "unknown"
            return f"tool_result:{tool_name}", f"Tool result: {tool_name}"
        return None

    def _sys_step_signature(self, event: dict[str, Any]) -> tuple[str, str] | None:
        et = str(event.get("type") or "")
        if et == "command_exec":
            bucket = self._command_bucket(self._event_command_text(event))
            return f"cmd:{bucket}", f"Command: {bucket}"
        if et in {"file_read", "file_write", "file_delete", "file_rename"}:
            bucket = self._path_bucket(str(event.get("path") or ""))
            op = et.replace("file_", "")
            # Reads are less strict than writes/deletes in blast-radius checks.
            if op == "read":
                return f"fs_read:{bucket}", f"File read: {bucket}"
            return f"fs:{op}:{bucket}", f"File {op}: {bucket}"
        if et in {"net_connect", "net_send", "net_recv"}:
            dest = self._network_display_label(event)
            parsed = urlparse(dest if "://" in dest else f"tcp://{dest}")
            host = parsed.hostname or dest.split(":", 1)[0]
            host = host.lower()
            if host in {"127.0.0.1", "localhost", "::1"}:
                host_bucket = "localhost"
            elif host in KNOWN_LLM_HOSTS:
                host_bucket = "llm_provider"
            else:
                host_bucket = host
            op = et.replace("net_", "")
            return f"net:{op}:{host_bucket}", f"Network {op}: {host_bucket}"
        return None

    def _semantic_trace_steps(self, trace: TraceState) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []

        for idx, event in enumerate(trace.agent_events):
            sig = self._agent_step_signature(event)
            if not sig:
                continue
            key, label = sig
            steps.append(
                {
                    "key": key,
                    "label": label,
                    "source": "agent",
                    "line_no": int(event.get("line_no") or 0),
                    "ts": float(event.get("ts") or 0.0),
                    "order_hint": idx,
                    "raw_type": str(event.get("event_type") or ""),
                }
            )

        for idx, event in enumerate(trace.sys_events):
            sig = self._sys_step_signature(event)
            if not sig:
                continue
            key, label = sig
            steps.append(
                {
                    "key": key,
                    "label": label,
                    "source": "sys",
                    "line_no": int(event.get("line_no") or 0),
                    "ts": float(event.get("ts") or 0.0),
                    "order_hint": idx,
                    "raw_type": str(event.get("type") or ""),
                }
            )

        steps.sort(key=lambda s: (float(s.get("ts") or 0.0), int(s.get("line_no") or 0), s.get("source") != "agent"))

        # Collapse adjacent duplicates to avoid noisy syscall-level over-fitting.
        compressed: list[dict[str, Any]] = []
        prev_key = ""
        for step in steps:
            key = str(step.get("key") or "")
            if not key:
                continue
            if key == prev_key:
                continue
            compressed.append(step)
            prev_key = key
        return compressed

    def blast_radius_template(self, trace_ids: list[str], min_coverage: float = 0.6) -> dict[str, Any]:
        selected = [self._get_trace(tid) for tid in trace_ids]
        if not selected:
            raise ValueError("at least one trace is required")

        per_trace_steps: dict[str, list[dict[str, Any]]] = {
            t.trace_id: self._semantic_trace_steps(t) for t in selected
        }

        key_presence: Counter[str] = Counter()
        key_positions: dict[str, list[int]] = defaultdict(list)
        transition_counts: Counter[tuple[str, str]] = Counter()
        from_counts: Counter[str] = Counter()
        labels: dict[str, str] = {}

        for trace_id, steps in per_trace_steps.items():
            seen_in_trace: set[str] = set()
            keys = [str(s.get("key") or "") for s in steps if s.get("key")]
            for pos, key in enumerate(keys):
                labels[key] = str(steps[pos].get("label") or key)
                key_positions[key].append(pos)
                if key not in seen_in_trace:
                    key_presence[key] += 1
                    seen_in_trace.add(key)
            for i in range(len(keys) - 1):
                pair = (keys[i], keys[i + 1])
                transition_counts[pair] += 1
                from_counts[keys[i]] += 1

        total = len(selected)
        expected_steps: list[dict[str, Any]] = []
        for key, count in key_presence.items():
            coverage = count / total
            if coverage < min_coverage:
                continue
            positions = sorted(key_positions.get(key, []))
            if positions:
                lo_idx = max(0, int(0.2 * (len(positions) - 1)))
                hi_idx = int(0.8 * (len(positions) - 1))
                pos_low = positions[lo_idx]
                pos_high = positions[hi_idx]
                pos_med = positions[len(positions) // 2]
            else:
                pos_low = 0
                pos_high = 0
                pos_med = 0
            expected_steps.append(
                {
                    "key": key,
                    "label": labels.get(key, key),
                    "coverage": round(coverage, 3),
                    "position_low": pos_low,
                    "position_high": pos_high,
                    "position_median": pos_med,
                }
            )

        expected_steps.sort(key=lambda x: (int(x["position_median"]), -float(x["coverage"]), str(x["key"])))

        transitions = []
        for (src, dst), c in transition_counts.items():
            denom = from_counts.get(src, 1)
            transitions.append(
                {
                    "from": src,
                    "to": dst,
                    "count": c,
                    "probability": round(c / denom, 4),
                }
            )

        transitions.sort(key=lambda t: (-int(t["count"]), str(t["from"]), str(t["to"])))

        return {
            "trace_ids": trace_ids,
            "trace_count": total,
            "min_coverage": min_coverage,
            "expected_steps": expected_steps,
            "transitions": transitions,
            "trace_lengths": {k: len(v) for k, v in per_trace_steps.items()},
        }

    def blast_radius_compare(self, baseline_ids: list[str], candidate_id: str, min_coverage: float = 0.6) -> dict[str, Any]:
        if not baseline_ids:
            raise ValueError("baseline_ids must not be empty")
        template = self.blast_radius_template(baseline_ids, min_coverage=min_coverage)
        candidate = self._get_trace(candidate_id)
        candidate_steps = self._semantic_trace_steps(candidate)

        expected = template.get("expected_steps") or []
        expected_keys = [str(s.get("key") or "") for s in expected]
        expected_set = set(expected_keys)
        expected_by_key = {str(s.get("key") or ""): s for s in expected}

        transition_probs: dict[tuple[str, str], float] = {}
        transition_counts: dict[tuple[str, str], int] = {}
        for t in template.get("transitions") or []:
            src = str(t.get("from") or "")
            dst = str(t.get("to") or "")
            transition_probs[(src, dst)] = float(t.get("probability") or 0.0)
            transition_counts[(src, dst)] = int(t.get("count") or 0)

        rows: list[dict[str, Any]] = []
        deviations: list[dict[str, Any]] = []
        max_len = max(len(expected), len(candidate_steps))

        for idx in range(max_len):
            exp = expected[idx] if idx < len(expected) else None
            obs = candidate_steps[idx] if idx < len(candidate_steps) else None
            exp_key = str((exp or {}).get("key") or "")
            obs_key = str((obs or {}).get("key") or "")
            status = "match"
            reason = ""
            severity = "info"

            if exp and not obs:
                status = "missing"
                coverage = float(exp.get("coverage") or 0.0)
                severity = "high" if coverage >= 0.8 else "medium"
                reason = "Expected step missing from candidate trace"
            elif obs and not exp:
                status = "extra"
                severity = "medium"
                reason = "Candidate has additional step beyond trained template"
            elif exp_key != obs_key:
                status = "mismatch"
                if obs_key in expected_set:
                    severity = "medium"
                    reason = "Known step occurred out-of-order"
                else:
                    severity = "high"
                    reason = "Unexpected semantic step outside training baseline"

            row = {
                "index": idx,
                "expected": exp,
                "observed": obs,
                "status": status,
                "reason": reason,
                "severity": severity,
            }
            rows.append(row)

            if status != "match":
                deviations.append(
                    {
                        "index": idx,
                        "kind": status,
                        "severity": severity,
                        "reason": reason,
                        "expected": exp,
                        "observed": obs,
                        "evidence": {
                            "line_no": int((obs or {}).get("line_no") or 0),
                            "source": str((obs or {}).get("source") or ""),
                            "raw_type": str((obs or {}).get("raw_type") or ""),
                        },
                    }
                )

        # Transition-level anomalies capture process drift without exact syscall matching.
        for i in range(len(candidate_steps) - 1):
            a = str(candidate_steps[i].get("key") or "")
            b = str(candidate_steps[i + 1].get("key") or "")
            if not a or not b:
                continue
            if a not in expected_set or b not in expected_set:
                continue
            prob = transition_probs.get((a, b), 0.0)
            cnt = transition_counts.get((a, b), 0)
            if prob < 0.2 and cnt < 2:
                deviations.append(
                    {
                        "index": i,
                        "kind": "transition",
                        "severity": "medium",
                        "reason": "Rare transition between known stages",
                        "expected": expected_by_key.get(a),
                        "observed": {
                            "from": candidate_steps[i],
                            "to": candidate_steps[i + 1],
                            "probability": prob,
                        },
                        "evidence": {
                            "line_no": int(candidate_steps[i + 1].get("line_no") or 0),
                            "source": str(candidate_steps[i + 1].get("source") or ""),
                            "raw_type": str(candidate_steps[i + 1].get("raw_type") or ""),
                        },
                    }
                )

        deviation_score = min(100, int(round((len(deviations) / max(1, len(rows))) * 100)))
        summary = {
            "rows": len(rows),
            "deviations": len(deviations),
            "deviation_score": deviation_score,
            "status": "deviating" if deviations else "aligned",
        }

        return {
            "candidate_id": candidate_id,
            "baseline_ids": baseline_ids,
            "template": template,
            "candidate_steps": candidate_steps,
            "rows": rows,
            "deviations": deviations,
            "summary": summary,
        }


app = FastAPI(title="Agent System Observability Dashboard")


@app.middleware("http")
async def disable_frontend_cache(request: Request, call_next):
    """Avoid stale JS/HTML in browser cache, especially across Docker rebuilds."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def _resolve_paths() -> tuple[Path, Path]:
    env_trace = os.getenv("OBS_TRACE_DIR")
    env_events = os.getenv("OBS_EVENTS_DIR")
    if env_trace and env_events:
        return Path(env_trace).expanduser(), Path(env_events).expanduser()

    # app.py lives at <repo>/mantle/dashboard/app.py, so repo root is 3 levels up.
    repo_root = Path(__file__).resolve().parents[2]
    obs_root_env = os.getenv("AGENT_OBS_ROOT", "").strip()
    obs_root = Path(obs_root_env).expanduser() if obs_root_env else (repo_root / "obs")

    candidate_pairs = [
        (obs_root / "traces", obs_root / "events"),
        (
            Path("~/shared/mantle/obs/traces").expanduser(),
            Path("~/shared/mantle/obs/events").expanduser(),
        ),
        (
            Path("~/ubuntu_shared/mantle/obs/traces").expanduser(),
            Path("~/ubuntu_shared/mantle/obs/events").expanduser(),
        ),
    ]

    best_pair = candidate_pairs[-1]
    best_score = -1

    for trace_dir, events_dir in candidate_pairs:
        trace_logs = len(list(trace_dir.glob("*.ebpf.jsonl"))) if trace_dir.exists() else 0
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
    stop_event = asyncio.Event()
    app.state.poll_stop_event = stop_event

    async def _poll_loop() -> None:
        while not stop_event.is_set():
            try:
                await store.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

    app.state.poll_task = asyncio.create_task(_poll_loop(), name="mantle-dashboard-poll")


@app.on_event("shutdown")
async def shutdown() -> None:
    stop_event = getattr(app.state, "poll_stop_event", None)
    poll_task = getattr(app.state, "poll_task", None)

    if stop_event is not None:
        stop_event.set()

    if poll_task is not None and not poll_task.done():
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass


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


@app.get("/api/traces/{trace_id}/process-graph/{pid}")
def process_graph(trace_id: str, pid: int) -> dict[str, Any]:
    try:
        return store.process_graph(trace_id, pid)
    except KeyError as exc:
        # Only treat missing trace-id lookups as 404. Other KeyErrors are
        # internal issues and should not be masked as "trace not found".
        if exc.args and str(exc.args[0]) == trace_id:
            raise HTTPException(status_code=404, detail="trace not found")
        raise HTTPException(status_code=500, detail="process graph build failed")


@app.get("/api/traces/{trace_id}/internal-graph/{line_start}/{line_end}")
def internal_graph(trace_id: str, line_start: int, line_end: int) -> dict[str, Any]:
    try:
        return store.internal_graph(trace_id, line_start, line_end)
    except KeyError:
        raise HTTPException(status_code=404, detail="trace not found")


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


@app.get("/api/traces/{trace_id}/taint-analysis")
def taint_analysis(trace_id: str, trust_policy: str = "nondeterministic") -> dict[str, Any]:
    try:
        return store.taint_analysis(trace_id, trust_policy=trust_policy)
    except KeyError:
        raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/blast-radius/template")
def blast_radius_template(trace_ids: str, min_coverage: float = 0.6) -> dict[str, Any]:
    ids = [t.strip() for t in trace_ids.split(",") if t.strip()]
    if not ids:
        raise HTTPException(status_code=400, detail="trace_ids is required")
    try:
        return store.blast_radius_template(ids, min_coverage=min_coverage)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Trace not found: {exc.args[0] if exc.args else 'unknown'}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/blast-radius/compare")
def blast_radius_compare(candidate_id: str, baseline_ids: str, min_coverage: float = 0.6) -> dict[str, Any]:
    baseline = [t.strip() for t in baseline_ids.split(",") if t.strip()]
    if not candidate_id.strip():
        raise HTTPException(status_code=400, detail="candidate_id is required")
    if not baseline:
        raise HTTPException(status_code=400, detail="baseline_ids is required")
    try:
        return store.blast_radius_compare(baseline, candidate_id.strip(), min_coverage=min_coverage)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Trace not found: {exc.args[0] if exc.args else 'unknown'}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
