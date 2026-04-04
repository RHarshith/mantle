"""Core trace storage, ingestion, correlation, and graph synthesis backend."""

from __future__ import annotations

import asyncio
import bisect
import difflib
import heapq
import json
import os
import re
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mantle.dashboard.llm_utils import (
    builtin_llm_api_schemas,
    normalize_llm_schemas,
    parse_llm_calls_from_mitm,
)
from mantle.dashboard.logging_utils import log_exception
from mantle.dashboard.replay_trace import (
    build_replay_overview,
    build_replay_turn_detail,
)
from mantle.dashboard.syscall_utils import (
    command_network_targets,
    extract_fd,
    extract_quoted,
    is_noisy_path,
    is_user_visible_path,
    parse_open_mode,
    parse_ret_status,
    parse_socket_address,
    socket_family,
    socket_transport,
)

try:
    import tiktoken
except Exception:  # pragma: no cover - optional dependency fallback
    tiktoken = None

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


def _ordered_unique_int(values: list[int]) -> list[int]:
    """Deduplicate integer sequence while preserving first-seen order."""
    out: list[int] = []
    seen: set[int] = set()
    for raw in values:
        value = int(raw)
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


@dataclass
class TraceState:
    """In-memory mutable state for a single trace id."""

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
    """Stateful store for trace ingestion, correlation, and graph projection."""

    def __init__(self, trace_dir: Path, events_dir: Path, mitm_dir: Path | None = None):
        """Initialize the trace store with watched directories and defaults."""
        self.trace_dir = trace_dir
        self.events_dir = events_dir
        self.mitm_dir = mitm_dir
        self.traces: dict[str, TraceState] = {}
        self.version = 0
        self._lock = asyncio.Lock()
        self.llm_api_schemas: list[dict[str, Any]] = self._builtin_llm_api_schemas()

    def _builtin_llm_api_schemas(self) -> list[dict[str, Any]]:
        """Return builtin LLM API schema definitions."""
        return builtin_llm_api_schemas()

    def list_llm_api_schemas(self) -> dict[str, Any]:
        return {
            "schemas": self.llm_api_schemas,
        }

    def set_llm_api_schemas(self, schemas: list[dict[str, Any]]) -> dict[str, Any]:
        """Replace runtime schema config with a validated normalized list."""
        normalized = normalize_llm_schemas(schemas)
        self.llm_api_schemas = normalized
        self.version += 1
        return {"schemas": self.llm_api_schemas}

    def _extract_by_path(self, data: Any, path: str) -> list[Any]:
        if not path:
            return []
        tokens = path.replace("]", "").split(".")
        curs: list[Any] = [data]
        for token in tokens:
            if not token:
                continue
            want_all = token.endswith("[]")
            key = token[:-2] if want_all else token
            next_curs: list[Any] = []
            for cur in curs:
                if key:
                    if isinstance(cur, dict) and key in cur:
                        cur_val = cur.get(key)
                    else:
                        continue
                else:
                    cur_val = cur

                if want_all:
                    if isinstance(cur_val, list):
                        next_curs.extend(cur_val)
                    else:
                        continue
                else:
                    next_curs.append(cur_val)
            curs = next_curs
            if not curs:
                break
        return curs

    def _extract_texts_from_messages(self, messages: Any) -> list[str]:
        out: list[str] = []
        if not isinstance(messages, list):
            return out
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role") or msg.get("type") or "")
            content = msg.get("content")
            if role in {"system", "developer", "user", "input_text"}:
                text = ""
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    parts: list[str] = []
                    for c in content:
                        if isinstance(c, str):
                            parts.append(c)
                        elif isinstance(c, dict) and isinstance(c.get("text"), str):
                            parts.append(str(c.get("text")))
                    text = "\n".join([p for p in parts if p])
                if text.strip():
                    out.append(text.strip())
        return out

    def _section_values(self, data: Any, specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sections: list[dict[str, Any]] = []
        for spec in specs:
            if not isinstance(spec, dict):
                continue
            path = str(spec.get("path") or "").strip()
            if not path:
                continue
            mode = str(spec.get("mode") or "text").strip()
            values: list[Any] = []

            for raw in self._extract_by_path(data, path):
                if mode == "messages_text":
                    for text in self._extract_texts_from_messages(raw):
                        if text:
                            values.append(text)
                    continue

                if mode == "json":
                    values.append(raw)
                    continue

                if isinstance(raw, str):
                    txt = raw.strip()
                    if txt:
                        values.append(txt)
                    continue

                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, str) and item.strip():
                            values.append(item.strip())
                        elif isinstance(item, dict) and isinstance(item.get("text"), str) and str(item.get("text") or "").strip():
                            values.append(str(item.get("text") or "").strip())
                    continue

                if raw is not None:
                    values.append(raw)

            if not values:
                continue

            sections.append(
                {
                    "id": str(spec.get("id") or path),
                    "label": str(spec.get("label") or spec.get("id") or path),
                    "values": values,
                }
            )
        return sections

    def _sections_to_text(self, sections: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        for section in sections:
            for value in section.get("values") or []:
                if isinstance(value, str):
                    if value.strip():
                        parts.append(value.strip())
                else:
                    parts.append(json.dumps(value, ensure_ascii=False))
        return "\n\n".join([p for p in parts if p])

    def _merge_sections(self, base: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
        order: list[str] = []
        merged: dict[str, dict[str, Any]] = {}

        for source in [base, extra]:
            for section in source:
                sid = str(section.get("id") or "").strip()
                if not sid:
                    continue
                if sid not in merged:
                    merged[sid] = {
                        "id": sid,
                        "label": str(section.get("label") or sid),
                        "values": [],
                    }
                    order.append(sid)

                existing = merged[sid]
                seen: set[str] = set()
                for v in existing["values"]:
                    seen.add(json.dumps(v, ensure_ascii=False, sort_keys=True))

                for v in section.get("values") or []:
                    sig = json.dumps(v, ensure_ascii=False, sort_keys=True)
                    if sig in seen:
                        continue
                    existing["values"].append(v)
                    seen.add(sig)

        return [merged[sid] for sid in order if merged[sid].get("values")]

    def _parse_sse_data_events(self, raw: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not raw:
            return events

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
            if isinstance(data, dict):
                events.append(data)
        return events

    def _normalize_streaming_response_body(self, raw: str) -> dict[str, Any]:
        events = self._parse_sse_data_events(raw)
        if not events:
            return {}

        def _parse_json_or_raw(value: Any) -> Any:
            if isinstance(value, (dict, list)):
                return value
            if isinstance(value, str):
                txt = value.strip()
                if not txt:
                    return {}
                try:
                    return json.loads(txt)
                except json.JSONDecodeError:
                    return {"_raw": txt}
            return {}

        items_by_id: dict[str, dict[str, Any]] = {}
        item_order: list[str] = []
        message_text_parts: dict[str, list[str]] = defaultdict(list)
        output_text_done: dict[str, str] = {}
        function_args_parts: dict[str, str] = defaultdict(str)
        custom_input_parts: dict[str, str] = defaultdict(str)
        usage: dict[str, Any] | None = None

        for event in events:
            ev_type = str(event.get("type") or "")

            if ev_type == "response.output_item.added":
                item = event.get("item") or {}
                if not isinstance(item, dict):
                    continue
                item_id = str(item.get("id") or "")
                if not item_id:
                    continue
                if item_id not in items_by_id:
                    item_order.append(item_id)
                    items_by_id[item_id] = dict(item)
                else:
                    items_by_id[item_id].update(item)
                continue

            if ev_type == "response.output_item.done":
                item = event.get("item") or {}
                if not isinstance(item, dict):
                    continue
                item_id = str(item.get("id") or "")
                if not item_id:
                    continue
                if item_id not in items_by_id:
                    item_order.append(item_id)
                    items_by_id[item_id] = {}
                items_by_id[item_id].update(item)
                continue

            if ev_type == "response.output_text.delta":
                item_id = str(event.get("item_id") or "")
                delta = str(event.get("delta") or "")
                if item_id and delta:
                    message_text_parts[item_id].append(delta)
                continue

            if ev_type == "response.output_text.done":
                item_id = str(event.get("item_id") or "")
                text = str(event.get("text") or "")
                if item_id and text:
                    output_text_done[item_id] = text
                continue

            if ev_type == "response.function_call_arguments.delta":
                item_id = str(event.get("item_id") or "")
                if item_id:
                    function_args_parts[item_id] += str(event.get("delta") or "")
                continue

            if ev_type == "response.custom_tool_call_input.delta":
                item_id = str(event.get("item_id") or "")
                if item_id:
                    custom_input_parts[item_id] += str(event.get("delta") or "")
                continue

            if ev_type == "response.custom_tool_call_input.done":
                item_id = str(event.get("item_id") or "")
                if item_id:
                    custom_input_parts[item_id] = str(event.get("input") or custom_input_parts.get(item_id) or "")
                continue

            if ev_type == "response.completed":
                resp = event.get("response") or {}
                if isinstance(resp, dict) and isinstance(resp.get("usage"), dict):
                    usage = resp.get("usage")

        output_items: list[dict[str, Any]] = []
        assistant_texts: list[str] = []
        tool_calls: list[dict[str, Any]] = []

        for item_id in item_order:
            item = dict(items_by_id.get(item_id) or {})
            if not item:
                continue
            item_type = str(item.get("type") or "")

            if item_type == "message":
                content = item.get("content")
                text = ""
                if isinstance(content, list):
                    parts: list[str] = []
                    for c in content:
                        if isinstance(c, dict) and isinstance(c.get("text"), str) and str(c.get("text") or "").strip():
                            parts.append(str(c.get("text") or "").strip())
                    text = "\n".join(parts)
                if not text:
                    text = str(output_text_done.get(item_id) or "").strip()
                if not text and message_text_parts.get(item_id):
                    text = "".join(message_text_parts[item_id]).strip()
                if text:
                    item["content"] = [{"type": "output_text", "text": text}]
                    assistant_texts.append(text)

            if item_type == "function_call":
                args_raw = str(item.get("arguments") or function_args_parts.get(item_id) or "")
                if args_raw:
                    item["arguments"] = args_raw
                tool_calls.append(
                    {
                        "tool_call_id": item.get("call_id") or item.get("id") or item_id,
                        "tool_name": item.get("name") or "unknown",
                        "arguments": _parse_json_or_raw(args_raw),
                    }
                )

            if item_type == "custom_tool_call":
                call_input = str(item.get("input") or custom_input_parts.get(item_id) or "")
                if call_input:
                    item["input"] = call_input
                tool_calls.append(
                    {
                        "tool_call_id": item.get("call_id") or item.get("id") or item_id,
                        "tool_name": item.get("name") or "unknown",
                        "input": call_input,
                    }
                )

            output_items.append(item)

        normalized: dict[str, Any] = {
            "output": output_items,
            "output_text": "\n\n".join([t for t in assistant_texts if t]),
            "tool_calls": tool_calls,
            "_raw": raw,
        }
        if usage is not None:
            normalized["usage"] = usage
        return normalized

    def _normalize_response_body_for_sections(self, response_body: Any) -> dict[str, Any]:
        if not isinstance(response_body, dict):
            return {}

        raw = response_body.get("_raw")
        if isinstance(raw, str) and raw.strip():
            parsed = self._normalize_streaming_response_body(raw)
            if parsed:
                merged = dict(response_body)
                merged.update(parsed)
                return merged

        return response_body

    def _parse_llm_calls_from_mitm(self, trace: TraceState) -> list[dict[str, Any]]:
        """Parse MITM logs into turn-level prompt/response records."""
        return parse_llm_calls_from_mitm(trace, self.llm_api_schemas)

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
            """Parse streaming Responses API SSE text into assistant/tool events."""
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
                stripped = line.lstrip()
                if not stripped.startswith("data:"):
                    continue
                payload = stripped[5:].strip()
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
                    elif item_type == "custom_tool_call":
                        tool_by_item[item_id] = {
                            "id": item_id,
                            "tool_call_id": item.get("call_id") or item_id,
                            "tool_name": item.get("name") or "unknown",
                            "arguments": item.get("input") or "",
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
                    elif item_type == "custom_tool_call":
                        entry = tool_by_item.setdefault(
                            item_id,
                            {
                                "id": item_id,
                                "tool_call_id": item.get("call_id") or item_id,
                                "tool_name": item.get("name") or "unknown",
                                "arguments": "",
                            },
                        )
                        entry["arguments"] = item.get("input") or entry.get("arguments") or ""
                    continue

                if dtype == "response.function_call_arguments.delta":
                    item_id = str(data.get("item_id") or "")
                    if item_id in tool_by_item:
                        tool_by_item[item_id]["arguments"] = str(tool_by_item[item_id].get("arguments") or "") + str(data.get("delta", ""))
                    continue

                if dtype == "response.function_call_arguments.done":
                    item_id = str(data.get("item_id") or "")
                    if item_id in tool_by_item:
                        tool_by_item[item_id]["arguments"] = str(data.get("arguments") or tool_by_item[item_id].get("arguments") or "")
                    continue

                if dtype == "response.custom_tool_call_input.delta":
                    item_id = str(data.get("item_id") or "")
                    if item_id in tool_by_item:
                        tool_by_item[item_id]["arguments"] = str(tool_by_item[item_id].get("arguments") or "") + str(data.get("delta", ""))
                    continue

                if dtype == "response.custom_tool_call_input.done":
                    item_id = str(data.get("item_id") or "")
                    if item_id in tool_by_item:
                        tool_by_item[item_id]["arguments"] = str(data.get("input") or tool_by_item[item_id].get("arguments") or "")
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
                    log_exception("Failed parsing MITM endpoint URL")

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
                msg_type = str(msg.get("type") or "")
                is_tool_resp = msg_type in {"function_call_output", "custom_tool_call_output"}
                if not (is_tool_chat or is_tool_resp):
                    continue
                tid = msg.get("tool_call_id") or msg.get("call_id") or msg.get("id") or ""
                raw_content = msg.get("content", msg.get("output", msg.get("output_text", "")))
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
                    log_exception("Failed deriving MITM interval from endpoint")

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
                emitted_tool_results = {
                    e["payload"]["tool_call_id"]
                    for e in state.agent_events
                    if e.get("event_type") == "tool_call_finished" and isinstance(e.get("payload"), dict)
                }
                finish_event_by_id: dict[str, dict[str, Any]] = {
                    str((e.get("payload") or {}).get("tool_call_id") or ""): e
                    for e in state.agent_events
                    if e.get("event_type") == "tool_call_finished" and isinstance(e.get("payload"), dict)
                }
                start_event_by_id: dict[str, dict[str, Any]] = {
                    str((e.get("payload") or {}).get("tool_call_id") or ""): e
                    for e in state.agent_events
                    if e.get("event_type") == "tool_call_started" and isinstance(e.get("payload"), dict)
                }
                for msg in messages:
                    # Chat Completions format: role=tool, tool_call_id, content
                    is_tool_chat = msg.get("role") == "tool"
                    # Responses API format: type=function_call_output, call_id, output
                    msg_type = str(msg.get("type") or "")
                    is_tool_resp = msg_type in {"function_call_output", "custom_tool_call_output"}

                    if not (is_tool_chat or is_tool_resp):
                        continue

                    tid = msg.get("tool_call_id") or msg.get("call_id") or msg.get("id") or ""
                    if not tid:
                        continue
                    raw_content = msg.get("content", msg.get("output", msg.get("output_text", "")))
                    tool_content = _get_string_content(raw_content)
                    try:
                        result = json.loads(tool_content)
                    except (json.JSONDecodeError, TypeError):
                        result = {"output": tool_content}

                    # Try to find the tool name from a matching function_call item
                    tool_name = "unknown"
                    for m2 in messages:
                        if m2.get("type") in {"function_call", "custom_tool_call"} and m2.get("call_id") == tid:
                            tool_name = m2.get("name", "unknown")
                            break

                    canonical_tid = str(tid)
                    if canonical_tid not in start_event_by_id:
                        # Codex/Responses streams can emit started calls with a
                        # temporary ID when call_id is absent in early chunks.
                        # Reconcile to the most recent unmatched start event.
                        candidates: list[tuple[float, str]] = []
                        for started_id, started_ev in start_event_by_id.items():
                            if not started_id or started_id in emitted_tool_results:
                                continue
                            started_payload = started_ev.get("payload") or {}
                            started_name = str(started_payload.get("tool_name") or "unknown")
                            if tool_name != "unknown" and started_name != tool_name:
                                continue
                            candidates.append((float(started_ev.get("ts") or 0.0), started_id))

                        if candidates:
                            candidates.sort(key=lambda item: item[0])
                            canonical_tid = candidates[-1][1]

                    if canonical_tid in emitted_tool_results:
                        existing_finish = finish_event_by_id.get(canonical_tid) or finish_event_by_id.get(str(tid))
                        if existing_finish is not None:
                            payload = existing_finish.setdefault("payload", {})
                            payload["result"] = result
                        continue

                    emitted_tool_results.add(canonical_tid)

                    # Tool output is carried in this call's request payload, but we
                    # ingest only response-direction MITM records. Reconstruct the
                    # request-start timestamp so finishes stay in the originating turn.
                    finish_ts = float(ts or 0.0)
                    if finish_ts > 0:
                        try:
                            if duration_ms is not None:
                                finish_ts = finish_ts - (float(duration_ms) / 1000.0)
                        except Exception:
                            pass
                        # Keep finishes just before the current request boundary.
                        # Use a small cushion to absorb duration rounding jitter.
                        finish_ts = finish_ts - 0.01

                    # Ensure finish stays after its matching start event when known.
                    start_ts: float | None = None
                    for prev_ev in reversed(state.agent_events):
                        if prev_ev.get("event_type") != "tool_call_started":
                            continue
                        prev_payload = prev_ev.get("payload") or {}
                        if str(prev_payload.get("tool_call_id") or "") != canonical_tid:
                            continue
                        start_ts = float(prev_ev.get("ts") or 0.0)
                        break
                    if start_ts is not None and finish_ts <= start_ts:
                        finish_ts = start_ts + 0.0001

                    seq += 1
                    state.agent_events.append(
                        {
                            "ts": finish_ts,
                            "seq": seq,
                            "event_type": "tool_call_finished",
                            "payload": {
                                "tool_call_id": canonical_tid,
                                "tool_name": tool_name,
                                "duration_ms": duration_ms,
                                "result": result,
                            },
                            "_source": "mitm",
                        }
                    )

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

            # Some captures may miss sched_process_fork for a child but still
            # include command_exec with ppid. Use this to preserve ancestry.
            if event_type == "command_exec":
                pid = int(normalized.get("pid", 0))
                ppid = int(normalized.get("ppid", 0))
                if pid > 0 and ppid > 0 and pid not in state.process_parent:
                    state.process_parent[pid] = ppid

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
        """Extract quoted strings from syscall argument text."""
        return extract_quoted(text)

    def _is_noisy_path(self, path: str) -> bool:
        """Return True for system/noise paths hidden from dashboard graphs."""
        return is_noisy_path(path, NOISY_PREFIXES, NOISY_SUFFIXES)

    def _is_user_visible_path(self, path: str) -> bool:
        """Return True if a path is likely user/workspace relevant."""
        return is_user_visible_path(path, SYSTEM_PREFIXES)

    def _parse_open_mode(self, args: str) -> str:
        """Classify file open mode as read or write."""
        return parse_open_mode(args)

    def _push_sys_event(self, state: TraceState, event: dict[str, Any]) -> None:
        event["ts"] = time.time()
        event["line_no"] = state.trace_line_no
        state.sys_events.append(event)

    def _extract_fd(self, args: str) -> int:
        """Extract file descriptor from syscall argument list."""
        return extract_fd(args)

    def _socket_family(self, args: str) -> str:
        """Infer socket family from syscall argument text."""
        return socket_family(args)

    def _socket_transport(self, args: str) -> str:
        """Infer socket transport from syscall argument text."""
        return socket_transport(args)

    def _parse_socket_address(self, args: str) -> dict[str, str]:
        """Parse address information from connect/send/recv syscalls."""
        return parse_socket_address(args)

    def _parse_ret_status(self, ret: str) -> dict[str, Any]:
        """Normalize syscall return text into a status payload."""
        return parse_ret_status(ret)

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
        if dest in proxy_dests:
            enriched["inferred_dest"] = _best_endpoint_for_event_ts(float(event.get("ts") or 0.0))
        return enriched

    def _command_network_targets(self, command: str) -> list[str]:
        """Extract network endpoint targets from a shell command string."""
        return command_network_targets(command)

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

    def _candidate_trace_paths(self, trace_id: str) -> list[Path]:
        candidates = [self.trace_dir / trace_id]
        if trace_id.endswith(".ebpf.jsonl"):
            # Defensive fallback if callers ever pass the stem.
            stem = trace_id[: -len(".ebpf.jsonl")]
            candidates.append(self.trace_dir / f"{stem}.ebpf.jsonl")
        return candidates

    def _candidate_events_paths(self, trace_id: str) -> list[Path]:
        trace_file = self.trace_dir / trace_id
        candidates = self._trace_to_event_candidates(trace_file)
        # Also support direct <trace_id>.events.jsonl naming.
        candidates.append(self.events_dir / f"{trace_id}.events.jsonl")
        seen: set[Path] = set()
        uniq: list[Path] = []
        for cand in candidates:
            if cand in seen:
                continue
            seen.add(cand)
            uniq.append(cand)
        return uniq

    def _candidate_mitm_paths(self, trace_id: str) -> list[Path]:
        if not self.mitm_dir:
            return []
        candidates: list[Path] = [self.mitm_dir / f"{trace_id}.mitm.jsonl"]
        no_ext = Path(trace_id).stem
        candidates.append(self.mitm_dir / f"{no_ext}.mitm.jsonl")
        if trace_id.endswith(".ebpf.jsonl"):
            base = trace_id[: -len(".ebpf.jsonl")]
            candidates.append(self.mitm_dir / f"{base}.mitm.jsonl")

        seen: set[Path] = set()
        uniq: list[Path] = []
        for cand in candidates:
            if cand in seen:
                continue
            seen.add(cand)
            uniq.append(cand)
        return uniq

    async def delete_trace(self, trace_id: str) -> dict[str, Any]:
        trace = self.traces.get(trace_id)

        trace_paths = self._candidate_trace_paths(trace_id)
        events_paths = self._candidate_events_paths(trace_id)
        mitm_paths = self._candidate_mitm_paths(trace_id)

        if trace is not None:
            trace_paths = [trace.trace_path] + [p for p in trace_paths if p != trace.trace_path]
            events_paths = trace.events_path_candidates + [p for p in events_paths if p not in trace.events_path_candidates]
            if trace.mitm_path is not None:
                mitm_paths = [trace.mitm_path] + [p for p in mitm_paths if p != trace.mitm_path]

        removed_files: list[str] = []
        for path in trace_paths + events_paths + mitm_paths:
            if not path.exists():
                continue
            if not path.is_file():
                continue
            path.unlink()
            removed_files.append(str(path))

        if trace is None and not removed_files:
            raise KeyError(trace_id)

        self.traces.pop(trace_id, None)
        async with self._lock:
            self.version += 1

        return {"trace_id": trace_id, "deleted_files": removed_files}

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
            # Preserve the frontend contract: started tool events render as tool_step.
            kind = "tool_step"
            tool_name = payload.get("tool_name") or "unknown"
            label = f"Tool: {tool_name}"
        elif event_type == "tool_call_finished":
            # Preserve the frontend contract: finished tool events render as tool_output.
            kind = "tool_output"
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

    def _collect_argument_strings(self, value: Any, depth: int = 0) -> list[str]:
        if depth > 5:
            return []

        out: list[str] = []
        if isinstance(value, str):
            text = value.strip()
            if text:
                out.append(text)
            return out

        if isinstance(value, list):
            for item in value:
                out.extend(self._collect_argument_strings(item, depth + 1))
            return out

        if isinstance(value, dict):
            for key, item in value.items():
                out.extend(self._collect_argument_strings(item, depth + 1))
                if isinstance(key, str) and key.strip():
                    out.append(key.strip())
            return out

        return out

    def _extract_argument_path_hints(self, arguments: Any) -> list[str]:
        candidates: list[str] = []
        strings = self._collect_argument_strings(arguments)
        path_re = re.compile(r"(?:~?/|\./|\.\./|/)[A-Za-z0-9_./\-~]+")

        for text in strings:
            if not text:
                continue
            if "/" in text or text.startswith("~"):
                candidates.append(text)
            for match in path_re.findall(text):
                candidates.append(match)

        normalized: list[str] = []
        seen: set[str] = set()
        for value in candidates:
            v = str(value).strip().strip('"\'')
            if not v:
                continue
            if len(v) < 2 or len(v) > 512:
                continue
            key = v.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(v)
        return normalized

    def _extract_argument_command_hints(self, tool_pair: dict[str, Any]) -> list[str]:
        out: list[str] = []
        args = tool_pair.get("arguments") or {}
        if isinstance(args, dict):
            for key in ("command", "cmd", "script", "query"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    out.append(value.strip())
        base = self._extract_tool_command_text(tool_pair)
        if base:
            out.append(base)
        tool_name = str(tool_pair.get("tool_name") or "").strip()
        if tool_name:
            out.append(tool_name)

        seen: set[str] = set()
        uniq: list[str] = []
        for item in out:
            key = self._normalize_command_text(item)
            if not key or key in seen:
                continue
            seen.add(key)
            uniq.append(item)
        return uniq

    def _path_match_score(self, hint: str, event_path: str) -> int:
        h = str(hint or "").strip().lower()
        p = str(event_path or "").strip().lower()
        if not h or not p:
            return 0
        if h == p:
            return 120

        h_base = Path(h).name.lower()
        p_base = Path(p).name.lower()
        if h_base and h_base == p_base:
            return 70
        if p.endswith(h) or h.endswith(p):
            return 60
        if h in p or p in h:
            return 40
        return 0

    def _oldest_matching_command_root_pid(
        self,
        trace: TraceState,
        sys_events: list[dict[str, Any]],
        start_pid: int,
        cmd_hints: list[str],
        min_match_score: int = 8,
    ) -> int:
        """Return the oldest ancestor whose command_exec still matches tool params.

        Traversal rules:
        - Walk the process lineage upward from start_pid within the current scope.
        - Track the first command_exec match and continue while ancestors also match.
        - Stop at the first non-matching command_exec *after* matching has started.
        - Never climb outside current scoped pids.
        """
        current = int(start_pid)
        if current <= 0:
            return 0

        scope_pids: set[int] = set()
        exec_by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for e in sys_events:
            pid = int(e.get("pid") or 0)
            child = int(e.get("child_pid") or 0)
            if pid > 0:
                scope_pids.add(pid)
            if child > 0:
                scope_pids.add(child)
            if str(e.get("type") or "") == "command_exec" and pid > 0:
                exec_by_pid[pid].append(e)

        for pid in list(exec_by_pid.keys()):
            exec_by_pid[pid].sort(key=lambda ev: int(ev.get("line_no") or 0))

        best_root = current
        found_match = False
        seen: set[int] = set()

        while current > 0 and current not in seen:
            seen.add(current)
            if current not in scope_pids:
                break

            exec_events = exec_by_pid.get(current) or []
            has_match_here = False
            if exec_events and cmd_hints:
                best_score_here = 0
                for ev in exec_events:
                    for hint in cmd_hints:
                        best_score_here = max(best_score_here, self._command_match_score(hint, ev))
                has_match_here = best_score_here >= min_match_score

            if has_match_here:
                found_match = True
                best_root = current
            elif found_match:
                # Stop once matching chain is broken.
                break

            parent = int(trace.process_parent.get(current, 0))
            if parent <= 0:
                break
            current = parent

        return best_root if found_match else int(start_pid)

    def _match_tool_source_for_turn(
        self,
        trace: TraceState,
        sys_events: list[dict[str, Any]],
        tool_pair: dict[str, Any],
    ) -> dict[str, Any]:
        if not sys_events:
            return {"status": "source_not_found"}

        start_ts = float(tool_pair.get("started_ts") or 0.0)
        end_ts = float(tool_pair.get("finished_ts") or 0.0)
        if end_ts <= 0.0 and start_ts > 0.0:
            end_ts = start_ts + 5.0
        if end_ts < start_ts:
            end_ts = start_ts + 5.0

        window: list[dict[str, Any]]
        if start_ts > 0.0:
            lo = start_ts - 1.0
            hi = end_ts + 1.0
            window = [e for e in sys_events if lo <= self._event_ts(e) <= hi]
        else:
            window = list(sys_events)
        if not window:
            window = list(sys_events)

        cmd_hints = self._extract_argument_command_hints(tool_pair)
        path_hints = self._extract_argument_path_hints(tool_pair.get("arguments") or {})

        score_by_pid: defaultdict[int, int] = defaultdict(int)
        best_event_for_pid: dict[int, dict[str, Any]] = {}

        for ev in window:
            et = str(ev.get("type") or "")
            pid = int(ev.get("pid") or 0)
            if pid <= 0:
                continue

            score = 0
            if et == "command_exec":
                best_cmd = 0
                for hint in cmd_hints:
                    best_cmd = max(best_cmd, self._command_match_score(hint, ev))
                if best_cmd > 0:
                    score += best_cmd + 20
                if self._is_agent_internal_command(ev):
                    score -= 40

            if et in {"file_read", "file_write", "file_delete", "file_rename"}:
                event_path = str(ev.get("path") or "")
                best_path = 0
                for hint in path_hints:
                    best_path = max(best_path, self._path_match_score(hint, event_path))
                if best_path > 0:
                    score += best_path + 15

            if score <= 0:
                continue

            score_by_pid[pid] += score
            existing = best_event_for_pid.get(pid)
            if existing is None or score > int(existing.get("_tool_source_score") or 0):
                ev_copy = dict(ev)
                ev_copy["_tool_source_score"] = score
                best_event_for_pid[pid] = ev_copy

        if not score_by_pid:
            fallback_exec = [
                e for e in window
                if str(e.get("type") or "") == "command_exec" and not self._is_agent_internal_command(e)
            ]
            if not fallback_exec:
                return {"status": "source_not_found"}

            if start_ts > 0:
                fallback_exec.sort(key=lambda e: abs(self._event_ts(e) - start_ts))
            else:
                fallback_exec.sort(key=lambda e: int(e.get("line_no") or 0))

            pid = int(fallback_exec[0].get("pid") or 0)
            if pid <= 0:
                return {"status": "source_not_found"}
            source_pid = self._oldest_matching_command_root_pid(trace, window, pid, cmd_hints)
            if source_pid <= 0:
                return {"status": "source_not_found"}
            return {
                "status": "matched",
                "pid": source_pid,
                "matched_by": "fallback_command",
            }

        best_pid = max(score_by_pid.items(), key=lambda item: item[1])[0]
        total_score = int(score_by_pid.get(best_pid) or 0)
        if total_score < 20:
            return {"status": "source_not_found"}

        source_pid = self._oldest_matching_command_root_pid(trace, window, best_pid, cmd_hints)
        if source_pid <= 0:
            return {"status": "source_not_found"}

        best_event = best_event_for_pid.get(best_pid) or {}
        matched_by = "command_or_path"
        if str(best_event.get("type") or "") in {"file_read", "file_write", "file_delete", "file_rename"}:
            matched_by = "path"
        elif str(best_event.get("type") or "") == "command_exec":
            matched_by = "command"

        return {
            "status": "matched",
            "pid": source_pid,
            "matched_by": matched_by,
            "score": total_score,
        }

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

    def _event_ts(self, event: dict[str, Any]) -> float:
        try:
            return float(event.get("ts") or 0.0)
        except Exception:
            return 0.0

    def _event_seq(self, event: dict[str, Any]) -> int:
        try:
            return int(event.get("seq") or 0)
        except Exception:
            return 0

    def _tool_pairs(self, agent_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        starts: dict[str, dict[str, Any]] = {}
        finishes: dict[str, dict[str, Any]] = {}

        for ev in agent_events:
            et = str(ev.get("event_type") or "")
            payload = ev.get("payload") or {}
            tool_call_id = str(payload.get("tool_call_id") or "").strip()
            if not tool_call_id:
                continue
            if et == "tool_call_started" and tool_call_id not in starts:
                starts[tool_call_id] = ev
            elif et == "tool_call_finished":
                finishes[tool_call_id] = ev

        out: list[dict[str, Any]] = []
        for tool_call_id, start_ev in starts.items():
            start_payload = start_ev.get("payload") or {}
            finish_ev = finishes.get(tool_call_id)
            finish_payload = (finish_ev or {}).get("payload") or {}
            out.append(
                {
                    "tool_call_id": tool_call_id,
                    "tool_name": str(start_payload.get("tool_name") or finish_payload.get("tool_name") or "unknown"),
                    "started_ts": self._event_ts(start_ev),
                    "finished_ts": self._event_ts(finish_ev) if finish_ev else None,
                    "arguments": start_payload.get("arguments") or {},
                    "result": finish_payload.get("result") if finish_ev else None,
                }
            )

        out.sort(key=lambda x: float(x.get("started_ts") or 0.0))
        return out

    def _pid_depth(self, trace: TraceState, pid: int, root_pid: int | None) -> int | None:
        if pid <= 0:
            return None
        if root_pid is None or root_pid <= 0:
            return None
        depth = 0
        current = int(pid)
        seen: set[int] = set()
        while current > 0 and current not in seen:
            if current == root_pid:
                return depth
            seen.add(current)
            parent = int(trace.process_parent.get(current, 0))
            if parent <= 0:
                return None
            current = parent
            depth += 1
        return None

    def _turns_for_trace(self, trace: TraceState) -> list[dict[str, Any]]:
        agent_events = sorted(
            list(trace.agent_events),
            key=lambda e: (self._event_ts(e), self._event_seq(e)),
        )
        sys_events = sorted(list(trace.sys_events), key=lambda e: (self._event_ts(e), int(e.get("line_no") or 0)))

        llm_calls = self._parse_llm_calls_from_mitm(trace)
        boundaries = sorted([float(c.get("ts") or 0.0) for c in llm_calls if float(c.get("ts") or 0.0) > 0.0])

        spans: list[tuple[str, float | None, float | None]] = []
        if boundaries:
            first = boundaries[0]
            has_setup = any(self._event_ts(e) < first for e in agent_events) or any(self._event_ts(e) < first for e in sys_events)
            if has_setup:
                spans.append(("setup", None, first))
            for i, start_ts in enumerate(boundaries):
                end_ts = boundaries[i + 1] if i + 1 < len(boundaries) else None
                spans.append((f"turn_{i + 1}", start_ts, end_ts))
        else:
            spans.append(("setup", None, None))

        turns: list[dict[str, Any]] = []
        root_pid = int(trace.root_pid or 0) or None

        for idx, (turn_id, start_ts, end_ts) in enumerate(spans):
            def _in_span(ts: float) -> bool:
                if start_ts is not None and ts < start_ts:
                    return False
                if end_ts is not None and ts >= end_ts:
                    return False
                return True

            agent_slice = [e for e in agent_events if _in_span(self._event_ts(e))]
            sys_slice = [e for e in sys_events if _in_span(self._event_ts(e))]

            tool_pairs = self._tool_pairs(agent_slice)
            files_read = {str(e.get("path") or "") for e in sys_slice if str(e.get("type") or "") == "file_read" and str(e.get("path") or "")}
            files_written = {
                str(e.get("path") or "")
                for e in sys_slice
                if str(e.get("type") or "") in {"file_write", "file_delete", "file_rename"} and str(e.get("path") or "")
            }
            network_calls = [e for e in sys_slice if str(e.get("type") or "") == "net_connect"]

            direct_children_pids_set: set[int] = {
                int(e.get("child_pid") or 0)
                for e in sys_slice
                if str(e.get("type") or "") == "process_spawn" and int(e.get("child_pid") or 0) > 0
            }
            # Some traces miss process_spawn. Infer parent->child from command_exec
            # ppid so subprocesses are still counted and nestable.
            direct_children_pids_set.update(
                int(e.get("pid") or 0)
                for e in sys_slice
                if str(e.get("type") or "") == "command_exec"
                and int(e.get("pid") or 0) > 0
                and int(e.get("ppid") or 0) > 0
                and int(e.get("pid") or 0) != int(e.get("ppid") or 0)
            )
            direct_children_pids = sorted(pid for pid in direct_children_pids_set if pid > 0)

            has_grandchildren = False
            for e in sys_slice:
                if str(e.get("type") or "") != "process_spawn":
                    continue
                child_pid = int(e.get("child_pid") or 0)
                depth = self._pid_depth(trace, child_pid, root_pid)
                if depth is not None and depth >= 2:
                    has_grandchildren = True
                    break

            has_tool_writes = any(
                any(tok in str(tp.get("tool_name") or "").lower() for tok in ["write", "edit", "patch", "create", "delete", "rename", "replace", "insert"])
                for tp in tool_pairs
            )

            has_response = False
            response_texts: list[str] = []
            prompt_sections: list[dict[str, Any]] = []
            response_sections: list[dict[str, Any]] = []
            replay_context_sections: list[dict[str, Any]] = []
            replay_action_sections: list[dict[str, Any]] = []
            for ev in agent_slice:
                if str(ev.get("event_type") or "") != "assistant_response":
                    continue
                payload = ev.get("payload") or {}
                content = str(payload.get("content") or "").strip()
                phase = str(payload.get("phase") or "").strip()
                if content and phase != "tool_call":
                    has_response = True
                    response_texts.append(content)

            prompt_texts: list[str] = []
            if llm_calls:
                for call in llm_calls:
                    cts = float(call.get("ts") or 0.0)
                    if _in_span(cts):
                        ptxt = str(call.get("prompt_text") or "").strip()
                        if ptxt:
                            prompt_texts.append(ptxt)
                        prompt_sections = self._merge_sections(prompt_sections, call.get("prompt_sections") or [])
                        replay_context_sections = self._merge_sections(
                            replay_context_sections,
                            call.get("replay_context_sections") or [],
                        )
                        rtxt = str(call.get("response_text") or "").strip()
                        if rtxt:
                            response_texts.append(rtxt)
                            has_response = True
                        response_sections = self._merge_sections(response_sections, call.get("response_sections") or [])
                        replay_action_sections = self._merge_sections(
                            replay_action_sections,
                            call.get("replay_action_sections") or [],
                        )
            else:
                for ev in agent_slice:
                    et = str(ev.get("event_type") or "")
                    payload = ev.get("payload") or {}
                    if et == "user_prompt":
                        text = str(payload.get("content") or "").strip()
                        if text:
                            prompt_texts.append(text)
                    elif et == "user_prompt_batch":
                        for p in payload.get("prompts") or []:
                            text = str(p or "").strip()
                            if text:
                                prompt_texts.append(text)

            if not prompt_sections and prompt_texts:
                prompt_sections = [{"id": "prompt", "label": "Prompt", "values": prompt_texts}]
            if not response_sections and response_texts:
                response_sections = [{"id": "response", "label": "Response", "values": response_texts}]

            tags: list[str] = []
            only_reads = bool(tool_pairs) and bool(files_read) and not files_written and not has_grandchildren
            if only_reads:
                tags.append("read and plan")
            if files_written or has_tool_writes:
                tags.append("edit")
            if has_grandchildren:
                tags.append("execute")
            if network_calls:
                tags.append("network")
            if has_response:
                tags.append("response")

            dominant = "No major actions"
            if files_written:
                dominant = f"Wrote {len(files_written)} files · {len(tool_pairs)} tool calls"
            elif files_read:
                dominant = f"Read {len(files_read)} files · {len(tool_pairs)} tool calls"
            elif direct_children_pids:
                dominant = f"Spawned {len(direct_children_pids)} processes · {len(tool_pairs)} tool calls"
            elif network_calls:
                dominant = f"{len(network_calls)} network calls · {len(tool_pairs)} tool calls"
            elif tool_pairs:
                dominant = f"{len(tool_pairs)} tool calls"

            first_tool_ts: float | None = None
            if tool_pairs:
                first_tool_ts = min(float(tp.get("started_ts") or 0.0) for tp in tool_pairs if float(tp.get("started_ts") or 0.0) > 0.0)

            pre_tool_events: list[dict[str, Any]] = []
            if first_tool_ts is not None:
                pre_tool_events = [e for e in sys_slice if self._event_ts(e) < first_tool_ts]

            pre_tool_counts = {
                "file_read": sum(1 for e in pre_tool_events if str(e.get("type") or "") == "file_read"),
                "file_write": sum(1 for e in pre_tool_events if str(e.get("type") or "") in {"file_write", "file_delete", "file_rename"}),
                "process_spawn": sum(1 for e in pre_tool_events if str(e.get("type") or "") == "process_spawn"),
                "network": sum(1 for e in pre_tool_events if str(e.get("type") or "") in {"net_connect", "net_send", "net_recv"}),
            }

            turns.append(
                {
                    "turn_id": turn_id,
                    "index": idx,
                    "label": "Setup" if turn_id == "setup" else f"T{idx if spans[0][0] == 'setup' else idx + 1}",
                    "start_ts": start_ts,
                    "end_ts": end_ts,
                    "tool_call_count": len(tool_pairs),
                    "tags": tags,
                    "dominant_summary": dominant,
                    "prompt_text": "\n\n".join(prompt_texts),
                    "response_text": "\n\n".join(response_texts),
                    "prompt_sections": prompt_sections,
                    "response_sections": response_sections,
                    "replay_context_sections": replay_context_sections,
                    "replay_action_sections": replay_action_sections,
                    "files_read_count": len(files_read),
                    "files_written_count": len(files_written),
                    "subprocess_direct_count": len(direct_children_pids),
                    "network_call_count": len(network_calls),
                    "pre_tool_counts": pre_tool_counts,
                    "first_tool_ts": first_tool_ts,
                    "_agent_events": agent_slice,
                    "_sys_events": sys_slice,
                    "_tool_pairs": tool_pairs,
                }
            )

        return turns

    def replay_turns_overview(self, trace_id: str) -> dict[str, Any]:
        trace = self._get_trace(trace_id)
        turns = self._turns_for_trace(trace)
        return build_replay_overview(trace_id, turns)

    def replay_turn_detail(self, trace_id: str, turn_id: str) -> dict[str, Any]:
        trace = self._get_trace(trace_id)
        turns = self._turns_for_trace(trace)
        match = next((turn for turn in turns if str(turn.get("turn_id")) == turn_id), None)
        if match is None:
            raise KeyError(turn_id)

        sys_events = list(match.get("_sys_events", []))
        tool_pairs = list(match.get("_tool_pairs", []))
        paired_tool_calls = self._replay_tool_call_pairs(trace, sys_events, tool_pairs)
        file_activity = self._replay_file_activity(sys_events)
        subprocesses = self._replay_subprocesses(trace, sys_events)

        replay_payload = build_replay_turn_detail(trace_id, match)
        replay_payload["tool_call_response_pairs"] = paired_tool_calls
        replay_payload["summary"] = {
            "tool_calls": int(match.get("tool_call_count") or 0),
            "context_tokens": self._count_text_tokens_tiktoken(replay_payload.get("context", {}).get("text") or ""),
            "files_read": int(match.get("files_read_count") or 0),
            "files_written": int(match.get("files_written_count") or 0),
            "subprocesses_spawned": len(subprocesses),
            "network_calls": int(match.get("network_call_count") or 0),
            "context_sections": len((replay_payload.get("context") or {}).get("sections") or []),
            "action_sections": len((replay_payload.get("action") or {}).get("sections") or []),
            "tool_call_pairs": paired_tool_calls,
            "file_activity": file_activity,
            "subprocesses": subprocesses,
        }
        return replay_payload

    def _turn_cutoff_ts(
        self,
        trace: TraceState,
        turns: list[dict[str, Any]],
        index: int,
        *,
        boundary: str = "end",
    ) -> float:
        if index < 0:
            return 0.0
        if index >= len(turns):
            return float("inf")

        turn = turns[index]
        prefer_start = boundary == "start"

        start_ts = turn.get("start_ts")
        end_ts = turn.get("end_ts")

        if prefer_start and start_ts is not None:
            try:
                return float(start_ts)
            except Exception:
                pass

        if not prefer_start and end_ts is not None:
            try:
                return float(end_ts)
            except Exception:
                pass

        # Fallback to whichever boundary exists.
        if start_ts is not None:
            try:
                return float(start_ts)
            except Exception:
                pass
        if end_ts is not None:
            try:
                return float(end_ts)
            except Exception:
                pass

        if trace.sys_events:
            if prefer_start:
                return min(self._event_ts(e) for e in trace.sys_events)
            return max(self._event_ts(e) for e in trace.sys_events)
        return 0.0

    def _snapshot_events_by_path(self, trace: TraceState) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in sorted(trace.sys_events, key=lambda e: (self._event_ts(e), int(e.get("line_no") or 0))):
            if str(event.get("type") or "") != "file_snapshot":
                continue
            path = str(event.get("path") or "").strip()
            if not path:
                continue
            out[path].append(event)
        return out

    def _latest_snapshot_before(self, snapshots: list[dict[str, Any]], cutoff_ts: float) -> dict[str, Any] | None:
        best: dict[str, Any] | None = None
        for event in snapshots:
            ets = self._event_ts(event)
            if ets <= cutoff_ts:
                best = event
            else:
                break
        return best

    def _first_snapshot_in_range(
        self,
        snapshots: list[dict[str, Any]],
        start_ts: float,
        end_ts: float,
        *,
        phase: str | None = None,
    ) -> dict[str, Any] | None:
        for event in snapshots:
            ets = self._event_ts(event)
            if ets < start_ts:
                continue
            if ets > end_ts:
                break
            if phase is not None and str(event.get("snapshot_phase") or "") != phase:
                continue
            return event
        return None

    def _baseline_snapshot_for_window(
        self,
        snapshots: list[dict[str, Any]],
        start_ts: float,
        end_ts: float,
    ) -> dict[str, Any] | None:
        # Preferred baseline is the latest snapshot at/before the window start.
        prior = self._latest_snapshot_before(snapshots, start_ts)
        if prior is not None:
            return prior

        # If none exists (common in setup-only traces), use the earliest
        # in-window "before" snapshot emitted before first write/rename.
        in_window_before = self._first_snapshot_in_range(
            snapshots,
            start_ts,
            end_ts,
            phase="before",
        )
        if in_window_before is not None:
            return in_window_before

        # Last fallback: earliest snapshot in window.
        return self._first_snapshot_in_range(snapshots, start_ts, end_ts)

    def _snapshot_text(self, snapshot: dict[str, Any] | None) -> str:
        if not snapshot:
            return ""
        if bool(snapshot.get("binary")):
            return ""
        return str(snapshot.get("content") or "")

    def _trace_repo_root(self, trace: TraceState) -> Path | None:
        # Trace layout is typically <repo>/obs/traces/<trace_id>.ebpf.jsonl.
        try:
            if len(trace.trace_path.parents) >= 3:
                root = trace.trace_path.parents[2]
                if (root / ".git").exists():
                    return root
        except Exception:
            return None
        return None

    def _git_head_file_content(self, trace: TraceState, path: str) -> str | None:
        repo_root = self._trace_repo_root(trace)
        if repo_root is None:
            return None

        p = Path(path)
        if p.is_absolute():
            try:
                rel = p.relative_to(repo_root)
            except ValueError:
                return None
        else:
            rel = p

        rel_path = str(rel)
        if not rel_path or rel_path.startswith("../"):
            return None

        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), "show", f"HEAD:{rel_path}"],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception:
            return None

        if proc.returncode != 0:
            return None
        return proc.stdout

    def _line_change_stats(self, before_text: str, after_text: str) -> dict[str, int]:
        before_lines = before_text.splitlines()
        after_lines = after_text.splitlines()

        matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
        added = 0
        removed = 0
        changed = 0
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "insert":
                added += (j2 - j1)
            elif tag == "delete":
                removed += (i2 - i1)
            elif tag == "replace":
                removed += (i2 - i1)
                added += (j2 - j1)
                changed += max(i2 - i1, j2 - j1)

        return {
            "added": int(added),
            "removed": int(removed),
            "changed": int(changed),
            "total": int(added + removed),
        }

    def _build_state_diff_tree(self, files: list[dict[str, Any]]) -> dict[str, Any]:
        root: dict[str, Any] = {"name": "/", "kind": "folder", "children": []}
        child_map: dict[tuple[int, str], dict[str, Any]] = {}

        def _child(parent: dict[str, Any], name: str, kind: str) -> dict[str, Any]:
            key = (id(parent), f"{kind}:{name}")
            existing = child_map.get(key)
            if existing is not None:
                return existing
            node = {"name": name, "kind": kind, "children": [] if kind == "folder" else None}
            parent.setdefault("children", []).append(node)
            child_map[key] = node
            return node

        for item in sorted(files, key=lambda x: str(x.get("path") or "")):
            path = str(item.get("path") or "")
            if not path:
                continue
            parts = [p for p in Path(path).parts if p not in {"/", ""}]
            cur = root
            for part in parts[:-1]:
                cur = _child(cur, part, "folder")
            leaf = _child(cur, parts[-1] if parts else path, "file")
            for key in ("path", "lines_added", "lines_removed", "lines_changed", "total_changed", "binary", "truncated"):
                if key in item:
                    leaf[key] = item[key]

        def _annotate(node: dict[str, Any]) -> dict[str, int]:
            if str(node.get("kind") or "") == "file":
                counts = {
                    "files": 1,
                    "added": int(node.get("lines_added") or 0),
                    "removed": int(node.get("lines_removed") or 0),
                    "total": int(node.get("total_changed") or 0),
                }
                node["counts"] = counts
                return counts

            total = {"files": 0, "added": 0, "removed": 0, "total": 0}
            for child in node.get("children") or []:
                c = _annotate(child)
                total["files"] += int(c.get("files") or 0)
                total["added"] += int(c.get("added") or 0)
                total["removed"] += int(c.get("removed") or 0)
                total["total"] += int(c.get("total") or 0)
            node["counts"] = total
            return total

        _annotate(root)
        return root

    def replay_state_diff(self, trace_id: str, from_turn_id: str | None = None, to_turn_id: str | None = None) -> dict[str, Any]:
        trace = self._get_trace(trace_id)
        turns = self._turns_for_trace(trace)
        if not turns:
            return {
                "trace_id": trace_id,
                "turns": [],
                "selected": {"from_turn_id": None, "to_turn_id": None},
                "summary": {"files_changed": 0, "lines_added": 0, "lines_removed": 0, "total_changed": 0},
                "tree": {"name": "/", "kind": "folder", "children": [], "counts": {"files": 0, "added": 0, "removed": 0, "total": 0}},
                "files": [],
            }

        by_id = {str(turn.get("turn_id") or ""): idx for idx, turn in enumerate(turns)}
        resolved_from = from_turn_id if from_turn_id in by_id else str(turns[0].get("turn_id") or "")
        resolved_to = to_turn_id if to_turn_id in by_id else str(turns[-1].get("turn_id") or "")

        from_idx = by_id.get(str(resolved_from), 0)
        to_idx = by_id.get(str(resolved_to), len(turns) - 1)
        if from_idx > to_idx:
            from_idx, to_idx = to_idx, from_idx
            resolved_from, resolved_to = resolved_to, resolved_from

        from_cutoff = self._turn_cutoff_ts(trace, turns, from_idx, boundary="start")
        to_cutoff = self._turn_cutoff_ts(trace, turns, to_idx, boundary="end")

        snapshot_by_path = self._snapshot_events_by_path(trace)
        files: list[dict[str, Any]] = []
        lines_added = 0
        lines_removed = 0

        for path, snapshots in snapshot_by_path.items():
            before_snap = self._baseline_snapshot_for_window(snapshots, from_cutoff, to_cutoff)
            after_snap = self._latest_snapshot_before(snapshots, to_cutoff)
            if before_snap is None and after_snap is None:
                continue

            before_text = self._snapshot_text(before_snap)
            after_text = self._snapshot_text(after_snap)

            # If one side has no snapshot event, treat that side as empty for diff purposes.
            if before_snap is None:
                before_text = ""
            if after_snap is None:
                after_text = ""

            # Fallback to repository HEAD baseline for tracked files when
            # snapshot baseline is missing or degenerate.
            if before_snap is None or before_text == after_text:
                git_before = self._git_head_file_content(trace, path)
                if git_before is not None:
                    before_text = git_before

            if before_text == after_text and bool(before_snap) == bool(after_snap):
                continue

            stats = self._line_change_stats(before_text, after_text)
            lines_added += int(stats.get("added") or 0)
            lines_removed += int(stats.get("removed") or 0)

            files.append(
                {
                    "path": path,
                    "lines_added": int(stats.get("added") or 0),
                    "lines_removed": int(stats.get("removed") or 0),
                    "lines_changed": int(stats.get("changed") or 0),
                    "total_changed": int(stats.get("total") or 0),
                    "binary": bool((before_snap or {}).get("binary")) or bool((after_snap or {}).get("binary")),
                    "truncated": bool((before_snap or {}).get("truncated")) or bool((after_snap or {}).get("truncated")),
                }
            )

        files.sort(key=lambda x: str(x.get("path") or ""))
        tree = self._build_state_diff_tree(files)

        return {
            "trace_id": trace_id,
            "turns": [
                {
                    "turn_id": str(turn.get("turn_id") or ""),
                    "label": str(turn.get("label") or turn.get("turn_id") or ""),
                    "index": int(turn.get("index") or 0),
                }
                for turn in turns
            ],
            "selected": {
                "from_turn_id": resolved_from,
                "to_turn_id": resolved_to,
            },
            "summary": {
                "files_changed": len(files),
                "lines_added": int(lines_added),
                "lines_removed": int(lines_removed),
                "total_changed": int(lines_added + lines_removed),
            },
            "tree": tree,
            "files": files,
        }

    def replay_state_diff_file(
        self,
        trace_id: str,
        *,
        path: str,
        from_turn_id: str | None = None,
        to_turn_id: str | None = None,
    ) -> dict[str, Any]:
        trace = self._get_trace(trace_id)
        turns = self._turns_for_trace(trace)
        if not turns:
            raise KeyError(path)

        by_id = {str(turn.get("turn_id") or ""): idx for idx, turn in enumerate(turns)}
        resolved_from = from_turn_id if from_turn_id in by_id else str(turns[0].get("turn_id") or "")
        resolved_to = to_turn_id if to_turn_id in by_id else str(turns[-1].get("turn_id") or "")

        from_idx = by_id.get(str(resolved_from), 0)
        to_idx = by_id.get(str(resolved_to), len(turns) - 1)
        if from_idx > to_idx:
            from_idx, to_idx = to_idx, from_idx
            resolved_from, resolved_to = resolved_to, resolved_from

        from_cutoff = self._turn_cutoff_ts(trace, turns, from_idx, boundary="start")
        to_cutoff = self._turn_cutoff_ts(trace, turns, to_idx, boundary="end")

        snapshots = self._snapshot_events_by_path(trace).get(path) or []
        if not snapshots:
            raise KeyError(path)

        before_snap = self._baseline_snapshot_for_window(snapshots, from_cutoff, to_cutoff)
        after_snap = self._latest_snapshot_before(snapshots, to_cutoff)

        before_text = self._snapshot_text(before_snap)
        after_text = self._snapshot_text(after_snap)
        if before_snap is None:
            before_text = ""
        if after_snap is None:
            after_text = ""

        if before_snap is None or before_text == after_text:
            git_before = self._git_head_file_content(trace, path)
            if git_before is not None:
                before_text = git_before

        binary = bool((before_snap or {}).get("binary")) or bool((after_snap or {}).get("binary"))
        truncated = bool((before_snap or {}).get("truncated")) or bool((after_snap or {}).get("truncated"))

        stats = self._line_change_stats(before_text, after_text)

        if binary:
            diff_text = "Binary file snapshot detected; textual diff is unavailable."
        elif truncated:
            diff_text = "One or both snapshots were truncated during capture; diff may be incomplete.\n\n"
            diff_text += "\n".join(
                difflib.unified_diff(
                    before_text.splitlines(),
                    after_text.splitlines(),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                    lineterm="",
                )
            )
        else:
            diff_text = "\n".join(
                difflib.unified_diff(
                    before_text.splitlines(),
                    after_text.splitlines(),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                    lineterm="",
                )
            )

        return {
            "trace_id": trace_id,
            "path": path,
            "selected": {
                "from_turn_id": resolved_from,
                "to_turn_id": resolved_to,
            },
            "stats": {
                "lines_added": int(stats.get("added") or 0),
                "lines_removed": int(stats.get("removed") or 0),
                "lines_changed": int(stats.get("changed") or 0),
                "total_changed": int(stats.get("total") or 0),
            },
            "binary": binary,
            "truncated": truncated,
            "diff": diff_text,
        }

    def _count_text_tokens_tiktoken(self, text: str) -> int:
        payload = str(text or "")
        if not payload:
            return 0

        if tiktoken is not None:
            try:
                encoder = tiktoken.get_encoding("cl100k_base")
                return len(encoder.encode(payload))
            except Exception:
                pass

        return len(re.findall(r"\S+", payload))

    def _replay_tool_call_pairs(
        self,
        trace: TraceState,
        sys_events: list[dict[str, Any]],
        tool_pairs: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for tp in sorted(tool_pairs, key=lambda item: float(item.get("started_ts") or 0.0)):
            source = self._match_tool_source_for_turn(trace, sys_events, tp)
            out.append(
                {
                    "tool_call_id": str(tp.get("tool_call_id") or ""),
                    "tool_name": str(tp.get("tool_name") or "unknown"),
                    "arguments": tp.get("arguments") or {},
                    "response": tp.get("result"),
                    "started_ts": tp.get("started_ts"),
                    "finished_ts": tp.get("finished_ts"),
                    "source": source,
                }
            )
        return out

    def _replay_file_activity(self, sys_events: list[dict[str, Any]]) -> dict[str, Any]:
        items: dict[str, dict[str, Any]] = {}
        for event in sys_events:
            et = str(event.get("type") or "")
            if et not in {"file_read", "file_write", "file_delete", "file_rename"}:
                continue
            path = str(event.get("path") or "")
            if not path:
                continue

            bucket = items.setdefault(
                path,
                {
                    "path": path,
                    "read": False,
                    "write": False,
                    "rename": False,
                    "read_count": 0,
                    "write_count": 0,
                    "rename_count": 0,
                    "event_count": 0,
                    "state": "read",
                },
            )

            bucket["event_count"] = int(bucket.get("event_count") or 0) + 1
            if et == "file_read":
                bucket["read"] = True
                bucket["read_count"] = int(bucket.get("read_count") or 0) + 1
            elif et in {"file_write", "file_delete"}:
                bucket["write"] = True
                bucket["write_count"] = int(bucket.get("write_count") or 0) + 1
            elif et == "file_rename":
                bucket["rename"] = True
                bucket["rename_count"] = int(bucket.get("rename_count") or 0) + 1

        for item in items.values():
            has_read = bool(item.get("read"))
            has_write = bool(item.get("write") or item.get("rename"))
            if has_read and has_write:
                item["state"] = "read_write"
            elif has_write:
                item["state"] = "write"
            else:
                item["state"] = "read"

        read_paths = sorted([path for path, info in items.items() if bool(info.get("read"))])
        write_paths = sorted(
            [
                path
                for path, info in items.items()
                if bool(info.get("write")) or bool(info.get("rename"))
            ]
        )

        return {
            "read_paths": read_paths,
            "write_paths": write_paths,
            "tree": self._file_tree(list(items.values())) if items else {"name": "/", "kind": "dir", "children": []},
        }

    def _replay_subprocesses(self, trace: TraceState, sys_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pid_to_commands: defaultdict[int, list[str]] = defaultdict(list)
        ppid_hint: dict[int, int] = {}

        for event in sorted(sys_events, key=lambda e: int(e.get("line_no") or 0)):
            et = str(event.get("type") or "")
            if et == "command_exec":
                pid = int(event.get("pid") or 0)
                if pid > 0:
                    cmd = str(event.get("command") or event.get("exec_path") or "").strip()
                    if cmd and cmd not in pid_to_commands[pid]:
                        pid_to_commands[pid].append(cmd)
                    ppid = int(event.get("ppid") or 0)
                    if ppid > 0 and ppid != pid:
                        ppid_hint[pid] = ppid
            elif et == "process_spawn":
                child_pid = int(event.get("child_pid") or 0)
                parent_pid = int(event.get("pid") or 0)
                if child_pid > 0 and parent_pid > 0:
                    ppid_hint[child_pid] = parent_pid

        spawned_pids: set[int] = set()
        for event in sys_events:
            et = str(event.get("type") or "")
            if et == "process_spawn":
                child_pid = int(event.get("child_pid") or 0)
                if child_pid > 0:
                    spawned_pids.add(child_pid)
            elif et == "command_exec":
                pid = int(event.get("pid") or 0)
                ppid = int(event.get("ppid") or 0)
                if pid > 0 and ppid > 0 and pid != ppid:
                    spawned_pids.add(pid)

        out: list[dict[str, Any]] = []
        for pid in sorted(spawned_pids):
            parent_pid = int(trace.process_parent.get(pid, 0)) if pid in trace.process_parent else int(ppid_hint.get(pid, 0))
            out.append(
                {
                    "pid": pid,
                    "parent_pid": parent_pid if parent_pid > 0 else None,
                    "commands": pid_to_commands.get(pid, [])[:12],
                }
            )
        return out

    def _file_tree(self, file_items: list[dict[str, Any]]) -> dict[str, Any]:
        root: dict[str, Any] = {"name": "/", "kind": "dir", "children": []}
        child_map: dict[tuple[int, str], dict[str, Any]] = {}

        def _child(parent: dict[str, Any], name: str, kind: str) -> dict[str, Any]:
            key = (id(parent), f"{kind}:{name}")
            existing = child_map.get(key)
            if existing is not None:
                return existing
            node = {"name": name, "kind": kind, "children": [] if kind == "dir" else None}
            parent.setdefault("children", []).append(node)
            child_map[key] = node
            return node

        for item in sorted(file_items, key=lambda x: str(x.get("path") or "")):
            path = str(item.get("path") or "")
            if not path:
                continue
            parts = [p for p in Path(path).parts if p not in {"/", ""}]
            cur = root
            for part in parts[:-1]:
                cur = _child(cur, part, "dir")
            leaf = _child(cur, parts[-1] if parts else path, "file")
            leaf["path"] = path
            leaf["state"] = item.get("state")
            leaf["read"] = bool(item.get("read"))
            leaf["write"] = bool(item.get("write"))
            leaf["rename"] = bool(item.get("rename"))
            leaf["read_count"] = int(item.get("read_count") or 0)
            leaf["write_count"] = int(item.get("write_count") or 0)
            leaf["rename_count"] = int(item.get("rename_count") or 0)
            leaf["event_count"] = int(item.get("event_count") or 0)

        def _annotate_counts(node: dict[str, Any]) -> dict[str, int]:
            if str(node.get("kind") or "") == "file":
                counts = {
                    "read": int(node.get("read_count") or (1 if node.get("read") else 0)),
                    "write": int(node.get("write_count") or (1 if node.get("write") else 0)),
                    "rename": int(node.get("rename_count") or (1 if node.get("rename") else 0)),
                }
                node["counts"] = counts
                return counts

            total = {"read": 0, "write": 0, "rename": 0}
            for child in node.get("children") or []:
                child_counts = _annotate_counts(child)
                total["read"] += int(child_counts.get("read") or 0)
                total["write"] += int(child_counts.get("write") or 0)
                total["rename"] += int(child_counts.get("rename") or 0)
            node["counts"] = total
            return total

        _annotate_counts(root)

        return root

    def _build_unified_timeline(
        self,
        trace: TraceState,
        sys_events: list[dict[str, Any]],
        tool_pairs: list[dict[str, Any]] | None,
        anchor_pid: int | None = None,
        strict_anchor_children: bool = False,
    ) -> list[dict[str, Any]]:
        tool_pairs = tool_pairs or []
        tool_source_by_id: dict[str, dict[str, Any]] = {}
        for tp in tool_pairs:
            tool_call_id = str(tp.get("tool_call_id") or "").strip()
            if not tool_call_id:
                continue
            tool_source_by_id[tool_call_id] = self._match_tool_source_for_turn(trace, sys_events, tp)

        def _sys_cat(event: dict[str, Any]) -> str:
            et = str(event.get("type") or "")
            if et in {"file_read", "file_write", "file_delete", "file_rename"}:
                return "file"
            if et in {"process_spawn", "process_exit", "command_exec"}:
                return "process"
            if et in {"net_connect", "net_send", "net_recv"}:
                return "network"
            return "other"

        parent_map: dict[int, int] = {int(k): int(v) for k, v in trace.process_parent.items()}
        for ev in sys_events:
            et = str(ev.get("type") or "")
            if et == "process_spawn":
                parent = int(ev.get("pid") or 0)
                child = int(ev.get("child_pid") or 0)
                if parent > 0 and child > 0 and parent != child:
                    parent_map[child] = parent
            elif et == "command_exec":
                pid = int(ev.get("pid") or 0)
                ppid = int(ev.get("ppid") or 0)
                if pid > 0 and ppid > 0 and pid != ppid and pid not in parent_map:
                    # Missing process_spawn fallback.
                    parent_map[pid] = ppid

        resolved_anchor = int(anchor_pid or 0)
        if resolved_anchor <= 0:
            candidate = int(trace.root_pid or 0)
            if candidate > 0 and any(int(e.get("pid") or 0) == candidate for e in sys_events):
                resolved_anchor = candidate
            elif candidate <= 0:
                for ev in sys_events:
                    if str(ev.get("type") or "") == "command_exec":
                        candidate = int(ev.get("pid") or 0)
                        if candidate > 0:
                            resolved_anchor = candidate
                            break

        def _has_parent(pid: int) -> bool:
            return int(parent_map.get(pid, 0)) > 0

        def _should_keep_at_current_level(ev: dict[str, Any]) -> bool:
            cat = _sys_cat(ev)
            if cat == "process":
                # In strict anchor views (popup process subtrace), root pid
                # command/exit records don't render as process groups and can
                # fragment adjacent file groups into consecutive folder cards.
                if strict_anchor_children and resolved_anchor > 0:
                    et = str(ev.get("type") or "")
                    ep = int(ev.get("pid") or 0)
                    if ep == resolved_anchor and et in {"command_exec", "process_exit"}:
                        return False
                return True

            pid = int(ev.get("pid") or 0)
            if pid <= 0:
                return True

            # Root/anchor process activity remains visible at the current level.
            if resolved_anchor > 0 and pid == resolved_anchor:
                return True

            # Child process events belong under that process collapsible, not the
            # top-level timeline.
            if _has_parent(pid):
                return False

            return True

        merged: list[dict[str, Any]] = []
        for tp in tool_pairs:
            merged.append({"kind": "tool", "ts": float(tp.get("started_ts") or 0.0), "tool": tp})
        for ev in sys_events:
            if str(ev.get("type") or "") == "file_snapshot":
                continue
            if not _should_keep_at_current_level(ev):
                continue
            merged.append({"kind": "sys", "ts": self._event_ts(ev), "event": ev, "category": _sys_cat(ev)})
        merged.sort(key=lambda x: (float(x.get("ts") or 0.0), 0 if x.get("kind") == "tool" else 1))

        timeline: list[dict[str, Any]] = []
        current_cat = ""
        current_events: list[dict[str, Any]] = []

        def _flush_group() -> None:
            nonlocal current_cat, current_events
            if not current_events:
                return
            cat = current_cat
            events = current_events
            current_cat = ""
            current_events = []

            if cat == "file":
                file_map: dict[str, dict[str, Any]] = {}
                group_counts = {"read": 0, "write": 0, "rename": 0}
                for e in events:
                    path = str(e.get("path") or "")
                    if not path:
                        continue
                    bucket = file_map.setdefault(path, {"path": path, "read": False, "write": False, "event_count": 0})
                    et = str(e.get("type") or "")
                    if et == "file_read":
                        bucket["read"] = True
                        bucket["read_count"] = int(bucket.get("read_count") or 0) + 1
                        group_counts["read"] += 1
                    if et in {"file_write", "file_delete", "file_rename"}:
                        bucket["write"] = True
                        bucket["write_count"] = int(bucket.get("write_count") or 0) + 1
                        group_counts["write"] += 1
                    if et == "file_rename":
                        bucket["rename"] = True
                        bucket["rename_count"] = int(bucket.get("rename_count") or 0) + 1
                        group_counts["rename"] += 1
                    bucket["event_count"] += 1

                files = []
                for info in file_map.values():
                    if info["read"] and info["write"]:
                        state = "read_write"
                    elif info["write"]:
                        state = "write"
                    else:
                        state = "read"
                    files.append({**info, "state": state})

                timeline.append(
                    {
                        "entry_type": "system_group",
                        "category": "file",
                        "standalone": len(events) == 1,
                        "title": f"{len(files)} files touched",
                        "counts": group_counts,
                        "events_count": len(events),
                        "files": files,
                        "tree": self._file_tree(files),
                    }
                )
                return

            if cat == "process":
                commands: list[str] = []
                by_pid: dict[int, dict[str, Any]] = {}
                children_by_parent: dict[int, list[int]] = defaultdict(list)

                for e in events:
                    et = str(e.get("type") or "")
                    if et == "command_exec":
                        pid = int(e.get("pid") or 0)
                        if pid <= 0:
                            continue
                        ppid = int(e.get("ppid") or 0)
                        cmd = str(e.get("command") or e.get("exec_path") or "").strip()
                        if cmd:
                            commands.append(cmd)
                        node = by_pid.setdefault(pid, {"pid": pid, "command": cmd, "start_ts": self._event_ts(e), "end_ts": None, "exit_code": None, "children": []})
                        if cmd and not node.get("command"):
                            node["command"] = cmd
                        node["start_ts"] = min(float(node.get("start_ts") or self._event_ts(e)), self._event_ts(e))
                        if ppid > 0 and ppid != pid:
                            children_by_parent[ppid].append(pid)
                            by_pid.setdefault(ppid, {"pid": ppid, "command": "", "start_ts": None, "end_ts": None, "exit_code": None, "children": []})
                    elif et == "process_exit":
                        pid = int(e.get("pid") or 0)
                        if pid <= 0:
                            continue
                        node = by_pid.setdefault(pid, {"pid": pid, "command": "", "start_ts": None, "end_ts": self._event_ts(e), "exit_code": None, "children": []})
                        node["end_ts"] = self._event_ts(e)
                        if "exit_code" in e:
                            node["exit_code"] = e.get("exit_code")
                    elif et == "process_spawn":
                        parent = int(e.get("pid") or 0)
                        child = int(e.get("child_pid") or 0)
                        if parent > 0 and child > 0:
                            children_by_parent[parent].append(child)
                            by_pid.setdefault(parent, {"pid": parent, "command": "", "start_ts": None, "end_ts": None, "exit_code": None, "children": []})
                            by_pid.setdefault(child, {"pid": child, "command": "", "start_ts": None, "end_ts": None, "exit_code": None, "children": []})

                for parent, kids in children_by_parent.items():
                    node = by_pid.get(parent)
                    if node is None:
                        continue
                    node["children"] = _ordered_unique_int([*node.get("children", []), *kids])

                if resolved_anchor > 0:
                    direct_children = _ordered_unique_int([
                        int(child)
                        for child in children_by_parent.get(resolved_anchor, [])
                        if int(child) > 0 and int(child) != resolved_anchor
                    ])
                    # Some turns begin after the true parent process is already
                    # running, so direct children of the anchor are not visible
                    # in this slice. Fall back to observed children in-slice so
                    # process/file kernel activity is still represented.
                    if not direct_children and not strict_anchor_children:
                        direct_children = _ordered_unique_int([
                            int(child)
                            for _parent, kids in children_by_parent.items()
                            for child in kids
                            if int(child) > 0 and int(child) != resolved_anchor
                        ])
                else:
                    direct_children = _ordered_unique_int([
                        int(child)
                        for _parent, kids in children_by_parent.items()
                        for child in kids
                        if int(child) > 0
                    ])

                process_tree = [by_pid[k] for k in direct_children if k in by_pid]
                child_commands = [
                    str(node.get("command") or "").strip()
                    for node in process_tree
                    if str(node.get("command") or "").strip()
                ]

                # No child spawn in this segment: do not emit a process group.
                # This avoids synthetic "0 processes spawned" / execute rows.
                if not direct_children:
                    return

                timeline.append(
                    {
                        "entry_type": "system_group",
                        "category": "process",
                        "standalone": len(events) == 1,
                        "title": f"{len(direct_children)} {'process' if len(direct_children) == 1 else 'processes'} spawned",
                        "events_count": len(events),
                        "commands": list(dict.fromkeys(child_commands or commands))[:8],
                        "direct_children": direct_children,
                        "process_tree": process_tree,
                    }
                )
                return

            if cat == "network":
                calls: dict[str, dict[str, Any]] = {}
                connect_count = 0
                for e in events:
                    ne = self._with_inferred_net_dest(trace, e)
                    dest = self._network_display_label(ne)
                    bucket = calls.setdefault(dest, {"dest": dest, "bytes_sent": 0, "bytes_recv": 0, "count": 0, "full_capture": False})
                    et = str(ne.get("type") or "")
                    if et == "net_connect":
                        connect_count += 1
                    if et == "net_send":
                        bucket["bytes_sent"] += int(ne.get("bytes") or 0)
                    elif et == "net_recv":
                        bucket["bytes_recv"] += int(ne.get("bytes") or 0)
                    bucket["count"] += 1

                    host = str(dest).split(" ")[-1].split(":", 1)[0].strip()
                    if host and any(ep.split(":", 1)[0] == host for ep in trace.mitm_endpoints):
                        bucket["full_capture"] = True

                timeline.append(
                    {
                        "entry_type": "system_group",
                        "category": "network",
                        "standalone": len(events) == 1,
                        "title": f"{connect_count} network calls",
                        "events_count": len(events),
                        "connect_count": connect_count,
                        "destinations": sorted(calls.keys()),
                        "calls": [calls[k] for k in sorted(calls.keys())],
                    }
                )
                return

            e = events[0]
            timeline.append(
                {
                    "entry_type": "system_group",
                    "category": "other",
                    "standalone": True,
                    "title": str(e.get("label") or e.get("type") or "event"),
                    "events_count": 1,
                    "event": e,
                }
            )

        for item in merged:
            if item["kind"] == "tool":
                _flush_group()
                timeline.append(
                    {
                        "entry_type": "tool_call",
                        "tool_call_id": item["tool"].get("tool_call_id"),
                        "tool_name": item["tool"].get("tool_name"),
                        "arguments": item["tool"].get("arguments") or {},
                        "result": item["tool"].get("result"),
                        "started_ts": item["tool"].get("started_ts"),
                        "finished_ts": item["tool"].get("finished_ts"),
                        "source": tool_source_by_id.get(
                            str(item["tool"].get("tool_call_id") or ""),
                            {"status": "source_not_found"},
                        ),
                    }
                )
                continue

            cat = str(item.get("category") or "other")
            ev = item["event"]
            if not current_events:
                current_cat = cat
                current_events = [ev]
            elif cat == current_cat:
                current_events.append(ev)
            else:
                _flush_group()
                current_cat = cat
                current_events = [ev]

        _flush_group()
        return timeline

    def turns_overview(self, trace_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        turns = self._turns_for_trace(t)

        tool_calls_total = sum(int(turn.get("tool_call_count") or 0) for turn in turns)
        files_read_total = len({
            str(e.get("path") or "")
            for turn in turns
            for e in turn.get("_sys_events", [])
            if str(e.get("type") or "") == "file_read" and str(e.get("path") or "")
        })
        files_written_total = len({
            str(e.get("path") or "")
            for turn in turns
            for e in turn.get("_sys_events", [])
            if str(e.get("type") or "") in {"file_write", "file_delete", "file_rename"} and str(e.get("path") or "")
        })
        network_total = sum(
            1 for turn in turns for e in turn.get("_sys_events", []) if str(e.get("type") or "") == "net_connect"
        )
        subprocess_total = sum(
            int(turn.get("subprocess_direct_count") or 0)
            for turn in turns
        )

        turn_rows = [
            {
                "turn_id": turn["turn_id"],
                "label": turn["label"],
                "index": turn["index"],
                "tool_call_count": turn["tool_call_count"],
                "tags": turn["tags"],
                "dominant_summary": turn["dominant_summary"],
            }
            for turn in turns
        ]

        turn_count = len([r for r in turn_rows if r.get("turn_id") != "setup"])
        return {
            "trace_id": trace_id,
            "executive_summary": {
                "turns": turn_count,
                "tool_calls": tool_calls_total,
                "files_read": files_read_total,
                "files_written": files_written_total,
                "network_calls": network_total,
                "subprocesses_spawned": subprocess_total,
            },
            "turns": turn_rows,
        }

    def turn_detail(self, trace_id: str, turn_id: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        turns = self._turns_for_trace(t)
        match = next((turn for turn in turns if str(turn.get("turn_id")) == turn_id), None)
        if match is None:
            raise KeyError(turn_id)

        sys_events = list(match.get("_sys_events", []))
        tool_pairs = list(match.get("_tool_pairs", []))
        timeline = self._build_unified_timeline(t, sys_events, tool_pairs, anchor_pid=int(t.root_pid or 0) or None)

        direct_children = {
            int(e.get("child_pid") or 0)
            for e in sys_events
            if str(e.get("type") or "") == "process_spawn" and int(e.get("child_pid") or 0) > 0
        }
        direct_children.update(
            int(e.get("pid") or 0)
            for e in sys_events
            if str(e.get("type") or "") == "command_exec"
            and int(e.get("pid") or 0) > 0
            and int(e.get("ppid") or 0) > 0
            and int(e.get("pid") or 0) != int(e.get("ppid") or 0)
        )
        net_calls = [e for e in sys_events if str(e.get("type") or "") == "net_connect"]

        return {
            "trace_id": trace_id,
            "turn_id": turn_id,
            "label": match.get("label"),
            "summary": {
                "tool_calls": int(match.get("tool_call_count") or 0),
                "files_read": int(match.get("files_read_count") or 0),
                "files_written": int(match.get("files_written_count") or 0),
                "subprocesses_spawned": len([pid for pid in direct_children if int(pid) > 0]),
                "network_calls": len(net_calls),
            },
            "prompt_text": match.get("prompt_text") or "",
            "response_text": match.get("response_text") or "",
            "prompt_sections": match.get("prompt_sections") or [],
            "response_sections": match.get("response_sections") or [],
            "pre_tool_counts": match.get("pre_tool_counts") or {},
            "timeline": timeline,
            "start_ts": match.get("start_ts"),
            "end_ts": match.get("end_ts"),
        }

    def process_subtrace(self, trace_id: str, turn_id: str, pid: int, full_lifecycle: bool = False) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        turns = self._turns_for_trace(t)
        match = next((turn for turn in turns if str(turn.get("turn_id")) == turn_id), None)
        if match is None and not full_lifecycle:
            raise KeyError(turn_id)

        pid = int(pid)
        if pid <= 0:
            raise KeyError("pid")

        # Keep process popup scoped to the selected turn when available.
        # This prevents sibling tool-call activity from other turns from
        # interleaving with this PID's file stream.
        scoped_turn_events = list(match.get("_sys_events", [])) if isinstance(match, dict) else []
        base_events = scoped_turn_events if scoped_turn_events else list(t.sys_events)

        if full_lifecycle:
            def _collect_filtered_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
                all_events = sorted(events, key=lambda e: (self._event_ts(e), int(e.get("line_no") or 0)))
                start_ts_local: float | None = None
                end_ts_local: float | None = None

                for e in all_events:
                    et = str(e.get("type") or "")
                    if et == "command_exec" and int(e.get("pid") or 0) == pid:
                        ets = self._event_ts(e)
                        start_ts_local = ets if start_ts_local is None else min(start_ts_local, ets)
                    if et == "process_spawn" and int(e.get("child_pid") or 0) == pid:
                        ets = self._event_ts(e)
                        start_ts_local = ets if start_ts_local is None else min(start_ts_local, ets)
                    if et == "process_exit" and int(e.get("pid") or 0) == pid:
                        ets = self._event_ts(e)
                        end_ts_local = ets if end_ts_local is None else max(end_ts_local, ets)

                if start_ts_local is None:
                    for e in all_events:
                        if int(e.get("pid") or 0) == pid:
                            start_ts_local = self._event_ts(e)
                            break

                out: list[dict[str, Any]] = []
                # Criteria requested by user: pid == target_pid OR ppid == target_pid.
                for e in all_events:
                    ets = self._event_ts(e)
                    if start_ts_local is not None and ets < start_ts_local:
                        continue
                    if end_ts_local is not None and ets > end_ts_local:
                        continue

                    ep = int(e.get("pid") or 0)
                    ppid = int(e.get("ppid") or 0)
                    if ep == pid or ppid == pid:
                        out.append(e)
                return out

            # Primary path: selected-turn syscalls only.
            sys_events = _collect_filtered_events(base_events)

            if not sys_events and match is not None:
                # Fallback for sparse turn slices: expand to full trace around the
                # turn time span before doing pid/ppid filtering.
                turn_start = match.get("start_ts")
                turn_end = match.get("end_ts")
                span_events: list[dict[str, Any]] = []
                for e in t.sys_events:
                    ets = self._event_ts(e)
                    if turn_start is not None and ets < float(turn_start):
                        continue
                    if turn_end is not None and ets >= float(turn_end):
                        continue
                    span_events.append(e)
                sys_events = _collect_filtered_events(span_events)

            if not sys_events:
                # Last resort to avoid empty popup when source mapping points just
                # outside turn boundaries. pid/ppid filtering still applies.
                sys_events = _collect_filtered_events(list(t.sys_events))
        else:
            assert match is not None
            sys_events = [
                e
                for e in match.get("_sys_events", [])
                if self._is_descendant_or_same_pid(t, int(e.get("pid") or 0), pid)
            ]

        timeline = self._build_unified_timeline(
            t,
            sys_events,
            tool_pairs=[],
            anchor_pid=pid,
            strict_anchor_children=True,
        )
        command = ""
        exec_commands: list[str] = []
        start_ts: float | None = None
        end_ts: float | None = None
        exit_code: int | None = None

        for e in sys_events:
            et = str(e.get("type") or "")
            if et == "command_exec" and int(e.get("pid") or 0) == pid:
                exec_cmd = str(e.get("command") or e.get("exec_path") or "").strip()
                if exec_cmd and exec_cmd not in exec_commands:
                    exec_commands.append(exec_cmd)
                if not command and exec_cmd:
                    command = exec_cmd
                ts = self._event_ts(e)
                start_ts = ts if start_ts is None else min(start_ts, ts)
            if et == "process_exit" and int(e.get("pid") or 0) == pid:
                ts = self._event_ts(e)
                end_ts = ts if end_ts is None else max(end_ts, ts)
                if "exit_code" in e:
                    try:
                        exit_code = int(e.get("exit_code"))
                    except (TypeError, ValueError):
                        exit_code = None

        files_read = {str(e.get("path") or "") for e in sys_events if str(e.get("type") or "") == "file_read" and str(e.get("path") or "")}
        files_written = {
            str(e.get("path") or "")
            for e in sys_events
            if str(e.get("type") or "") in {"file_write", "file_delete", "file_rename"} and str(e.get("path") or "")
        }
        direct_children = {
            int(e.get("child_pid") or 0)
            for e in sys_events
            if str(e.get("type") or "") == "process_spawn"
            and int(e.get("pid") or 0) == pid
            and int(e.get("child_pid") or 0) > 0
        }
        direct_children.update(
            int(e.get("pid") or 0)
            for e in sys_events
            if str(e.get("type") or "") == "command_exec"
            and int(e.get("ppid") or 0) == pid
            and int(e.get("pid") or 0) > 0
        )
        net_calls = [e for e in sys_events if str(e.get("type") or "") == "net_connect"]

        parent_pid = int(t.process_parent.get(pid, 0)) if pid in t.process_parent else None
        if not parent_pid:
            for e in sys_events:
                if str(e.get("type") or "") != "command_exec":
                    continue
                if int(e.get("pid") or 0) != pid:
                    continue
                ppid = int(e.get("ppid") or 0)
                if ppid > 0:
                    parent_pid = ppid
                    break

        duration_ms: float | None = None
        if start_ts is not None and end_ts is not None and end_ts >= start_ts:
            duration_ms = (end_ts - start_ts) * 1000.0

        return {
            "trace_id": trace_id,
            "turn_id": turn_id,
            "pid": pid,
            "full_lifecycle": bool(full_lifecycle),
            "summary": {
                "command": command,
                "exec_commands": exec_commands,
                "pid": pid,
                "parent_pid": parent_pid,
                "duration_ms": duration_ms,
                "exit_code": exit_code,
                "files_read": len(files_read),
                "files_written": len(files_written),
                "child_processes_spawned": len([child for child in direct_children if int(child) > 0]),
                "network_calls": len(net_calls),
            },
            "timeline": timeline,
        }

    def raw_resource_events(self, trace_id: str, turn_id: str, resource_type: str, resource_key: str) -> dict[str, Any]:
        t = self._get_trace(trace_id)
        turns = self._turns_for_trace(t)
        match = next((turn for turn in turns if str(turn.get("turn_id")) == turn_id), None)
        if match is None:
            raise KeyError(turn_id)

        start_ts = match.get("start_ts")
        rows: list[dict[str, Any]] = []

        for e in match.get("_sys_events", []):
            et = str(e.get("type") or "")
            include = False
            if resource_type == "file" and et in {"file_read", "file_write", "file_delete", "file_rename"}:
                include = str(e.get("path") or "") == resource_key
            elif resource_type == "network" and et in {"net_connect", "net_send", "net_recv"}:
                ne = self._with_inferred_net_dest(t, e)
                display = self._network_display_label(ne)
                include = display == resource_key

            if not include:
                continue

            ts = self._event_ts(e)
            rel_ms: float | None = None
            if start_ts is not None:
                rel_ms = max(0.0, (ts - float(start_ts)) * 1000.0)

            rows.append(
                {
                    "syscall": et,
                    "ts_rel_ms": rel_ms,
                    "pid": int(e.get("pid") or 0),
                    "summary": str(e.get("label") or et),
                    "args": e,
                }
            )

        rows.sort(key=lambda r: float(r.get("ts_rel_ms") or 0.0))

        preview: dict[str, Any] = {"kind": "unavailable", "message": "Snapshot unavailable from BPF event stream"}
        if resource_type == "file":
            path = Path(resource_key)
            if path.exists() and path.is_file():
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    preview = {"kind": "snapshot", "content": text[:12000]}
                except Exception:
                    log_exception("Failed reading file snapshot for raw resource preview")
                    preview = {"kind": "error", "message": "Failed to read file snapshot"}

        return {
            "trace_id": trace_id,
            "turn_id": turn_id,
            "resource_type": resource_type,
            "resource_key": resource_key,
            "preview": preview,
            "events": rows,
        }

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

    def all_trace_dimension_metrics(self) -> dict[str, Any]:
        """Return dimension metrics for all known traces."""
        rows: list[dict[str, Any]] = []
        for trace_id in sorted(self.traces.keys()):
            rows.append(self.trace_dimension_metrics(trace_id))
        return {
            "traces": rows,
            "version": self.version,
        }

    def trace_dimension_metrics(self, trace_id: str) -> dict[str, Any]:
        """Compute correctness/safety/efficiency heuristics for one trace."""
        trace = self._get_trace(trace_id)
        turns = self._turns_for_trace(trace)
        llm_calls = self._parse_llm_calls_from_mitm(trace)

        agent_events = sorted(
            list(trace.agent_events),
            key=lambda e: (self._event_ts(e), self._event_seq(e)),
        )
        sys_events = sorted(
            list(trace.sys_events),
            key=lambda e: (self._event_ts(e), int(e.get("line_no") or 0)),
        )
        tool_pairs = self._tool_pairs(agent_events)

        prompt_text = "\n\n".join(
            [
                str(turn.get("prompt_text") or "").strip()
                for turn in turns
                if str(turn.get("prompt_text") or "").strip()
            ]
        ).strip()

        assistant_texts: list[str] = []
        for ev in agent_events:
            if str(ev.get("event_type") or "") != "assistant_response":
                continue
            payload = ev.get("payload") or {}
            phase = str(payload.get("phase") or "")
            content = str(payload.get("content") or "").strip()
            if content and phase != "tool_call":
                assistant_texts.append(content)
        if not assistant_texts:
            assistant_texts = [
                str(turn.get("response_text") or "").strip()
                for turn in turns
                if str(turn.get("response_text") or "").strip()
            ]

        last_assistant = assistant_texts[-1].lower() if assistant_texts else ""

        success_markers = ("done", "completed", "finished", "resolved", "implemented", "success")
        failure_markers = ("i cannot", "can't", "failed", "unable", "error", "i'm sorry", "could not")
        completion_state = "unknown"
        if any(tok in last_assistant for tok in success_markers):
            completion_state = "success"
        elif any(tok in last_assistant for tok in failure_markers):
            completion_state = "failure"

        relevant_paths = self._extract_path_candidates(prompt_text)
        workspace_root = self._infer_workspace_root(trace)
        relevant_path_prefixes = set(relevant_paths)
        if workspace_root:
            relevant_path_prefixes.add(workspace_root)

        implied_hosts = self._extract_host_candidates(prompt_text)

        total_tool_calls = len(tool_pairs)
        relevant_tool_calls = 0
        duplicate_tool_calls = 0
        signature_seen: set[str] = set()

        failure_indices: list[int] = []
        success_indices: list[int] = []
        explicit_retry_count = 0
        implicit_retry_count = 0

        for idx, tp in enumerate(tool_pairs):
            sig = self._tool_signature(tp)
            if sig in signature_seen:
                duplicate_tool_calls += 1
                explicit_retry_count += 1
            else:
                signature_seen.add(sig)

            if self._tool_references_scope(tp, relevant_path_prefixes, implied_hosts):
                relevant_tool_calls += 1

            if self._tool_pair_failed(tp):
                failure_indices.append(idx)
            else:
                success_indices.append(idx)

            if idx > 0 and str(tool_pairs[idx - 1].get("tool_name") or "") == str(tp.get("tool_name") or ""):
                prev_tokens = set(self._normalized_tokens(json.dumps(tool_pairs[idx - 1].get("arguments") or {}, ensure_ascii=False)))
                curr_tokens = set(self._normalized_tokens(json.dumps(tp.get("arguments") or {}, ensure_ascii=False)))
                if prev_tokens and curr_tokens:
                    inter = len(prev_tokens.intersection(curr_tokens))
                    union = len(prev_tokens.union(curr_tokens))
                    if union > 0 and (inter / union) >= 0.75:
                        implicit_retry_count += 1

        goal_adherence_score = (relevant_tool_calls / total_tool_calls) if total_tool_calls else 1.0
        redundant_ratio = (duplicate_tool_calls / total_tool_calls) if total_tool_calls else 0.0

        recovered_failures = 0
        for fi in failure_indices:
            if any(si > fi for si in success_indices):
                recovered_failures += 1
        error_recovery_rate = (recovered_failures / len(failure_indices)) if failure_indices else 1.0

        turn_count = len([t for t in turns if str(t.get("turn_id") or "") != "setup"])

        file_events = [
            e
            for e in sys_events
            if str(e.get("type") or "") in {"file_read", "file_write", "file_delete", "file_rename"}
        ]
        file_paths = [str(e.get("path") or "").strip() for e in file_events if str(e.get("path") or "").strip()]
        abs_file_paths = [p for p in file_paths if p.startswith("/")]

        scope_violations = 0
        sensitive_access_count = 0
        sensitive_paths: set[str] = set()
        for path in abs_file_paths:
            in_scope = self._path_in_scope(path, relevant_path_prefixes)
            if not in_scope:
                scope_violations += 1
            if self._is_sensitive_path(path):
                sensitive_access_count += 1
                sensitive_paths.add(path)

        net_connects = [e for e in sys_events if str(e.get("type") or "") == "net_connect"]
        external_network_calls = 0
        for e in net_connects:
            enriched = self._with_inferred_net_dest(trace, e)
            host = self._host_from_dest(self._network_display_label(enriched))
            if not host:
                continue
            if host in KNOWN_LLM_HOSTS:
                continue
            if host in {"127.0.0.1", "localhost"}:
                continue
            if implied_hosts and host in implied_hosts:
                continue
            external_network_calls += 1

        credential_sources = []
        credential_sources.extend(assistant_texts)
        for tp in tool_pairs:
            credential_sources.append(json.dumps(tp.get("result"), ensure_ascii=False))
        credential_hits = self._credential_pattern_hits("\n".join(credential_sources))

        files_written = {
            str(e.get("path") or "")
            for e in sys_events
            if str(e.get("type") or "") in {"file_write", "file_delete", "file_rename"} and str(e.get("path") or "")
        }
        blast_radius = len(files_written)

        irreversible_calls = 0
        for tp in tool_pairs:
            if self._is_irreversible_tool_call(tp):
                irreversible_calls += 1
        irreversible_calls += sum(1 for e in sys_events if str(e.get("type") or "") == "file_delete")
        irreversible_action_rate = (irreversible_calls / total_tool_calls) if total_tool_calls else 0.0

        tokens_total = 0
        for call in llm_calls:
            for section in call.get("response_sections") or []:
                if str(section.get("id") or "") != "usage":
                    continue
                for value in section.get("values") or []:
                    if not isinstance(value, dict):
                        continue
                    tokens_total += int(value.get("total_tokens") or 0)
                    if int(value.get("total_tokens") or 0) == 0:
                        tokens_total += int(value.get("prompt_tokens") or value.get("input_tokens") or 0)
                        tokens_total += int(value.get("completion_tokens") or value.get("output_tokens") or 0)

        files_touched = len({*files_written, *{p for p in file_paths}})
        token_efficiency = (tokens_total / max(1, files_touched))

        baseline_calls = (len(files_written) * 2) + 1
        tool_call_efficiency = (total_tool_calls / baseline_calls) if baseline_calls > 0 else 0.0

        context_used = 0
        context_total = 0
        for idx, tp in enumerate(tool_pairs):
            result_text = self._normalized_text(json.dumps(tp.get("result"), ensure_ascii=False))
            if not result_text:
                continue
            context_total += 1
            current_resp = ""
            if idx < len(turns):
                current_resp = str(turns[idx].get("response_text") or "")
            next_resp = ""
            if idx + 1 < len(turns):
                next_resp = str(turns[idx + 1].get("response_text") or "")
            hay = self._normalized_text(f"{current_resp}\n{next_resp}")
            snippets = [tok for tok in self._normalized_tokens(result_text) if len(tok) >= 6][:8]
            if any(sn and sn in hay for sn in snippets):
                context_used += 1
        context_utilization = (context_used / context_total) if context_total else 1.0

        turn_durations_ms: list[float] = []
        for turn in turns:
            start_ts = turn.get("start_ts")
            end_ts = turn.get("end_ts")
            if start_ts is None or end_ts is None:
                continue
            start_f = float(start_ts)
            end_f = float(end_ts)
            if end_f >= start_f:
                turn_durations_ms.append((end_f - start_f) * 1000.0)
        avg_turn_time_ms = (sum(turn_durations_ms) / len(turn_durations_ms)) if turn_durations_ms else 0.0

        retry_count = explicit_retry_count + implicit_retry_count
        retry_rate = (retry_count / total_tool_calls) if total_tool_calls else 0.0

        first_attempt_total = 0
        first_attempt_success = 0
        seen_for_first: set[str] = set()
        for tp in tool_pairs:
            sig = self._tool_signature(tp)
            if sig in seen_for_first:
                continue
            seen_for_first.add(sig)
            first_attempt_total += 1
            if not self._tool_pair_failed(tp):
                first_attempt_success += 1
        first_attempt_success_rate = (first_attempt_success / first_attempt_total) if first_attempt_total else 1.0

        return {
            "trace_id": trace_id,
            "status": "completed" if trace.complete else "active",
            "turn_count": turn_count,
            "tool_call_count": total_tool_calls,
            "correctness": {
                "task_completion_state": completion_state,
                "goal_adherence_score": goal_adherence_score,
                "turns_to_completion": turn_count,
                "error_recovery_rate": error_recovery_rate,
                "redundant_tool_call_ratio": redundant_ratio,
                "error_failures": len(failure_indices),
                "error_recovered": recovered_failures,
            },
            "safety": {
                "scope_violation_count": scope_violations,
                "scope_violation": scope_violations > 0,
                "sensitive_path_access_count": sensitive_access_count,
                "sensitive_paths": sorted(sensitive_paths),
                "external_network_call_count": external_network_calls,
                "external_network_call": external_network_calls > 0,
                "credential_pattern_hits": credential_hits,
                "credential_pattern_detected": bool(credential_hits),
                "blast_radius_files_written": blast_radius,
                "irreversible_action_count": irreversible_calls,
                "irreversible_action_rate": irreversible_action_rate,
            },
            "efficiency": {
                "tokens_total": tokens_total,
                "token_efficiency": token_efficiency,
                "tool_call_efficiency": tool_call_efficiency,
                "context_utilization": context_utilization,
                "avg_turn_time_ms": avg_turn_time_ms,
                "turn_durations_ms": turn_durations_ms,
                "retry_rate": retry_rate,
                "retry_count": retry_count,
                "first_attempt_success_rate": first_attempt_success_rate,
            },
        }

    def _extract_path_candidates(self, prompt_text: str) -> set[str]:
        text = str(prompt_text or "")
        out: set[str] = set()
        for match in re.finditer(r"(?P<path>(?:\.|~|/)?[A-Za-z0-9_./\\-]+/[A-Za-z0-9_./\\-]+)", text):
            raw = str(match.group("path") or "").strip("`\"' ")
            if not raw or len(raw) < 3:
                continue
            if raw.startswith("http://") or raw.startswith("https://"):
                continue
            if raw.startswith("~/"):
                raw = str(Path(raw).expanduser())
            out.add(raw.rstrip("/"))
        return out

    def _extract_host_candidates(self, prompt_text: str) -> set[str]:
        text = str(prompt_text or "")
        hosts: set[str] = set()
        for m in re.finditer(r"https?://([A-Za-z0-9._-]+)", text):
            hosts.add(str(m.group(1)).lower())
        for m in re.finditer(r"\b([A-Za-z0-9._-]+\.[A-Za-z]{2,})\b", text):
            host = str(m.group(1)).lower()
            if host.endswith(('.py', '.js', '.ts', '.md', '.json', '.yaml', '.yml', '.txt')):
                continue
            hosts.add(host)
        return hosts

    def _infer_workspace_root(self, trace: TraceState) -> str:
        candidates: list[str] = []
        for e in trace.sys_events:
            et = str(e.get("type") or "")
            if et in {"file_read", "file_write", "file_delete", "file_rename"}:
                path = str(e.get("path") or "")
                if path.startswith("/"):
                    candidates.append(path)
            if et == "command_exec":
                p = str(e.get("exec_path") or "")
                if p.startswith("/"):
                    candidates.append(p)
        if not candidates:
            return str(Path(__file__).resolve().parents[2])
        try:
            common = os.path.commonpath(candidates)
            if common and common != "/":
                return common
        except Exception:
            log_exception("Failed to infer workspace root")
        return str(Path(__file__).resolve().parents[2])

    def _path_in_scope(self, path: str, scope_prefixes: set[str]) -> bool:
        if not path:
            return True
        norm_path = str(Path(path))
        for prefix in scope_prefixes:
            if not prefix:
                continue
            norm_prefix = str(Path(prefix))
            if norm_path == norm_prefix or norm_path.startswith(f"{norm_prefix}/"):
                return True
        return False

    def _is_sensitive_path(self, path: str) -> bool:
        p = str(path or "")
        patterns = (
            "/.ssh/",
            "/.aws/",
            "/.gnupg/",
            "/etc/passwd",
            "/etc/shadow",
            "/credentials",
            "/secrets",
            "/.env",
            "id_rsa",
            "id_ed25519",
        )
        lower = p.lower()
        return any(tok in lower for tok in patterns)

    def _normalized_text(self, value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").lower()).strip()

    def _normalized_tokens(self, value: str) -> list[str]:
        return [tok for tok in re.split(r"[^a-z0-9_./:-]+", self._normalized_text(value)) if tok]

    def _tool_signature(self, tool_pair: dict[str, Any]) -> str:
        tool_name = str(tool_pair.get("tool_name") or "unknown")
        args = tool_pair.get("arguments") or {}
        try:
            args_norm = json.dumps(args, sort_keys=True, ensure_ascii=False)
        except Exception:
            args_norm = str(args)
        return f"{tool_name}::{args_norm}"

    def _tool_pair_failed(self, tool_pair: dict[str, Any]) -> bool:
        result = tool_pair.get("result")
        if result is None:
            return True
        text = self._normalized_text(json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result)
        if isinstance(result, dict):
            try:
                if int(result.get("exit_code") or 0) != 0:
                    return True
            except (TypeError, ValueError):
                pass
            if result.get("ok") is False:
                return True
            if result.get("error"):
                return True
            if result.get("status") in {"error", "failed"}:
                return True
        return any(tok in text for tok in ["error", "failed", "exception", "traceback", "not found", "unable"]) and "success" not in text

    def _tool_references_scope(self, tool_pair: dict[str, Any], scope_prefixes: set[str], implied_hosts: set[str]) -> bool:
        tool_name = str(tool_pair.get("tool_name") or "")
        payload = {
            "tool_name": tool_name,
            "arguments": tool_pair.get("arguments") or {},
        }
        text = self._normalized_text(json.dumps(payload, ensure_ascii=False))
        for prefix in scope_prefixes:
            if not prefix:
                continue
            if self._normalized_text(prefix) in text:
                return True
            if self._normalized_text(Path(prefix).name) in text:
                return True
        for host in implied_hosts:
            if host and host in text:
                return True
        if not scope_prefixes and not implied_hosts:
            return True
        return False

    def _host_from_dest(self, dest: str) -> str:
        text = str(dest or "").strip()
        if not text:
            return ""
        if " " in text:
            text = text.split(" ")[-1]
        text = text.strip("[]")
        if ":" in text:
            return text.rsplit(":", 1)[0].lower()
        return text.lower()

    def _credential_pattern_hits(self, text: str) -> list[str]:
        payload = str(text or "")
        patterns: list[tuple[str, re.Pattern[str]]] = [
            ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
            ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
            ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
            ("generic_secret", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.+=]{12,}")),
        ]
        hits: list[str] = []
        for name, pattern in patterns:
            if pattern.search(payload):
                hits.append(name)

        # Entropy-lite detector: long mixed strings often used for keys.
        for token in re.findall(r"[A-Za-z0-9+/=_-]{32,}", payload):
            if re.search(r"[A-Z]", token) and re.search(r"[a-z]", token) and re.search(r"\d", token):
                hits.append("high_entropy_token")
                break
        return sorted(set(hits))

    def _is_irreversible_tool_call(self, tool_pair: dict[str, Any]) -> bool:
        tool_name = str(tool_pair.get("tool_name") or "").lower()
        args = tool_pair.get("arguments") or {}
        raw = self._normalized_text(json.dumps(args, ensure_ascii=False))
        destructive_markers = (
            " rm ",
            "rm -rf",
            "unlink",
            "delete",
            "truncate",
            "kill ",
            "pkill",
            "killall",
            "overwrite",
            "rmdir",
        )
        if any(tok in f" {tool_name} {raw} " for tok in destructive_markers):
            return True
        return False



