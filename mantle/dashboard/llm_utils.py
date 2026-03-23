"""LLM schema and payload parsing helpers for dashboard traces."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any


def builtin_llm_api_schemas() -> list[dict[str, Any]]:
    """Return builtin schema definitions used for MITM LLM payload parsing."""
    return [
        {
            "id": "builtin_tamu_chat_completions",
            "name": "TAMU Chat Completions",
            "endpoint_pattern": r"/(?:v1/|api/)?chat/completions(?:\?.*)?$",
            "request": {
                "messages_path": "messages",
                "instructions_path": "instructions",
                "sections": [
                    {"id": "instructions", "label": "Instructions", "path": "instructions", "mode": "text"},
                    {"id": "messages", "label": "Messages", "path": "messages", "mode": "messages_text"},
                    {"id": "available_tools", "label": "Available tools", "path": "tools", "mode": "json"},
                ],
            },
            "response": {
                "assistant_paths": ["choices[].message.content"],
                "sections": [
                    {"id": "assistant_text", "label": "Assistant text", "path": "choices[].message.content", "mode": "text"},
                    {"id": "tool_calls", "label": "Tool calls", "path": "choices[].message.tool_calls", "mode": "json"},
                    {"id": "finish_reason", "label": "Finish reason", "path": "choices[].finish_reason", "mode": "text"},
                    {"id": "usage", "label": "Usage", "path": "usage", "mode": "json"},
                ],
            },
        },
        {
            "id": "builtin_openai_chat_completions",
            "name": "OpenAI Chat Completions",
            "endpoint_pattern": r"/(?:v1/|api/)?chat/completions(?:\?.*)?$",
            "request": {
                "messages_path": "messages",
                "instructions_path": "instructions",
                "sections": [
                    {"id": "instructions", "label": "Instructions", "path": "instructions", "mode": "text"},
                    {"id": "messages", "label": "Messages", "path": "messages", "mode": "messages_text"},
                    {"id": "available_tools", "label": "Available tools", "path": "tools", "mode": "json"},
                ],
            },
            "response": {
                "assistant_paths": ["choices[].message.content"],
                "sections": [
                    {"id": "assistant_text", "label": "Assistant text", "path": "choices[].message.content", "mode": "text"},
                    {"id": "tool_calls", "label": "Tool calls", "path": "choices[].message.tool_calls", "mode": "json"},
                    {"id": "finish_reason", "label": "Finish reason", "path": "choices[].finish_reason", "mode": "text"},
                    {"id": "usage", "label": "Usage", "path": "usage", "mode": "json"},
                ],
            },
        },
        {
            "id": "builtin_openai_responses",
            "name": "OpenAI Responses API",
            "endpoint_pattern": r"/(?:v1/)?responses(?:\?.*)?$",
            "request": {
                "messages_path": "input",
                "instructions_path": "instructions",
                "sections": [
                    {"id": "instructions", "label": "Instructions", "path": "instructions", "mode": "text"},
                    {"id": "input_messages", "label": "Input messages", "path": "input", "mode": "messages_text"},
                    {"id": "input_text", "label": "Input text", "path": "input[].content[].text", "mode": "text"},
                    {"id": "tool_outputs", "label": "Tool outputs", "path": "input[].output", "mode": "text"},
                    {"id": "tool_output_text", "label": "Tool output text", "path": "input[].content[].output_text", "mode": "text"},
                    {"id": "input_types", "label": "Input item types", "path": "input[].type", "mode": "text"},
                    {"id": "tool_inputs", "label": "Tool inputs", "path": "input[].arguments", "mode": "json"},
                    {"id": "available_tools", "label": "Available tools", "path": "tools", "mode": "json"},
                ],
            },
            "response": {
                "assistant_paths": ["output[].content[].text", "output_text"],
                "sections": [
                    {"id": "assistant_text", "label": "Assistant text", "path": "output_text", "mode": "text"},
                    {"id": "assistant_messages", "label": "Assistant messages", "path": "output[].content[].text", "mode": "text"},
                    {"id": "tool_calls", "label": "Tool calls", "path": "tool_calls", "mode": "json"},
                    {"id": "output_items", "label": "Output items", "path": "output", "mode": "json"},
                    {"id": "usage", "label": "Usage", "path": "usage", "mode": "json"},
                ],
            },
        },
    ]


def normalize_llm_schemas(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize and validate custom schema payloads from API settings."""
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in schemas:
        if not isinstance(raw, dict):
            continue
        schema_id = str(raw.get("id") or "").strip()
        if not schema_id or schema_id in seen:
            continue
        endpoint_pattern = str(raw.get("endpoint_pattern") or "").strip()
        if not endpoint_pattern:
            continue
        req = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}

        req_sections = req.get("sections") if isinstance(req.get("sections"), list) else []
        resp_sections = resp.get("sections") if isinstance(resp.get("sections"), list) else []

        normalized.append(
            {
                "id": schema_id,
                "name": str(raw.get("name") or schema_id),
                "endpoint_pattern": endpoint_pattern,
                "request": {
                    "messages_path": str(req.get("messages_path") or "").strip(),
                    "instructions_path": str(req.get("instructions_path") or "").strip(),
                    "sections": _norm_sections(req_sections),
                },
                "response": {
                    "assistant_paths": [str(p) for p in (resp.get("assistant_paths") or []) if isinstance(p, str) and p.strip()],
                    "sections": _norm_sections(resp_sections),
                },
            }
        )
        seen.add(schema_id)

    return normalized or builtin_llm_api_schemas()


def _norm_sections(items: list[Any]) -> list[dict[str, str]]:
    """Normalize request/response section specs into a canonical shape."""
    out_sections: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if not path:
            continue
        out_sections.append(
            {
                "id": str(item.get("id") or path).strip(),
                "label": str(item.get("label") or item.get("id") or path).strip(),
                "path": path,
                "mode": str(item.get("mode") or "text").strip(),
            }
        )
    return out_sections


def extract_by_path(data: Any, path: str) -> list[Any]:
    """Extract values from nested dict/list payloads using dotted [] paths."""
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


def extract_texts_from_messages(messages: Any) -> list[str]:
    """Extract textual content from chat-style message arrays.

    Includes tool/function output items so request prompt sections reflect
    the full context the model received in subsequent turns.
    """
    out: list[str] = []
    if not isinstance(messages, list):
        return out

    def _content_to_text(content: Any) -> str:
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts: list[str] = []
            for c in content:
                if isinstance(c, str):
                    if c.strip():
                        parts.append(c.strip())
                    continue
                if not isinstance(c, dict):
                    continue
                for key in ("text", "output_text", "output", "input"):
                    value = c.get(key)
                    if isinstance(value, str) and value.strip():
                        parts.append(value.strip())
            return "\n".join([p for p in parts if p]).strip()
        if isinstance(content, dict):
            for key in ("text", "output_text", "output", "input"):
                value = content.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or msg.get("type") or "unknown")

        content = msg.get("content")
        if content is None and msg.get("type") == "function_call_output":
            content = msg.get("output")

        text = _content_to_text(content)
        if not text:
            raw_out = msg.get("output")
            if isinstance(raw_out, str) and raw_out.strip():
                text = raw_out.strip()

        if not text:
            continue

        if role in {"user", "system", "developer", "assistant"}:
            out.append(f"[{role}] {text}")
        elif role in {"tool", "function_call_output", "custom_tool_call_output"}:
            out.append(f"[tool_output] {text}")
        elif role in {"function_call", "tool_call"}:
            out.append(f"[tool_call] {text}")
        else:
            out.append(f"[{role}] {text}")
    return out


def section_values(data: Any, specs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resolve schema section specs to concrete values from payload data."""
    sections: list[dict[str, Any]] = []
    for spec in specs:
        if not isinstance(spec, dict):
            continue
        path = str(spec.get("path") or "").strip()
        if not path:
            continue
        mode = str(spec.get("mode") or "text").strip()
        values: list[Any] = []

        for raw in extract_by_path(data, path):
            if mode == "messages_text":
                for text in extract_texts_from_messages(raw):
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
                    elif isinstance(item, dict):
                        captured = False
                        for key in ("text", "output_text", "output", "input"):
                            val = item.get(key)
                            if isinstance(val, str) and val.strip():
                                values.append(val.strip())
                                captured = True
                        if not captured and item:
                            values.append(item)
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


def sections_to_text(sections: list[dict[str, Any]]) -> str:
    """Concatenate section values into a text-friendly representation."""
    parts: list[str] = []
    for section in sections:
        for value in section.get("values") or []:
            if isinstance(value, str):
                if value.strip():
                    parts.append(value.strip())
            else:
                parts.append(json.dumps(value, ensure_ascii=False))
    return "\n\n".join([p for p in parts if p])


def merge_sections(base: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge section arrays while preserving order and deduplicating values."""
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


def parse_sse_data_events(raw: str) -> list[dict[str, Any]]:
    """Extract JSON `data:` records from an SSE text payload."""
    events: list[dict[str, Any]] = []
    if not raw:
        return events

    # Some proxies hand through a full JSON response body instead of raw SSE.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

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
        if isinstance(data, dict):
            events.append(data)
    return events


def normalize_streaming_response_body(raw: str) -> dict[str, Any]:
    """Normalize streamed Responses API SSE payload into a structured object."""
    events = parse_sse_data_events(raw)
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

        if ev_type == "response.function_call_arguments.done":
            item_id = str(event.get("item_id") or "")
            if item_id:
                function_args_parts[item_id] = str(event.get("arguments") or function_args_parts.get(item_id) or "")
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


def normalize_response_body_for_sections(response_body: Any) -> dict[str, Any]:
    """Normalize raw response objects before section extraction."""
    if not isinstance(response_body, dict):
        return {}

    raw = response_body.get("_raw")
    if isinstance(raw, str) and raw.strip():
        parsed = normalize_streaming_response_body(raw)
        if parsed:
            merged = dict(response_body)
            merged.update(parsed)
            return merged

    return response_body


def parse_llm_calls_from_mitm(trace: Any, llm_api_schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse MITM JSONL and return prompt/response turns matched by URL+time."""
    if not trace.mitm_path or not trace.mitm_path.exists():
        return []

    compiled: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    for schema in llm_api_schemas:
        pattern = str(schema.get("endpoint_pattern") or "").strip()
        if not pattern:
            continue
        try:
            compiled.append((schema, re.compile(pattern)))
        except re.error:
            continue

    if not compiled:
        return []

    pending: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []

    with trace.mitm_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = str(rec.get("url") or "")
            schema_match: dict[str, Any] | None = None
            for schema, regex in compiled:
                if regex.search(url):
                    schema_match = schema
                    break
            if schema_match is None:
                continue

            direction = str(rec.get("direction") or "")
            ts = float(rec.get("ts") or 0.0)
            req_body = rec.get("request_body") or {}
            resp_body = rec.get("response_body") or {}
            req_cfg = schema_match.get("request") or {}
            resp_cfg = schema_match.get("response") or {}

            if direction == "request":
                req_sections = req_cfg.get("sections") if isinstance(req_cfg.get("sections"), list) else []
                if not req_sections:
                    req_sections = []
                    instructions_path = str(req_cfg.get("instructions_path") or "")
                    messages_path = str(req_cfg.get("messages_path") or "")
                    if instructions_path:
                        req_sections.append({"id": "instructions", "label": "Instructions", "path": instructions_path, "mode": "text"})
                    if messages_path:
                        req_sections.append({"id": "messages", "label": "Messages", "path": messages_path, "mode": "messages_text"})

                prompt_sections = section_values(req_body, req_sections)

                pending.append(
                    {
                        "ts": ts,
                        "url": url,
                        "schema_id": schema_match.get("id"),
                        "prompt_sections": prompt_sections,
                        "prompt_text": sections_to_text(prompt_sections),
                        "response_sections": [],
                        "response_text": "",
                        "matched": False,
                    }
                )
                continue

            if direction == "response":
                resp_sections = resp_cfg.get("sections") if isinstance(resp_cfg.get("sections"), list) else []
                if not resp_sections:
                    resp_sections = [
                        {"id": "assistant_text", "label": "Assistant text", "path": str(path), "mode": "text"}
                        for path in (resp_cfg.get("assistant_paths") or [])
                        if isinstance(path, str) and str(path).strip()
                    ]

                normalized_resp_body = normalize_response_body_for_sections(resp_body)
                response_sections = section_values(normalized_resp_body, resp_sections)
                if normalized_resp_body is not resp_body:
                    response_sections = merge_sections(response_sections, section_values(resp_body, resp_sections))
                response_text = sections_to_text(response_sections)

                if not response_text:
                    response_texts: list[str] = []
                    choices = normalized_resp_body.get("choices")
                    if isinstance(choices, list):
                        for choice in choices:
                            if not isinstance(choice, dict):
                                continue
                            msg = choice.get("message") if isinstance(choice.get("message"), dict) else {}
                            content = msg.get("content")
                            if isinstance(content, str) and content.strip():
                                response_texts.append(content.strip())

                    output_text = normalized_resp_body.get("output_text")
                    if isinstance(output_text, str) and output_text.strip():
                        response_texts.append(output_text.strip())

                    tool_calls = normalized_resp_body.get("tool_calls")
                    fallback_sections: list[dict[str, Any]] = []
                    if isinstance(tool_calls, list) and tool_calls:
                        fallback_sections.append({"id": "tool_calls", "label": "Tool calls", "values": [tool_calls]})

                    if response_texts:
                        fallback_sections.insert(0, {"id": "assistant_text", "label": "Assistant text", "values": response_texts})

                    if fallback_sections:
                        response_sections = merge_sections(response_sections, fallback_sections)
                        response_text = sections_to_text(response_sections)

                target_idx: int | None = None
                for i in range(len(pending) - 1, -1, -1):
                    item = pending[i]
                    if item.get("matched"):
                        continue
                    if str(item.get("url") or "") != url:
                        continue
                    if float(item.get("ts") or 0.0) <= ts:
                        target_idx = i
                        break

                if target_idx is not None:
                    item = pending[target_idx]
                    item["matched"] = True
                    item["response_sections"] = response_sections
                    item["response_text"] = response_text
                    calls.append(item)

    for item in pending:
        if not item.get("matched"):
            calls.append(item)

    calls.sort(key=lambda x: float(x.get("ts") or 0.0))
    return calls
