"""URL-like non-interactive route handlers for mantle CLI."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .store import CliStore


@dataclass
class RouteResult:
    title: str
    text: str
    pager: bool = False
    meta: dict[str, Any] = field(default_factory=dict)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=False)


def _preview(value: Any, max_len: int = 96) -> str:
    if isinstance(value, str):
        txt = " ".join(value.split())
    else:
        txt = " ".join(_json(value).split())
    if len(txt) <= max_len:
        return txt
    return f"{txt[: max_len - 3]}..."


def _normalize(path: str) -> list[str]:
    raw = str(path or "").strip()
    if raw.startswith("/"):
        raw = raw[1:]
    if raw.endswith("/"):
        raw = raw[:-1]
    if not raw:
        return []
    return [unquote(p) for p in raw.split("/") if p]


def _help_text() -> str:
    return "\n".join(
        [
            "Mantle CLI Routes",
            "",
            "Core:",
            "  traces",
            "  <trace_id>",
            "  <trace_id>/summary",
            "",
            "Trace View:",
            "  <trace_id>/trace",
            "  <trace_id>/trace/<turn_id>/summary",
            "  <trace_id>/trace/<turn_id>/timeline",
            "  <trace_id>/trace/<turn_id>/timeline/<index>",
            "  <trace_id>/trace/<turn_id>/prompt",
            "  <trace_id>/trace/<turn_id>/prompt/<section_id>",
            "  <trace_id>/trace/<turn_id>/prompt/<section_id>/<message_index>",
            "  <trace_id>/trace/<turn_id>/response",
            "  <trace_id>/trace/<turn_id>/response/<section_id>",
            "  <trace_id>/trace/<turn_id>/response/<section_id>/<message_index>",
            "  <trace_id>/trace/<turn_id>/process/<pid>",
            "  <trace_id>/trace/<turn_id>/resource/<file|network>/<urlencoded_resource_key>",
            "",
            "Replay:",
            "  <trace_id>/replay",
            "  <trace_id>/replay/<turn_id>/summary",
            "  <trace_id>/replay/<turn_id>/context",
            "  <trace_id>/replay/<turn_id>/context/<section_id>",
            "  <trace_id>/replay/<turn_id>/context/<section_id>/<message_index>",
            "  <trace_id>/replay/<turn_id>/action",
            "  <trace_id>/replay/<turn_id>/action/<section_id>",
            "  <trace_id>/replay/<turn_id>/action/<section_id>/<message_index>",
            "  <trace_id>/replay/<turn_id>/tool-calls",
            "  <trace_id>/replay/<turn_id>/files",
            "  <trace_id>/replay/<turn_id>/subprocesses",
        ]
    )


def _find_section(sections: list[dict[str, Any]], selector: str) -> dict[str, Any] | None:
    wanted = str(selector or "").strip()
    wanted_slug = _slug(wanted)
    for section in sections:
        sid = str(section.get("id") or "")
        label = str(section.get("label") or sid)
        if wanted == sid or wanted == label or wanted_slug in {_slug(sid), _slug(label)}:
            return section
    return None


def _format_sections(kind: str, sections: list[dict[str, Any]]) -> str:
    if not sections:
        return f"No {kind} sections found."
    lines = [f"{kind.title()} sections:"]
    for sec in sections:
        sid = str(sec.get("id") or "")
        label = str(sec.get("label") or sid)
        values = sec.get("values") or []
        lines.append(f"- {sid} ({label}): {len(values)} messages")
    return "\n".join(lines)


def _format_section_messages(section: dict[str, Any]) -> str:
    sid = str(section.get("id") or "")
    label = str(section.get("label") or sid)
    values = section.get("values") or []
    lines = [f"Section {sid} ({label})", ""]
    for idx, value in enumerate(values):
        lines.append(f"[{idx}] {_preview(value)}")
    return "\n".join(lines)


def _format_turn_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No turns found for this trace."
    lines = ["Turns:"]
    for row in rows:
        tid = str(row.get("turn_id") or "")
        label = str(row.get("label") or tid)
        tools = int(row.get("tool_call_count") or 0)
        summary = str(row.get("dominant_summary") or "").strip()
        summary_txt = f" | {_preview(summary, max_len=80)}" if summary else ""
        lines.append(f"- {tid} ({label}) | tools={tools}{summary_txt}")
    return "\n".join(lines)


def _format_replay_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No replay turns found for this trace."
    lines = ["Replay turns:"]
    for row in rows:
        tid = str(row.get("turn_id") or "")
        label = str(row.get("label") or tid)
        ctx = int(row.get("context_section_count") or 0)
        act = int(row.get("action_section_count") or 0)
        tools = int(row.get("tool_call_count") or 0)
        lines.append(f"- {tid} ({label}) | context={ctx} action={act} tools={tools}")
    return "\n".join(lines)


def _format_traces(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No traces found."
    lines = ["Traces:"]
    for row in rows:
        trace_id = str(row.get("trace_id") or "")
        status = str(row.get("status") or "unknown")
        sys_count = int(row.get("sys_event_count") or 0)
        agent_count = int(row.get("agent_event_count") or 0)
        lines.append(f"- {trace_id} | {status} | sys={sys_count} agent={agent_count}")
    return "\n".join(lines)


def _resolve_trace_or_error(cli_store: CliStore, trace_id: str) -> tuple[str, list[dict[str, Any]]]:
    traces = cli_store.store.list_traces()
    ids = [str(t.get("trace_id") or "") for t in traces]
    if trace_id not in ids:
        raise KeyError(f"unknown trace_id: {trace_id}")
    return trace_id, traces


def execute_route(cli_store: CliStore, path: str) -> RouteResult:
    """Resolve a URL-like route and return formatted output."""
    cli_store.refresh()
    parts = _normalize(path)
    if not parts or parts == ["help"]:
        return RouteResult(title="help", text=_help_text(), pager=False)

    if parts[0] == "traces":
        traces = cli_store.store.list_traces()
        return RouteResult(
            title="traces",
            text=_format_traces(traces),
            pager=False,
            meta={"trace_ids": [str(t.get("trace_id") or "") for t in traces]},
        )

    trace_id = parts[0]
    _resolve_trace_or_error(cli_store, trace_id)

    if len(parts) == 1:
        overview = cli_store.store.turns_overview(trace_id)
        summary = cli_store.store.trace_summary(trace_id)
        text = "\n\n".join(
            [
                f"Trace: {trace_id}",
                "Executive Summary:",
                _json(overview.get("executive_summary") or {}),
                "Top-level Trace Summary:",
                _json(summary),
                "",
                "Try routes:",
                f"  {trace_id}/trace",
                f"  {trace_id}/replay",
            ]
        )
        return RouteResult(title=trace_id, text=text, pager=True)

    if parts[1] == "summary":
        return RouteResult(
            title=f"{trace_id}/summary",
            text=_json(cli_store.store.trace_summary(trace_id)),
            pager=True,
        )

    if parts[1] in {"turns", "trace"}:
        if len(parts) == 2:
            overview = cli_store.store.turns_overview(trace_id)
            turns = overview.get("turns") or []
            return RouteResult(
                title=f"{trace_id}/trace",
                text=_format_turn_rows(turns),
                pager=False,
                meta={
                    "turn_ids": [str(t.get("turn_id") or "") for t in turns],
                    "turn_labels": {str(t.get("turn_id") or ""): str(t.get("label") or "") for t in turns},
                },
            )

        turn_id = parts[2]
        detail = cli_store.store.turn_detail(trace_id, turn_id)

        if len(parts) == 3 or (len(parts) == 4 and parts[3] == "summary"):
            return RouteResult(
                title=f"{trace_id}/trace/{turn_id}/summary",
                text=_json(detail.get("summary") or {}),
                pager=False,
            )

        if len(parts) >= 4 and parts[3] == "timeline":
            timeline = detail.get("timeline") or []
            if len(parts) == 4:
                lines = [f"Timeline entries for turn {turn_id}:"]
                for idx, entry in enumerate(timeline):
                    label = str(entry.get("title") or entry.get("entry_type") or f"entry_{idx}")
                    category = str(entry.get("entry_type") or "unknown")
                    lines.append(f"[{idx}] {category}: {_preview(label, max_len=90)}")
                return RouteResult(title=f"{trace_id}/trace/{turn_id}/timeline", text="\n".join(lines), pager=False)

            index = int(parts[4])
            if index < 0 or index >= len(timeline):
                raise KeyError(f"timeline index out of range: {index}")
            return RouteResult(
                title=f"{trace_id}/trace/{turn_id}/timeline/{index}",
                text=_json(timeline[index]),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] in {"prompt", "response"}:
            key = "prompt_sections" if parts[3] == "prompt" else "response_sections"
            sections = detail.get(key) or []
            if len(parts) == 4:
                return RouteResult(
                    title=f"{trace_id}/trace/{turn_id}/{parts[3]}",
                    text=_format_sections(parts[3], sections),
                    pager=False,
                    meta={"section_ids": [str(s.get("id") or "") for s in sections]},
                )
            section = _find_section(sections, parts[4])
            if section is None:
                raise KeyError(f"section not found: {parts[4]}")
            if len(parts) == 5:
                values = section.get("values") or []
                return RouteResult(
                    title=f"{trace_id}/trace/{turn_id}/{parts[3]}/{parts[4]}",
                    text=_format_section_messages(section),
                    pager=False,
                    meta={"message_indices": list(range(len(values)))},
                )
            msg_idx = int(parts[5])
            values = section.get("values") or []
            if msg_idx < 0 or msg_idx >= len(values):
                raise KeyError(f"message index out of range: {msg_idx}")
            return RouteResult(
                title=f"{trace_id}/trace/{turn_id}/{parts[3]}/{parts[4]}/{msg_idx}",
                text=_json(values[msg_idx]) if not isinstance(values[msg_idx], str) else str(values[msg_idx]),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "process":
            if len(parts) < 5:
                raise KeyError("missing pid")
            pid = int(parts[4])
            payload = cli_store.store.process_subtrace(trace_id, turn_id, pid)
            return RouteResult(
                title=f"{trace_id}/trace/{turn_id}/process/{pid}",
                text=_json(payload),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "resource":
            if len(parts) < 6:
                raise KeyError("resource route requires type and key")
            resource_type = parts[4]
            resource_key = "/".join(parts[5:])
            payload = cli_store.store.raw_resource_events(trace_id, turn_id, resource_type, resource_key)
            return RouteResult(
                title=f"{trace_id}/trace/{turn_id}/resource/{resource_type}/{resource_key}",
                text=_json(payload),
                pager=True,
            )

        raise KeyError(f"unsupported trace route: {'/'.join(parts)}")

    if parts[1] == "replay":
        if len(parts) == 2:
            overview = cli_store.store.replay_turns_overview(trace_id)
            turns = overview.get("turns") or []
            return RouteResult(
                title=f"{trace_id}/replay",
                text=_format_replay_rows(turns),
                pager=False,
                meta={
                    "turn_ids": [str(t.get("turn_id") or "") for t in turns],
                    "turn_labels": {str(t.get("turn_id") or ""): str(t.get("label") or "") for t in turns},
                },
            )

        turn_id = parts[2]
        detail = cli_store.store.replay_turn_detail(trace_id, turn_id)
        summary = detail.get("summary") or {}

        if len(parts) == 3 or (len(parts) == 4 and parts[3] == "summary"):
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/summary",
                text=_json(summary),
                pager=False,
            )

        if len(parts) >= 4 and parts[3] in {"context", "action"}:
            pane = parts[3]
            pane_obj = detail.get(pane) or {}
            sections = pane_obj.get("sections") or []
            if len(parts) == 4:
                return RouteResult(
                    title=f"{trace_id}/replay/{turn_id}/{pane}",
                    text=_format_sections(pane, sections),
                    pager=False,
                    meta={"section_ids": [str(s.get("id") or "") for s in sections]},
                )
            section = _find_section(sections, parts[4])
            if section is None:
                raise KeyError(f"section not found: {parts[4]}")
            if len(parts) == 5:
                values = section.get("values") or []
                return RouteResult(
                    title=f"{trace_id}/replay/{turn_id}/{pane}/{parts[4]}",
                    text=_format_section_messages(section),
                    pager=False,
                    meta={"message_indices": list(range(len(values)))},
                )
            msg_idx = int(parts[5])
            values = section.get("values") or []
            if msg_idx < 0 or msg_idx >= len(values):
                raise KeyError(f"message index out of range: {msg_idx}")
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/{pane}/{parts[4]}/{msg_idx}",
                text=_json(values[msg_idx]) if not isinstance(values[msg_idx], str) else str(values[msg_idx]),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "tool-calls":
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/tool-calls",
                text=_json(summary.get("tool_call_pairs") or []),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "files":
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/files",
                text=_json(summary.get("file_activity") or {}),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "subprocesses":
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/subprocesses",
                text=_json(summary.get("subprocesses") or []),
                pager=True,
            )

        raise KeyError(f"unsupported replay route: {'/'.join(parts)}")

    raise KeyError(f"unsupported route: {'/'.join(parts)}")
