"""Replay-trace business logic for dashboard context/action views."""

from __future__ import annotations

from typing import Any

from .llm_utils import merge_sections, sections_to_text


CONTEXT_BAND_STYLE: dict[str, str] = {
    "system_prompt": "system",
    "system_messages": "system",
    "developer_messages": "developer",
    "user_messages": "user",
    "assistant_messages": "assistant",
    "tool_outputs": "tool_output",
    "tool_calls_in_context": "tool_call",
    "available_tools": "tools",
}

ACTION_BAND_STYLE: dict[str, str] = {
    "assistant_text": "assistant",
    "assistant_messages": "assistant",
    "tool_calls": "tool_call",
}


def _section_key(section: dict[str, Any]) -> str:
    return str(section.get("id") or "").strip()


def _section_values_count(section: dict[str, Any]) -> int:
    return len(section.get("values") or [])


def _style_for_context(section: dict[str, Any]) -> str:
    key = _section_key(section)
    if key in CONTEXT_BAND_STYLE:
        return CONTEXT_BAND_STYLE[key]
    label = str(section.get("label") or "").lower()
    if "system" in label:
        return "system"
    if "developer" in label:
        return "developer"
    if "user" in label:
        return "user"
    if "assistant" in label:
        return "assistant"
    if "tool" in label and "output" in label:
        return "tool_output"
    if "tool" in label:
        return "tool_call"
    return "generic"


def _style_for_action(section: dict[str, Any]) -> str:
    key = _section_key(section)
    if key in ACTION_BAND_STYLE:
        return ACTION_BAND_STYLE[key]
    label = str(section.get("label") or "").lower()
    if "assistant" in label:
        return "assistant"
    if "tool" in label:
        return "tool_call"
    return "generic"


def _decorate_sections(sections: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        values = section.get("values") if isinstance(section.get("values"), list) else []
        if not values:
            continue
        item = {
            "id": _section_key(section) or str(section.get("label") or "section"),
            "label": str(section.get("label") or section.get("id") or "Section"),
            "values": values,
            "count": _section_values_count(section),
            "style": _style_for_context(section) if mode == "context" else _style_for_action(section),
        }
        out.append(item)
    return out


def build_replay_overview(trace_id: str, turns: list[dict[str, Any]]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for turn in turns:
        turn_id = str(turn.get("turn_id") or "")
        if not turn_id:
            continue
        context_sections = list(turn.get("replay_context_sections") or [])
        action_sections = list(turn.get("replay_action_sections") or [])
        items.append(
            {
                "turn_id": turn_id,
                "label": str(turn.get("label") or turn_id),
                "index": int(turn.get("index") or 0),
                "tool_call_count": int(turn.get("tool_call_count") or 0),
                "context_section_count": len(context_sections),
                "action_section_count": len(action_sections),
                "start_ts": turn.get("start_ts"),
                "end_ts": turn.get("end_ts"),
            }
        )

    return {
        "trace_id": trace_id,
        "turns": items,
    }


def build_replay_turn_detail(trace_id: str, turn: dict[str, Any]) -> dict[str, Any]:
    context_sections = _decorate_sections(list(turn.get("replay_context_sections") or []), mode="context")
    action_sections = _decorate_sections(list(turn.get("replay_action_sections") or []), mode="action")

    if not context_sections:
        # Fall back to existing prompt sections to avoid empty panes on older traces.
        context_sections = _decorate_sections(list(turn.get("prompt_sections") or []), mode="context")
    if not action_sections:
        action_sections = _decorate_sections(list(turn.get("response_sections") or []), mode="action")

    return {
        "trace_id": trace_id,
        "turn_id": str(turn.get("turn_id") or ""),
        "label": str(turn.get("label") or ""),
        "start_ts": turn.get("start_ts"),
        "end_ts": turn.get("end_ts"),
        "context": {
            "sections": context_sections,
            "text": sections_to_text(context_sections),
        },
        "action": {
            "sections": action_sections,
            "text": sections_to_text(action_sections),
        },
    }


def attach_replay_sections(turns: list[dict[str, Any]], llm_calls: list[dict[str, Any]]) -> None:
    """Mutate turn objects with replay context/action sections merged per turn span."""
    for turn in turns:
        turn["replay_context_sections"] = []
        turn["replay_action_sections"] = []

    for turn in turns:
        start_ts = turn.get("start_ts")
        end_ts = turn.get("end_ts")

        def _in_span(ts: float) -> bool:
            if start_ts is not None and ts < float(start_ts):
                return False
            if end_ts is not None and ts >= float(end_ts):
                return False
            return True

        context_sections: list[dict[str, Any]] = []
        action_sections: list[dict[str, Any]] = []
        for call in llm_calls:
            cts = float(call.get("ts") or 0.0)
            if not _in_span(cts):
                continue
            context_sections = merge_sections(context_sections, call.get("replay_context_sections") or [])
            action_sections = merge_sections(action_sections, call.get("replay_action_sections") or [])

        turn["replay_context_sections"] = context_sections
        turn["replay_action_sections"] = action_sections
