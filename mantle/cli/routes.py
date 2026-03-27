"""URL-like non-interactive route handlers for mantle CLI."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .disclosure import folder_node_entries, format_metric_summary, index_tree_nodes
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
            "  <trace_id>/summary",
            "  <trace_id>/summary/metric/<metric_name>",
            "",
            "Replay:",
            "  <trace_id>/replay",
            "  <trace_id>/replay/<turn_id>/summary",
            "  <trace_id>/replay/<turn_id>/summary/metric/<metric_name>",
            "  <trace_id>/replay/<turn_id>/context",
            "  <trace_id>/replay/<turn_id>/context/<section_id>",
            "  <trace_id>/replay/<turn_id>/context/<section_id>/<message_index>",
            "  <trace_id>/replay/<turn_id>/action",
            "  <trace_id>/replay/<turn_id>/action/<section_id>",
            "  <trace_id>/replay/<turn_id>/action/<section_id>/<message_index>",
            "  <trace_id>/replay/<turn_id>/tool-calls",
            "  <trace_id>/replay/<turn_id>/files",
            "  <trace_id>/replay/<turn_id>/files/node/<node_id>",
            "  <trace_id>/replay/<turn_id>/subprocesses",
            "  <trace_id>/replay/<turn_id>/pids",
            "  <trace_id>/replay/<turn_id>/pids/<pid>",
            "",
            "Kernel Objects (generic, reusable):",
            "  objects/pids",
            "  objects/pids/trace/<trace_id>",
            "  objects/pids/trace/<trace_id>/turn/<turn_id>",
            "  objects/pids/<pid>",
            "  objects/pids/<pid>/trace/<trace_id>/turn/<turn_id>",
            "  objects/files",
            "  objects/files/node/<node_id>",
            "  objects/files/trace/<trace_id>",
            "  objects/files/trace/<trace_id>/node/<node_id>",
            "  objects/files/trace/<trace_id>/turn/<turn_id>",
            "  objects/files/trace/<trace_id>/turn/<turn_id>/node/<node_id>",
            "  objects/files/path/<urlencoded_file_path>",
            "  objects/files/trace/<trace_id>/path/<urlencoded_file_path>",
            "  objects/files/trace/<trace_id>/turn/<turn_id>/path/<urlencoded_file_path>",
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


def _format_metric_detail(metric: str, value: Any, drilldown: str | None = None) -> str:
    lines = [f"Metric: {metric}", f"Value: {value}"]
    if drilldown:
        lines.append(f"Drilldown: {drilldown}")
    return "\n".join(lines)


def _trace_metrics_from_overview(trace_id: str, overview: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    metrics = dict(overview.get("executive_summary") or {})
    hints = {
        "turns": f"{trace_id}/replay",
        "tool_calls": f"{trace_id}/replay",
        "files_read": f"objects/files/trace/{trace_id}",
        "files_written": f"objects/files/trace/{trace_id}",
        "network_calls": f"{trace_id}/replay",
        "subprocesses_spawned": f"objects/pids/trace/{trace_id}",
    }
    return metrics, hints


def _replay_turn_metrics(trace_id: str, turn_id: str, summary: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    metrics = {
        "tool_calls": int(summary.get("tool_calls") or 0),
        "context_tokens": int(summary.get("context_tokens") or 0),
        "files_read": int(summary.get("files_read") or 0),
        "files_written": int(summary.get("files_written") or 0),
        "subprocesses_spawned": int(summary.get("subprocesses_spawned") or 0),
        "network_calls": int(summary.get("network_calls") or 0),
        "context_sections": int(summary.get("context_sections") or 0),
        "action_sections": int(summary.get("action_sections") or 0),
    }
    hints = {
        "tool_calls": f"{trace_id}/replay/{turn_id}/tool-calls",
        "context_tokens": f"{trace_id}/replay/{turn_id}/context",
        "files_read": f"{trace_id}/replay/{turn_id}/files",
        "files_written": f"{trace_id}/replay/{turn_id}/files",
        "subprocesses_spawned": f"{trace_id}/replay/{turn_id}/pids",
        "network_calls": f"{trace_id}/replay/{turn_id}/subprocesses",
        "context_sections": f"{trace_id}/replay/{turn_id}/context",
        "action_sections": f"{trace_id}/replay/{turn_id}/action",
    }
    return metrics, hints


def _render_folder_node(tree: dict[str, Any] | None, node_id: str) -> RouteResult:
    index = index_tree_nodes(tree)
    if not index:
        return RouteResult(title="files", text="No file activity tree available.", pager=False)

    node, entries, parent_id = folder_node_entries(index, node_id)
    node_name = str(node.get("name") or "/")
    node_kind = str(node.get("kind") or "dir")
    node_state = str(node.get("state") or "")

    lines = [f"Folder Node: {node_id}", f"Name: {node_name}", f"Kind: {node_kind}"]
    if node_state:
        lines.append(f"State: {node_state}")
    if parent_id:
        lines.append(f"Parent: {parent_id}")
    lines.append("")

    if entries:
        lines.append("Children (direct only):")
        for item in entries:
            tag = "D" if item.get("kind") == "dir" else "F"
            state = str(item.get("state") or "")
            state_txt = f" | state={state}" if state else ""
            lines.append(f"- [{tag}] {item.get('node_id')}: {item.get('name')}{state_txt}")
    else:
        lines.append("No children.")

    meta = {
        "node_id": node_id,
        "parent_node_id": parent_id,
        "entries": entries,
        "is_dir": node_kind == "dir",
    }
    return RouteResult(title=f"files/node/{node_id}", text="\n".join(lines), pager=False, meta=meta)


def _flatten_file_tree(tree: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(tree, dict):
        return []

    out: list[dict[str, Any]] = []

    def _walk(node: dict[str, Any], parent: str) -> None:
        kind = str(node.get("kind") or "")
        name = str(node.get("name") or "")
        next_parent = parent
        if name and name != "/":
            next_parent = f"{parent}/{name}" if parent else f"/{name}"

        if kind == "file":
            path = str(node.get("path") or next_parent)
            out.append(
                {
                    "path": path,
                    "state": str(node.get("state") or ""),
                    "read_count": int(node.get("read_count") or 0),
                    "write_count": int(node.get("write_count") or 0),
                    "rename_count": int(node.get("rename_count") or 0),
                    "event_count": int(node.get("event_count") or 0),
                }
            )
            return

        children = node.get("children") or []
        if not isinstance(children, list):
            return
        for child in children:
            if isinstance(child, dict):
                _walk(child, next_parent)

    _walk(tree, "")
    return out


def _merge_file_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = str(row.get("path") or "")
        if not path:
            continue
        bucket = by_path.setdefault(
            path,
            {
                "path": path,
                "read_count": 0,
                "write_count": 0,
                "rename_count": 0,
                "event_count": 0,
                "state": "read",
            },
        )
        bucket["read_count"] += int(row.get("read_count") or 0)
        bucket["write_count"] += int(row.get("write_count") or 0)
        bucket["rename_count"] += int(row.get("rename_count") or 0)
        bucket["event_count"] += int(row.get("event_count") or 0)

    for bucket in by_path.values():
        has_read = int(bucket.get("read_count") or 0) > 0
        has_write = int(bucket.get("write_count") or 0) > 0 or int(bucket.get("rename_count") or 0) > 0
        if has_read and has_write:
            bucket["state"] = "read_write"
        elif has_write:
            bucket["state"] = "write"
        else:
            bucket["state"] = "read"

    return sorted(by_path.values(), key=lambda item: str(item.get("path") or ""))


def _file_tree_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
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

    for item in sorted(rows, key=lambda x: str(x.get("path") or "")):
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
        leaf["read_count"] = int(item.get("read_count") or 0)
        leaf["write_count"] = int(item.get("write_count") or 0)
        leaf["rename_count"] = int(item.get("rename_count") or 0)
        leaf["event_count"] = int(item.get("event_count") or 0)

    return root


def _iter_replay_turn_details(cli_store: CliStore, trace_filter: str | None = None, turn_filter: str | None = None) -> list[tuple[str, str, dict[str, Any]]]:
    traces = cli_store.store.list_traces()
    out: list[tuple[str, str, dict[str, Any]]] = []

    for row in traces:
        trace_id = str(row.get("trace_id") or "")
        if not trace_id:
            continue
        if trace_filter and trace_id != trace_filter:
            continue

        replay = cli_store.store.replay_turns_overview(trace_id)
        turns = replay.get("turns") or []
        for turn in turns:
            turn_id = str(turn.get("turn_id") or "")
            if not turn_id:
                continue
            if turn_filter and turn_id != turn_filter:
                continue
            detail = cli_store.store.replay_turn_detail(trace_id, turn_id)
            out.append((trace_id, turn_id, detail))

    return out


def _collect_pid_index(cli_store: CliStore, trace_filter: str | None = None, turn_filter: str | None = None) -> dict[int, dict[str, Any]]:
    index: dict[int, dict[str, Any]] = {}
    for trace_id, turn_id, detail in _iter_replay_turn_details(cli_store, trace_filter=trace_filter, turn_filter=turn_filter):
        summary = detail.get("summary") or {}
        subprocesses = summary.get("subprocesses") or []
        for proc in subprocesses:
            pid = int(proc.get("pid") or 0)
            if pid <= 0:
                continue

            bucket = index.setdefault(
                pid,
                {
                    "pid": pid,
                    "parent_pids": set(),
                    "commands": set(),
                    "refs": [],
                },
            )

            parent_pid = int(proc.get("parent_pid") or 0)
            if parent_pid > 0:
                bucket["parent_pids"].add(parent_pid)

            for cmd in proc.get("commands") or []:
                cmd_txt = str(cmd or "").strip()
                if cmd_txt:
                    bucket["commands"].add(cmd_txt)

            bucket["refs"].append(
                {
                    "trace_id": trace_id,
                    "turn_id": turn_id,
                    "route": f"{trace_id}/replay/{turn_id}/pids/{pid}",
                }
            )

    return index


def _collect_file_index(cli_store: CliStore, trace_filter: str | None = None, turn_filter: str | None = None) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    rows: list[dict[str, Any]] = []
    refs: dict[str, list[dict[str, Any]]] = {}

    for trace_id, turn_id, detail in _iter_replay_turn_details(cli_store, trace_filter=trace_filter, turn_filter=turn_filter):
        summary = detail.get("summary") or {}
        file_activity = summary.get("file_activity") or {}
        tree = file_activity.get("tree") if isinstance(file_activity, dict) else None
        for item in _flatten_file_tree(tree):
            rows.append(item)
            path = str(item.get("path") or "")
            if not path:
                continue
            refs.setdefault(path, []).append(
                {
                    "trace_id": trace_id,
                    "turn_id": turn_id,
                    "route": f"{trace_id}/replay/{turn_id}/resource/file/{path}",
                }
            )

    return _merge_file_rows(rows), refs


def _render_pid_list(pid_index: dict[int, dict[str, Any]], title: str) -> RouteResult:
    if not pid_index:
        return RouteResult(title=title, text="No subprocess PIDs found.", pager=False, meta={"pid_ids": []})

    lines = ["PIDs:"]
    pid_ids = sorted(pid_index.keys())
    for pid in pid_ids:
        row = pid_index[pid]
        refs = row.get("refs") or []
        commands = sorted(list(row.get("commands") or []))
        sample = _preview(commands[0], max_len=72) if commands else "unknown"
        lines.append(f"- {pid} | refs={len(refs)} | cmd={sample}")

    return RouteResult(title=title, text="\n".join(lines), pager=False, meta={"pid_ids": pid_ids})


def _render_pid_refs(pid: int, row: dict[str, Any], title: str) -> RouteResult:
    refs = row.get("refs") or []
    parents = sorted([int(v) for v in row.get("parent_pids") or [] if int(v) > 0])
    commands = sorted(list(row.get("commands") or []))

    lines = [f"PID: {pid}"]
    lines.append(f"Parent pids: {parents if parents else 'unknown'}")
    lines.append(f"Command samples: {len(commands)}")
    for cmd in commands[:8]:
        lines.append(f"- {_preview(cmd, max_len=120)}")

    lines.append("")
    lines.append("References:")
    for ref in refs:
        lines.append(f"- {ref.get('trace_id')}/{ref.get('turn_id')} -> {ref.get('route')}")

    lines.append("")
    lines.append("Open one reference with:")
    lines.append(f"  objects/pids/{pid}/trace/<trace_id>/turn/<turn_id>")

    return RouteResult(title=title, text="\n".join(lines), pager=False, meta={"refs": refs})


def _render_files_scope(title: str, rows: list[dict[str, Any]]) -> RouteResult:
    if not rows:
        return RouteResult(title=title, text="No file events in this scope.", pager=False)

    tree = _file_tree_from_rows(rows)
    payload = _render_folder_node(tree, "root")
    payload.title = title
    payload.meta["file_paths"] = [str(item.get("path") or "") for item in rows]
    return payload


def _render_file_path_detail(title: str, path_value: str, refs: list[dict[str, Any]]) -> RouteResult:
    if not refs:
        return RouteResult(title=title, text=f"No references found for file path: {path_value}", pager=False)

    lines = [f"File: {path_value}", "", "References:"]
    for ref in refs:
        lines.append(f"- {ref.get('trace_id')}/{ref.get('turn_id')} -> {ref.get('route')}")

    lines.append("")
    lines.append("Open exact event list by scoped route:")
    lines.append("  <trace_id>/replay/<turn_id>/resource/file/<path>")

    return RouteResult(title=title, text="\n".join(lines), pager=False, meta={"refs": refs})


def _handle_kernel_objects(cli_store: CliStore, parts: list[str]) -> RouteResult:
    if len(parts) < 2:
        raise KeyError("objects requires a category (pids|files)")

    category = parts[1]

    if category == "pids":
        # objects/pids
        if len(parts) == 2:
            return _render_pid_list(_collect_pid_index(cli_store), title="objects/pids")

        # objects/pids/trace/<trace_id>
        if len(parts) == 4 and parts[2] == "trace":
            trace_id = parts[3]
            _resolve_trace_or_error(cli_store, trace_id)
            return _render_pid_list(_collect_pid_index(cli_store, trace_filter=trace_id), title=f"objects/pids/trace/{trace_id}")

        # objects/pids/trace/<trace_id>/turn/<turn_id>
        if len(parts) == 6 and parts[2] == "trace" and parts[4] == "turn":
            trace_id = parts[3]
            turn_id = parts[5]
            _resolve_trace_or_error(cli_store, trace_id)
            return _render_pid_list(
                _collect_pid_index(cli_store, trace_filter=trace_id, turn_filter=turn_id),
                title=f"objects/pids/trace/{trace_id}/turn/{turn_id}",
            )

        # objects/pids/<pid>
        if len(parts) == 3 and parts[2].isdigit():
            pid = int(parts[2])
            pid_index = _collect_pid_index(cli_store)
            if pid not in pid_index:
                raise KeyError(f"pid not found: {pid}")
            return _render_pid_refs(pid, pid_index[pid], title=f"objects/pids/{pid}")

        # objects/pids/<pid>/trace/<trace_id>/turn/<turn_id>
        if len(parts) == 7 and parts[2].isdigit() and parts[3] == "trace" and parts[5] == "turn":
            pid = int(parts[2])
            trace_id = parts[4]
            turn_id = parts[6]
            _resolve_trace_or_error(cli_store, trace_id)
            payload = cli_store.store.process_subtrace(trace_id, turn_id, pid, full_lifecycle=True)
            return RouteResult(
                title=f"objects/pids/{pid}/trace/{trace_id}/turn/{turn_id}",
                text=_json(payload),
                pager=True,
            )

        raise KeyError("unsupported objects/pids route")

    if category == "files":
        # objects/files
        if len(parts) == 2:
            rows, _ = _collect_file_index(cli_store)
            return _render_files_scope("objects/files", rows)

        # objects/files/node/<node_id>
        if len(parts) >= 4 and parts[2] == "node":
            node_id = str(parts[3] or "root")
            rows, _ = _collect_file_index(cli_store)
            payload = _render_folder_node(_file_tree_from_rows(rows), node_id)
            payload.title = f"objects/files/node/{node_id}"
            return payload

        # objects/files/trace/<trace_id>
        if len(parts) == 4 and parts[2] == "trace":
            trace_id = parts[3]
            _resolve_trace_or_error(cli_store, trace_id)
            rows, _ = _collect_file_index(cli_store, trace_filter=trace_id)
            return _render_files_scope(f"objects/files/trace/{trace_id}", rows)

        # objects/files/trace/<trace_id>/node/<node_id>
        if len(parts) >= 6 and parts[2] == "trace" and parts[4] == "node":
            trace_id = parts[3]
            node_id = str(parts[5] or "root")
            _resolve_trace_or_error(cli_store, trace_id)
            rows, _ = _collect_file_index(cli_store, trace_filter=trace_id)
            payload = _render_folder_node(_file_tree_from_rows(rows), node_id)
            payload.title = f"objects/files/trace/{trace_id}/node/{node_id}"
            return payload

        # objects/files/trace/<trace_id>/turn/<turn_id>
        if len(parts) == 6 and parts[2] == "trace" and parts[4] == "turn":
            trace_id = parts[3]
            turn_id = parts[5]
            _resolve_trace_or_error(cli_store, trace_id)
            rows, _ = _collect_file_index(cli_store, trace_filter=trace_id, turn_filter=turn_id)
            return _render_files_scope(f"objects/files/trace/{trace_id}/turn/{turn_id}", rows)

        # objects/files/trace/<trace_id>/turn/<turn_id>/node/<node_id>
        if len(parts) >= 8 and parts[2] == "trace" and parts[4] == "turn" and parts[6] == "node":
            trace_id = parts[3]
            turn_id = parts[5]
            node_id = str(parts[7] or "root")
            _resolve_trace_or_error(cli_store, trace_id)
            rows, _ = _collect_file_index(cli_store, trace_filter=trace_id, turn_filter=turn_id)
            payload = _render_folder_node(_file_tree_from_rows(rows), node_id)
            payload.title = f"objects/files/trace/{trace_id}/turn/{turn_id}/node/{node_id}"
            return payload

        # objects/files/path/<path>
        if len(parts) >= 4 and parts[2] == "path":
            path_value = "/".join(parts[3:])
            rows, refs = _collect_file_index(cli_store)
            _ = rows
            return _render_file_path_detail(f"objects/files/path/{path_value}", path_value, refs.get(path_value, []))

        # objects/files/trace/<trace_id>/path/<path>
        if len(parts) >= 6 and parts[2] == "trace" and parts[4] == "path":
            trace_id = parts[3]
            path_value = "/".join(parts[5:])
            _resolve_trace_or_error(cli_store, trace_id)
            rows, refs = _collect_file_index(cli_store, trace_filter=trace_id)
            _ = rows
            return _render_file_path_detail(
                f"objects/files/trace/{trace_id}/path/{path_value}",
                path_value,
                refs.get(path_value, []),
            )

        # objects/files/trace/<trace_id>/turn/<turn_id>/path/<path>
        if len(parts) >= 8 and parts[2] == "trace" and parts[4] == "turn" and parts[6] == "path":
            trace_id = parts[3]
            turn_id = parts[5]
            path_value = "/".join(parts[7:])
            _resolve_trace_or_error(cli_store, trace_id)
            rows, refs = _collect_file_index(cli_store, trace_filter=trace_id, turn_filter=turn_id)
            _ = rows
            return _render_file_path_detail(
                f"objects/files/trace/{trace_id}/turn/{turn_id}/path/{path_value}",
                path_value,
                refs.get(path_value, []),
            )

        raise KeyError("unsupported objects/files route")

    raise KeyError(f"unknown objects category: {category}")


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

    if parts[0] == "objects":
        return _handle_kernel_objects(cli_store, parts)

    trace_id = parts[0]
    _resolve_trace_or_error(cli_store, trace_id)

    if len(parts) == 1 or parts[1] == "summary":
        overview = cli_store.store.turns_overview(trace_id)
        metrics, hints = _trace_metrics_from_overview(trace_id, overview)

        if len(parts) == 1:
            return RouteResult(
                title=f"{trace_id}/summary",
                text=format_metric_summary("Trace Summary Metrics", metrics, hints=hints),
                pager=False,
                meta={"metrics": list(metrics.keys())},
            )

        if len(parts) == 2:
            return RouteResult(
                title=f"{trace_id}/summary",
                text=format_metric_summary("Trace Summary Metrics", metrics, hints=hints),
                pager=False,
                meta={"metrics": list(metrics.keys())},
            )

        if len(parts) >= 4 and parts[2] == "metric":
            metric = str(parts[3] or "")
            if metric not in metrics:
                raise KeyError(f"unknown metric: {metric}")
            return RouteResult(
                title=f"{trace_id}/summary/metric/{metric}",
                text=_format_metric_detail(metric, metrics[metric], hints.get(metric)),
                pager=False,
            )

        raise KeyError(f"unsupported summary route: {'/'.join(parts)}")

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
            metrics, hints = _replay_turn_metrics(trace_id, turn_id, summary)
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/summary",
                text=format_metric_summary("Replay Turn Summary Metrics", metrics, hints=hints),
                pager=False,
                meta={
                    "metrics": list(metrics.keys()),
                    "sections": ["context", "action", "tool-calls", "files", "subprocesses", "pids"],
                },
            )

        if len(parts) >= 6 and parts[3] == "summary" and parts[4] == "metric":
            metrics, hints = _replay_turn_metrics(trace_id, turn_id, summary)
            metric = str(parts[5] or "")
            if metric not in metrics:
                raise KeyError(f"unknown metric: {metric}")
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/summary/metric/{metric}",
                text=_format_metric_detail(metric, metrics[metric], hints.get(metric)),
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
            file_activity = summary.get("file_activity") or {}
            tree = file_activity.get("tree") if isinstance(file_activity, dict) else None
            if len(parts) == 4:
                payload = _render_folder_node(tree, "root")
                payload.title = f"{trace_id}/replay/{turn_id}/files"
                return payload
            if len(parts) >= 6 and parts[4] == "node":
                node_id = str(parts[5] or "root")
                payload = _render_folder_node(tree, node_id)
                payload.title = f"{trace_id}/replay/{turn_id}/files/node/{node_id}"
                return payload
            raise KeyError("files route supports /files and /files/node/<node_id>")

        if len(parts) >= 4 and parts[3] == "subprocesses":
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/subprocesses",
                text=_json(summary.get("subprocesses") or []),
                pager=True,
            )

        if len(parts) >= 4 and parts[3] == "pids":
            subprocesses = summary.get("subprocesses") or []
            if len(parts) == 4:
                pid_rows = []
                for item in subprocesses:
                    pid = int(item.get("pid") or 0)
                    if pid > 0:
                        pid_rows.append({"pid": pid, "commands": item.get("commands") or []})
                lines = ["Turn PIDs:"]
                for row in sorted(pid_rows, key=lambda x: int(x.get("pid") or 0)):
                    commands = row.get("commands") or []
                    cmd = _preview(commands[0], max_len=72) if commands else "unknown"
                    lines.append(f"- {row.get('pid')} | cmd={cmd}")
                if len(lines) == 1:
                    lines.append("No subprocess PIDs found.")
                return RouteResult(
                    title=f"{trace_id}/replay/{turn_id}/pids",
                    text="\n".join(lines),
                    pager=False,
                    meta={"pid_ids": [int(row.get("pid") or 0) for row in pid_rows if int(row.get("pid") or 0) > 0]},
                )

            pid = int(parts[4])
            payload = cli_store.store.process_subtrace(trace_id, turn_id, pid, full_lifecycle=False)
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/pids/{pid}",
                text=_json(payload),
                pager=True,
            )

        if len(parts) >= 6 and parts[3] == "resource":
            resource_type = parts[4]
            resource_key = "/".join(parts[5:])
            payload = cli_store.store.raw_resource_events(trace_id, turn_id, resource_type, resource_key)
            return RouteResult(
                title=f"{trace_id}/replay/{turn_id}/resource/{resource_type}/{resource_key}",
                text=_json(payload),
                pager=True,
            )

        raise KeyError(f"unsupported replay route: {'/'.join(parts)}")

    raise KeyError(f"unsupported route: {'/'.join(parts)}")
