"""Progressive-disclosure helpers for CLI summaries and folder navigation."""

from __future__ import annotations

from typing import Any


def format_metric_summary(title: str, metrics: dict[str, Any], hints: dict[str, str] | None = None) -> str:
    """Render concise metric-only output with optional drilldown hints."""
    lines = [title, ""]
    for key, value in metrics.items():
        hint = ""
        if hints and key in hints:
            hint = f" -> {hints[key]}"
        lines.append(f"- {key}: {value}{hint}")
    return "\n".join(lines)


def index_tree_nodes(tree: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Create stable node ids for a hierarchical file tree."""
    if not isinstance(tree, dict):
        return {}

    out: dict[str, dict[str, Any]] = {}

    def _walk(node: dict[str, Any], node_id: str, parent_id: str | None) -> None:
        out[node_id] = {"node": node, "parent": parent_id}
        children = node.get("children")
        if not isinstance(children, list):
            return
        for idx, child in enumerate(children):
            if not isinstance(child, dict):
                continue
            _walk(child, f"{node_id}.{idx}", node_id)

    _walk(tree, "root", None)
    return out


def folder_node_entries(index: dict[str, dict[str, Any]], node_id: str) -> tuple[dict[str, Any], list[dict[str, Any]], str | None]:
    """Return current node metadata and direct child entries only."""
    if node_id not in index:
        raise KeyError(f"unknown folder node id: {node_id}")

    wrapped = index[node_id]
    node = wrapped["node"]
    parent_id = wrapped.get("parent")
    children = node.get("children") if isinstance(node.get("children"), list) else []

    entries: list[dict[str, Any]] = []
    for idx, child in enumerate(children):
        if not isinstance(child, dict):
            continue
        child_id = f"{node_id}.{idx}"
        kind = str(child.get("kind") or "file")
        entries.append(
            {
                "node_id": child_id,
                "name": str(child.get("name") or ""),
                "kind": kind,
                "state": str(child.get("state") or ""),
                "event_count": int(child.get("event_count") or 0),
            }
        )

    return node, entries, parent_id
