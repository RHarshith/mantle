"""Protocol defining the TraceStore contract.

Any class that satisfies this protocol can be used as the backing store for
the dashboard API and CLI. Write tests against this interface, not against
the concrete TraceStore implementation.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ITraceStore(Protocol):
    """Contract for trace ingestion, querying, and graph projection."""

    version: int

    # ── Lifecycle ────────────────────────────────────────────────

    async def poll_once(self) -> None:
        """Scan watched directories and ingest new trace data."""
        ...

    async def delete_trace(self, trace_id: str) -> dict[str, Any]:
        """Delete a trace and all associated files. Raises KeyError if not found."""
        ...

    # ── Listing ──────────────────────────────────────────────────

    def list_traces(self) -> list[dict[str, Any]]:
        """Return metadata for all known traces."""
        ...

    # ── Schema configuration ─────────────────────────────────────

    def list_llm_api_schemas(self) -> dict[str, Any]:
        """Return configured LLM schema parsing rules."""
        ...

    def set_llm_api_schemas(self, schemas: list[dict[str, Any]]) -> dict[str, Any]:
        """Update LLM schema parsing rules."""
        ...

    # ── Graph projections ────────────────────────────────────────

    def high_level_graph(self, trace_id: str) -> dict[str, Any]:
        """Build high-level trace graph. Raises KeyError if not found."""
        ...

    def process_graph(self, trace_id: str, pid: int) -> dict[str, Any]:
        """Build process-centric graph rooted at a pid."""
        ...

    def internal_graph(self, trace_id: str, line_start: int, line_end: int) -> dict[str, Any]:
        """Build internal graph for a selected syscall line range."""
        ...

    def tool_graph(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        """Build tool-call-centric graph for a specific tool invocation."""
        ...

    # ── Turn views ───────────────────────────────────────────────

    def turns_overview(self, trace_id: str) -> dict[str, Any]:
        """Return conversation/tool turns summary."""
        ...

    def turn_detail(self, trace_id: str, turn_id: str) -> dict[str, Any]:
        """Return detailed timeline/context for a single turn."""
        ...

    # ── Replay views ─────────────────────────────────────────────

    def replay_turns_overview(self, trace_id: str) -> dict[str, Any]:
        """Return replay-oriented turn list for debugger-style playback."""
        ...

    def replay_turn_detail(self, trace_id: str, turn_id: str) -> dict[str, Any]:
        """Return structured context/action panes for one replay turn."""
        ...

    def replay_state_diff(
        self, trace_id: str, from_turn_id: str | None = None, to_turn_id: str | None = None
    ) -> dict[str, Any]:
        """Return folder-tree state diff between two replay turns."""
        ...

    def replay_state_diff_file(
        self, trace_id: str, path: str, from_turn_id: str | None = None, to_turn_id: str | None = None
    ) -> dict[str, Any]:
        """Return unified diff for one file between two replay turns."""
        ...

    # ── Process & resource views ─────────────────────────────────

    def process_subtrace(
        self, trace_id: str, turn_id: str, pid: int, full_lifecycle: bool = False
    ) -> dict[str, Any]:
        """Return a focused sub-trace for one process within a turn."""
        ...

    def raw_resource_events(
        self, trace_id: str, turn_id: str, resource_type: str, resource_key: str
    ) -> dict[str, Any]:
        """Return raw syscall events for a specific file or network resource."""
        ...

    # ── Summary & metrics ────────────────────────────────────────

    def trace_summary(self, trace_id: str) -> dict[str, Any]:
        """Return summary metrics and grouped behavior for a trace."""
        ...

    def tool_summary(self, trace_id: str, tool_call_id: str) -> dict[str, Any]:
        """Return summarized insights for one tool call."""
        ...

    def trace_dimension_metrics(self, trace_id: str) -> dict[str, Any]:
        """Return correctness/safety/efficiency heuristic metrics."""
        ...

    def all_trace_dimension_metrics(self) -> dict[str, Any]:
        """Return dimension metrics for all traces."""
        ...
