"""Store bootstrap and refresh helpers for mantle CLI."""

from __future__ import annotations

import asyncio
from pathlib import Path

from mantle.dashboard.config import resolve_observability_paths
from mantle.dashboard.store import TraceStore


class CliStore:
    """Thin wrapper around dashboard TraceStore for CLI access."""

    def __init__(self, obs_root: str | None = None):
        if obs_root:
            root = Path(obs_root).expanduser()
            trace_dir = root / "traces"
            events_dir = root / "events"
        else:
            trace_dir, events_dir = resolve_observability_paths()
        mitm_dir = trace_dir.parent / "mitm"
        self.trace_dir = trace_dir
        self.events_dir = events_dir
        self.mitm_dir = mitm_dir
        self.store = TraceStore(trace_dir=trace_dir, events_dir=events_dir, mitm_dir=mitm_dir)

    def refresh(self) -> None:
        """Poll trace/event files once so each command sees current state."""
        try:
            asyncio.run(self.store.poll_once())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self.store.poll_once())
            finally:
                loop.close()
