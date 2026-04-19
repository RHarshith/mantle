"""Configuration helpers for the Mantle runtime.

This module centralizes environment/path resolution for observability files.
"""

from __future__ import annotations

from pathlib import Path
from mantle.runtime.paths import resolve_runtime_layout


def resolve_observability_paths() -> tuple[Path, Path]:
    """Resolve trace/events directories from the fixed runtime layout."""
    layout = resolve_runtime_layout()
    return layout.traces_dir, layout.events_dir
