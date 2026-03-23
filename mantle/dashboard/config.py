"""Configuration helpers for the dashboard runtime.

This module centralizes environment/path resolution for observability files.
"""

from __future__ import annotations

from pathlib import Path
import os


def resolve_observability_paths() -> tuple[Path, Path]:
    """Resolve trace and events directories from env vars and known locations."""
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
