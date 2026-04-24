"""Reward engine — loosely coupled evaluation of agent progress.

The engine defines a Protocol (``RewardAlgorithm``) so that the reward
computation can be swapped without touching the rest of the codebase.

Inputs:  guide BPF events + current BPF events + metadata dict.
Outputs: RewardResult (progress, score, satisfied/pending, hint).

V1 algorithm: ``CheckpointRewardAlgorithm`` — extracts structural BPF
predicates from the guide trace and evaluates them against the active trace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Protocol

from mantle.reward.checkpoints import Checkpoint, extract_checkpoints


# ── Data transfer objects ────────────────────────────────────────────


@dataclass
class RewardInput:
    """Everything a reward algorithm needs to compute a result."""

    guide_events: list[dict[str, Any]]
    current_events: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RewardResult:
    """The output of a reward evaluation."""

    progress: float         # 0.0 – 1.0
    score: float            # shaped reward value
    satisfied: list[str]    # checkpoint names satisfied
    pending: list[str]      # checkpoint names remaining
    next_hint: str          # human-readable guidance for the agent
    raw: dict[str, Any] = field(default_factory=dict)  # algorithm-specific details


# ── Protocol ─────────────────────────────────────────────────────────


class RewardAlgorithm(Protocol):
    """Interface that any reward algorithm must implement."""

    def evaluate(self, input: RewardInput) -> RewardResult:
        ...


# ── V1: Checkpoint-based reward ──────────────────────────────────────


class CheckpointRewardAlgorithm:
    """Extracts BPF checkpoints from the guide and evaluates progress.

    Stateless — checkpoints are re-extracted on each call (cheap for V1
    trace sizes).  A future optimisation can cache by guide_trace_id.
    """

    def evaluate(self, input: RewardInput) -> RewardResult:
        checkpoints = extract_checkpoints(input.guide_events)

        if not checkpoints:
            return RewardResult(
                progress=1.0,
                score=0.0,
                satisfied=[],
                pending=[],
                next_hint="No structural checkpoints found in guide trace.",
                raw={"checkpoint_count": 0},
            )

        # Evaluate each checkpoint against current events.
        for cp in checkpoints:
            cp.satisfied = cp.predicate(input.current_events)

        satisfied = [cp.name for cp in checkpoints if cp.satisfied]
        pending = [cp.name for cp in checkpoints if not cp.satisfied]
        progress = len(satisfied) / len(checkpoints) if checkpoints else 1.0

        # Shaped reward: progress fraction × 10, plus step penalty.
        score = progress * 10.0 - 0.01

        # Hint: describe the first pending checkpoint.
        if pending:
            first_pending = next(cp for cp in checkpoints if not cp.satisfied)
            next_hint = f"Next: {first_pending.description}"
        else:
            next_hint = "All checkpoints satisfied! Task appears complete."

        return RewardResult(
            progress=progress,
            score=score,
            satisfied=satisfied,
            pending=pending,
            next_hint=next_hint,
            raw={
                "checkpoint_count": len(checkpoints),
                "checkpoints": [
                    {"name": cp.name, "description": cp.description, "satisfied": cp.satisfied}
                    for cp in checkpoints
                ],
            },
        )


# ── Default algorithm instance ───────────────────────────────────────

_DEFAULT_ALGORITHM: RewardAlgorithm = CheckpointRewardAlgorithm()


_FILE_EVENT_TYPES = {"file_open", "file_write", "openat"}


def _events_for_tool_windows(sqlite_store: Any, trace_id: str) -> list[dict[str, Any]]:
    """Return trace events constrained to tool-call windows only."""
    windows = sqlite_store.tool_call_windows_for_trace(trace_id)
    if not windows:
        return []

    out: dict[int, dict[str, Any]] = {}
    for start_ns, end_ns in windows:
        for event in sqlite_store.events_for_window(trace_id, start_ts_ns=start_ns, end_ts_ns=end_ns):
            event_id = int(event.get("id") or 0)
            if event_id <= 0:
                continue
            out[event_id] = event

    ordered = list(out.values())
    ordered.sort(key=lambda e: (int(e.get("timestamp_ns") or 0), int(e.get("id") or 0)))
    return ordered


def _is_file_event(event: dict[str, Any]) -> bool:
    return str(event.get("event_type") or "") in _FILE_EVENT_TYPES


def _path_in_home(path: str, home_dir: str) -> bool:
    # Relative paths are treated as in-scope; absolute paths must be under home.
    p = path.strip()
    if not p.startswith("/"):
        return True
    normalized = p.rstrip("/")
    home_norm = home_dir.rstrip("/")
    return normalized == home_norm or normalized.startswith(home_norm + "/")


def _infer_home_dir(events: list[dict[str, Any]]) -> str | None:
    """Infer the most likely home directory from observed file paths."""
    counts: dict[str, int] = {}
    for event in events:
        for key in ("path", "src", "exec_path", "command"):
            raw = str(event.get(key) or "").strip()
            if not raw.startswith("/home/"):
                continue
            parts = Path(raw).parts
            if len(parts) < 3:
                continue
            candidate = str(Path(parts[0]) / parts[1] / parts[2])
            counts[candidate] = counts.get(candidate, 0) + 1

    if counts:
        return max(counts.items(), key=lambda item: item[1])[0]

    host_home = os.getenv("MANTLE_HOST_HOME", "").strip()
    if host_home.startswith("/home/"):
        return host_home

    env_home = os.getenv("HOME", "").strip()
    if env_home.startswith("/home/"):
        return env_home
    # Last-resort constraint for Linux host-style home layouts.
    return "/home"


def _filter_file_events_to_home(
    events: list[dict[str, Any]],
    *,
    home_dir: str | None,
) -> list[dict[str, Any]]:
    if not home_dir:
        return events

    filtered: list[dict[str, Any]] = []
    for event in events:
        if not _is_file_event(event):
            filtered.append(event)
            continue

        # Keep file events only if at least one file path is under home.
        in_home = False
        for key in ("path", "src"):
            raw = str(event.get(key) or "").strip()
            if raw and _path_in_home(raw, home_dir):
                in_home = True
                break
        if in_home:
            filtered.append(event)
    return filtered


def compute_reward_status(
    *,
    guide_trace_id: str,
    active_trace_id: str,
    process_name: str,
    sqlite_store: Any,
) -> dict[str, Any]:
    """Convenience function called by the server endpoint.

    Reads BPF events from SQLite for both traces and runs the default
    reward algorithm.
    """
    # Fetch only events that fall within tool-call windows for each trace.
    guide_events = _events_for_tool_windows(sqlite_store, guide_trace_id)
    current_events = _events_for_tool_windows(sqlite_store, active_trace_id)

    # Filter to sys events only (BPF events, not proxy/agent events).
    guide_sys = [e for e in guide_events if e.get("event_kind") == "sys"]
    current_sys = [e for e in current_events if e.get("event_kind") == "sys"]

    # Drop file events outside the inferred home directory to reduce noise.
    guide_home = _infer_home_dir(guide_sys)
    current_home = _infer_home_dir(current_sys)
    guide_sys = _filter_file_events_to_home(guide_sys, home_dir=guide_home)
    current_sys = _filter_file_events_to_home(current_sys, home_dir=current_home)

    ri = RewardInput(
        guide_events=guide_sys,
        current_events=current_sys,
        metadata={
            "process_name": process_name,
            "guide_trace_id": guide_trace_id,
            "active_trace_id": active_trace_id,
            "guide_home_dir": guide_home,
            "active_home_dir": current_home,
        },
    )

    result = _DEFAULT_ALGORITHM.evaluate(ri)

    return {
        "process_name": process_name,
        "guide_trace_id": guide_trace_id,
        "active_trace_id": active_trace_id,
        "progress": result.progress,
        "score": result.score,
        "satisfied": result.satisfied,
        "pending": result.pending,
        "next_hint": result.next_hint,
        "checkpoints": result.raw.get("checkpoints", []),
        "guide_home_dir": guide_home,
        "active_home_dir": current_home,
        "guide_event_count": len(guide_sys),
        "active_event_count": len(current_sys),
    }
