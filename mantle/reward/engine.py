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
    # Fetch sys events for guide and active traces from SQLite.
    guide_events = sqlite_store.events_for_window(
        guide_trace_id, start_ts_ns=0, end_ts_ns=2**63 - 1,
    )
    current_events = sqlite_store.events_for_window(
        active_trace_id, start_ts_ns=0, end_ts_ns=2**63 - 1,
    )

    # Filter to sys events only (BPF events, not proxy/agent events).
    guide_sys = [e for e in guide_events if e.get("event_kind") == "sys"]
    current_sys = [e for e in current_events if e.get("event_kind") == "sys"]

    ri = RewardInput(
        guide_events=guide_sys,
        current_events=current_sys,
        metadata={
            "process_name": process_name,
            "guide_trace_id": guide_trace_id,
            "active_trace_id": active_trace_id,
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
    }
