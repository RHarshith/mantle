"""E2E scenarios for replay state diff behavior across agent turns."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e._cli_agent_harness import (
    DEFAULT_ALLOW_POLICY,
    MockLLMPlan,
    has_mantle_watch,
    run_cli_agent_watch,
)


pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def state_diff_trace_run(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace that should produce snapshot-backed file changes for replay diff APIs."""
    tmp_path = tmp_path_factory.mktemp("state-diff")
    file_a = tmp_path / "state_diff_a.txt"
    file_b = tmp_path / "state_diff_b.txt"

    prompt = (
        f"Create {file_a} containing two lines: first and second. "
        f"Then create {file_b} by copying {file_a} and appending a third line 'third'. "
        "Use shell commands and then respond with exactly: done"
    )

    run = run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id="state_diff_case.ebpf.jsonl",
        prompt=prompt,
        policy_text=DEFAULT_ALLOW_POLICY,
        mock_plan=MockLLMPlan(
            tool_commands=[
                f"printf 'first\\nsecond\\n' > {file_a} && cp {file_a} {file_b} && printf 'third\\n' >> {file_b}"
            ],
            final_response="done",
        ),
    )

    # Preserve paths for targeted file-diff assertions.
    run.file_a = file_a  # type: ignore[attr-defined]
    run.file_b = file_b  # type: ignore[attr-defined]
    return run


def test_replay_state_diff_reports_changed_files(state_diff_trace_run):
    """Scenario: replay state diff should report at least one changed file and non-zero totals."""
    diff = state_diff_trace_run.store.replay_state_diff(state_diff_trace_run.trace_id)

    assert diff["trace_id"] == state_diff_trace_run.trace_id
    assert state_diff_trace_run.mock_request_count == 2
    assert int((diff.get("summary") or {}).get("files_changed") or 0) >= 1, diff
    assert len(diff.get("files") or []) >= 1, diff


def test_replay_state_diff_tree_contains_counts(state_diff_trace_run):
    """Scenario: replay state diff tree should expose aggregated folder/file counts."""
    diff = state_diff_trace_run.store.replay_state_diff(state_diff_trace_run.trace_id)
    tree = diff.get("tree") or {}
    counts = tree.get("counts") or {}

    assert tree.get("kind") == "folder", tree
    assert int(counts.get("files") or 0) >= 1, tree
    assert int(counts.get("total") or 0) >= 1, tree


def test_replay_state_diff_file_returns_unified_diff(state_diff_trace_run):
    """Scenario: replay state diff file endpoint should return a readable unified diff."""
    file_b = str(getattr(state_diff_trace_run, "file_b"))
    file_diff = state_diff_trace_run.store.replay_state_diff_file(
        state_diff_trace_run.trace_id,
        path=file_b,
    )

    diff_text = str(file_diff.get("diff") or "")
    assert diff_text.strip(), file_diff
    assert f"a/{file_b}" in diff_text, diff_text
    assert f"b/{file_b}" in diff_text, diff_text


def test_replay_state_diff_selected_turn_bounds_are_resolved(state_diff_trace_run):
    """Scenario: explicit turn selection should resolve to valid from/to turn ids."""
    base = state_diff_trace_run.store.replay_state_diff(state_diff_trace_run.trace_id)
    turns = list(base.get("turns") or [])
    assert turns, base

    from_turn = str(turns[-1].get("turn_id") or "")
    to_turn = str(turns[0].get("turn_id") or "")

    # Intentionally reverse order to verify normalization logic.
    selected = state_diff_trace_run.store.replay_state_diff(
        state_diff_trace_run.trace_id,
        from_turn_id=from_turn,
        to_turn_id=to_turn,
    )

    chosen = selected.get("selected") or {}
    assert str(chosen.get("from_turn_id") or "") in {from_turn, to_turn}, chosen
    assert str(chosen.get("to_turn_id") or "") in {from_turn, to_turn}, chosen
