"""E2E scenarios for trace replay visibility (prompts, responses, and tool calls)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e._cli_agent_harness import (
    DEFAULT_ALLOW_POLICY,
    MockLLMPlan,
    find_turn_with_tool_calls,
    has_mantle_watch,
    run_cli_agent_watch,
)


pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def replay_trace_run(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Create a trace with clear file read/write behavior for replay assertions."""
    tmp_path = tmp_path_factory.mktemp("replay-trace")
    input_path = tmp_path / "sample_input.txt"
    output_path = tmp_path / "sample_output.txt"

    command = (
        f"printf '3,4,5\n' > {input_path} && "
        f"awk -F, '{{s=$1+$2+$3; print s}}' {input_path} > {output_path}"
    )
    prompt = f"Run exactly this shell command: {command} . Then reply with exactly: done"

    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id="replay_trace_case.ebpf.jsonl",
        prompt=prompt,
        policy_text=DEFAULT_ALLOW_POLICY,
        mock_plan=MockLLMPlan(tool_commands=[command], final_response="done"),
    )


def test_replay_turns_overview_exposes_turns_and_tool_counts(replay_trace_run):
    """Scenario: replay overview should expose non-setup turns with tool calls."""
    replay = replay_trace_run.store.replay_turns_overview(replay_trace_run.trace_id)
    assert replay["trace_id"] == replay_trace_run.trace_id
    assert replay_trace_run.mock_request_count == 2
    assert len(replay.get("turns") or []) == 3

    non_setup = [t for t in replay["turns"] if str(t.get("turn_id") or "") != "setup"]
    assert len(non_setup) == 2, replay
    assert int(non_setup[0].get("tool_call_count") or 0) == 1, replay
    assert int(non_setup[1].get("tool_call_count") or 0) == 0, replay


def test_replay_turn_detail_contains_context_and_action_sections(replay_trace_run):
    """Scenario: replay turn detail should include context and action sections with text."""
    turns = replay_trace_run.store.turns_overview(replay_trace_run.trace_id)
    turn = find_turn_with_tool_calls(turns)

    detail = replay_trace_run.store.replay_turn_detail(replay_trace_run.trace_id, str(turn["turn_id"]))
    context = detail.get("context") or {}
    action = detail.get("action") or {}

    assert len(context.get("sections") or []) >= 1, detail
    assert str(action.get("text") or "").strip() == '{"completion_tokens": 0, "prompt_tokens": 0, "total_tokens": 0}'
    assert str(context.get("text") or "").strip(), detail


def test_turn_detail_surfaces_prompt_response_and_timeline(replay_trace_run):
    """Scenario: turn detail should surface prompt/response text and timeline entries."""
    turns = replay_trace_run.store.turns_overview(replay_trace_run.trace_id)
    turn = find_turn_with_tool_calls(turns)
    detail = replay_trace_run.store.turn_detail(replay_trace_run.trace_id, str(turn["turn_id"]))

    assert str(detail.get("prompt_text") or "").strip(), detail
    assert len(detail.get("timeline") or []) >= 1, detail
    assert int((detail.get("summary") or {}).get("tool_calls") or 0) >= 1, detail

    # With mocked final completion, response text is deterministic.
    turns = [t for t in replay_trace_run.store.turns_overview(replay_trace_run.trace_id).get("turns") or [] if str(t.get("turn_id") or "") != "setup"]
    final_detail = replay_trace_run.store.turn_detail(replay_trace_run.trace_id, str(turns[-1]["turn_id"]))
    final_text = str(final_detail.get("response_text") or "").strip()
    assert final_text.startswith("done"), final_detail
    assert '{"completion_tokens": 0, "prompt_tokens": 0, "total_tokens": 0}' in final_text, final_detail


def test_high_level_graph_contains_agent_nodes(replay_trace_run):
    """Scenario: high-level graph should include prompt, tool, and assistant agent nodes."""
    graph = replay_trace_run.store.high_level_graph(replay_trace_run.trace_id)
    nodes = list(graph.get("nodes") or [])

    kinds = {str(node.get("kind") or "") for node in nodes}
    assert "prompt" in kinds or "prompt_batch" in kinds, kinds
    assert "tool_step" in kinds, kinds
    assert "assistant_response" in kinds, kinds

    assert int((graph.get("summary") or {}).get("tool_steps") or 0) >= 1
