"""Unit tests for mantle.dashboard.replay_trace."""

import pytest

from mantle.analysis.replay import (
    attach_replay_sections,
    build_replay_overview,
    build_replay_turn_detail,
)


@pytest.mark.unit
class TestBuildReplayOverview:
    def test_basic_overview(self):
        turns = [
            {
                "turn_id": "turn_1",
                "label": "Turn 1",
                "index": 0,
                "tool_call_count": 2,
                "replay_context_sections": [{"id": "s1", "values": ["a"]}],
                "replay_action_sections": [{"id": "a1", "values": ["b"]}],
                "start_ts": 1000.0,
                "end_ts": 1001.0,
            }
        ]
        result = build_replay_overview("trace_001", turns)
        assert result["trace_id"] == "trace_001"
        assert len(result["turns"]) == 1
        assert result["turns"][0]["turn_id"] == "turn_1"
        assert result["turns"][0]["context_section_count"] == 1
        assert result["turns"][0]["action_section_count"] == 1

    def test_skips_empty_turn_ids(self):
        turns = [{"turn_id": "", "label": ""}]
        result = build_replay_overview("trace_001", turns)
        assert len(result["turns"]) == 0

    def test_empty_turns(self):
        result = build_replay_overview("trace_001", [])
        assert result["turns"] == []


@pytest.mark.unit
class TestBuildReplayTurnDetail:
    def test_with_replay_sections(self):
        turn = {
            "turn_id": "turn_1",
            "label": "Turn 1",
            "start_ts": 1000.0,
            "end_ts": 1001.0,
            "replay_context_sections": [
                {"id": "user_messages", "label": "User messages", "values": ["Hello"]},
            ],
            "replay_action_sections": [
                {"id": "assistant_text", "label": "Assistant text", "values": ["Hi there"]},
            ],
        }
        result = build_replay_turn_detail("trace_001", turn)
        assert result["trace_id"] == "trace_001"
        assert result["turn_id"] == "turn_1"
        assert len(result["context"]["sections"]) == 1
        assert len(result["action"]["sections"]) == 1
        assert result["context"]["sections"][0]["style"] == "user"
        assert result["action"]["sections"][0]["style"] == "assistant"

    def test_fallback_to_prompt_sections(self):
        turn = {
            "turn_id": "turn_1",
            "label": "Turn 1",
            "replay_context_sections": [],
            "replay_action_sections": [],
            "prompt_sections": [
                {"id": "system_prompt", "label": "System prompt", "values": ["Be helpful."]},
            ],
            "response_sections": [
                {"id": "assistant_text", "label": "Assistant text", "values": ["OK"]},
            ],
        }
        result = build_replay_turn_detail("trace_001", turn)
        assert len(result["context"]["sections"]) == 1
        assert len(result["action"]["sections"]) == 1


@pytest.mark.unit
class TestAttachReplaySections:
    def test_attaches_matching_llm_calls(self):
        turns = [
            {"turn_id": "t1", "start_ts": 100.0, "end_ts": 200.0},
            {"turn_id": "t2", "start_ts": 200.0, "end_ts": 300.0},
        ]
        llm_calls = [
            {
                "ts": 150.0,
                "replay_context_sections": [{"id": "user", "values": ["q1"]}],
                "replay_action_sections": [{"id": "assistant", "values": ["a1"]}],
            },
            {
                "ts": 250.0,
                "replay_context_sections": [{"id": "user", "values": ["q2"]}],
                "replay_action_sections": [{"id": "assistant", "values": ["a2"]}],
            },
        ]
        attach_replay_sections(turns, llm_calls)
        assert len(turns[0]["replay_context_sections"]) == 1
        assert turns[0]["replay_context_sections"][0]["values"] == ["q1"]
        assert len(turns[1]["replay_context_sections"]) == 1
        assert turns[1]["replay_context_sections"][0]["values"] == ["q2"]

    def test_no_matching_calls(self):
        turns = [{"turn_id": "t1", "start_ts": 100.0, "end_ts": 200.0}]
        llm_calls = [
            {
                "ts": 500.0,
                "replay_context_sections": [{"id": "user", "values": ["late"]}],
                "replay_action_sections": [],
            }
        ]
        attach_replay_sections(turns, llm_calls)
        assert turns[0]["replay_context_sections"] == []
