"""Integration tests for replay tool pairing from MITM-only (codex-like) traces."""

from __future__ import annotations

import asyncio
import json

import pytest

from mantle.ingest.store import TraceStore


@pytest.mark.integration
def test_mitm_only_trace_builds_tool_pairs_and_context_source_links(tmp_path):
    obs = tmp_path / "obs"
    traces_dir = obs / "traces"
    events_dir = obs / "events"
    mitm_dir = obs / "mitm"
    traces_dir.mkdir(parents=True)
    events_dir.mkdir(parents=True)
    mitm_dir.mkdir(parents=True)

    trace_id = "codex_like_case.ebpf.jsonl"
    trace_file = traces_dir / trace_id
    mitm_file = mitm_dir / "codex_like_case.mitm.jsonl"

    command_text = "printf 'hello' > /tmp/codex_file.txt"

    trace_rows = [
        {
            "ts": 1000.250,
            "line_no": 1,
            "type": "command_exec",
            "pid": 500,
            "ppid": 1,
            "exec_path": "/usr/bin/sh",
            "argv": ["sh", "-lc", command_text],
            "command": command_text,
        },
        {
            "ts": 1000.260,
            "line_no": 2,
            "type": "file_write",
            "pid": 500,
            "path": "/tmp/codex_file.txt",
            "bytes": 6,
        },
    ]
    trace_file.write_text("\n".join(json.dumps(row, ensure_ascii=True) for row in trace_rows) + "\n", encoding="utf-8")

    req1 = {
        "model": "gpt-4.1",
        "instructions": "You are codex",
        "input": [{"role": "user", "content": "Write hello to /tmp/codex_file.txt"}],
        "tools": [{"type": "function", "name": "command_exec"}],
    }
    resp1 = {
        "id": "resp_1",
        "output": [
            {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "command_exec",
                "arguments": json.dumps({"command": command_text}),
            },
            {
                "id": "m_1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Running command"}],
            },
        ],
        "output_text": "Running command",
        "usage": {"total_tokens": 10},
    }

    req2 = {
        "model": "gpt-4.1",
        "instructions": "You are codex",
        "input": [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "command_exec",
                "arguments": json.dumps({"command": command_text}),
            },
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "ok",
            },
            {"role": "user", "content": "done?"},
        ],
        "tools": [{"type": "function", "name": "command_exec"}],
    }
    resp2 = {
        "id": "resp_2",
        "output": [
            {
                "id": "m_2",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "done"}],
            }
        ],
        "output_text": "done",
        "usage": {"total_tokens": 8},
    }

    mitm_rows = [
        {
            "direction": "request",
            "ts": 1000.000,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req1,
            "response_body": {},
        },
        {
            "direction": "response",
            "ts": 1000.200,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req1,
            "response_body": resp1,
        },
        {
            "direction": "request",
            "ts": 1001.000,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req2,
            "response_body": {},
        },
        {
            "direction": "response",
            "ts": 1001.100,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req2,
            "response_body": resp2,
        },
    ]
    mitm_file.write_text("\n".join(json.dumps(row, ensure_ascii=True) for row in mitm_rows) + "\n", encoding="utf-8")

    store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, mitm_dir=mitm_dir)
    asyncio.run(store.poll_once())

    turns = store.replay_turns_overview(trace_id)
    non_setup = [t for t in list(turns.get("turns") or []) if str(t.get("turn_id") or "") != "setup"]
    assert non_setup, turns
    assert any(int(t.get("tool_call_count") or 0) >= 1 for t in non_setup), turns

    tool_turn = next(t for t in non_setup if int(t.get("tool_call_count") or 0) >= 1)
    tool_detail = store.replay_turn_detail(trace_id, str(tool_turn["turn_id"]))
    pairs = list(((tool_detail.get("summary") or {}).get("tool_call_pairs") or []))
    assert pairs, tool_detail
    assert any((pair.get("source") or {}).get("status") == "matched" and int((pair.get("source") or {}).get("pid") or 0) > 0 for pair in pairs), pairs

    context_source_found = False
    for turn in non_setup:
        detail = store.replay_turn_detail(trace_id, str(turn["turn_id"]))
        context_sections = list(((detail.get("context") or {}).get("sections") or []))
        for section in context_sections:
            if str(section.get("id") or "") != "tool_calls_in_context":
                continue
            for value in list(section.get("values") or []):
                if not isinstance(value, dict):
                    continue
                if str(value.get("tool_call_id") or "") != "call_1":
                    continue
                source = value.get("source") if isinstance(value.get("source"), dict) else {}
                if str(source.get("status") or "") == "matched" and int(source.get("pid") or 0) > 0:
                    context_source_found = True
    assert context_source_found


@pytest.mark.integration
def test_responses_previous_response_id_does_not_split_turns(tmp_path):
    obs = tmp_path / "obs"
    traces_dir = obs / "traces"
    events_dir = obs / "events"
    mitm_dir = obs / "mitm"
    traces_dir.mkdir(parents=True)
    events_dir.mkdir(parents=True)
    mitm_dir.mkdir(parents=True)

    trace_id = "responses_continuation_chain.ebpf.jsonl"
    trace_file = traces_dir / trace_id
    mitm_file = mitm_dir / "responses_continuation_chain.mitm.jsonl"

    command_text = "pwd"
    trace_rows = [
        {
            "ts": 2000.250,
            "line_no": 1,
            "type": "command_exec",
            "pid": 777,
            "ppid": 1,
            "exec_path": "/usr/bin/sh",
            "argv": ["sh", "-lc", command_text],
            "command": command_text,
        }
    ]
    trace_file.write_text("\n".join(json.dumps(row, ensure_ascii=True) for row in trace_rows) + "\n", encoding="utf-8")

    req1 = {
        "model": "gpt-4.1",
        "instructions": "You are codex",
        "input": [{"role": "user", "content": "show working directory"}],
        "tools": [{"type": "function", "name": "exec_command"}],
    }
    resp1 = {
        "id": "resp_root",
        "output": [
            {
                "id": "fc_pwd",
                "type": "function_call",
                "call_id": "call_pwd",
                "name": "exec_command",
                "arguments": json.dumps({"command": command_text}),
            }
        ],
        "usage": {"total_tokens": 5},
    }

    req2 = {
        "model": "gpt-4.1",
        "previous_response_id": "resp_root",
        "instructions": "You are codex",
        "input": [
            {
                "type": "function_call",
                "call_id": "call_pwd",
                "name": "exec_command",
                "arguments": json.dumps({"command": command_text}),
            },
            {"type": "function_call_output", "call_id": "call_pwd", "output": "/tmp/project"},
        ],
        "tools": [{"type": "function", "name": "exec_command"}],
    }
    resp2 = {
        "id": "resp_followup",
        "output": [
            {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "You are in /tmp/project"}],
            }
        ],
        "output_text": "You are in /tmp/project",
        "usage": {"total_tokens": 6},
    }

    mitm_rows = [
        {
            "direction": "request",
            "ts": 2000.000,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req1,
            "response_body": {},
        },
        {
            "direction": "response",
            "ts": 2000.200,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req1,
            "response_body": resp1,
        },
        {
            "direction": "request",
            "ts": 2001.000,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req2,
            "response_body": {},
        },
        {
            "direction": "response",
            "ts": 2001.120,
            "url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "request_body": req2,
            "response_body": resp2,
        },
    ]
    mitm_file.write_text("\n".join(json.dumps(row, ensure_ascii=True) for row in mitm_rows) + "\n", encoding="utf-8")

    store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, mitm_dir=mitm_dir)
    asyncio.run(store.poll_once())

    overview = store.replay_turns_overview(trace_id)
    non_setup = [t for t in list(overview.get("turns") or []) if str(t.get("turn_id") or "") != "setup"]

    assert len(non_setup) == 1, overview
    assert str(non_setup[0].get("turn_id") or "") == "turn_1", overview
