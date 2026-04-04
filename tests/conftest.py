"""Shared test fixtures and factories for Mantle test suite."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from mantle.ingest.store import TraceStore


# ── Sample Data ──────────────────────────────────────────────────

SAMPLE_EBPF_EVENTS: list[dict[str, Any]] = [
    {
        "ts": 1710000000.0,
        "line_no": 1,
        "type": "command_exec",
        "pid": 1000,
        "ppid": 999,
        "exec_path": "/usr/bin/node",
        "argv": ["node", "index.js"],
        "command": "node index.js",
        "label": "exec node index.js",
    },
    {
        "ts": 1710000001.0,
        "line_no": 2,
        "type": "file_read",
        "pid": 1000,
        "path": "/home/user/project/index.js",
        "flags": 0,
        "label": "file read /home/user/project/index.js",
    },
    {
        "ts": 1710000002.0,
        "line_no": 3,
        "type": "net_connect",
        "pid": 1000,
        "fd": 5,
        "dest": "api.openai.com:443",
        "transport": "tcp",
        "family": "AF_INET",
        "ok": True,
        "label": "connect api.openai.com:443",
    },
    {
        "ts": 1710000003.0,
        "line_no": 4,
        "type": "file_write",
        "pid": 1000,
        "path": "/home/user/project/output.txt",
        "flags": 65,
        "label": "file write /home/user/project/output.txt",
    },
    {
        "ts": 1710000004.0,
        "line_no": 5,
        "type": "process_exit",
        "pid": 1000,
        "label": "pid 1000 exited",
    },
]

SAMPLE_MITM_REQUEST: dict[str, Any] = {
    "ts": 1710000002.5,
    "direction": "request",
    "url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "pid": 1000,
    "model": "gpt-4",
    "request_body": {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a test assistant."},
            {"role": "user", "content": "Say hello."},
        ],
        "tools": [],
    },
}

SAMPLE_MITM_RESPONSE: dict[str, Any] = {
    "ts": 1710000003.0,
    "direction": "response",
    "url": "https://api.openai.com/v1/chat/completions",
    "method": "POST",
    "pid": 1000,
    "status_code": 200,
    "model": "gpt-4",
    "duration_ms": 500,
    "request_body": SAMPLE_MITM_REQUEST["request_body"],
    "response_body": {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you?",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 8, "total_tokens": 28},
    },
}

SAMPLE_AGENT_EVENTS: list[dict[str, Any]] = [
    {
        "ts": 1710000000.0,
        "monotonic_ns": 0,
        "trace_id": "test-trace",
        "session_id": "test-session",
        "seq": 1,
        "event_type": "session_started",
        "payload": {"mode": "task", "model": "gpt-4", "base_url": "https://api.openai.com"},
    },
    {
        "ts": 1710000001.0,
        "monotonic_ns": 1000000000,
        "trace_id": "test-trace",
        "session_id": "test-session",
        "seq": 2,
        "event_type": "user_prompt",
        "payload": {"content": "Say hello."},
    },
    {
        "ts": 1710000003.5,
        "monotonic_ns": 3500000000,
        "trace_id": "test-trace",
        "session_id": "test-session",
        "seq": 3,
        "event_type": "assistant_response",
        "payload": {"content": "Hello! How can I help you?"},
    },
    {
        "ts": 1710000004.0,
        "monotonic_ns": 4000000000,
        "trace_id": "test-trace",
        "session_id": "test-session",
        "seq": 4,
        "event_type": "session_ended",
        "payload": {"reason": "task_complete"},
    },
]


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def obs_dir(tmp_path: Path) -> Path:
    """Create a temporary obs directory structure matching Mantle's expected layout."""
    traces_dir = tmp_path / "traces"
    events_dir = tmp_path / "events"
    mitm_dir = tmp_path / "mitm"
    traces_dir.mkdir()
    events_dir.mkdir()
    mitm_dir.mkdir()
    return tmp_path


@pytest.fixture
def populated_obs_dir(obs_dir: Path) -> Path:
    """Create an obs directory pre-populated with sample trace data."""
    trace_id = "test_trace_001.ebpf.jsonl"

    # Write eBPF trace
    trace_file = obs_dir / "traces" / trace_id
    with trace_file.open("w") as f:
        for event in SAMPLE_EBPF_EVENTS:
            f.write(json.dumps(event) + "\n")

    # Write MITM capture
    mitm_file = obs_dir / "mitm" / "test_trace_001.mitm.jsonl"
    with mitm_file.open("w") as f:
        f.write(json.dumps(SAMPLE_MITM_REQUEST) + "\n")
        f.write(json.dumps(SAMPLE_MITM_RESPONSE) + "\n")

    # Write agent events
    events_file = obs_dir / "events" / "test_trace_001.events.jsonl"
    with events_file.open("w") as f:
        for event in SAMPLE_AGENT_EVENTS:
            f.write(json.dumps(event) + "\n")

    return obs_dir


@pytest.fixture
def empty_store(obs_dir: Path) -> TraceStore:
    """Create a TraceStore backed by an empty obs directory."""
    return TraceStore(
        trace_dir=obs_dir / "traces",
        events_dir=obs_dir / "events",
        mitm_dir=obs_dir / "mitm",
    )


@pytest.fixture
def populated_store(populated_obs_dir: Path) -> TraceStore:
    """Create a TraceStore backed by a populated obs directory."""
    return TraceStore(
        trace_dir=populated_obs_dir / "traces",
        events_dir=populated_obs_dir / "events",
        mitm_dir=populated_obs_dir / "mitm",
    )
