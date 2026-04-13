"""Shared helpers for cli_agent end-to-end runs under `bin/mantle watch`."""

from __future__ import annotations

import asyncio
import contextlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mantle.ingest.store import TraceStore


@pytest.fixture(scope="module")
def has_llm_key() -> None:
    """Skip E2E runs that require a live LLM when no key is configured."""
    if not os.getenv("OAK1") and not os.getenv("OPENAI_API_KEY"):
        pytest.skip("No LLM API key configured (OAK1 or OPENAI_API_KEY)")


@pytest.fixture(scope="module")
def has_mantle_watch() -> None:
    """Skip when local runtime dependencies for `bin/mantle watch` are missing."""
    if not Path("bin/mantle").exists():
        pytest.skip("bin/mantle not available")
    if shutil.which("sudo") is None:
        pytest.skip("sudo is required for `bin/mantle watch`")


@dataclass
class TraceRun:
    trace_id: str
    obs_root: Path
    stdout: str
    stderr: str
    store: TraceStore
    mock_request_count: int = 0


@dataclass
class MockLLMPlan:
    """Deterministic chat-completions script for one cli_agent run."""

    tool_commands: list[str]
    final_response: str


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _mock_llm_server(plan: MockLLMPlan):
    state = {"requests": 0}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_POST(self):
            if self.path.rstrip("/") != "/v1/chat/completions":
                self.send_response(404)
                self.end_headers()
                return

            raw_len = int(self.headers.get("content-length", "0") or "0")
            payload = self.rfile.read(raw_len) if raw_len > 0 else b"{}"
            try:
                req = json.loads(payload.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                req = {}

            _ = req.get("messages")
            state["requests"] += 1
            idx = state["requests"] - 1

            message: dict[str, Any] = {"role": "assistant", "content": ""}
            if idx < len(plan.tool_commands):
                call_id = f"mock_call_{idx + 1}"
                args = {"command": plan.tool_commands[idx], "timeout": 60}
                message["tool_calls"] = [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": "command_exec",
                            "arguments": json.dumps(args, ensure_ascii=True),
                        },
                    }
                ]
            else:
                message["content"] = plan.final_response

            body = {
                "id": f"chatcmpl-mock-{state['requests']}",
                "object": "chat.completion",
                "created": 0,
                "model": "mock-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": message,
                    }
                ],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            }

            encoded = json.dumps(body, ensure_ascii=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = _ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{int(port)}", state
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


DEFAULT_ALLOW_POLICY = """
defaults:
  unmatched: allow
""".strip()


def write_policy(path: Path, policy_text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(policy_text.strip() + "\n", encoding="utf-8")


def write_decisions(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")


def run_cli_agent_watch(
    *,
    tmp_path: Path,
    trace_id: str,
    prompt: str,
    policy_text: str = DEFAULT_ALLOW_POLICY,
    decisions: list[dict[str, Any]] | None = None,
    timeout: int = 420,
    mock_plan: MockLLMPlan | None = None,
) -> TraceRun:
    """Run one full traced agent task and return a loaded TraceStore."""
    obs_root = tmp_path / "obs"
    (obs_root / "traces").mkdir(parents=True, exist_ok=True)
    (obs_root / "events").mkdir(parents=True, exist_ok=True)
    (obs_root / "mitm").mkdir(parents=True, exist_ok=True)
    # The launcher prefers repo obs when AGENT_OBS_ROOT appears empty.
    # Seed one inert file in traces/events so the temp root wins deterministically.
    (obs_root / "traces" / ".seed.ebpf.jsonl").write_text("", encoding="utf-8")
    (obs_root / "events" / ".seed.events.jsonl").write_text("", encoding="utf-8")

    policy_file = tmp_path / ".mantle" / "intercept.yaml"
    decisions_file = tmp_path / ".mantle" / "intercept.decisions.jsonl"
    decision_current_dir = tmp_path / ".mantle" / "intercept.decision-current"

    write_policy(policy_file, policy_text)
    write_decisions(decisions_file, decisions or [])
    decision_current_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["AGENT_OBS_ROOT"] = str(obs_root)
    env["AGENT_MAX_TURNS"] = env.get("AGENT_MAX_TURNS", "8")
    env["MANTLE_INTERCEPT_POLICY_FILE"] = str(policy_file)
    env["MANTLE_INTERCEPT_DECISIONS_FILE"] = str(decisions_file)
    env["MANTLE_INTERCEPT_DECISION_CURRENT_DIR"] = str(decision_current_dir)

    env.setdefault("OAK1", "mock-oak1-key")

    cmd = [
        "bin/mantle",
        "watch",
        "--trace-id",
        trace_id,
        "python",
        "cli_agent.py",
        prompt,
    ]

    mock_request_count = 0
    if mock_plan is None:
        proc = subprocess.run(
            cmd,
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    else:
        with _mock_llm_server(mock_plan) as (mock_base, mock_state):
            env["MANTLE_FORCE_OPENAI_BASE"] = mock_base
            env["OPENAI_MODEL"] = "mock-model"
            proc = subprocess.run(
                cmd,
                cwd=Path(__file__).resolve().parents[2],
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            mock_request_count = int(mock_state.get("requests") or 0)

    output = f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}"
    assert proc.returncode == 0, output

    store = TraceStore(
        trace_dir=obs_root / "traces",
        events_dir=obs_root / "events",
        mitm_dir=obs_root / "mitm",
    )
    asyncio.run(store.poll_once())

    trace_file = obs_root / "traces" / trace_id
    events_file = obs_root / "events" / f"{trace_id.removesuffix('.ebpf.jsonl')}.events.jsonl"
    assert trace_file.exists(), f"Missing trace file: {trace_file}\n{output}"
    assert events_file.exists(), f"Missing events file: {events_file}\n{output}"

    return TraceRun(
        trace_id=trace_id,
        obs_root=obs_root,
        stdout=proc.stdout,
        stderr=proc.stderr,
        store=store,
        mock_request_count=mock_request_count,
    )


def find_turn_with_tool_calls(turns_overview: dict[str, Any]) -> dict[str, Any]:
    """Return the first non-setup turn that has at least one tool call."""
    turns = list(turns_overview.get("turns") or [])
    for turn in turns:
        if str(turn.get("turn_id") or "") == "setup":
            continue
        if int(turn.get("tool_call_count") or 0) > 0:
            return turn
    raise AssertionError(f"No tool-call turn found in turns: {turns}")


def first_tool_timeline_entry(turn_detail: dict[str, Any]) -> dict[str, Any]:
    """Extract the first `tool_call` entry from a turn timeline."""
    for entry in list(turn_detail.get("timeline") or []):
        if str(entry.get("entry_type") or "") == "tool_call":
            return entry
    raise AssertionError(f"No tool_call timeline entry found: {turn_detail.get('timeline')}")
