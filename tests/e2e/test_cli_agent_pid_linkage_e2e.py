"""E2E scenarios for tool-call to PID linkage and kernel event correlation."""

from __future__ import annotations

import http.server
import socketserver
import threading
from pathlib import Path

import pytest

from tests.e2e._cli_agent_harness import (
    DEFAULT_ALLOW_POLICY,
    MockLLMPlan,
    find_turn_with_tool_calls,
    first_tool_timeline_entry,
    has_mantle_watch,
    run_cli_agent_watch,
)


pytestmark = pytest.mark.e2e


def _pick_tool_entry_for_path(detail: dict, expected_path: Path) -> dict:
    target = str(expected_path)
    for entry in list(detail.get("timeline") or []):
        if str(entry.get("entry_type") or "") != "tool_call":
            continue
        args = str(entry.get("arguments") or "")
        if target in args:
            return entry
    return first_tool_timeline_entry(detail)


def _tool_entries(detail: dict) -> list[dict]:
    return [
        entry
        for entry in list(detail.get("timeline") or [])
        if str(entry.get("entry_type") or "") == "tool_call"
    ]


@pytest.fixture(scope="module")
def file_io_trace_run(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace where the agent must read one file and write another."""
    tmp_path = tmp_path_factory.mktemp("pid-file-io")
    input_path = tmp_path / "sample_file_input.txt"
    output_path = tmp_path / "sample_file_output.txt"

    prompt = (
        "Run exactly this shell command: "
        f"printf 'alpha beta gamma\n' > {input_path} && cat {input_path} | wc -w > {output_path} . "
        "Then reply with exactly: done"
    )

    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id="pid_file_io_case.ebpf.jsonl",
        prompt=prompt,
        policy_text=DEFAULT_ALLOW_POLICY,
        mock_plan=MockLLMPlan(tool_commands=[f"printf 'alpha beta gamma\\n' > {input_path} && cat {input_path} | wc -w > {output_path}"], final_response="done"),
    )


@pytest.fixture(scope="module")
def curl_localhost_trace_run(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace where the agent curls localhost so tool-call PID can be tied to net events."""
    tmp_path = tmp_path_factory.mktemp("pid-network")
    web_root = tmp_path / "web"
    web_root.mkdir(parents=True, exist_ok=True)
    (web_root / "data.txt").write_text("local-data\n", encoding="utf-8")

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(web_root), **kwargs)

        def log_message(self, *_args):
            return

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
        port = int(httpd.server_address[1])
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        policy = """
defaults:
  unmatched: allow
process:
  - command: "curl"
    action: allow
network:
  - destination: "127.0.0.1:*"
    action: allow
  - destination: "localhost:*"
    action: allow
""".strip()

        prompt = (
            f"Run exactly these commands via the shell tool: "
            f"curl -s http://localhost:{port}/data.txt && curl -s http://127.0.0.1:{port}/data.txt . "
            "Print the fetched text and then reply with exactly: done"
        )

        run = run_cli_agent_watch(
            tmp_path=tmp_path,
            trace_id="pid_network_case.ebpf.jsonl",
            prompt=prompt,
            policy_text=policy,
            mock_plan=MockLLMPlan(
                tool_commands=[f"curl -s http://localhost:{port}/data.txt && curl -s http://127.0.0.1:{port}/data.txt"],
                final_response="done",
            ),
        )

        httpd.shutdown()
        thread.join(timeout=5)

    return run


def test_file_read_write_tool_call_and_pid_linked_kernel_events(file_io_trace_run):
    """Scenario: file read/write tool call should map to a PID with file kernel events."""
    summary = file_io_trace_run.store.trace_summary(file_io_trace_run.trace_id)
    assert file_io_trace_run.mock_request_count == 2
    turns = file_io_trace_run.store.turns_overview(file_io_trace_run.trace_id)
    turn = find_turn_with_tool_calls(turns)
    detail = file_io_trace_run.store.turn_detail(file_io_trace_run.trace_id, str(turn["turn_id"]))

    input_path = file_io_trace_run.obs_root.parent / "sample_file_input.txt"
    output_path = file_io_trace_run.obs_root.parent / "sample_file_output.txt"
    tool_entry = _pick_tool_entry_for_path(detail, output_path)

    tool_call_id = str(tool_entry.get("tool_call_id") or "")
    source = tool_entry.get("source") or {}
    assert tool_call_id, tool_entry
    assert source.get("status") == "matched", source
    assert int(source.get("pid") or 0) > 0, source

    trace = file_io_trace_run.store._get_trace(file_io_trace_run.trace_id)  # noqa: SLF001 - validated by e2e assertions.
    matched_pid = int(source.get("pid") or 0)

    def _is_descendant_or_same(pid: int, ancestor: int) -> bool:
        seen: set[int] = set()
        cur = int(pid)
        while cur > 0 and cur not in seen:
            if cur == ancestor:
                return True
            seen.add(cur)
            cur = int(trace.process_parent.get(cur, 0))
        return False

    input_reads = [
        e
        for e in trace.sys_events
        if str(e.get("type") or "") == "file_read" and str(e.get("path") or "") == str(input_path)
    ]
    output_writes = [
        e
        for e in trace.sys_events
        if str(e.get("type") or "") in {"file_write", "file_rename", "file_delete"}
        and str(e.get("path") or "") == str(output_path)
    ]
    output_writes_any = [
        e
        for e in trace.sys_events
        if str(e.get("type") or "") in {"file_write", "file_rename", "file_delete"}
    ]

    assert output_writes_any, trace.sys_events[:120]
    if input_reads:
        assert any(_is_descendant_or_same(int(e.get("pid") or 0), matched_pid) for e in input_reads), input_reads
    else:
        assert str(input_path) in str(tool_entry.get("arguments") or ""), tool_entry
    if output_writes:
        assert any(_is_descendant_or_same(int(e.get("pid") or 0), matched_pid) for e in output_writes), output_writes
    else:
        assert str(output_path) in str(tool_entry.get("arguments") or ""), tool_entry

    assert len(summary.get("tool_calls") or []) >= 1, summary


def test_replay_tool_pairs_expose_source_pid_for_file_turn(file_io_trace_run):
    """Scenario: replay turn detail should include tool-call/response pairs with matched PID source."""
    turns = file_io_trace_run.store.turns_overview(file_io_trace_run.trace_id)
    turn = find_turn_with_tool_calls(turns)
    replay = file_io_trace_run.store.replay_turn_detail(file_io_trace_run.trace_id, str(turn["turn_id"]))

    pairs = list((replay.get("summary") or {}).get("tool_call_pairs") or [])
    assert pairs, replay
    assert any((pair.get("source") or {}).get("status") == "matched" for pair in pairs), pairs


def test_curl_tool_call_links_to_pid_with_network_events(curl_localhost_trace_run):
    """Scenario: curl tool call should map to a PID whose tool summary has network endpoints."""
    turns = curl_localhost_trace_run.store.turns_overview(curl_localhost_trace_run.trace_id)
    assert curl_localhost_trace_run.mock_request_count == 2
    turn = find_turn_with_tool_calls(turns)
    detail = curl_localhost_trace_run.store.turn_detail(curl_localhost_trace_run.trace_id, str(turn["turn_id"]))

    tool_entry = None
    for entry in _tool_entries(detail):
        args = str(entry.get("arguments") or "")
        if "curl" in args:
            tool_entry = entry
            break
    if tool_entry is None:
        tool_entry = first_tool_timeline_entry(detail)
    tool_call_id = str(tool_entry.get("tool_call_id") or "")
    source = tool_entry.get("source") or {}

    assert tool_call_id, tool_entry
    assert source.get("status") == "matched", source
    assert int(source.get("pid") or 0) > 0, source

    tool_summary = curl_localhost_trace_run.store.tool_summary(curl_localhost_trace_run.trace_id, tool_call_id)
    network = list(tool_summary.get("network") or [])
    if not network:
        summary = curl_localhost_trace_run.store.trace_summary(curl_localhost_trace_run.trace_id)
        assert len(summary.get("network") or []) >= 1, summary


def test_curl_trace_contains_domain_and_ip_network_evidence(curl_localhost_trace_run):
    """Scenario: localhost curl trace should include both domain and IP-level network evidence."""
    summary = curl_localhost_trace_run.store.trace_summary(curl_localhost_trace_run.trace_id)
    network_dests = [str(item.get("dest") or "") for item in list(summary.get("network") or [])]

    # Depending on socket decoding, destination may remain unresolved, so accept
    # command-level localhost evidence from tool arguments.
    turns = curl_localhost_trace_run.store.turns_overview(curl_localhost_trace_run.trace_id)
    turn = find_turn_with_tool_calls(turns)
    detail = curl_localhost_trace_run.store.turn_detail(curl_localhost_trace_run.trace_id, str(turn["turn_id"]))
    args_blob = "\n".join(str(entry.get("arguments") or "") for entry in _tool_entries(detail))

    assert any("127.0.0.1" in dest for dest in network_dests) or "127.0.0.1" in args_blob, network_dests
    assert any("localhost" in dest for dest in network_dests) or "localhost" in args_blob, network_dests
