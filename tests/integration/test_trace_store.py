"""Integration tests for TraceStore ingestion and querying."""

import asyncio
import json
from pathlib import Path

import pytest

from mantle.ingest.store import TraceStore


@pytest.mark.integration
class TestTraceStorePollAndList:
    """Test that poll_once ingests trace data and list_traces returns it."""

    def test_empty_store(self, empty_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(empty_store.poll_once())
        traces = empty_store.list_traces()
        assert isinstance(traces, list)
        assert len(traces) == 0

    def test_populated_store(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        assert isinstance(traces, list)
        assert len(traces) >= 1

    def test_trace_has_expected_fields(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        if traces:
            trace = traces[0]
            assert "trace_id" in trace

    def test_proxy_non_object_lines_are_ignored(self, tmp_path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_scalar_regression.ebpf.jsonl"
        trace_file = traces_dir / trace_id
        trace_file.write_text(
            json.dumps(
                {
                    "ts": 1710000000.0,
                    "line_no": 1,
                    "type": "command_exec",
                    "pid": 123,
                    "ppid": 1,
                    "exec_path": "/usr/bin/python3",
                    "argv": ["python3", "-c", "pass"],
                    "command": "python3 -c pass",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        proxy_file = proxy_dir / "proxy_scalar_regression.proxy.jsonl"
        proxy_file.write_text(
            "\n".join(
                [
                    "1",
                    json.dumps(
                        {
                            "direction": "response",
                            "ts": 1710000001.0,
                            "url": "https://api.openai.com/v1/chat/completions",
                            "request_body": {},
                            "response_body": {},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=proxy_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        traces = store.list_traces()
        assert len(traces) == 1
        # One api_call should be ingested from the valid response object, while
        # the scalar line is skipped without crashing.
        assert traces[0]["agent_event_count"] == 1

    def test_activity_only_trace_uses_turn_1_instead_of_setup(self, tmp_path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "activity_only_turn_fallback.ebpf.jsonl"
        (traces_dir / trace_id).write_text(
            json.dumps(
                {
                    "ts": 1710000200.0,
                    "line_no": 1,
                    "type": "command_exec",
                    "pid": 123,
                    "ppid": 1,
                    "exec_path": "/usr/bin/bash",
                    "argv": ["bash", "-lc", "echo hi"],
                    "command": "bash -lc 'echo hi'",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "ts": 1710000200.2,
                    "line_no": 2,
                    "type": "net_connect",
                    "pid": 123,
                    "fd": 7,
                    "dest": "140.82.113.4:443",
                    "transport": "tcp",
                    "family": "AF_INET",
                    "ok": True,
                    "label": "connect 140.82.113.4:443",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=proxy_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        overview = store.turns_overview(trace_id)
        assert overview["executive_summary"]["turns"] == 1
        assert len(overview["turns"]) == 1
        assert overview["turns"][0]["turn_id"] == "turn_1"
        assert overview["turns"][0]["label"] == "T1"


@pytest.mark.integration
class TestTraceStoreLiteLLMProxyIngest:
    def _write_min_trace(self, traces_dir: Path, trace_id: str) -> None:
        (traces_dir / trace_id).write_text(
            json.dumps(
                {
                    "ts": 1710000100.0,
                    "line_no": 1,
                    "type": "command_exec",
                    "pid": 777,
                    "ppid": 1,
                    "exec_path": "/usr/bin/python3",
                    "argv": ["python3", "-c", "pass"],
                    "command": "python3 -c pass",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def _write_proxy_record(self, path: Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "direction": "response",
                    "ts": 1710000101.5,
                    "url": "https://api.openai.com/v1/responses",
                    "method": "POST",
                    "status_code": 200,
                    "duration_ms": 250,
                    "model": "gpt-5.4-nano",
                    "request_body": {
                        "model": "gpt-5.4-nano",
                        "input": [{"role": "user", "content": "hello from proxy"}],
                    },
                    "response_body": {
                        "output_text": "hello from assistant",
                        "output": [
                            {
                                "type": "message",
                                "role": "assistant",
                                "content": [
                                    {"type": "output_text", "text": "hello from assistant"}
                                ],
                            }
                        ],
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_proxy_source_opt_in_ingests_proxy_events(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_ingest_opt_in.ebpf.jsonl"
        self._write_min_trace(traces_dir, trace_id)
        self._write_proxy_record(proxy_dir / "proxy_ingest_opt_in.proxy.jsonl")

        store = TraceStore(
            trace_dir=traces_dir,
            events_dir=events_dir,
            proxy_dir=proxy_dir,
            llm_capture_source="proxy",
        )
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        traces = store.list_traces()
        assert len(traces) == 1
        assert traces[0]["agent_event_count"] >= 1
        state = store.traces[trace_id]
        assert any(str(ev.get("_source") or "") == "proxy" for ev in state.agent_events)

    def test_proxy_logs_are_ingested_when_source_is_default_proxy(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_ingest_opt_out.ebpf.jsonl"
        self._write_min_trace(traces_dir, trace_id)
        self._write_proxy_record(proxy_dir / "proxy_ingest_opt_out.proxy.jsonl")

        store = TraceStore(
            trace_dir=traces_dir,
            events_dir=events_dir,
            proxy_dir=proxy_dir,
        )
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        traces = store.list_traces()
        assert len(traces) == 1
        assert traces[0]["agent_event_count"] >= 1

    def test_proxy_logs_named_as_trace_file_are_ingested(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_same_name.ebpf.jsonl"
        self._write_min_trace(traces_dir, trace_id)
        self._write_proxy_record(proxy_dir / trace_id)

        store = TraceStore(
            trace_dir=traces_dir,
            events_dir=events_dir,
            proxy_dir=proxy_dir,
            llm_capture_source="proxy",
        )
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        traces = store.list_traces()
        assert len(traces) == 1
        assert traces[0]["agent_event_count"] >= 1

    def test_proxy_source_raises_when_log_selection_is_ambiguous(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_ingest_ambiguous.ebpf.jsonl"
        self._write_min_trace(traces_dir, trace_id)
        self._write_proxy_record(proxy_dir / "43100.log")
        self._write_proxy_record(proxy_dir / "43104.log")

        store = TraceStore(
            trace_dir=traces_dir,
            events_dir=events_dir,
            proxy_dir=proxy_dir,
            llm_capture_source="proxy",
        )

        with pytest.raises(RuntimeError, match="Ambiguous proxy log selection"):
            asyncio.get_event_loop().run_until_complete(store.poll_once())


@pytest.mark.integration
class TestTraceStoreGraphAndViews:
    """Test graph and view methods against ingested trace data."""

    def _setup_store(self, populated_store: TraceStore) -> tuple[TraceStore, str]:
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        assert len(traces) >= 1
        return populated_store, traces[0]["trace_id"]

    def test_high_level_graph(self, populated_store: TraceStore):
        store, trace_id = self._setup_store(populated_store)
        graph = store.high_level_graph(trace_id)
        assert isinstance(graph, dict)
        assert "nodes" in graph or "edges" in graph or "error" not in graph

    def test_turns_overview(self, populated_store: TraceStore):
        store, trace_id = self._setup_store(populated_store)
        overview = store.turns_overview(trace_id)
        assert isinstance(overview, dict)

    def test_trace_summary(self, populated_store: TraceStore):
        store, trace_id = self._setup_store(populated_store)
        summary = store.trace_summary(trace_id)
        assert isinstance(summary, dict)

    def test_unknown_trace_raises(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        with pytest.raises(KeyError):
            populated_store.high_level_graph("nonexistent_trace.ebpf.jsonl")

    def test_replay_turn_two_tool_outputs_include_sources(self):
        """Regression: context tool outputs in later turns should carry source metadata."""
        repo_root = Path(__file__).resolve().parents[2]
        obs_root = repo_root / ".mantle" / "obs"
        traces_dir = obs_root / "traces"
        events_dir = obs_root / "events"
        proxy_dir = obs_root / "proxy"

        if not traces_dir.exists() or not events_dir.exists() or not proxy_dir.exists():
            pytest.skip("Local obs fixtures not available")

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=proxy_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        target = "python_20260414_105434.ebpf.jsonl"
        trace_ids = {t["trace_id"] for t in store.list_traces()}
        if target not in trace_ids:
            pytest.skip(f"Trace fixture {target} not available")

        replay = store.replay_turn_detail(target, "turn_2")
        context_sections = ((replay.get("context") or {}).get("sections") or [])
        tool_outputs = [s for s in context_sections if str(s.get("id") or "") == "tool_outputs"]
        assert tool_outputs, "Expected tool_outputs section in turn_2 context"

        sources = tool_outputs[0].get("sources") or []
        assert sources, "Expected source metadata for tool_outputs values"
        assert any(int((src or {}).get("pid") or 0) > 0 for src in sources)


@pytest.mark.integration
class TestTraceCaptureQuality:
    def test_capture_quality_defaults_to_tier3_without_proxy_inference(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        assert traces

        quality = populated_store.trace_capture_quality(traces[0]["trace_id"])
        assert quality["overall_tier"] in {
            "tier1_payload_exact",
            "tier2_payload_mapped",
            "tier3_network_only",
        }
        assert quality["network_event_count"] >= 1
        assert "tiers" in quality
        assert "tier3_network_only" in quality["tiers"]

    def test_capture_quality_exact_interval_inference_is_tier1(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        proxy_dir = obs / "proxy_logs"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        proxy_dir.mkdir(parents=True)

        trace_id = "proxy_tier_quality.ebpf.jsonl"
        trace_file = traces_dir / trace_id
        trace_file.write_text(
            json.dumps(
                {
                    "ts": 1710000000.8,
                    "line_no": 1,
                    "type": "command_exec",
                    "pid": 1200,
                    "ppid": 1,
                    "exec_path": "/usr/bin/python3",
                    "argv": ["python3", "-c", "pass"],
                    "command": "python3 -c pass",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "ts": 1710000001.0,
                    "line_no": 2,
                    "type": "net_connect",
                    "pid": 1200,
                    "dest": "127.0.0.1:8899",
                    "transport": "tcp",
                    "family": "AF_INET",
                    "ok": True,
                    "label": "connect 127.0.0.1:8899",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        proxy_file = proxy_dir / "proxy_tier_quality.proxy.jsonl"
        proxy_file.write_text(
            json.dumps(
                {
                    "direction": "response",
                    "ts": 1710000001.3,
                    "duration_ms": 400,
                    "url": "https://api.openai.com/v1/chat/completions",
                    "request_body": {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
                    "response_body": {"choices": [{"message": {"role": "assistant", "content": "hi"}}]},
                }
            )
            + "\n",
            encoding="utf-8",
        )

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=proxy_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        quality = store.trace_capture_quality(trace_id)
        assert quality["overall_tier"] == "tier1_payload_exact"
        assert quality["tiers"]["tier1_payload_exact"] >= 1
        assert quality["inference_sources"].get("proxy_interval_exact", 0) >= 1


@pytest.mark.integration
class TestDisplayTraceView:
    def _write_scope_trace(self, traces_dir: Path, trace_id: str) -> None:
        events = [
            {
                "ts": 1710000400.0,
                "line_no": 1,
                "type": "command_exec",
                "pid": 100,
                "ppid": 1,
                "exec_path": "/usr/bin/bash",
                "argv": ["bash", "-lc", "echo root"],
                "command": "bash -lc 'echo root'",
            },
            {
                "ts": 1710000400.1,
                "line_no": 2,
                "type": "file_read",
                "pid": 100,
                "path": "/workspace/root.txt",
            },
            {
                "ts": 1710000400.2,
                "line_no": 3,
                "type": "process_spawn",
                "pid": 100,
                "child_pid": 200,
            },
            {
                "ts": 1710000400.25,
                "line_no": 4,
                "type": "command_exec",
                "pid": 200,
                "ppid": 100,
                "exec_path": "/usr/bin/python3",
                "argv": ["python3", "-c", "print(1)"],
                "command": "python3 -c print(1)",
            },
            {
                "ts": 1710000400.3,
                "line_no": 5,
                "type": "file_read",
                "pid": 200,
                "path": "/workspace/child.txt",
            },
            {
                "ts": 1710000400.35,
                "line_no": 6,
                "type": "net_connect",
                "pid": 100,
                "dest": "127.0.0.1:8899",
                "transport": "tcp",
                "family": "AF_INET",
                "ok": True,
            },
            {
                "ts": 1710000400.4,
                "line_no": 7,
                "type": "net_connect",
                "pid": 200,
                "dest": "127.0.0.1:8899",
                "transport": "tcp",
                "family": "AF_INET",
                "ok": True,
            },
            {
                "ts": 1710000400.5,
                "line_no": 8,
                "type": "process_exit",
                "pid": 200,
            },
            {
                "ts": 1710000400.6,
                "line_no": 9,
                "type": "process_exit",
                "pid": 100,
            },
            {
                "ts": 1710000401.0,
                "line_no": 10,
                "type": "command_exec",
                "pid": 300,
                "ppid": 1,
                "exec_path": "/usr/bin/cat",
                "argv": ["cat", "README.md"],
                "command": "cat README.md",
            },
            {
                "ts": 1710000401.1,
                "line_no": 11,
                "type": "file_read",
                "pid": 300,
                "path": "/workspace/other_root.txt",
            },
        ]
        (traces_dir / trace_id).write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    def test_display_trace_timestamp_scope_reports_nested_metrics(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)

        trace_id = "display_trace_scope.ebpf.jsonl"
        self._write_scope_trace(traces_dir, trace_id)

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=None)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        view = store.display_trace(
            trace_id,
            start_timestamp=1710000400.0,
            end_timestamp=1710000400.9,
        )

        summary = view["summary"]
        assert summary["totals"]["files_read"] == 2
        assert summary["direct"]["files_read"] == 1
        assert summary["nested"]["files_read"] == 1
        assert summary["totals"]["network_calls"] == 2
        assert summary["direct"]["network_calls"] == 1
        assert summary["nested"]["network_calls"] == 1
        assert summary["totals"]["process_spawns"] == 1

    def test_display_trace_pid_scope_without_timestamps_uses_lifecycle(self, tmp_path: Path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)

        trace_id = "display_trace_lifecycle.ebpf.jsonl"
        self._write_scope_trace(traces_dir, trace_id)

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, proxy_dir=None)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        view = store.display_trace(trace_id, pid=100)

        scope = view["scope"]
        summary = view["summary"]
        assert scope["pid"] == 100
        assert scope["start_timestamp"] is not None
        assert scope["end_timestamp"] is not None
        assert summary["totals"]["files_read"] == 2
        assert summary["direct"]["files_read"] == 1
        assert summary["nested"]["files_read"] == 1
        # Root pid lifecycle scope must not include the later unrelated root pid=300 read.
        assert summary["totals"]["files_read"] != 3


@pytest.mark.integration
class TestTraceStoreDelete:
    """Test trace deletion."""

    def test_delete_existing_trace(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        assert len(traces) >= 1
        trace_id = traces[0]["trace_id"]

        result = asyncio.get_event_loop().run_until_complete(
            populated_store.delete_trace(trace_id)
        )
        assert isinstance(result, dict)

        # After deletion, trace should not be listed
        remaining = populated_store.list_traces()
        trace_ids = [t["trace_id"] for t in remaining]
        assert trace_id not in trace_ids

    def test_delete_nonexistent_trace_raises(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        with pytest.raises(KeyError):
            asyncio.get_event_loop().run_until_complete(
                populated_store.delete_trace("nonexistent.ebpf.jsonl")
            )


@pytest.mark.integration
class TestStructuredSQLiteEvents:
    """Validate that sqlite event rows store structured AbstractEvent fields."""

    def test_sys_events_use_columns_and_payload_keeps_only_extras(self, populated_store: TraceStore):
        asyncio.get_event_loop().run_until_complete(populated_store.poll_once())
        traces = populated_store.list_traces()
        assert traces
        trace_id = traces[0]["trace_id"]

        events = populated_store.sqlite_store.events_for_window(
            trace_id,
            start_ts_ns=0,
            end_ts_ns=9_223_372_036_854_775_807,
        )
        assert events

        file_read = next(
            e
            for e in events
            if str(e.get("event_kind") or "") == "sys" and str(e.get("event_type") or "") == "file_read"
        )
        assert str(file_read.get("path") or "").endswith("index.js")
        assert int(file_read.get("pid") or 0) > 0
        assert int(file_read.get("line_no") or 0) > 0
        assert isinstance(file_read.get("payload"), dict)
        assert "path" not in file_read["payload"]

        command_exec = next(
            e
            for e in events
            if str(e.get("event_kind") or "") == "sys" and str(e.get("event_type") or "") == "command_exec"
        )
        assert str(command_exec.get("exec_path") or "")
        assert str(command_exec.get("command") or "")
        assert isinstance(command_exec.get("argv"), list)

        agent_events = [e for e in events if str(e.get("event_kind") or "") == "agent"]
        assert agent_events
