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

    def test_mitm_non_object_lines_are_ignored(self, tmp_path):
        obs = tmp_path / "obs"
        traces_dir = obs / "traces"
        events_dir = obs / "events"
        mitm_dir = obs / "mitm"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        mitm_dir.mkdir(parents=True)

        trace_id = "mitm_scalar_regression.ebpf.jsonl"
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

        mitm_file = mitm_dir / "mitm_scalar_regression.mitm.jsonl"
        mitm_file.write_text(
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

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, mitm_dir=mitm_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        traces = store.list_traces()
        assert len(traces) == 1
        # One api_call should be ingested from the valid response object, while
        # the scalar line is skipped without crashing.
        assert traces[0]["agent_event_count"] == 1


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
        obs_root = repo_root / "obs"
        traces_dir = obs_root / "traces"
        events_dir = obs_root / "events"
        mitm_dir = obs_root / "mitm"

        if not traces_dir.exists() or not events_dir.exists() or not mitm_dir.exists():
            pytest.skip("Local obs fixtures not available")

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, mitm_dir=mitm_dir)
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
        mitm_dir = obs / "mitm"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)
        mitm_dir.mkdir(parents=True)

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

        mitm_file = mitm_dir / "proxy_tier_quality.mitm.jsonl"
        mitm_file.write_text(
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

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir, mitm_dir=mitm_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        quality = store.trace_capture_quality(trace_id)
        assert quality["overall_tier"] == "tier1_payload_exact"
        assert quality["tiers"]["tier1_payload_exact"] >= 1
        assert quality["inference_sources"].get("mitm_interval_exact", 0) >= 1


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
