"""Integration tests for TraceStore ingestion and querying."""

import asyncio
import json

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
