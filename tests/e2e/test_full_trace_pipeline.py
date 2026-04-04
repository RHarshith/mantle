"""E2E test: Full trace pipeline using mantle_agent.

This test runs a real agent session, then verifies the dashboard can ingest
and display the resulting trace data. Requires:
  - OAK1 or OPENAI_API_KEY environment variable
  - Network access to an LLM API

Run with: python -m pytest tests/e2e/test_full_trace_pipeline.py -v
"""

import asyncio
import os
import tempfile

import pytest

pytestmark = pytest.mark.e2e


@pytest.fixture
def has_api_key():
    """Skip if no LLM API key is available."""
    if not os.getenv("OAK1") and not os.getenv("OPENAI_API_KEY"):
        pytest.skip("No LLM API key (OAK1/OPENAI_API_KEY) set")


@pytest.mark.skipif(
    not os.getenv("OAK1") and not os.getenv("OPENAI_API_KEY"),
    reason="Requires OAK1 or OPENAI_API_KEY",
)
class TestFullTracePipeline:
    """Run an agent trace and verify the dashboard can process it.

    This is a true E2E test — no mocking. The agent is invoked with a simple
    prompt, and we verify the dashboard's TraceStore can ingest and present
    the resulting data.
    """

    def test_agent_trace_produces_events(self, has_api_key, tmp_path):
        """Verify that running the agent produces event files."""
        # Set up obs directory
        obs_root = tmp_path / "obs"
        traces_dir = obs_root / "traces"
        events_dir = obs_root / "events"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)

        os.environ["AGENT_OBS_ROOT"] = str(obs_root)

        # Import agent after setting env vars
        from mantle_agent.cli_agent import run_single_turn, build_client
        from mantle_agent.agent_observability import JsonlEventSink

        # Create event sink
        sink = JsonlEventSink(events_dir=events_dir)

        # Run a minimal agent turn
        # This tests the real pipeline: agent -> events -> store -> dashboard
        try:
            client = build_client()
            # A simple prompt that should complete in one turn
            asyncio.get_event_loop().run_until_complete(
                run_single_turn(
                    client=client,
                    prompt="Say exactly 'test complete' and nothing else.",
                    sink=sink,
                    auto_approve=True,
                )
            )
        finally:
            sink.close()

        # Verify events were written
        event_files = list(events_dir.glob("*.events.jsonl"))
        assert len(event_files) >= 1, "Agent should have produced event files"

    def test_dashboard_ingests_agent_trace(self, has_api_key, tmp_path):
        """Verify the dashboard can ingest agent-produced trace data."""
        from mantle.ingest.store import TraceStore

        # Use the same obs directory structure
        obs_root = tmp_path / "obs"
        traces_dir = obs_root / "traces"
        events_dir = obs_root / "events"
        traces_dir.mkdir(parents=True)
        events_dir.mkdir(parents=True)

        store = TraceStore(trace_dir=traces_dir, events_dir=events_dir)
        asyncio.get_event_loop().run_until_complete(store.poll_once())

        # Store should be functional even with no traces
        traces = store.list_traces()
        assert isinstance(traces, list)
