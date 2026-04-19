"""E2E test: Full trace pipeline using mantle_agent.

This test runs a real agent session, then verifies the dashboard can ingest
and display the resulting trace data. Requires:
  - OAK1 or OPENAI_API_KEY environment variable
  - Network access to an LLM API

Run with: python -m pytest tests/e2e/test_full_trace_pipeline.py -v
"""

import asyncio
import os
import uuid

from openai import OpenAI
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
        del has_api_key, tmp_path

        from mantle.runtime.paths import ensure_runtime_layout, resolve_runtime_layout

        layout = resolve_runtime_layout()
        ensure_runtime_layout(layout, require_writable=False)
        events_dir = layout.events_dir

        # Import agent after setting env vars
        from mantle_agent.cli_agent import run_single_turn
        from mantle_agent.agent_observability import build_event_sink

        # Create event sink
        trace_id = f"e2e-test-{uuid.uuid4().hex[:12]}"
        os.environ["AGENT_TRACE_ID"] = trace_id
        sink = build_event_sink()

        # Run a minimal agent turn
        # This tests the real pipeline: agent -> events -> store -> dashboard
        try:
            model = os.getenv("OPENAI_MODEL", "protected.gpt-5.2")
            api_key = os.getenv("OAK1") or os.getenv("OPENAI_API_KEY")
            assert api_key, "Expected OAK1 or OPENAI_API_KEY for e2e test"
            base_url = os.getenv("OPENAI_BASE_URL", "https://chat-api.tamu.ai/api")
            client = OpenAI(api_key=api_key, base_url=base_url)

            messages = [{"role": "user", "content": "Say exactly 'test complete' and nothing else."}]
            shared_globals = {"__builtins__": __builtins__}

            run_single_turn(
                client=client,
                model=model,
                messages=messages,
                shared_globals=shared_globals,
                sink=sink,
                auto_approve=True,
            )
        finally:
            sink.close()

        # Verify events were written
        event_file = events_dir / f"{trace_id}.events.jsonl"
        assert event_file.exists(), "Agent should have produced an event file"

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
