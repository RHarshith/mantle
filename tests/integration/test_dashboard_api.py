"""Integration tests for the FastAPI dashboard REST endpoints."""

import asyncio
import json
from pathlib import Path

import pytest

from mantle.ingest.store import TraceStore

# FastAPI TestClient requires httpx — guard import for environments without it.
try:
    from fastapi.testclient import TestClient
    HAS_TEST_CLIENT = True
except ImportError:
    HAS_TEST_CLIENT = False


@pytest.fixture
def dashboard_app(populated_obs_dir: Path):
    """Create a FastAPI app wired to a populated TraceStore."""
    if not HAS_TEST_CLIENT:
        pytest.skip("fastapi[testclient] / httpx not installed")

    # Import inline to avoid top-level failure if fastapi is not installed.
    from mantle.server.app import app, store

    # Rewire the global store with our test data directory.
    store.trace_dir = populated_obs_dir / "traces"
    store.events_dir = populated_obs_dir / "events"
    store.mitm_dir = populated_obs_dir / "mitm"
    store.traces.clear()
    store.version = 0

    asyncio.get_event_loop().run_until_complete(store.poll_once())
    return app


@pytest.fixture
def client(dashboard_app):
    return TestClient(dashboard_app)


@pytest.mark.integration
class TestDashboardAPI:
    def test_list_traces(self, client):
        resp = client.get("/api/traces")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list) or "traces" in data

    def test_get_settings(self, client):
        resp = client.get("/api/settings/llm-schemas")
        assert resp.status_code == 200

    def test_unknown_trace_returns_404_or_error(self, client):
        resp = client.get("/api/traces/nonexistent/graph")
        # May return 404 or error body depending on implementation
        assert resp.status_code in (404, 400, 500)
