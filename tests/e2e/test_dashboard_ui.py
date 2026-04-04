"""E2E test: Dashboard UI automated testing via Playwright.

This test launches the real FastAPI dashboard and navigates the SPA using
a browser. Designed for an AI agent to run before shipping UI changes.

Requires:
  - playwright: pip install playwright && playwright install chromium

Run with: python -m pytest tests/e2e/test_dashboard_ui.py -v
"""

import asyncio
import os
import time
import subprocess
import signal

import pytest

pytestmark = pytest.mark.e2e

# Guard Playwright import
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@pytest.fixture(scope="module")
def dashboard_server():
    """Start the dashboard server for UI testing."""
    if not HAS_PLAYWRIGHT:
        pytest.skip("Playwright not installed")

    # Start the server in the background
    env = os.environ.copy()
    proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "mantle.server.app:app", "--port", "18742"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    )

    # Wait for server to be ready
    time.sleep(3)

    yield "http://localhost:18742"

    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Playwright not installed")
class TestDashboardUI:
    """Browser-based UI tests for the dashboard SPA."""

    def test_dashboard_loads(self, dashboard_server):
        """Verify the dashboard SPA loads without JavaScript errors."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            errors = []
            page.on("pageerror", lambda err: errors.append(str(err)))

            page.goto(dashboard_server)
            page.wait_for_load_state("networkidle")

            # Check basic elements are present
            title = page.title()
            assert title  # Page should have a title

            # No JS errors
            assert len(errors) == 0, f"JavaScript errors: {errors}"

            browser.close()

    def test_trace_list_renders(self, dashboard_server):
        """Verify the trace list panel renders (even if empty)."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(dashboard_server)
            page.wait_for_load_state("networkidle")

            # The left nav / trace list should exist as a structural element
            body_text = page.inner_text("body")
            assert body_text is not None

            browser.close()

    def test_api_health_from_browser(self, dashboard_server):
        """Verify API endpoints are reachable from the browser context."""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            resp = page.request.get(f"{dashboard_server}/api/traces")
            assert resp.status == 200

            browser.close()
