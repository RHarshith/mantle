"""Integration regression tests for intercepted command feedback in cli_agent."""

from __future__ import annotations

import json
import sys

import pytest

import cli_agent


@pytest.mark.integration
def test_denied_command_appends_intercept_reason_to_stderr(monkeypatch):
    """Denied command stderr should include a human-readable intercept explanation."""

    # Future behavior: cli_agent should consult the latest intercept violation
    # and append an actionable message for the agent.
    monkeypatch.setattr(
        cli_agent,
        "_find_recent_intercept_violation_for_pid",
        lambda _pid: {
            "details": {"category": "filesystem", "op": "open", "path": "/tmp/secret.txt"},
            "reason": "ask_decision_deny",
        },
        raising=False,
    )

    raw = cli_agent.run_command_exec(
        f"{sys.executable} -c \"import sys; sys.stderr.write('Permission denied\\n'); raise SystemExit(1)\""
    )
    payload = json.loads(raw)

    assert payload["ok"] is False
    assert "Permission denied" in payload.get("stderr", "")
    assert "Denied by Mantle intercept policy" in payload.get("stderr", "")
