"""Integration regression tests for watch launcher environment propagation."""

from pathlib import Path

import pytest


@pytest.mark.integration
def test_watch_sudo_preserve_env_includes_home():
    """`mantle watch` should preserve HOME when escalating via sudo."""
    script = Path("bin/mantle").read_text(encoding="utf-8")
    assert "--preserve-env=" in script
    assert "HOME" in script
    assert "PWD" in script
    assert "MANTLE_AGENT_CWD" in script


@pytest.mark.integration
def test_watch_sudo_preserve_env_includes_copilot_auth_context():
    """`mantle watch` should keep Copilot auth env/context variables across sudo."""
    script = Path("bin/mantle").read_text(encoding="utf-8")
    assert "--preserve-env=" in script
    assert "XDG_CONFIG_HOME" in script
    assert "XDG_STATE_HOME" in script
    assert "XDG_CACHE_HOME" in script
    assert "XDG_RUNTIME_DIR" in script
    assert "DBUS_SESSION_BUS_ADDRESS" in script
    assert "GITHUB_TOKEN" in script
    assert "GH_TOKEN" in script


@pytest.mark.integration
def test_runner_executes_agent_as_invoking_user_when_sudoed():
    """Runner should drop back to invoking user context for agent execution."""
    script = Path("run_intercepted_agent.sh").read_text(encoding="utf-8")
    assert "SUDO_USER" in script
    assert "sudo -u" in script


@pytest.mark.integration
def test_runner_preserves_agent_observability_env_when_sudoed():
    """Runner should preserve trace/event env vars when executing agent as invoking user."""
    script = Path("run_intercepted_agent.sh").read_text(encoding="utf-8")
    assert "agent_preserve_env=" in script
    assert "AGENT_TRACE_ID" in script
    assert "AGENT_OBS_ENABLED" in script
    assert "AGENT_OBS_ROOT" in script
    assert "PWD" in script
    assert "MANTLE_AGENT_CWD" in script


@pytest.mark.integration
def test_runner_enforces_agent_cwd_before_monitor_exec():
    """Runner should `cd` into caller cwd before launching the intercept monitor."""
    script = Path("run_intercepted_agent.sh").read_text(encoding="utf-8")
    assert "AGENT_CWD" in script
    assert "cd $(printf '%q' \"$AGENT_CWD\")" in script


@pytest.mark.integration
def test_runner_seeds_copilot_mitm_when_capture_empty():
    """Runner should include a Copilot MITM fallback seeding path for empty captures."""
    script = Path("run_intercepted_agent.sh").read_text(encoding="utf-8")
    assert "seed_copilot_mitm_from_logs_if_empty" in script
    assert ".copilot/logs" in script
    assert "copilot-log-fallback" in script
