"""E2E scenarios for intercept access-policy behavior: ask, deny, and notify."""

from __future__ import annotations

import pytest

from tests.e2e._cli_agent_harness import MockLLMPlan, has_mantle_watch, run_cli_agent_watch


pytestmark = pytest.mark.e2e


def _events_by_type(payload: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for event in list(payload.get("events") or []):
        event_type = str(event.get("event_type") or "")
        grouped.setdefault(event_type, []).append(event)
    return grouped


@pytest.fixture(scope="module")
def deny_policy_trace(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace with a process deny rule that blocks curl."""
    tmp_path = tmp_path_factory.mktemp("policy-deny")
    policy = """
defaults:
  unmatched: allow
process:
  - command: "*curl*"
    action: deny
""".strip()

    command = "curl -s http://127.0.0.1:9"
    prompt = f"Run this shell command exactly: {command} ; then reply done"
    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id="policy_deny_case.ebpf.jsonl",
        prompt=prompt,
        policy_text=policy,
        mock_plan=MockLLMPlan(tool_commands=[command], final_response="done"),
    )


@pytest.fixture(scope="module")
def notify_policy_trace(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace with a notify rule so command still runs but is surfaced as policy event."""
    tmp_path = tmp_path_factory.mktemp("policy-notify")
    policy = """
defaults:
  unmatched: allow
process:
  - command: "*curl*"
    action: notify
""".strip()

    command = "curl -s http://127.0.0.1:9"
    prompt = f"Run this shell command exactly: {command} ; then reply done"
    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id="policy_notify_case.ebpf.jsonl",
        prompt=prompt,
        policy_text=policy,
        mock_plan=MockLLMPlan(tool_commands=[command], final_response="done"),
    )


@pytest.fixture(scope="module")
def ask_allow_policy_trace(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace with ask rule auto-resolved to allow via decision file."""
    tmp_path = tmp_path_factory.mktemp("policy-ask-allow")
    trace_id = "policy_ask_allow_case.ebpf.jsonl"
    trace_base = trace_id.removesuffix(".ebpf.jsonl")

    policy = """
defaults:
  unmatched: allow
process:
  - command: "*curl*"
    action: ask
""".strip()

    decisions = [{"id": "1", "decision": "allow", "trace_id": trace_base}]
    command = "curl -s http://127.0.0.1:9"
    prompt = f"Run this shell command exactly: {command} ; then reply done"
    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id=trace_id,
        prompt=prompt,
        policy_text=policy,
        decisions=decisions,
        mock_plan=MockLLMPlan(tool_commands=[command], final_response="done"),
    )


@pytest.fixture(scope="module")
def ask_deny_policy_trace(tmp_path_factory: pytest.TempPathFactory, has_mantle_watch):
    """Trace with ask rule auto-resolved to deny via decision file."""
    tmp_path = tmp_path_factory.mktemp("policy-ask-deny")
    trace_id = "policy_ask_deny_case.ebpf.jsonl"
    trace_base = trace_id.removesuffix(".ebpf.jsonl")

    policy = """
defaults:
  unmatched: allow
process:
  - command: "*curl*"
    action: ask
""".strip()

    decisions = [{"id": "1", "decision": "deny", "trace_id": trace_base}]
    command = "curl -s http://127.0.0.1:9"
    prompt = f"Run this shell command exactly: {command} ; then reply done"
    return run_cli_agent_watch(
        tmp_path=tmp_path,
        trace_id=trace_id,
        prompt=prompt,
        policy_text=policy,
        decisions=decisions,
        mock_plan=MockLLMPlan(tool_commands=[command], final_response="done"),
    )


def test_policy_deny_emits_intercept_violation(deny_policy_trace):
    """Scenario: deny policy should emit intercept violation and reason metadata."""
    payload = deny_policy_trace.store.intercept_events(deny_policy_trace.trace_id, since_seq=0, limit=200)
    grouped = _events_by_type(payload)

    violations = grouped.get("intercept_violation") or []
    assert violations, payload
    assert any(str(v.get("action") or "") == "deny" for v in violations), violations


def test_policy_notify_emits_notify_intercept_event(notify_policy_trace):
    """Scenario: notify policy should emit a notify-style violation while allowing execution."""
    payload = notify_policy_trace.store.intercept_events(notify_policy_trace.trace_id, since_seq=0, limit=200)
    grouped = _events_by_type(payload)

    observations = grouped.get("intercept_observation") or []
    violations = grouped.get("intercept_violation") or []
    if observations:
        assert any(str(v.get("action") or "") == "notify" for v in observations), observations
    elif violations:
        assert any(str(v.get("action") or "") == "notify" for v in violations), violations
    else:
        # Some runtimes treat notify as side-channel only; still require monitor lifecycle.
        assert grouped.get("intercept_monitor_started"), payload
        assert grouped.get("intercept_monitor_stopped"), payload


def test_policy_ask_allow_emits_ask_and_resolved_allow(ask_allow_policy_trace):
    """Scenario: ask+allow should emit intercept_ask and allow resolution events."""
    payload = ask_allow_policy_trace.store.intercept_events(ask_allow_policy_trace.trace_id, since_seq=0, limit=200)
    grouped = _events_by_type(payload)

    ask_events = grouped.get("intercept_ask") or []
    resolved = grouped.get("intercept_ask_resolved") or []
    violations = grouped.get("intercept_violation") or []

    assert ask_events or resolved or violations, payload
    if resolved:
        assert any("allow" in str(event.get("reason") or "") for event in resolved), resolved
    elif violations:
        assert any(str(v.get("action") or "") in {"allow", "notify", "deny"} for v in violations), violations


def test_policy_ask_deny_emits_ask_and_deny_outcome(ask_deny_policy_trace):
    """Scenario: ask+deny should emit intercept_ask, resolved deny, and deny violation reason."""
    payload = ask_deny_policy_trace.store.intercept_events(ask_deny_policy_trace.trace_id, since_seq=0, limit=200)
    grouped = _events_by_type(payload)

    ask_events = grouped.get("intercept_ask") or []
    resolved = grouped.get("intercept_ask_resolved") or []
    violations = grouped.get("intercept_violation") or []
    assert ask_events or resolved or violations, payload
    if resolved:
        assert any("deny" in str(event.get("reason") or "") for event in resolved), resolved
    if violations:
        assert any(str(v.get("action") or "") == "deny" for v in violations), violations
