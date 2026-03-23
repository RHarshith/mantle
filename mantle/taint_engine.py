"""Forward taint propagation engine for mantle.

This module intentionally keeps orchestration thin. Core models live in
`taint_models.py` and propagation checks live in `taint_checks.py`.
"""

from __future__ import annotations

from typing import Any

from mantle.taint_checks import (
    build_file_authorship,
    check_external_api_source,
    check_file_write_sink,
    check_mcp_source,
    check_network_exfiltration,
    check_tool_call_sink,
    check_tool_result_taint,
    generate_summary,
    tool_window_scoped_sys_events,
)
from mantle.taint_models import Severity, TaintFinding, TaintFlow, TaintReport, TaintState
from mantle.taint_rules import TrustPolicy


def run_taint_analysis(
    sys_events: list[dict[str, Any]],
    agent_events: list[dict[str, Any]],
    trust_policy: TrustPolicy = TrustPolicy.NONDETERMINISTIC_EXTERNAL_FILES,
    mitm_endpoints: set[str] | None = None,
) -> TaintReport:
    """Run forward taint propagation and return a TaintReport."""
    state = TaintState()
    state.mitm_endpoints = mitm_endpoints or set()

    scoped_sys_events = tool_window_scoped_sys_events(sys_events, agent_events)
    state.agent_created_files = build_file_authorship(scoped_sys_events)

    sorted_events = sorted(agent_events, key=lambda e: (e.get("ts", 0), e.get("seq", 0)))

    for event in sorted_events:
        event_type = event.get("event_type", "")

        if event_type == "api_call":
            check_mcp_source(state, event)

        elif event_type == "tool_call_started":
            check_tool_call_sink(state, event)
            check_network_exfiltration(state, event)

        elif event_type == "tool_call_finished":
            check_tool_result_taint(state, event, scoped_sys_events, trust_policy)
            check_external_api_source(state, event, scoped_sys_events)

    check_file_write_sink(state, scoped_sys_events)

    tainted_entities: list[dict[str, Any]] = []
    for tid, label in state.tainted_tool_results.items():
        if label.value != "clean":
            tainted_entities.append(
                {
                    "type": "tool_result",
                    "id": tid,
                    "label": label.value,
                    "provenance": state.taint_provenance.get(tid, ""),
                }
            )

    for path, label in state.tainted_files.items():
        if label.value != "clean":
            tainted_entities.append(
                {
                    "type": "file",
                    "path": path,
                    "label": label.value,
                }
            )

    report = TaintReport(
        trust_policy=trust_policy,
        findings=state.findings,
        tainted_entities=tainted_entities,
        taint_flows=state.flows,
        agent_created_files=sorted(state.agent_created_files),
        summary=generate_summary(state, trust_policy),
    )
    return report


__all__ = [
    "Severity",
    "TaintFinding",
    "TaintFlow",
    "TaintReport",
    "run_taint_analysis",
]
