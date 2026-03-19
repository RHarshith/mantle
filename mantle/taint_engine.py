"""Forward taint propagation engine for mantle.

Analyses a combination of BPF syscall events and agent-level events to
detect when untrusted data reaches a sensitive sink.

The engine operates on the **agent event stream** for data-flow tracking
and uses **BPF events** for corroboration (file authorship, network
destinations).  It does NOT attempt to reconstruct data content from
raw syscalls — that information is only available in the agent event
payloads (tool call arguments and results).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mantle.taint_rules import (
    TaintLabel,
    TrustPolicy,
    classify_file_access,
    classify_network_endpoint,
    extract_file_paths_from_command,
    is_command_exec_sink,
    is_mcp_endpoint,
    is_python_exec_sink,
    is_sensitive_write_path,
    is_system_path,
)


# ── Data structures ──────────────────────────────────────────────────


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class TaintFinding:
    """A single taint-analysis finding (source → sink)."""

    severity: Severity
    title: str
    description: str
    source_event: dict[str, Any] | None = None
    sink_event: dict[str, Any] | None = None
    taint_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_event_seq": (self.source_event or {}).get("seq"),
            "sink_event_seq": (self.sink_event or {}).get("seq"),
            "taint_chain": self.taint_chain,
        }


@dataclass
class TaintFlow:
    """An edge in the taint propagation graph."""

    from_label: str
    to_label: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_label,
            "to": self.to_label,
            "reason": self.reason,
        }


@dataclass
class TaintReport:
    """Complete taint analysis result."""

    trust_policy: TrustPolicy
    findings: list[TaintFinding] = field(default_factory=list)
    tainted_entities: list[dict[str, Any]] = field(default_factory=list)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    agent_created_files: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_policy": self.trust_policy.value,
            "findings": [f.to_dict() for f in self.findings],
            "tainted_entities": self.tainted_entities,
            "taint_flows": [f.to_dict() for f in self.taint_flows],
            "agent_created_files": self.agent_created_files,
            "summary": self.summary,
            "finding_counts": {
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "warning": sum(1 for f in self.findings if f.severity == Severity.WARNING),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }


# ── Internal state ───────────────────────────────────────────────────


@dataclass
class _TaintState:
    """Mutable state used during forward propagation."""

    agent_created_files: set[str] = field(default_factory=set)
    tainted_files: dict[str, TaintLabel] = field(default_factory=dict)
    tainted_tool_results: dict[str, TaintLabel] = field(default_factory=dict)
    # Maps tool_call_id → source description for provenance tracking.
    taint_provenance: dict[str, str] = field(default_factory=dict)
    findings: list[TaintFinding] = field(default_factory=list)
    flows: list[TaintFlow] = field(default_factory=list)
    # BPF-derived network endpoint taint cache.
    endpoint_taint: dict[str, TaintLabel] = field(default_factory=dict)
    mitm_endpoints: set[str] = field(default_factory=set)


# ── Phase 1: Build file authorship from BPF events ──────────────────


def _build_file_authorship(sys_events: list[dict[str, Any]]) -> set[str]:
    """Return a set of file paths the agent created (wrote to)."""
    written: set[str] = set()
    for ev in sys_events:
        if ev.get("type") == "file_write":
            path = ev.get("path", "")
            if path and not is_system_path(path):
                written.add(path)
    return written


# ── Phase 2: Forward propagation over agent events ──────────────────


def _correlate_bpf_events(
    sys_events: list[dict[str, Any]],
    ts_start: float,
    ts_end: float,
) -> list[dict[str, Any]]:
    """Return BPF events whose timestamp falls within [ts_start, ts_end]."""
    return [
        ev for ev in sys_events
        if ts_start <= ev.get("ts", 0) <= ts_end
    ]


def _taint_label_max(a: TaintLabel, b: TaintLabel) -> TaintLabel:
    """Return the more severe of two labels."""
    order = {TaintLabel.CLEAN: 0, TaintLabel.NONDETERMINISTIC: 1, TaintLabel.TAINTED: 2}
    return a if order[a] >= order[b] else b


def _check_tool_result_taint(
    state: _TaintState,
    event: dict[str, Any],
    sys_events: list[dict[str, Any]],
    trust_policy: TrustPolicy,
) -> None:
    """When a tool_call_finished event arrives, check if its result is tainted."""
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")
    tool_name = payload.get("tool_name", "")
    result = payload.get("result", {})
    result_str = json.dumps(result) if isinstance(result, dict) else str(result)

    if not tool_call_id:
        return

    # Find the matching tool_call_started to get the command/arguments.
    # This is already linked by tool_call_id; for BPF correlation we use
    # the timestamp window.
    ts = event.get("ts", 0)
    duration_ms = payload.get("duration_ms", 0) or 0
    ts_start = ts - (duration_ms / 1000.0) if duration_ms else ts - 5.0
    ts_end = ts

    label = TaintLabel.CLEAN
    source_desc = ""

    if tool_name == "command_exec":
        # Check if any files read during this tool call are tainted.
        correlated_bpf = _correlate_bpf_events(sys_events, ts_start, ts_end)
        for bpf_ev in correlated_bpf:
            if bpf_ev.get("type") == "file_read":
                path = bpf_ev.get("path", "")
                file_label = classify_file_access(path, state.agent_created_files, trust_policy)
                if file_label != TaintLabel.CLEAN:
                    label = _taint_label_max(label, file_label)
                    source_desc = f"read external file: {path}"
                    state.flows.append(TaintFlow(
                        from_label=f"file:{path}",
                        to_label=f"tool_result:{tool_call_id}",
                        reason=f"command read {file_label.value} file",
                    ))

            if bpf_ev.get("type") in {"net_recv", "net_connect"}:
                dest = bpf_ev.get("dest", "")
                ep_label = classify_network_endpoint(dest, state.mitm_endpoints)
                if ep_label != TaintLabel.CLEAN:
                    label = _taint_label_max(label, ep_label)
                    source_desc = f"network recv from: {dest}"
                    state.flows.append(TaintFlow(
                        from_label=f"net:{dest}",
                        to_label=f"tool_result:{tool_call_id}",
                        reason=f"received data from {ep_label.value} endpoint",
                    ))

    # If this tool result contains content from a previously tainted tool
    # result (heuristic: check if any tainted content substrings appear),
    # propagate taint.
    for prev_id, prev_label in state.tainted_tool_results.items():
        if prev_label == TaintLabel.CLEAN:
            continue
        # Taint flows through the LLM — if a previous tool result was
        # tainted, subsequent tool calls that the LLM generates based on
        # that result carry taint forward.
        label = _taint_label_max(label, prev_label)
        if not source_desc:
            source_desc = state.taint_provenance.get(prev_id, f"tainted tool result {prev_id}")

    if label != TaintLabel.CLEAN:
        state.tainted_tool_results[tool_call_id] = label
        state.taint_provenance[tool_call_id] = source_desc


def _check_tool_call_sink(
    state: _TaintState,
    event: dict[str, Any],
) -> None:
    """When a tool_call_started event arrives, check if it's a tainted sink."""
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")
    tool_name = payload.get("tool_name", "")
    arguments = payload.get("arguments", {})

    # We detect sink violations when there are previously tainted tool results
    # and the LLM is now using that data in a sensitive operation.
    if not state.tainted_tool_results:
        return

    # Get the highest taint level from previous results.
    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = _taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    if tool_name == "command_exec":
        command = arguments.get("command", "") if isinstance(arguments, dict) else ""
        severity = Severity.CRITICAL if max_taint == TaintLabel.TAINTED else Severity.WARNING
        state.findings.append(TaintFinding(
            severity=severity,
            title="Tainted data used in shell command",
            description=(
                f"Tool call executes a shell command after receiving "
                f"{max_taint.value} data from: {taint_source}. "
                f"Command: {command[:200]}"
            ),
            source_event=None,
            sink_event=event,
            taint_chain=[taint_source, f"command_exec: {command[:100]}"],
        ))
        state.flows.append(TaintFlow(
            from_label=f"tainted_data ({taint_source})",
            to_label=f"command_exec:{tool_call_id}",
            reason="tainted data reaches shell execution",
        ))

    elif tool_name == "python_exec":
        code = arguments.get("code", "") if isinstance(arguments, dict) else ""
        severity = Severity.CRITICAL if max_taint == TaintLabel.TAINTED else Severity.WARNING
        state.findings.append(TaintFinding(
            severity=severity,
            title="Tainted data used in Python exec",
            description=(
                f"Tool call executes Python code after receiving "
                f"{max_taint.value} data from: {taint_source}. "
                f"Code preview: {code[:200]}"
            ),
            source_event=None,
            sink_event=event,
            taint_chain=[taint_source, f"python_exec: {code[:100]}"],
        ))
        state.flows.append(TaintFlow(
            from_label=f"tainted_data ({taint_source})",
            to_label=f"python_exec:{tool_call_id}",
            reason="tainted data reaches Python execution",
        ))


def _check_file_write_sink(
    state: _TaintState,
    bpf_events: list[dict[str, Any]],
) -> None:
    """Check BPF file_write events for writes to sensitive paths with tainted data."""
    if not state.tainted_tool_results:
        return

    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = _taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    for ev in bpf_events:
        if ev.get("type") != "file_write":
            continue
        path = ev.get("path", "")
        if is_sensitive_write_path(path):
            state.findings.append(TaintFinding(
                severity=Severity.CRITICAL,
                title="Tainted data written to sensitive path",
                description=(
                    f"File write to {path} occurred while tainted data "
                    f"({max_taint.value}) from {taint_source} is in scope."
                ),
                sink_event=ev,
                taint_chain=[taint_source, f"file_write: {path}"],
            ))
            state.flows.append(TaintFlow(
                from_label=f"tainted_data ({taint_source})",
                to_label=f"file_write:{path}",
                reason="tainted data written to sensitive path",
            ))


def _check_network_exfiltration(
    state: _TaintState,
    event: dict[str, Any],
) -> None:
    """Check if a tool call sends data to a non-LLM endpoint (exfiltration)."""
    payload = event.get("payload", {})
    tool_name = payload.get("tool_name", "")
    arguments = payload.get("arguments", {})

    if tool_name != "command_exec":
        return

    if not state.tainted_tool_results:
        return

    command = arguments.get("command", "") if isinstance(arguments, dict) else ""
    # Heuristic: commands that use curl/wget to POST data to external endpoints.
    sends_data = any(kw in command for kw in ("curl", "wget", "nc ", "ncat"))
    if not sends_data:
        return

    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = _taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    state.findings.append(TaintFinding(
        severity=Severity.WARNING,
        title="Potential data exfiltration",
        description=(
            f"Network-sending command executed while tainted data "
            f"({max_taint.value}) from {taint_source} is in scope. "
            f"Command: {command[:200]}"
        ),
        sink_event=event,
        taint_chain=[taint_source, f"net_send via: {command[:100]}"],
    ))


def _check_mcp_source(
    state: _TaintState,
    event: dict[str, Any],
) -> None:
    """Mark tool results from MCP servers as tainted."""
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")
    tool_name = payload.get("tool_name", "")

    # Agent events from MITM may show the endpoint; we also look at
    # tool names that hint at MCP origin.
    if not tool_call_id:
        return

    # If this is an api_call event, check the endpoint.
    if event.get("event_type") == "api_call":
        endpoint = payload.get("endpoint", "")
        if is_mcp_endpoint(endpoint):
            state.tainted_tool_results[tool_call_id] = TaintLabel.TAINTED
            state.taint_provenance[tool_call_id] = f"MCP server: {endpoint}"
            state.flows.append(TaintFlow(
                from_label=f"mcp:{endpoint}",
                to_label=f"tool_result:{tool_call_id}",
                reason="MCP server response (always tainted)",
            ))
            state.findings.append(TaintFinding(
                severity=Severity.INFO,
                title="MCP server data ingested",
                description=f"Data received from MCP server at {endpoint}",
                source_event=event,
                taint_chain=[f"mcp:{endpoint}"],
            ))


def _check_external_api_source(
    state: _TaintState,
    event: dict[str, Any],
    sys_events: list[dict[str, Any]],
) -> None:
    """Mark tool results that received data from external APIs as tainted."""
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")

    if not tool_call_id or tool_call_id in state.tainted_tool_results:
        return

    ts = event.get("ts", 0)
    duration_ms = payload.get("duration_ms", 0) or 0
    ts_start = ts - (duration_ms / 1000.0) if duration_ms else ts - 5.0

    for bpf_ev in sys_events:
        bpf_ts = bpf_ev.get("ts", 0)
        if bpf_ts < ts_start or bpf_ts > ts:
            continue
        if bpf_ev.get("type") in {"net_recv", "net_connect"}:
            dest = bpf_ev.get("dest", "")
            label = classify_network_endpoint(dest, state.mitm_endpoints)
            if label == TaintLabel.TAINTED:
                state.tainted_tool_results[tool_call_id] = TaintLabel.TAINTED
                state.taint_provenance[tool_call_id] = f"external API: {dest}"
                state.flows.append(TaintFlow(
                    from_label=f"net:{dest}",
                    to_label=f"tool_result:{tool_call_id}",
                    reason="data from external (non-LLM) API",
                ))
                state.findings.append(TaintFinding(
                    severity=Severity.INFO,
                    title="External API data ingested",
                    description=f"Tool call received data from external endpoint: {dest}",
                    source_event=event,
                    taint_chain=[f"external_api:{dest}"],
                ))
                break


# ── Phase 3: Produce report ──────────────────────────────────────────


def _generate_summary(state: _TaintState, trust_policy: TrustPolicy) -> str:
    """Generate a human-readable summary."""
    n_crit = sum(1 for f in state.findings if f.severity == Severity.CRITICAL)
    n_warn = sum(1 for f in state.findings if f.severity == Severity.WARNING)
    n_info = sum(1 for f in state.findings if f.severity == Severity.INFO)
    n_tainted = sum(1 for v in state.tainted_tool_results.values() if v != TaintLabel.CLEAN)

    parts = []
    parts.append(f"Trust policy: {trust_policy.value}")
    parts.append(f"Agent-created files: {len(state.agent_created_files)}")
    parts.append(f"Tainted tool results: {n_tainted}")
    parts.append(f"Findings: {n_crit} critical, {n_warn} warning, {n_info} info")

    if n_crit > 0:
        parts.append("⚠️  CRITICAL: Tainted data reached sensitive sinks.")
    elif n_warn > 0:
        parts.append("⚠️  WARNING: Potential taint propagation detected.")
    elif n_tainted > 0:
        parts.append("ℹ️  Tainted data was ingested but did not reach sensitive sinks.")
    else:
        parts.append("✅ No taint propagation detected.")

    return "\n".join(parts)


# ── Public API ───────────────────────────────────────────────────────


def run_taint_analysis(
    sys_events: list[dict[str, Any]],
    agent_events: list[dict[str, Any]],
    trust_policy: TrustPolicy = TrustPolicy.NONDETERMINISTIC_EXTERNAL_FILES,
    mitm_endpoints: set[str] | None = None,
) -> TaintReport:
    """Run forward taint propagation and return a TaintReport.

    Parameters
    ----------
    sys_events : list
        BPF syscall events (from .ebpf.jsonl).
    agent_events : list
        Agent-level events (from .events.jsonl or MITM-derived).
    trust_policy : TrustPolicy
        How to treat files not created by the agent.
    mitm_endpoints : set, optional
        Known MITM proxy endpoints to treat as LLM passthrough.
    """
    state = _TaintState()
    state.mitm_endpoints = mitm_endpoints or set()

    # Phase 1: File authorship.
    state.agent_created_files = _build_file_authorship(sys_events)

    # Phase 2: Forward propagation over agent events.
    sorted_events = sorted(agent_events, key=lambda e: (e.get("ts", 0), e.get("seq", 0)))

    for event in sorted_events:
        event_type = event.get("event_type", "")

        if event_type == "api_call":
            _check_mcp_source(state, event)

        elif event_type == "tool_call_started":
            _check_tool_call_sink(state, event)
            _check_network_exfiltration(state, event)

        elif event_type == "tool_call_finished":
            _check_tool_result_taint(state, event, sys_events, trust_policy)
            _check_external_api_source(state, event, sys_events)

    # Check BPF-level file write sinks.
    _check_file_write_sink(state, sys_events)

    # Phase 3: Report.
    tainted_entities = []
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            tainted_entities.append({
                "type": "tool_result",
                "id": tid,
                "label": label.value,
                "provenance": state.taint_provenance.get(tid, ""),
            })
    for path, label in state.tainted_files.items():
        if label != TaintLabel.CLEAN:
            tainted_entities.append({
                "type": "file",
                "path": path,
                "label": label.value,
            })

    report = TaintReport(
        trust_policy=trust_policy,
        findings=state.findings,
        tainted_entities=tainted_entities,
        taint_flows=state.flows,
        agent_created_files=sorted(state.agent_created_files),
        summary=_generate_summary(state, trust_policy),
    )
    return report
