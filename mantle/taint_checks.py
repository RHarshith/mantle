"""Taint propagation checks and helper routines."""

from __future__ import annotations

import json
from typing import Any

from mantle.taint_models import Severity, TaintFinding, TaintFlow, TaintState
from mantle.taint_rules import (
    TaintLabel,
    TrustPolicy,
    classify_file_access,
    classify_network_endpoint,
    is_mcp_endpoint,
    is_sensitive_write_path,
    is_system_path,
)


def build_file_authorship(sys_events: list[dict[str, Any]]) -> set[str]:
    """Return a set of file paths the agent created (wrote to)."""
    written: set[str] = set()
    for ev in sys_events:
        if ev.get("type") == "file_write":
            path = ev.get("path", "")
            if path and not is_system_path(path):
                written.add(path)
    return written


def tool_window_scoped_sys_events(
    sys_events: list[dict[str, Any]],
    agent_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return syscall events that happened during agent tool execution windows."""
    starts: dict[str, float] = {}
    windows: list[tuple[float, float]] = []

    sorted_agent = sorted(agent_events, key=lambda e: (e.get("ts", 0), e.get("seq", 0)))
    for event in sorted_agent:
        et = str(event.get("event_type") or "")
        payload = event.get("payload") or {}
        tool_call_id = str(payload.get("tool_call_id") or "")
        ts = float(event.get("ts") or 0.0)
        if not tool_call_id or ts <= 0:
            continue

        if et == "tool_call_started":
            starts[tool_call_id] = ts
            continue

        if et != "tool_call_finished":
            continue

        start_ts = starts.pop(tool_call_id, 0.0)
        if start_ts <= 0:
            duration_ms = float(payload.get("duration_ms") or 0.0)
            start_ts = ts - (duration_ms / 1000.0) if duration_ms > 0 else (ts - 3.0)

        if start_ts > ts:
            start_ts, ts = ts, start_ts
        windows.append((start_ts, ts))

    if not windows:
        return []

    merged: list[list[float]] = []
    for start, end in sorted(windows, key=lambda w: w[0]):
        if not merged or start > merged[-1][1] + 0.2:
            merged.append([start, end])
            continue
        merged[-1][1] = max(merged[-1][1], end)

    scoped: list[dict[str, Any]] = []
    allowed_types = {
        "file_read",
        "file_write",
        "file_delete",
        "file_rename",
        "net_connect",
        "net_send",
        "net_recv",
        "command_exec",
    }

    for ev in sorted(sys_events, key=lambda e: (e.get("ts", 0), e.get("line_no", 0))):
        et = str(ev.get("type") or "")
        if et not in allowed_types:
            continue
        ts = float(ev.get("ts") or 0.0)
        if ts <= 0:
            continue
        in_window = any((start - 0.1) <= ts <= (end + 0.6) for start, end in merged)
        if in_window:
            scoped.append(ev)

    return scoped


def correlate_bpf_events(
    sys_events: list[dict[str, Any]],
    ts_start: float,
    ts_end: float,
) -> list[dict[str, Any]]:
    return [ev for ev in sys_events if ts_start <= ev.get("ts", 0) <= ts_end]


def taint_label_max(a: TaintLabel, b: TaintLabel) -> TaintLabel:
    order = {TaintLabel.CLEAN: 0, TaintLabel.NONDETERMINISTIC: 1, TaintLabel.TAINTED: 2}
    return a if order[a] >= order[b] else b


def check_tool_result_taint(
    state: TaintState,
    event: dict[str, Any],
    sys_events: list[dict[str, Any]],
    trust_policy: TrustPolicy,
) -> None:
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")
    tool_name = payload.get("tool_name", "")
    result = payload.get("result", {})
    _ = json.dumps(result) if isinstance(result, dict) else str(result)

    if not tool_call_id:
        return

    ts = event.get("ts", 0)
    duration_ms = payload.get("duration_ms", 0) or 0
    ts_start = ts - (duration_ms / 1000.0) if duration_ms else ts - 5.0
    ts_end = ts

    label = TaintLabel.CLEAN
    source_desc = ""

    if tool_name == "command_exec":
        correlated_bpf = correlate_bpf_events(sys_events, ts_start, ts_end)
        for bpf_ev in correlated_bpf:
            if bpf_ev.get("type") == "file_read":
                path = bpf_ev.get("path", "")
                file_label = classify_file_access(path, state.agent_created_files, trust_policy)
                if file_label != TaintLabel.CLEAN:
                    label = taint_label_max(label, file_label)
                    source_desc = f"read external file: {path}"
                    state.flows.append(
                        TaintFlow(
                            from_label=f"file:{path}",
                            to_label=f"tool_result:{tool_call_id}",
                            reason=f"command read {file_label.value} file",
                        )
                    )

            if bpf_ev.get("type") in {"net_recv", "net_connect"}:
                dest = bpf_ev.get("dest", "")
                ep_label = classify_network_endpoint(dest, state.mitm_endpoints)
                if ep_label != TaintLabel.CLEAN:
                    label = taint_label_max(label, ep_label)
                    source_desc = f"network recv from: {dest}"
                    state.flows.append(
                        TaintFlow(
                            from_label=f"net:{dest}",
                            to_label=f"tool_result:{tool_call_id}",
                            reason=f"received data from {ep_label.value} endpoint",
                        )
                    )

    for prev_id, prev_label in state.tainted_tool_results.items():
        if prev_label == TaintLabel.CLEAN:
            continue
        label = taint_label_max(label, prev_label)
        if not source_desc:
            source_desc = state.taint_provenance.get(prev_id, f"tainted tool result {prev_id}")

    if label != TaintLabel.CLEAN:
        state.tainted_tool_results[tool_call_id] = label
        state.taint_provenance[tool_call_id] = source_desc


def check_tool_call_sink(
    state: TaintState,
    event: dict[str, Any],
) -> None:
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")
    tool_name = payload.get("tool_name", "")
    arguments = payload.get("arguments", {})

    if not state.tainted_tool_results:
        return

    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    if tool_name == "command_exec":
        command = arguments.get("command", "") if isinstance(arguments, dict) else ""
        severity = Severity.CRITICAL if max_taint == TaintLabel.TAINTED else Severity.WARNING
        state.findings.append(
            TaintFinding(
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
            )
        )
        state.flows.append(
            TaintFlow(
                from_label=f"tainted_data ({taint_source})",
                to_label=f"command_exec:{tool_call_id}",
                reason="tainted data reaches shell execution",
            )
        )

    elif tool_name == "python_exec":
        code = arguments.get("code", "") if isinstance(arguments, dict) else ""
        severity = Severity.CRITICAL if max_taint == TaintLabel.TAINTED else Severity.WARNING
        state.findings.append(
            TaintFinding(
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
            )
        )
        state.flows.append(
            TaintFlow(
                from_label=f"tainted_data ({taint_source})",
                to_label=f"python_exec:{tool_call_id}",
                reason="tainted data reaches Python execution",
            )
        )


def check_file_write_sink(
    state: TaintState,
    bpf_events: list[dict[str, Any]],
) -> None:
    if not state.tainted_tool_results:
        return

    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    for ev in bpf_events:
        if ev.get("type") != "file_write":
            continue
        path = ev.get("path", "")
        if is_sensitive_write_path(path):
            state.findings.append(
                TaintFinding(
                    severity=Severity.CRITICAL,
                    title="Tainted data written to sensitive path",
                    description=(
                        f"File write to {path} occurred while tainted data "
                        f"({max_taint.value}) from {taint_source} is in scope."
                    ),
                    sink_event=ev,
                    taint_chain=[taint_source, f"file_write: {path}"],
                )
            )
            state.flows.append(
                TaintFlow(
                    from_label=f"tainted_data ({taint_source})",
                    to_label=f"file_write:{path}",
                    reason="tainted data written to sensitive path",
                )
            )


def check_network_exfiltration(
    state: TaintState,
    event: dict[str, Any],
) -> None:
    payload = event.get("payload", {})
    tool_name = payload.get("tool_name", "")
    arguments = payload.get("arguments", {})

    if tool_name != "command_exec":
        return

    if not state.tainted_tool_results:
        return

    command = arguments.get("command", "") if isinstance(arguments, dict) else ""
    sends_data = any(kw in command for kw in ("curl", "wget", "nc ", "ncat"))
    if not sends_data:
        return

    max_taint = TaintLabel.CLEAN
    taint_source = ""
    for tid, label in state.tainted_tool_results.items():
        if label != TaintLabel.CLEAN:
            max_taint = taint_label_max(max_taint, label)
            taint_source = state.taint_provenance.get(tid, f"tool result {tid}")

    if max_taint == TaintLabel.CLEAN:
        return

    state.findings.append(
        TaintFinding(
            severity=Severity.WARNING,
            title="Potential data exfiltration",
            description=(
                f"Network-sending command executed while tainted data "
                f"({max_taint.value}) from {taint_source} is in scope. "
                f"Command: {command[:200]}"
            ),
            sink_event=event,
            taint_chain=[taint_source, f"net_send via: {command[:100]}"],
        )
    )


def check_mcp_source(
    state: TaintState,
    event: dict[str, Any],
) -> None:
    payload = event.get("payload", {})
    tool_call_id = payload.get("tool_call_id", "")

    if not tool_call_id:
        return

    if event.get("event_type") == "api_call":
        endpoint = payload.get("endpoint", "")
        if is_mcp_endpoint(endpoint):
            state.tainted_tool_results[tool_call_id] = TaintLabel.TAINTED
            state.taint_provenance[tool_call_id] = f"MCP server: {endpoint}"
            state.flows.append(
                TaintFlow(
                    from_label=f"mcp:{endpoint}",
                    to_label=f"tool_result:{tool_call_id}",
                    reason="MCP server response (always tainted)",
                )
            )
            state.findings.append(
                TaintFinding(
                    severity=Severity.INFO,
                    title="MCP server data ingested",
                    description=f"Data received from MCP server at {endpoint}",
                    source_event=event,
                    taint_chain=[f"mcp:{endpoint}"],
                )
            )


def check_external_api_source(
    state: TaintState,
    event: dict[str, Any],
    sys_events: list[dict[str, Any]],
) -> None:
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
                state.flows.append(
                    TaintFlow(
                        from_label=f"net:{dest}",
                        to_label=f"tool_result:{tool_call_id}",
                        reason="data from external (non-LLM) API",
                    )
                )
                state.findings.append(
                    TaintFinding(
                        severity=Severity.INFO,
                        title="External API data ingested",
                        description=f"Tool call received data from external endpoint: {dest}",
                        source_event=event,
                        taint_chain=[f"external_api:{dest}"],
                    )
                )
                break


def generate_summary(state: TaintState, trust_policy: TrustPolicy) -> str:
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
        parts.append("WARNING: CRITICAL tainted data reached sensitive sinks.")
    elif n_warn > 0:
        parts.append("WARNING: Potential taint propagation detected.")
    elif n_tainted > 0:
        parts.append("INFO: Tainted data was ingested but did not reach sensitive sinks.")
    else:
        parts.append("OK: No taint propagation detected.")

    return "\n".join(parts)
