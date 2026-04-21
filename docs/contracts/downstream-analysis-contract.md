# Contract: Downstream Analysis and API Payloads

Status: active
Version: v1
Owner: mantle/ingest/store.py + mantle/server/app.py
Boundary: SQLite + correlated in-memory trace model -> HTTP API payloads for dashboard

## Purpose

Define exact API response shapes used by dashboard analysis features, with replay as the primary consumer.

## Endpoint Contract Set (Replay-Critical)

## Anomaly Report Shape

When present, anomaly payloads follow this structure:

```json
{
  "verdict": "CLEAN|SUSPICIOUS|VIOLATION",
  "has_anomaly": false,
  "summary": "verified tool call",
  "total_violations": 0,
  "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
}
```

Tool-level anomaly reports may also include detailed fields:

```json
{
  "command": "python3 script.py",
  "root_pid": 123,
  "violations": [],
  "unsupported_checks": [
    "sensitive_env_var_reads_not_captured",
    "chmod_chown_outside_scope_not_captured"
  ]
}
```

### 1) Replay turn list

`GET /api/traces/{trace_id}/replay-turns`

```json
{
  "trace_id": "python_20260414_105434.ebpf.jsonl",
  "turns": [
    {
      "turn_id": "turn_1",
      "label": "T1",
      "index": 1,
      "tool_call_count": 1,
      "context_section_count": 4,
      "action_section_count": 3,
      "start_ts": 1776182079.47,
      "end_ts": 1776182081.35
    }
  ]
}
```

### 2) Replay turn detail

`GET /api/traces/{trace_id}/replay-turns/{turn_id}`

```json
{
  "trace_id": "...",
  "turn_id": "turn_1",
  "label": "T1",
  "start_ts": 1776182079.47,
  "end_ts": 1776182081.35,
  "context": {
    "sections": [
      {
        "id": "system_prompt",
        "label": "System prompt",
        "values": ["..."],
        "count": 1,
        "style": "system",
        "sources": [{"status": "matched", "pid": 1234}]
      }
    ],
    "text": "..."
  },
  "action": {
    "sections": [
      {
        "id": "assistant_text",
        "label": "Assistant text",
        "values": ["..."],
        "count": 1,
        "style": "assistant"
      }
    ],
    "text": "..."
  },
  "tool_call_response_pairs": [
    {
      "tool_call_id": "call_x",
      "tool_name": "command_exec",
      "arguments": {},
      "response": {},
      "started_ts": 1776182079.48,
      "finished_ts": 1776182079.49,
      "source": {"status": "matched", "pid": 522158},
      "anomaly": {"verdict": "CLEAN", "has_anomaly": false, "summary": "verified tool call", "total_violations": 0, "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}}
    }
  ],
  "summary": {
    "tool_calls": 1,
    "context_tokens": 123,
    "files_read": 0,
    "files_written": 1,
    "subprocesses_spawned": 0,
    "network_calls": 0,
    "context_sections": 4,
    "action_sections": 3,
    "anomaly": {"verdict": "CLEAN", "has_anomaly": false, "summary": "verified tool call", "total_violations": 0, "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}},
    "tool_call_pairs": [],
    "file_activity": {"read_paths": [], "write_paths": [], "tree": {}},
    "subprocesses": []
  }
}
```

`source` object contract:

- matched: `{"status": "matched", "pid": <int>}`
- unresolved: `{"status": "source_not_found"}`

### 3) Turn detail (used by replay source-map priming and process drilldown)

`GET /api/traces/{trace_id}/turns/{turn_id}`

```json
{
  "trace_id": "...",
  "turn_id": "turn_1",
  "label": "T1",
  "summary": {
    "tool_calls": 1,
    "files_read": 0,
    "files_written": 1,
    "subprocesses_spawned": 0,
    "network_calls": 0,
    "anomaly": {"verdict": "CLEAN", "has_anomaly": false, "summary": "verified tool call", "total_violations": 0, "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}}
  },
  "anomaly": {"verdict": "CLEAN", "has_anomaly": false, "summary": "verified tool call", "total_violations": 0, "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}},
  "prompt_text": "...",
  "response_text": "...",
  "prompt_sections": [],
  "response_sections": [],
  "pre_tool_counts": {"file_read": 0, "file_write": 0, "process_spawn": 0, "network": 0},
  "timeline": [
    {"entry_type": "tool_call", "tool_call_id": "call_x", "source": {"status": "matched", "pid": 522158}},
    {"entry_type": "system_group", "category": "file", "tree": {}}
  ],
  "start_ts": 1776182079.47,
  "end_ts": 1776182081.35
}
```

### 4) Process subtrace (popup from source links)

`GET /api/traces/{trace_id}/process-subtrace/{turn_id}/{pid}?full_lifecycle=1`

```json
{
  "trace_id": "...",
  "turn_id": "turn_1",
  "pid": 522158,
  "full_lifecycle": true,
  "summary": {
    "command": "...",
    "exec_commands": ["..."],
    "pid": 522158,
    "parent_pid": 522100,
    "duration_ms": 1234.5,
    "exit_code": 0,
    "files_read": 3,
    "files_written": 1,
    "child_processes_spawned": 0,
    "network_calls": 1
  },
  "timeline": []
}
```

### 5) Replay state diff (turn range)

`GET /api/traces/{trace_id}/replay-state-diff?from_turn_id=turn_1&to_turn_id=turn_4`

```json
{
  "trace_id": "...",
  "turns": [{"turn_id": "turn_1", "label": "T1", "index": 1}],
  "selected": {"from_turn_id": "turn_1", "to_turn_id": "turn_4"},
  "summary": {"files_changed": 2, "lines_added": 15, "lines_removed": 4, "total_changed": 19},
  "tree": {"name": "/", "kind": "folder", "children": [], "counts": {"files": 2, "added": 15, "removed": 4, "total": 19}},
  "files": [
    {
      "path": "temp.txt",
      "lines_added": 1,
      "lines_removed": 0,
      "lines_changed": 1,
      "total_changed": 1,
      "binary": false,
      "truncated": false
    }
  ]
}
```

### 6) Replay state diff for one file

`GET /api/traces/{trace_id}/replay-state-diff/file?path=temp.txt&from_turn_id=turn_1&to_turn_id=turn_4`

```json
{
  "trace_id": "...",
  "path": "temp.txt",
  "selected": {"from_turn_id": "turn_1", "to_turn_id": "turn_4"},
  "stats": {"lines_added": 1, "lines_removed": 0, "lines_changed": 1, "total_changed": 1},
  "binary": false,
  "truncated": false,
  "diff": "--- a/temp.txt\n+++ b/temp.txt\n..."
}
```

### 7) Unified event viewer (raw/system timeline)

`GET /api/traces/{trace_id}/display-trace?pid=<optional>&start_timestamp=<optional>&end_timestamp=<optional>`

```json
{
  "trace_id": "...",
  "scope": {
    "pid": 522158,
    "start_timestamp": 1776182079.47,
    "end_timestamp": 1776182081.35,
    "has_timestamp_filter": true
  },
  "summary": {
    "event_count": 21,
    "direct": {"files_read": 1, "files_written": 0, "network_calls": 1, "process_spawns": 1},
    "nested": {"files_read": 2, "files_written": 1, "network_calls": 0, "process_spawns": 0},
    "totals": {"files_read": 3, "files_written": 1, "network_calls": 1, "process_spawns": 1}
  },
  "timeline": []
}
```

Rules:

- `pid` omitted: include all events in the provided timestamp range.
- `pid` present + timestamps omitted: infer lifecycle window from process start/fork to exit.
- `pid` present + timestamps present: apply pid-descendant filter and timestamp filter.
- frontend raw-event viewers must call this endpoint for both replay raw-tab and source-pid popup flows.

## Additional Anomaly-Carrying Endpoints

- `GET /api/traces` trace rows include:
  - `anomaly` (Anomaly Report Shape)
  - `anomaly_verdict`
  - `anomaly_detected`

- `GET /api/traces/{trace_id}/summary` includes:
  - `anomaly` (Anomaly Report Shape)

- `GET /api/traces/{trace_id}/tool-summary/{tool_call_id}` includes:
  - `anomalies` (tool-level anomaly report)

- `GET /api/traces/{trace_id}/tool-graph/{tool_call_id}` includes:
  - `anomalies` (tool-level anomaly report)

## Additional Dashboard Metrics API (Overview Tabs)

- `GET /api/dimensions/metrics` returns:

```json
{
  "traces": [
    {
      "trace_id": "...",
      "status": "active|completed",
      "turn_count": 1,
      "tool_call_count": 1,
      "correctness": {},
      "safety": {},
      "efficiency": {}
    }
  ],
  "version": 12
}
```

Frontend correctness/safety/efficiency cards depend on these nested objects and key names.

## Error Contract

- Unknown `trace_id` -> HTTP 404 from server layer.
- Unknown `turn_id` / missing file diff target -> HTTP 404.
- Validation errors (for example missing query `path`) -> HTTP 400.

## Change Gate

Any response-shape change here is breaking for frontend rendering and must update together:

- `mantle/ingest/store.py`
- `mantle/server/app.py`
- `mantle/server/static/app.js`
- API integration tests and dashboard e2e smoke tests
