# Contract: Post-processing, Correlation, and DB Ingest

Status: active
Version: v1
Owner: mantle/ingest/store.py + mantle/ingest/sqlite_store.py
Boundary: raw capture files (ebpf + events + proxy) -> correlated turns/tool calls -> SQLite

## Purpose

Define how raw capture inputs are merged, normalized, correlated into turn semantics, and persisted into canonical SQLite tables.

## Input Sources

- System capture: `obs/traces/<trace_id>.ebpf.jsonl`
- Native agent events (optional): `obs/events/<trace_id>.events.jsonl`
- LiteLLM proxy traffic (optional): `litellm_proxy/bpf_logs/*.log` (or configured proxy log file)

## Source Priority Rules

For each trace in `TraceStore.poll_once`:

- eBPF lines are always tailed for system events.
- `llm_capture_source` is proxy-only (`proxy`).
- if native events file exists:
  - native events become primary agent-event source
  - proxy payload source is tailed in `intervals_only=true` mode (endpoint interval inference only)
- if native events file does not exist:
  - proxy payload source is tailed and converted into synthetic agent events

Deterministic proxy log resolution rules:

- explicit configured proxy log file has highest priority
- then trace-id keyed files (for example `<trace_id>` and `<trace>.proxy.jsonl`)
- in `proxy` mode only, if exactly one `*.log` exists it is used
- in `proxy` mode, multiple unmatched `*.log` files are an error (no silent fallback)

## Agent Event Canonical Shape

```json
{
  "ts": 1776182079.4761615,
  "seq": 3,
  "event_type": "tool_call_started",
  "payload": {},
  "_source": "proxy"
}
```

Synthetic `event_type` values produced from active LLM payload response records:

- `api_call`
- `system_instruction`
- `user_prompt_batch`
- `reasoning_summary`
- `assistant_response`
- `tool_call_started`
- `tool_call_finished`

`api_call.payload` shape:

```json
{
  "endpoint": "https://chat-api.tamu.ai/api/chat/completions",
  "method": "POST",
  "model": "gpt-5.2-2025-12-11",
  "duration_ms": 1565,
  "status_code": 200,
  "reasoning": "low|medium|high|...",
  "available_tools": ["python_exec", "command_exec"]
}
```

Tool event payload contract:

```json
{
  "tool_call_id": "call_x",
  "tool_name": "command_exec",
  "arguments": {},
  "duration_ms": 10,
  "result": {}
}
```

## System Event Enrichment Contract

Network events may be enriched with inferred endpoint metadata:

```json
{
  "inferred_dest": "api.openai.com:443",
  "inferred_dest_source": "proxy_interval_exact|proxy_interval_nearest|proxy_global_fallback|precomputed",
  "capture_tier": "tier1_payload_exact|tier2_payload_mapped|tier3_network_only",
  "capture_tier_rank": 1,
  "capture_tier_reason": "proxy_interval_exact"
}
```

Tier semantics:

- `tier1_payload_exact`: proxy interval exact containment
- `tier2_payload_mapped`: heuristic/nearest/mapped endpoint inference
- `tier3_network_only`: only baseline network telemetry

## Turn Correlation Contract

Turns are derived from proxy payload timestamps with response-driven boundaries.

Boundary parser contract (`mantle/analysis/llm_parser.py`):

- each `direction=response` record that matches an LLM schema is boundary-capable
- if a prior `direction=request` record exists for the same URL (`request.ts <= response.ts`),
  request context is attached to that response boundary
- unmatched requests are retained as pending calls for visibility, but turn segmentation
  should be interpreted as response-driven

- if LLM call boundaries exist:
  - optional `setup` span before first boundary
  - `turn_1`, `turn_2`, ... by boundary intervals
- if no LLM boundaries:
  - single `setup` span

Timestamp-correlation caveat:

- turn/event mapping is timestamp-based, not syscall-causal
- clock skew, coarse timestamps, or missing proxy timestamps can shift event-to-turn assignment
- degraded mapping must remain explicit via inference source/tier metadata

Each turn internal model includes:

```json
{
  "turn_id": "turn_1|setup",
  "index": 1,
  "label": "T1|Setup",
  "start_ts": 1776182079.47,
  "end_ts": 1776182081.35,
  "tool_call_count": 1,
  "tags": ["edit", "response"],
  "dominant_summary": "Wrote 1 files · 1 tool calls",
  "prompt_text": "...",
  "response_text": "...",
  "prompt_sections": [],
  "response_sections": [],
  "replay_context_sections": [],
  "replay_action_sections": [],
  "files_read_count": 0,
  "files_written_count": 1,
  "subprocess_direct_count": 0,
  "network_call_count": 0,
  "pre_tool_counts": {"file_read": 0, "file_write": 0, "process_spawn": 0, "network": 0},
  "first_tool_ts": 1776182079.47
}
```

## SQLite Persistence Contract

Canonical DB schema is defined in `mantle/ingest/sql/schema.sql`.

### event table

```text
event(
  id,
  trace_id,
  timestamp_ns,
  source,
  event_kind,    -- 'sys' | 'agent'
  event_type,
  line_no,
  pid,
  ppid,
  child_pid,
  path,
  src,
  dest,
  bytes_count,
  exec_path,
  command,
  argv_json,
  label,
  payload
)
```

Rules:

- `timestamp_ns` is nanoseconds since epoch (converted from `ts`)
- canonical mapped columns store primary queryable fields
- `payload` stores extension/unmapped residual fields

### turns table

```text
turns(
  id,
  trace_id,
  turn_id,
  start_ts_ns,
  end_ts_ns,
  prompt,
  metadata
)
```

### tool_calls table

```text
tool_calls(
  id,
  trace_id,
  turn_id,
  tool_index,
  tool_name,
  start_ts_ns,
  end_ts_ns,
  metadata
)
```

## Failure and Visibility Rules

- Invalid eBPF JSON/type errors raise and fail ingest (no silent failures).
- Invalid proxy records are skipped when not parseable JSON object.
- URL parsing failures and snapshot read failures are logged via `log_exception`.
- Proxy log ambiguity in `proxy` mode is a hard error (must be resolved via explicit log file mapping).
- Capture degradation must remain explicit through tier metadata and capture-quality endpoint.

## Change Gate Requirements

Any schema/boundary changes here MUST update together:

- `mantle/analysis/llm_parser.py` boundary extraction contract
- `mantle/ingest/store.py` correlation logic
- `mantle/ingest/sqlite_store.py` column mapping
- `mantle/ingest/sql/schema.sql` (if persistence shape changes)
- replay/API consumers in server + frontend
- integration/e2e tests covering turn/tool correlation
