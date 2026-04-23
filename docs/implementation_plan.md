# Guided Reward Generation — Implementation Plan (v3)

## Overview

Users "show" the agent how to perform a task by recording a reference (guide) trace. When a subsequent agent trace runs inside the same **process**, the agent can query an **oracle executable** that compares its BPF events against the guide trace and returns a structured reward/guidance result.

**Design principles:**
- Process identified by **name** (unique key) — CLI uses `--process-name`.
- Checkpoints are **BPF-only** — no proxy log extraction.
- Reward delivery via **oracle executable** the agent calls itself.
- Proxy only adds a **system prompt instruction** telling the agent to run the oracle.
- Reward engine has a **clean, loosely-coupled interface** for algorithm iteration.

---

## Layer 1 — Data Model

### [MODIFY] [schema.sql](file:///home/harshith/code_projects/mantle/mantle/ingest/sql/schema.sql)

```sql
CREATE TABLE IF NOT EXISTS process (
    name       TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL        -- unix epoch seconds
);

CREATE TABLE IF NOT EXISTS traces (
    id           TEXT PRIMARY KEY,      -- same value as existing trace_id (filename)
    process_name TEXT REFERENCES process(name) ON DELETE SET NULL,
    is_guide     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    file_name    TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_traces_process ON traces(process_name);
```

> [!NOTE]
> Existing `turns.trace_id` and `event.trace_id` use the filename string. The new `traces.id` uses the same value, so existing data works without migration. No FK is added from `turns → traces` to avoid breaking existing rows that predate the `traces` table.

### [MODIFY] [sqlite_store.py](file:///home/harshith/code_projects/mantle/mantle/ingest/sqlite_store.py)

New CRUD methods:

| Method | Notes |
|---|---|
| `create_process(name)` | Insert; no-op if name exists (auto-creation from CLI) |
| `list_processes()` | Ordered by `created_at DESC` |
| `delete_process(name)` | Cascades: sets `process_name=NULL` on associated traces |
| `register_trace(trace_id, file_name, process_name=None)` | **Upsert** — if trace already exists, update `process_name` only if currently NULL |
| `assign_trace_to_process(trace_id, process_name)` | Explicit assignment (from UI) |
| `set_guide_trace(process_name, trace_id)` | Set `is_guide=1`, clear others in same process |
| `get_guide_trace(process_name) → str\|None` | Return the guide trace_id |
| `list_traces_for_process(process_name)` | All traces in a process |

### [MODIFY] [store.py](file:///home/harshith/code_projects/mantle/mantle/ingest/store.py)

- `poll_once()`: when a new `.ebpf.jsonl` file is discovered, also call `sqlite_store.register_trace(trace_id, file_name)`.
- `list_traces()`: keep existing in-memory computation (status, event counts, anomaly), then **augment** each entry with `process_name`, `is_guide` by joining against `sqlite_store` — do NOT replace the existing logic.
- Add thin wrapper methods for process/guide CRUD that delegate to `sqlite_store`.

---

## Layer 2 — CLI: `mantle watch --process-name`

### [MODIFY] [bin/mantle](file:///home/harshith/code_projects/mantle/bin/mantle)

```bash
mantle watch --process-name <name> [--trace-id <id>] <executable> [args...]
```

**Changes:**
1. Parse `--process-name` flag in `watch_cmd()`.
2. After trace starts (daemon socket + proxy active-trace calls), make two additional best-effort HTTP calls:
   - `POST ${server_url}/api/processes` with `{"name": "$process_name"}` — auto-creates if not exists.
   - `POST ${server_url}/api/processes/${process_name}/traces` with `{"trace_id": "$trace_id"}` — registers trace under process.
   - `POST ${proxy_url}/mantle/active-process` with `{"process_name": "$process_name"}`.
3. Cleanup trap: POST `{"process_name": null}` to `/mantle/active-process`.

> [!IMPORTANT]
> The server may not have discovered the trace file yet when the CLI POSTs to `/api/processes/{name}/traces`. This is why `register_trace` in the SQLite store must be an **upsert** — the CLI call creates a minimal `traces` row, and `poll_once()` later enriches it.

---

## Layer 3 — Server API

### [MODIFY] [app.py](file:///home/harshith/code_projects/mantle/mantle/server/app.py)

```
POST   /api/processes                         body: {name}
GET    /api/processes
DELETE /api/processes/{name}
POST   /api/processes/{name}/traces           body: {trace_id}
POST   /api/traces/{trace_id}/set-guide
GET    /api/traces/{trace_id}/reward-status
```

`GET /api/traces/{trace_id}/reward-status` flow:
1. Look up `traces` row → get `process_name`.
2. Look up guide trace for that process.
3. Query BPF events for both guide and current trace from SQLite.
4. Instantiate `RewardAlgorithm`, call `evaluate()`, return result.

> [!NOTE]
> BPF events in SQLite lag up to ~1-2 seconds behind the actual trace file because `poll_once()` runs on a 1-second interval. This is acceptable for V1 — the oracle is advisory, not real-time critical.

---

## Layer 4 — Reward Engine (Loosely Coupled)

### [NEW] `mantle/reward/__init__.py`
### [NEW] `mantle/reward/checkpoints.py`
### [NEW] `mantle/reward/engine.py`

#### Interface contract

```python
@dataclass
class RewardInput:
    guide_events: list[dict]      # BPF events from guide trace
    current_events: list[dict]    # BPF events from active trace
    metadata: dict                # extensible: {process_name, guide_trace_id, active_trace_id, ...}

@dataclass
class RewardResult:
    progress: float               # 0.0–1.0
    score: float                  # shaped reward
    satisfied: list[str]          # checkpoint names satisfied
    pending: list[str]            # checkpoint names remaining
    next_hint: str                # human-readable guidance
    raw: dict                     # algorithm-specific details

class RewardAlgorithm(Protocol):
    def evaluate(self, input: RewardInput) -> RewardResult: ...
```

#### `checkpoints.py` — Predicate library + extraction

Contains:
- `Checkpoint` dataclass (name, predicate function, satisfied flag).
- Built-in predicates: `file_opened_for_write(pattern)`, `file_created(pattern)`, `command_executed(pattern)`, `command_succeeded(pattern)`, `network_connected(pattern, port)`.
- `extract_checkpoints(guide_events: list[dict]) -> list[Checkpoint]`: scans guide BPF events, creates one `Checkpoint` per significant syscall pattern (openat+write, execve, connect). Deduplicates by (syscall, path-pattern).

#### `engine.py` — V1 algorithm

`CheckpointRewardAlgorithm` implements `RewardAlgorithm`:
1. On `evaluate()`, extracts checkpoints from `input.guide_events` (cached after first call).
2. Evaluates each checkpoint against `input.current_events`.
3. Computes progress-based shaped reward + step penalty.
4. Generates `next_hint` from the first unsatisfied checkpoint.

Future algorithms (e.g., embedding-based similarity, LLM-based evaluation) implement the same `RewardAlgorithm` protocol and swap in via config.

---

## Layer 5 — Oracle Executable + Proxy System Prompt

### [NEW] `bin/mantle-oracle`

A bash script (like `bin/mantle`) that:
1. Parses `--process-name <name>` and `--trace-id <id>`.
2. Reads `MANTLE_SERVER_URL` (defaults to `http://127.0.0.1:8099`).
3. Calls `GET ${MANTLE_SERVER_URL}/api/traces/${trace_id}/reward-status`.
4. Pretty-prints the JSON result to stdout for the agent to consume.

### [MODIFY] [proxy.py](file:///home/harshith/code_projects/mantle/mantle/litellm_proxy/proxy.py)

**New global state:**

```python
_ACTIVE_PROCESS_NAME: str | None = None
```

**New endpoints:**

```
POST /mantle/active-process   body: {"process_name": "..."|null}
GET  /mantle/active-process   → {"process_name": "..."|null}
```

**System prompt injection — two code paths:**

1. **Responses API** (`proxy_responses_passthrough`): Before forwarding to upstream, parse `request_payload`, check if `_ACTIVE_PROCESS_NAME` is set. If so, append the oracle instruction to the `instructions` field (creating it if absent). Re-serialize the modified body and forward.

2. **Chat Completions API** (LiteLLM path): Add a new middleware or use LiteLLM's callback hooks to intercept the messages list. If `_ACTIVE_PROCESS_NAME` is set, append the oracle instruction to the last `system` message, or insert a new `system` message.

**Injected instruction text:**

```
[Mantle] An oracle is available to evaluate your progress against a reference trace.
Run this command periodically to check your progress:
  /path/to/bin/mantle-oracle --process-name <NAME> --trace-id <TRACE_ID>
```

Where `<NAME>` and `<TRACE_ID>` are substituted from `_ACTIVE_PROCESS_NAME` and `_ACTIVE_TRACE_FILE`.

> [!IMPORTANT]
> The proxy needs the **absolute path** to `mantle-oracle` since the agent's PATH may not include it. Use `MANTLE_ORACLE_PATH` env var (defaulting to `/app/bin/mantle-oracle` in container, or auto-detected relative to proxy).

---

## Layer 6 — Frontend

### [MODIFY] [index.html](file:///home/harshith/code_projects/mantle/mantle/server/static/index.html) + [app.js](file:///home/harshith/code_projects/mantle/mantle/server/static/app.js)

- Sidebar restructure: group traces under process headers, "Unassigned" section for orphan traces.
- Process CRUD: "+ New Process" button (already exists in HTML), delete button per process.
- Per-trace: "Set as Guide ⭐" button; guide traces show a badge.
- Reward status panel: when viewing a non-guide trace in a process that has a guide, show progress bar + checkpoint list via `GET /api/traces/{trace_id}/reward-status` (auto-refresh every 3s for active traces).

---

## Verification Plan

### Automated
- Unit tests for `CheckpointRewardAlgorithm.evaluate()` with synthetic BPF event lists.
- Unit tests for `SQLiteTraceStore` new CRUD methods (process, trace, guide).
- Unit tests for `extract_checkpoints()` with realistic guide trace data.

### Integration
- Create process → register two traces → set guide → call oracle → verify JSON output.
- Verify proxy system prompt injection by inspecting upstream request bodies in proxy logs.

### Manual
- Run `mantle watch --process-name demo aider` for guide trace, mark as guide in UI.
- Run `mantle watch --process-name demo aider` for agent trace.
- Observe reward status panel in dashboard.
- Verify agent receives oracle instruction in its system prompt.
