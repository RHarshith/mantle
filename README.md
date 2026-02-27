# Agent System Observability (Demo)

## Goal
Build a **system-level observability layer** for an LLM agent: not just prompts/tools/responses, but also what the tool execution does at OS level (processes spawned, commands executed, files touched).

## What this system provides
- **Realtime dashboard** for trace sessions (one trace file = one trace ID).
- **Two-level view**:
  - **Level 1 (conversation):** `Prompt -> Tool Step (call + result) -> Agent Response`
  - **Level 2 (tool drilldown):** command chain + user-relevant file nodes.
- **Noise reduction** for low-value Linux internals (`/usr`, loader/runtime setup, package internals).
- **Right-side summaries** of files read/written/deleted/executed.

## Components
- Agent: [simple_agent/cli_agent.py](simple_agent/cli_agent.py)
- Agent instrumentation sink: [simple_agent/agent_observability.py](simple_agent/agent_observability.py)
- Traced run script: [run_traced_agent.sh](run_traced_agent.sh)
- Dashboard backend: [observability_dashboard/app.py](observability_dashboard/app.py)
- Dashboard UI: [observability_dashboard/static/index.html](observability_dashboard/static/index.html), [observability_dashboard/static/app.js](observability_dashboard/static/app.js)

## Runtime paths
Default observability root:
- `~/shared/simple_agent/obs`

Produced files:
- Strace logs: `~/shared/simple_agent/obs/traces/<trace_id>.log`
- Agent events: `~/shared/simple_agent/obs/events/<trace_id>.log.events.jsonl`

## VM note
In your VM setup, `~/ubuntu_shared` is mounted at `~/shared`.
This repo runs from `~/shared/simple_agent` on VM.

## How to run
### 1) Start dashboard (This is run in host)
```bash
cd ~/shared/simple_agent
/Users/harshithreddy/ubuntu_shared/simple_agent/.venv/bin/python -m uvicorn observability_dashboard.app:app --host 127.0.0.1 --port 8099
```
Open: `http://127.0.0.1:8099`

### 2) Run agent with tracing (This part is run in VM)
```bash
cd ~/shared/simple_agent
./run_traced_agent.sh
```
(Optional) Pass explicit trace filename:
```bash
./run_traced_agent.sh trace_20260227_example.strace.log
```

## Key env vars
- `AGENT_TRACE_ID`: trace ID used to correlate agent events with strace.
- `AGENT_OBS_ROOT`: base output path for traces/events.
- `AGENT_PYTHON`: explicit python interpreter for traced run.
- `OBS_TRACE_DIR`, `OBS_EVENTS_DIR`: dashboard override paths.

## Quick troubleshooting
- **Address already in use**: stop process on port `8099`.
- **Empty dashboard**: check `GET /api/config` and verify watched dirs match actual `obs/traces` + `obs/events`.
- **`sudo` path issues**: use `run_traced_agent.sh` (it handles sudo home/python resolution).
