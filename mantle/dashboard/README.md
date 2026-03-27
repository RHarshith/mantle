# Agent Observability Dashboard

This service monitors low-level eBPF JSONL trace logs + agent instrumentation events + mitm captures and renders a realtime drilldown graph.

## Code Layout

- `mantle/dashboard/app.py`: FastAPI wiring only (routes, startup/shutdown, path resolution).
- `mantle/dashboard/store.py`: trace ingestion, parsing, graph building, replay/turn orchestration.
- `mantle/dashboard/config.py`: observability path/environment resolution.
- `mantle/dashboard/llm_utils.py`: schema normalization and MITM LLM payload parsing.
- `mantle/dashboard/syscall_utils.py`: syscall parsing and endpoint/path classification helpers.
- `mantle/dashboard/logging_utils.py`: centralized dashboard logging helpers.

Use this split when debugging:
- API/runtime issues (HTTP status, route behavior, websocket updates): start in `app.py`.
- Data/parsing/graph issues (missing nodes, bad turn mapping, MITM correlation): start in `store.py`.

For terminal-first workflows, use `mantle cli` / `mantlecli` for replay and trace drilldowns without UI dependencies.

## Folder Convention

- eBPF logs directory (watched): `~/shared/mantle/obs/traces`
- Agent event logs directory: `~/shared/mantle/obs/events`

## Run the Dashboard

Recommended (from repo root):

```bash
mantle serve --host 0.0.0.0 --port 8099
```

Direct uvicorn alternative:

```bash
cd mantle/dashboard
/Users/harshithreddy/ubuntu_shared/mantle/.venv/bin/python -m pip install -r requirements.txt
/Users/harshithreddy/ubuntu_shared/mantle/.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8099 --reload
```

Open: `http://127.0.0.1:8099`

If dashboard runs inside VM/container and is not already port-exposed, forward it to host:

```bash
sshpass -p 'password' ssh -fN -p 2222 \
	-L 8099:127.0.0.1:8099 \
	-o ExitOnForwardFailure=yes \
	-o StrictHostKeyChecking=no \
	-o PreferredAuthentications=password \
	-o PubkeyAuthentication=no \
	root@127.0.0.1
```

Then open: `http://127.0.0.1:8099`

## Run Agent + eBPF with Matching Trace ID

Choose a trace id, e.g. `trace_001.ebpf.jsonl`.

```bash
export AGENT_TRACE_ID=trace_001.ebpf.jsonl
export AGENT_OBS_ROOT=~/shared/mantle/obs
mantle watch --trace-id trace_001.ebpf.jsonl codex exec "inspect this repository and summarize"
```

This writes:
- eBPF trace: `~/shared/mantle/obs/traces/trace_001.ebpf.jsonl`
- agent events: `~/shared/mantle/obs/events/trace_001.ebpf.jsonl.events.jsonl`

## Optional Environment Overrides

- `OBS_TRACE_DIR` (dashboard watched trace dir)
- `OBS_EVENTS_DIR` (dashboard watched events dir)
- `AGENT_OBS_ENABLED` (`1`/`0`)
- `AGENT_TRACE_ID` (must match trace log file name for best correlation)
- `AGENT_OBS_ROOT` (defaults to `~/shared/mantle/obs`)
