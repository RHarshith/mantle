# Agent Observability Dashboard

This service monitors low-level trace logs (strace or eBPF JSONL) + agent instrumentation events + mitm captures and renders a realtime drilldown graph.

## Folder Convention

- Strace logs directory (watched): `~/shared/simple_agent/obs/traces`
- Agent event logs directory: `~/shared/simple_agent/obs/events`

## Run the Dashboard

Recommended (from repo root):

```bash
rtrace_monitor --host 0.0.0.0 --port 8099
```

Direct uvicorn alternative:

```bash
cd observability_dashboard
/Users/harshithreddy/ubuntu_shared/simple_agent/.venv/bin/python -m pip install -r requirements.txt
/Users/harshithreddy/ubuntu_shared/simple_agent/.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8099 --reload
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

## Run Agent + Strace with Matching Trace ID

Choose a trace id, e.g. `trace_001.ebpf.jsonl`.

```bash
export AGENT_TRACE_ID=trace_001.ebpf.jsonl
export AGENT_OBS_ROOT=~/shared/simple_agent/obs
python ebpf_capture.py --output ~/shared/simple_agent/obs/traces/trace_001.ebpf.jsonl -- python cli_agent.py
```

This writes:
- eBPF trace: `~/shared/simple_agent/obs/traces/trace_001.ebpf.jsonl`
- agent events: `~/shared/simple_agent/obs/events/trace_001.ebpf.jsonl.events.jsonl`

## Optional Environment Overrides

- `OBS_TRACE_DIR` (dashboard watched trace dir)
- `OBS_EVENTS_DIR` (dashboard watched events dir)
- `AGENT_OBS_ENABLED` (`1`/`0`)
- `AGENT_TRACE_ID` (must match trace log file name for best correlation)
- `AGENT_OBS_ROOT` (defaults to `~/shared/simple_agent/obs`)
