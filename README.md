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

## Environment & Setup
This project uses a split Host-VM architecture to securely trace agents:
- **Host**: MacOS 
- **Guest VM**: Ubuntu 24.04 running on UTM
- **Workspace**: 
  - Host path: `/Users/harshithreddy/ubuntu_shared/simple_agent`
  - VM path: `/home/harshith/simple_agent_local`
  - Both are linked to a remote github repo, so to make changes to the codebase, edit in this workspace and push code to github.
- **SSH Access**: You can execute commands in the VM seamlessly from the host using:
  ```bash
  sshpass -p 'password' ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no root@127.0.0.1 "<command>"
  ```

## Components
- Agent: `simple_agent/cli_agent.py`
- Agent instrumentation sink: `simple_agent/agent_observability.py`
- Traced run scripts: `run_traced_agent.sh`, `run_intercepted_agent.sh`, `run_intercepted_codex.sh`
- Dashboard backend: `observability_dashboard/app.py`
- Dashboard UI: `observability_dashboard/static/index.html`, `observability_dashboard/static/app.js`

## Runtime paths
Default observability root:
- `/home/harshith/simple_agent_local/obs` (in VM)

Produced files:
- Strace logs: `obs/traces/<trace_id>.strace.log`
- API Interception logs: `obs/mitm/<trace_id>.mitm.jsonl`
- Agent events (for Python agents): `obs/events/<trace_id>.log.events.jsonl`

## How to run

### 1) Start dashboard
Run the dashboard inside the VM:
```bash
# In the VM
cd /home/harshith/simple_agent_local
source .venv/bin/activate  # Or use appropriate python if venv exists
python3 -m uvicorn observability_dashboard.app:app --host 0.0.0.0 --port 8099
```

From the host, create a local tunnel to the VM dashboard:
```bash
sshpass -p 'password' ssh -fN -p 2222 \
  -L 8099:127.0.0.1:8099 \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  root@127.0.0.1
```

Then open `http://127.0.0.1:8099` on the host.

To stop the tunnel:
```bash
pkill -f "ssh.*-L 8099:127.0.0.1:8099"
```

### 2) Run agent with tracing
Run the tracing scripts in the VM:
```bash
# In the VM
cd /home/harshith/simple_agent_local
./run_intercepted_codex.sh codex exec "how many shell scripts in current folder"
```

## Key env vars
- `AGENT_TRACE_ID`: trace ID used to correlate agent events with strace.
- `AGENT_OBS_ROOT`: base output path for traces/events.
- `AGENT_PYTHON`: explicit python interpreter for traced run.
- `OBS_TRACE_DIR`, `OBS_EVENTS_DIR`: dashboard override paths.
