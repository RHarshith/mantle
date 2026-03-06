# RTrace Observability

Productionized tracing stack for coding agents (Codex-focused):
- intercepts OpenAI API calls via mitmproxy,
- captures system behavior via strace,
- renders a live observability dashboard.

## Core Commands

After setup, these are the main commands:

- `rtrace_monitor`: start dashboard server
- `rtrace codex [--strace|--no-strace] <exec[optional] prompt>`: run traced codex session

Examples:

```bash
rtrace_monitor
rtrace codex
rtrace codex --no-strace "quick run without syscall capture"
rtrace codex "summarize this repository"
rtrace codex exec "count shell scripts and print the result"
```

## Quick Start (Native Linux/macOS)

1. Clone repo and install runtime:

```bash
git clone <your-repo-url>
cd simple_agent
bash scripts/install_rtrace.sh
```

2. Ensure commands are in path (if needed):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

3. Start dashboard:

```bash
rtrace_monitor --host 0.0.0.0 --port 8099
```

4. In another shell, run traced codex:

```bash
rtrace codex exec "inspect this codebase and list 3 improvements"
```

5. Open dashboard:

```text
http://127.0.0.1:8099
```

## Dockerized Environment (No VM Required)

This is the recommended path for quick installation and testing in macOS/Windows/Linux.

### 1) Build and launch persistent container

```bash
git clone <your-repo-url>
cd simple_agent
export OPENAI_API_KEY="<your_key_in_local_shell>"
docker compose up -d --build
```

The container stays alive (`sleep infinity`) so you can exec into it anytime.

### 2) Enter container shell

```bash
docker compose exec rtrace-lab bash
```

### 3) Inside container, run monitor and trace

Terminal A:

```bash
rtrace_monitor --host 0.0.0.0 --port 8099
```

Terminal B:

```bash
docker compose exec rtrace-lab bash
rtrace codex exec "count shell scripts and print result"
```

### 4) Open dashboard from host

The compose file publishes dashboard port directly:

```text
http://127.0.0.1:8099
```

## Docker Notes

- `docker-compose.yml` grants `NET_ADMIN`/`NET_RAW` capabilities required for transparent interception.
- `@openai/codex` is installed in image so codex CLI setup is not required separately.
- Secrets are read from host environment and synced by setup scripts at container startup.
- Do not commit local secret files; `.env` is ignored by git.

## Agent Setup Framework

To support multiple agents and future custom configuration requirements, startup setup is manifest-driven:

- Manifest: `agent_setup/setup.yml`
- Setup scripts folder: `scripts/agent_setup/`
- Setup runner: `scripts/agent_setup/run_setup_scripts.sh`

At container startup, entrypoint reads `RTRACE_AGENT_SETUP_CONFIG` and executes each script listed in the YAML.

Current script:

- `scripts/agent_setup/codex_setup.sh`:
  - reads `OPENAI_API_KEY` from host-passed env,
  - writes container-local runtime env file (`/root/.config/rtrace/agent-env/codex.env`),
  - runs `codex login --with-api-key` non-interactively to initialize Codex auth store,
  - wires shell startup to source agent env snippets.

You can add future scripts (e.g., writing agent config files, auth material, policy files) and register them in `agent_setup/setup.yml`.

### Codex Auth Notes

- `run_intercepted_codex.sh` uses transparent interception and does **not** force `OPENAI_BASE_URL` by default.
- This avoids auth-header issues seen on newer Codex versions when base URL is plain `http://127.0.0.1:...`.
- If you need the old behavior for debugging, set `RTRACE_FORCE_OPENAI_BASE=1` before running `rtrace codex ...`.

Optional `.env` workflow (still local-only, never committed):

```bash
cp .env.example .env
# edit .env locally
docker compose up -d --build
```

## Legacy VM Workflow (Optional)

If you still use VM-host split, port-forward dashboard with:

```bash
sshpass -p 'password' ssh -fN -p 2222 \
  -L 8099:127.0.0.1:8099 \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  root@127.0.0.1
```

Stop tunnel:

```bash
pkill -f "ssh.*-L 8099:127.0.0.1:8099"
```

## Output Layout

- `obs/traces/<trace_id>.strace.log`
- `obs/mitm/<trace_id>.mitm.jsonl`
- `obs/events/<trace_id>.events.jsonl`

## Key Environment Variables

- `AGENT_OBS_ROOT`: base output path (default: `<repo>/obs`)
- `AGENT_TRACE_ID`: explicit trace id override
- `RTRACE_VENV`: Python env used by wrappers
- `OBS_TRACE_DIR`, `OBS_EVENTS_DIR`: dashboard parser overrides
