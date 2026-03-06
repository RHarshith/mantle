# RTrace Observability

RTrace is a productionized observability stack for coding agents.

It captures:
- API-level behavior via `mitmproxy`
- system calls via `strace`
- agent flow in a dashboard (`FastAPI` + static UI)

Current primary target is Codex, with an extension model for other agents.

## Quick Start

### Native (Linux/macOS)

```bash
git clone <your-repo-url>
cd simple_agent
bash scripts/install_rtrace.sh
export PATH="$HOME/.local/bin:$PATH"

# Terminal 1
rtrace_monitor --host 0.0.0.0 --port 8099

# Terminal 2
rtrace codex exec "inspect this repository and summarize"
```

Open: `http://127.0.0.1:8099`

### Docker (recommended for reproducibility)

```bash
git clone <your-repo-url>
cd simple_agent
export OPENAI_API_KEY="<your_key_in_local_shell>"
docker compose up -d --build

# Terminal 1
docker compose exec rtrace-lab bash -lc 'rtrace_monitor'

# Terminal 2
docker compose exec rtrace-lab bash -lc 'rtrace codex exec "count shell scripts and print result"'
```

Open: `http://127.0.0.1:8099`

## Command Reference

### `rtrace_monitor`

Start dashboard server.

Usage:
```bash
rtrace_monitor [--host <host>] [--port <port>] [--obs-root <path>]
```

Options:
- `--host`: bind host; defaults to `0.0.0.0` in Docker and `127.0.0.1` outside Docker.
- `--port`: dashboard port (default `8099`).
- `--obs-root`: observability root directory (default `<repo>/obs`).

### `rtrace codex`

Run Codex with interception and optional syscall tracing.

Usage:
```bash
rtrace codex [--strace|--no-strace] [exec] [prompt...]
```

Examples:
```bash
rtrace codex
rtrace codex "summarize this repository"
rtrace codex exec "count shell scripts and print result"
rtrace codex --no-strace exec "fast run without low-level syscall capture"
```

Notes:
- `--strace` is default.
- `--no-strace` disables low-level syscall capture.
- Under the hood this calls `run_intercepted_codex.sh`.

### `run_intercepted_codex.sh` (advanced)

Usage:
```bash
./run_intercepted_codex.sh [--no-strace] [--mode proxy|transparent] [--trace-id <id>] [--agent <bin>] [prompt...]
```

Important options:
- `--mode proxy`: default and recommended in Docker.
- `--mode transparent`: iptables-based transparent interception.
- `--no-strace`: disable syscall capture.

## Folder Structure

```text
.
├── agent_setup/
│   └── setup.yml                      # manifest for agent setup scripts
├── bin/
│   ├── rtrace                         # primary trace CLI
│   └── rtrace_monitor                 # dashboard launcher
├── docker/
│   └── entrypoint.sh                  # container entrypoint + setup runner hook
├── observability_dashboard/
│   ├── app.py                         # dashboard API/backend
│   ├── static/                        # frontend UI
│   └── requirements.txt
├── scripts/
│   ├── install_rtrace.sh              # native installer
│   └── agent_setup/
│       ├── run_setup_scripts.sh       # executes scripts from setup.yml
│       └── codex_setup.sh             # codex auth/env bootstrap
├── simple_agent/
│   ├── cli_agent.py                   # sample Python agent
│   └── agent_observability.py
├── Dockerfile
├── docker-compose.yml
├── mitm_capture.py                    # mitmproxy addon for capture
├── requirements.runtime.txt
├── run_intercepted_codex.sh
└── obs/                               # generated traces and captures
```

Generated data:
- `obs/traces/<trace_id>.strace.log`
- `obs/mitm/<trace_id>.mitm.jsonl`
- `obs/events/<trace_id>.events.jsonl`

## Environment Model

Secrets are not committed.

Recommended:
- export on host shell before `docker compose up`:

```bash
export OPENAI_API_KEY="<your_key>"
```

Optional local helper:
```bash
cp .env.example .env
# edit .env locally (git-ignored)
```

Key runtime env vars:
- `OPENAI_API_KEY`: OpenAI credential
- `AGENT_OBS_ROOT`: output root (default `<repo>/obs`)
- `RTRACE_VENV`: Python venv path used by wrappers
- `RTRACE_INTERCEPT_MODE`: default intercept mode (`proxy` or `transparent`)
- `RTRACE_FORCE_OPENAI_BASE=1`: force legacy local reverse base URL behavior (debug only)
- `RTRACE_AGENT_SETUP_CONFIG`: path to setup manifest

## Adding Support for Another Agent

Use the setup manifest + script pattern.

1. Add setup script:
- Create `scripts/agent_setup/<agent>_setup.sh`
- Keep script idempotent.
- Use it to write required local config/auth files in container.

2. Register in manifest:
- Edit `agent_setup/setup.yml` and add script path under `setup_scripts`.

3. Add runtime wrapper:
- Extend `bin/rtrace` with new subcommand (e.g. `rtrace aider ...`).
- Add corresponding run script (similar to `run_intercepted_codex.sh`) if behavior differs.

4. Update docs:
- Add command examples and required env vars.

## Troubleshooting

### No low-level syscall nodes in drilldown
- Ensure you are not using `--no-strace`.
- Confirm run output shows `Strace: true` and `Strace file: ...`.

### Dashboard unreachable from host in Docker
- Start monitor with `rtrace_monitor` (Docker-aware default bind is `0.0.0.0`).
- Check mapping:
  - `docker compose ps`
  - `docker compose port rtrace-lab 8099`

### Codex auth errors
- Re-sync auth from current key:
  - `docker compose exec rtrace-lab bash -lc 'printenv OPENAI_API_KEY | codex login --with-api-key && codex login status'`

### Interception transport issues
- Use proxy mode (default) first.
- Transparent mode is advanced and depends on iptables behavior.

## Development Notes

- Keep `rtrace` UX stable: operator should need only `rtrace_monitor` + `rtrace <agent> ...`.
- Prefer adding new agent support through setup scripts and wrapper subcommands rather than ad-hoc one-off scripts.
- Preserve generated data in `obs/` for reproducible debugging and dashboard verification.
