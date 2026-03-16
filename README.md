# Mantle Observability

Mantle captures coding-agent behavior at three layers:
- API traffic via `mitmproxy`
- process/file/network activity via eBPF (`bpftrace`)
- timeline + drilldown in a FastAPI dashboard

Mantle now uses a single executable: `mantle`.

## Native Setup (Linux/macOS)

```bash
git clone <your-repo-url>
cd mantle
bash scripts/install_mantle.sh
export PATH="$HOME/.local/bin:$PATH"
export OPENAI_API_KEY="<your_key>"
```

Verify install:

```bash
mantle --help
mantle serve --help
mantle watch --help
```

## Native Run

Terminal 1 (dashboard):

```bash
mantle serve --host 0.0.0.0 --port 8099
```

Terminal 2 (observe an executable):

```bash
mantle watch codex exec "inspect this repository and summarize"
```

Open: `http://127.0.0.1:8099`

## Docker Setup And Run

```bash
git clone <your-repo-url>
cd mantle
export OPENAI_API_KEY="<your_key_in_local_shell>"
docker compose up -d --build
```

Terminal 1:

```bash
docker compose exec mantle-lab bash -lc 'mantle serve'
```

Terminal 2:

```bash
docker compose exec mantle-lab bash -lc 'mantle watch codex exec "count shell scripts and print result"'
```

Open: `http://127.0.0.1:8099`

## Command Reference

`mantle serve`
- Starts the dashboard server.
- Usage: `mantle serve [--host <host>] [--port <port>] [--obs-root <path>]`

`mantle watch`
- Runs an executable under MITM + eBPF capture.
- Usage: `mantle watch [--mode <proxy|transparent>] [--trace-id <id>] [--port <mitm_port>] <executable> [exec] [prompt...]`

Examples:

```bash
mantle watch codex
mantle watch codex exec "summarize this repository"
mantle watch --mode transparent codex exec "trace outbound API calls"
mantle watch aider "fix failing tests"
```

## Folder Structure

```text
.
├── agent_setup/
│   └── setup.yml
├── bin/
│   ├── mantle
│   └── rtrace_test                   # scenario runner helper (not globally installed)
├── docker/
│   └── entrypoint.sh
├── mantle/
│   ├── dashboard/
│   │   ├── app.py
│   │   ├── static/
│   │   └── requirements.txt
│   ├── ebpf_capture.py
│   └── mitm_capture.py
├── mantle_agent/
│   ├── agent_observability.py
│   └── cli_agent.py
├── scripts/
│   ├── bootstrap_ubuntu.sh
│   ├── install_mantle.sh
│   └── agent_setup/
├── trace_scenarios/
├── run_intercepted_codex.sh
└── obs/
```

Generated data:
- `obs/traces/<trace_id>.ebpf.jsonl`
- `obs/mitm/<trace_id>.mitm.jsonl`
- `obs/events/<trace_id>.events.jsonl`

## Key Environment Variables

- `OPENAI_API_KEY`: OpenAI credential
- `AGENT_OBS_ROOT`: output root (default `<repo>/obs`)
- `MANTLE_VENV`: Python venv path used by wrappers
- `MANTLE_INTERCEPT_MODE`: default intercept mode (`proxy` or `transparent`)
- `MANTLE_FORCE_OPENAI_BASE=1`: forces local reverse base URL behavior (debug only)

Compatibility fallback variables (`RTRACE_*`) are still accepted.

## Troubleshooting

Dashboard unreachable from host in Docker:
- Run `docker compose ps`
- Run `docker compose port mantle-lab 8099`

No low-level syscall nodes in drilldown:
- Ensure `bpftrace` is installed and runnable as root.
- Confirm run output prints `eBPF trace: true`.

Codex auth errors:

```bash
docker compose exec mantle-lab bash -lc 'printenv OPENAI_API_KEY | codex login --with-api-key && codex login status'
```
