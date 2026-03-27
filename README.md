# Mantle

An observability platform for coding agents.

Mantle captures how an AI coding agent reasons, calls tools, touches files, and talks to networks, then reconstructs that execution into a live drilldown dashboard and a URL-driven CLI explorer.

## Why This Project Exists

AI coding agents are powerful, but most teams still treat their behavior as a black box. Mantle was built to answer practical engineering and security questions:

- What exactly did the agent do over time?
- Which tools and files were involved in each step?
- Which network endpoints were contacted?

The goal is to make agent behavior inspectable, testable, and reviewable.

## Core Capabilities

- Multi-layer capture:
	- API traffic via `mitmproxy`
	- process/file/network activity via eBPF (`bpftrace`)
	- agent-native events via JSONL instrumentation
- Live observability dashboard (`mantle serve`):
	- trace timeline
	- tool and process drilldowns
	- file/network activity panels
	- websocket-driven updates
- Observability CLI (`mantle cli` / `mantlecli`):
	- non-interactive URL-like routes for traces, turns, replay context/action, and summaries
	- interactive arrow-key navigation across traces and turns
	- pager-based drilldowns for long process trees and message bodies
- Scenario-based validation:
	- reproducible suites under `trace_scenarios/`
	- setup, verify, and cleanup lifecycle

## Architecture At A Glance

```text
Agent Runtime
	-> mantle watch
			-> eBPF syscall capture (process/file/network)
			-> MITM capture (API/network payload view)
			-> agent event sink (structured JSONL)

Captured data (obs/)
	-> traces/*.ebpf.jsonl
	-> mitm/*.mitm.jsonl
	-> events/*.events.jsonl

mantle serve
	-> FastAPI backend
	-> static UI + websocket updates
	-> timeline and drilldown views

mantle cli / mantlecli
	-> trace/replay route explorer
	-> interactive and non-interactive terminal navigation
```

## Quickstart

### Native Setup (Linux/macOS)

```bash
git clone <your-repo-url>
cd mantle
bash scripts/install_mantle.sh
export PATH="$HOME/.local/bin:$PATH"
export OPENAI_API_KEY="<your_key>"
```

Verify installation:

```bash
mantle --help
mantle serve --help
mantle watch --help
mantle cli --help
```

### Run A Live Trace

Terminal 1 (dashboard):

```bash
mantle serve --host 0.0.0.0 --port 8099
```

Terminal 2 (run and trace an agent command):

```bash
mantle watch codex exec "inspect this repository and summarize"
```

Open `http://127.0.0.1:8099`.

## Docker Workflow

```bash
git clone <your-repo-url>
cd mantle
export OPENAI_API_KEY="<your_key_in_local_shell>"
docker compose up -d --build
```

Start dashboard:

```bash
docker compose exec mantle-lab bash -lc 'mantle serve'
```

Run traced task:

```bash
docker compose exec mantle-lab bash -lc 'mantle watch codex exec "count shell scripts and print result"'
```

Open `http://127.0.0.1:8099`.

## CLI Reference

`mantle serve`

- Starts the FastAPI dashboard server.
- Usage: `mantle serve [--host <host>] [--port <port>] [--obs-root <path>]`

`mantle watch`

- Runs an executable under MITM + eBPF capture.
- Interactive mode (`mantle watch <agent>`) preserves TTY behavior and disables eBPF capture by default; use `--interactive-ebpf` to opt in to interactive eBPF tracing.
- Usage: `mantle watch [--mode <proxy|transparent>] [--trace-id <id>] [--port <mitm_port>] [--interactive-ebpf] <executable> [exec] [prompt...]`

Examples:

```bash
mantle watch codex
mantle watch --interactive-ebpf codex
mantle watch codex exec "summarize this repository"
mantle watch --mode transparent codex exec "trace outbound API calls"
mantle watch aider "fix failing tests"
```

`mantle cli`

- Explore trace and replay data from terminal without opening the dashboard.
- Usage: `mantle cli [-i|--interactive] [--obs-root <path>] [<route>]`

Examples:

```bash
mantle cli --interactive
mantle cli traces
mantle cli trace_001.ebpf.jsonl/trace
mantle cli trace_001.ebpf.jsonl/replay/turn_2/summary
mantlecli trace_001.ebpf.jsonl/replay/turn_2/context/system_prompt/0
```

## Data Artifacts

Mantle writes trace outputs to `obs/`:

- `obs/traces/<trace_id>.ebpf.jsonl`
- `obs/mitm/<trace_id>.mitm.jsonl`
- `obs/events/<trace_id>.events.jsonl`

These files are the source of truth for replay, debugging, and analysis.

## Project Structure

```text
.
├── bin/
│   ├── mantle
│   └── mantle_test
├── mantle/
│   ├── dashboard/
│   │   ├── app.py
│   │   └── static/
│   ├── cli/
│   ├── ebpf_capture.py
│   └── mitm_capture.py
├── mantle_agent/
│   ├── agent_observability.py
│   └── cli_agent.py
├── trace_scenarios/
├── scripts/
├── run_intercepted_codex.sh
└── obs/
```

## Engineering Highlights

- End-to-end instrumentation design spanning agent-level and OS-level telemetry
- Real-time UX with backend polling and websocket update flow
- Reproducible scenario harness for validation and regression checks

## Environment Variables

- `OPENAI_API_KEY`: API credential
- `AGENT_OBS_ROOT`: output root (default `<repo>/obs`)
- `MANTLE_VENV`: Python venv path used by wrappers
- `MANTLE_INTERCEPT_MODE`: default intercept mode (`proxy` or `transparent`)
- `MANTLE_FORCE_OPENAI_BASE=1`: debug override for base URL behavior

Compatibility fallback variables (`RTRACE_*`) are supported.

## Troubleshooting

Dashboard unreachable from host in Docker:

- `docker compose ps`
- `docker compose port mantle-lab 8099`

No low-level syscall nodes in drilldown:

- Ensure `bpftrace` is installed and runnable as root.
- Confirm run output prints `eBPF trace: true` (`mantle watch <agent>` prints `false` unless `--interactive-ebpf` is provided).

Codex authentication issues:

```bash
docker compose exec mantle-lab bash -lc 'printenv OPENAI_API_KEY | codex login --with-api-key && codex login status'
```

## Demo And Portfolio Notes

For recruiter or hiring panel review, include:

- a short architecture diagram screenshot from the dashboard
- one end-to-end trace walkthrough (input -> tool calls -> outputs)
- one replay-turn drilldown walkthrough from terminal (`mantle cli`) and dashboard

This makes both product thinking and systems engineering depth obvious in a quick review.
