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
- Tiered API tracing confidence:
	- `tier1_payload_exact`: payload + exact endpoint match
	- `tier2_payload_mapped`: payload + heuristic/mapped endpoint
	- `tier3_network_only`: baseline network telemetry only
	- per-trace quality endpoint: `/api/traces/{trace_id}/capture-quality`

## Architecture At A Glance

```text
Agent Runtime
	-> mantle watch
			-> eBPF syscall capture (process/file/network)
			-> MITM capture (API/network payload view)
			-> agent event sink (structured JSONL)

Captured data (.mantle/obs/)
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
mantle watch python3 -m mantle_agent.cli_agent "inspect this repository and summarize"
```

Open `http://127.0.0.1:8099`.

## Demo Readiness Mode

For client demos, run Mantle in hardening mode:

- Freeze non-demo feature work for the sprint.
- Validate runtime matrix:
	- OpenAI Codex (latest)
	- GitHub Copilot CLI
	- `mantle_agent` with custom OpenAI-compatible endpoint
- Require contract checks before behavior changes:
	- frontend <-> API
	- API <-> store
	- store <-> capture
	- userspace capture <-> kernel event ABI
- Require test evidence before merge (`unit`, `integration`, and demo-relevant `e2e`).
- Document micro decisions in `docs/micro-decisions.md`.

See `docs/api-tracing-limitations.md` for capture guarantees and limitations.

## CLI Reference

`mantle serve`

- Starts the FastAPI dashboard server.
- Usage: `mantle serve [--host <host>] [--port <port>]`

`mantle watch`

- Runs an executable under MITM + eBPF capture.
- Interactive mode (`mantle watch <agent>`) preserves TTY behavior and disables eBPF capture by default; use `--interactive-ebpf` to opt in to interactive eBPF tracing.
- Usage: `mantle watch [--mode <proxy|transparent>] [--trace-id <id>] [--port <mitm_port>] [--interactive-ebpf] <executable> [exec] [prompt...]`

Examples:

```bash
mantle watch python3 -m mantle_agent.cli_agent --interactive
mantle watch --interactive-ebpf python3 -m mantle_agent.cli_agent --interactive
mantle watch python3 -m mantle_agent.cli_agent "summarize this repository"
mantle watch --mode transparent python3 -m mantle_agent.cli_agent "trace outbound API calls"
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

Mantle writes trace outputs to a fixed repo-local layout under `.mantle/obs/`:

- `.mantle/obs/traces/<trace_id>.ebpf.jsonl`
- `.mantle/obs/mitm/<trace_id>.mitm.jsonl`
- `.mantle/obs/events/<trace_id>.events.jsonl`
- `.mantle/obs/proxy/<trace_id>.ebpf.jsonl` (LiteLLM proxy payload capture)

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
├── run_intercepted_agent.sh
└── .mantle/
	├── obs/
	├── config/
	└── logs/
	    └── runtime/
```

## Engineering Highlights

- End-to-end instrumentation design spanning agent-level and OS-level telemetry
- Real-time UX with backend polling and websocket update flow
- Reproducible scenario harness for validation and regression checks

## Environment Variables

- `OPENAI_API_KEY`: API credential
- `MANTLE_VENV`: Python venv path used by wrappers
- `MANTLE_INTERCEPT_MODE`: default intercept mode (`proxy` or `transparent`)
- `MANTLE_FORCE_OPENAI_BASE=1`: debug override for base URL behavior

Folder locations are fixed to `<repo>/.mantle/{obs,config,logs}`.

Compatibility fallback variables (`RTRACE_*`) are supported.

## Troubleshooting

Dashboard unreachable from host:

- Confirm `mantle serve` is running and bound to the expected host/port.
- Check local firewall rules and ensure the selected port is available.

No low-level syscall nodes in drilldown:

- Ensure `bpftrace` is installed and runnable as root.
- Confirm run output prints `eBPF trace: true` (`mantle watch <agent>` prints `false` unless `--interactive-ebpf` is provided).

API credential issues:

```bash
printenv OPENAI_API_KEY | wc -c
```

## Demo And Portfolio Notes

For recruiter or hiring panel review, include:

- a short architecture diagram screenshot from the dashboard
- one end-to-end trace walkthrough (input -> tool calls -> outputs)
- one replay-turn drilldown walkthrough from terminal (`mantle cli`) and dashboard

This makes both product thinking and systems engineering depth obvious in a quick review.
