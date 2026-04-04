# Architecture Invariants

This file defines structural rules that MUST be maintained. A lint script
(`scripts/check_architecture.py`) validates these automatically.

## Import Boundaries

| Source Module      | May Import From                                  | Must NOT Import From       |
|--------------------|--------------------------------------------------|----------------------------|
| `interfaces/`     | stdlib, typing only                              | capture, ingest, analysis, server, agent |
| `errors.py`       | stdlib only                                      | everything else in mantle  |
| `capture/`        | interfaces, errors, stdlib                       | ingest, analysis, server, agent |
| `ingest/`         | interfaces, errors, analysis, stdlib             | capture, server, agent     |
| `analysis/`       | interfaces, errors, stdlib                       | capture, ingest, server, agent |
| `server/`         | interfaces, errors, ingest, analysis, stdlib     | capture, agent             |
| `mantle_agent/`   | stdlib only (fully isolated)                     | mantle.* (any)             |
| `tests/`          | everything (test code has no boundary)           | —                          |

## Module Responsibilities

| Module                     | Single Responsibility                                    |
|----------------------------|----------------------------------------------------------|
| `interfaces/trace_store`   | ITraceStore Protocol definition                          |
| `interfaces/capture`       | ICapture Protocol definition                             |
| `interfaces/llm_parser`    | ILLMParser Protocol definition                           |
| `errors`                   | Canonical exception hierarchy                            |
| `capture/ebpf`             | eBPF tracing via bpftrace                                |
| `capture/mitm`             | MITM HTTP interception via mitmproxy                     |
| `ingest/store`             | Trace ingestion, correlation, graph projection           |
| `ingest/config`            | Environment/path resolution                              |
| `analysis/llm_parser`      | LLM payload parsing and schema application               |
| `analysis/syscall_parser`  | Syscall argument string parsing                          |
| `analysis/replay`          | Replay view business logic                               |
| `server/app`               | HTTP API routes and WebSocket handlers                   |
| `server/logging`           | Server-side logging utilities                            |

## Forbidden Patterns

1. **Never catch bare `Exception`** in production code. Use specific exceptions.
2. **Never add global mutable state** outside of `TraceStore`. Shared state = bugs.
3. **Never inline test data** in test files. Use `tests/conftest.py` fixtures.
4. **Never skip writing a test** for a bug fix. The test proves the fix works.
5. **Never import from `mantle.*`** inside `mantle_agent/`. The agent is isolated.
