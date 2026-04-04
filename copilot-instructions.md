# Mantle Development Guide

## Project Structure

```
mantle/
├── interfaces/       # Protocol definitions (NEVER import from implementation)
│   ├── trace_store.py
│   ├── capture.py
│   └── llm_parser.py
├── errors.py         # Canonical exceptions (use these, not bare KeyError)
├── capture/          # System-level capture backends
│   ├── ebpf.py       # eBPF syscall tracing
│   └── mitm.py       # MITM HTTP interception
├── ingest/           # Trace storage and ingestion
│   ├── store.py      # TraceStore (implements ITraceStore)
│   └── config.py     # Path/env resolution
├── analysis/         # Trace analysis and parsing
│   ├── llm_parser.py # LLM payload parsing
│   ├── syscall_parser.py # Syscall argument parsing
│   └── replay.py     # Replay view logic
└── server/           # Web server
    ├── app.py        # FastAPI routes
    ├── logging.py    # Server logging
    └── static/       # SPA frontend
mantle_agent/         # Agent implementation (isolated, no mantle imports)
tests/                # unit/ integration/ e2e/
```

## Where to Add New Files

| Question | Package |
|----------|---------|
| New capture backend? | `capture/` |
| New storage/ingestion logic? | `ingest/` |
| New parser or analysis? | `analysis/` |
| New API endpoint or UI? | `server/` |
| New contract between components? | `interfaces/` |

## Rules for AI Agents

### 1. Test Before Ship
Every change must pass `make test` before committing. No exceptions.

### 2. Interface-First Development
When adding a new feature:
1. Define the interface in `mantle/interfaces/`
2. Write tests against the interface
3. Implement the interface
4. Verify: `make test`

### 3. Bug Fixes Require Root Cause Analysis
Do NOT fix symptoms. Follow the `/fix-bug` workflow:
1. Write a failing test that reproduces the bug
2. Create `tmp/rca_<issue>.md` using 5-WHYs
3. Fix the ROOT CAUSE
4. Verify the failing test passes
5. Delete the RCA doc

### 4. Import Boundaries
- `interfaces/` → must NOT import from any implementation module
- `capture/` → may import from `interfaces/` and `errors.py`
- `ingest/` → may import from `interfaces/`, `errors.py`, and `analysis/`
- `analysis/` → may import from `interfaces/` and `errors.py`
- `server/` → may import from `interfaces/`, `errors.py`, `ingest/`, and `analysis/`
- `mantle_agent/` → fully isolated, no mantle imports

### 5. Error Handling
Use `mantle/errors.py` exceptions:
- `TraceNotFoundError` instead of `KeyError` for missing traces
- `ParseError` for malformed data
- `CaptureError` for tracing failures
- Never catch bare `Exception`

### 6. Testing Levels
- **Unit** (`tests/unit/`): Pure functions, no I/O. Run with `make test-unit`.
- **Integration** (`tests/integration/`): Multi-module, uses filesystem. Run with `make test-integration`.
- **E2E** (`tests/e2e/`): Real agent + browser. Run with `make test-e2e`.

## Common Commands

```bash
make test              # Run all tests
make test-unit         # Unit tests only (~fast)
make test-integration  # Integration tests
make check-architecture # Validate import boundaries
make serve             # Start dashboard
```
