# Mantle Development Guide

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
