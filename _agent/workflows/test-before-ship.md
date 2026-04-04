---
description: How to verify changes before shipping
---

# Test Before Ship Workflow

Run this workflow before committing any change.

## Steps

1. **Run all unit tests**
   ```bash
   // turbo
   make test-unit
   ```

2. **Run integration tests** 
   ```bash
   // turbo
   make test-integration
   ```

3. **Check imports and types** (if mypy is available)
   ```bash
   // turbo
   make lint
   ```

4. **Verify the dashboard starts**
   ```bash
   make serve
   ```
   Then open http://localhost:8765 and verify the page loads.

5. **If UI changes were made**, run UI tests
   ```bash
   make test-e2e
   ```

## Quick Check (Minimum)

If you only have time for one command:
```bash
// turbo
make test
```

This runs unit + integration tests. E2E tests are separate because they
require external dependencies (API keys, Playwright).
