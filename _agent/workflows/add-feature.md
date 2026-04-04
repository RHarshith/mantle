---
description: How to add a new feature following interface-first design
---

# Add Feature Workflow

This workflow ensures every new feature has a clean interface and tests
before any implementation code is written.

## Steps

1. **Define the interface** in `mantle/interfaces/`
   - Add new methods to an existing Protocol, OR
   - Create a new Protocol file if it's a new domain
   - The interface file should have docstrings explaining the contract

2. **Write tests against the interface**
   ```bash
   # Add tests to tests/unit/ or tests/integration/
   # Tests should test the interface contract, not implementation details
   # For example: "given these inputs, expect these outputs"
   # Use mock/stub implementations if needed to test the contract
   ```

3. **Run the tests** — they should ALL FAIL (no implementation yet)
   ```bash
   // turbo
   .venv/bin/python -m pytest tests/ -k "test_new_feature" -v
   ```

4. **Implement the feature**
   - Write the implementation that satisfies the interface
   - Import and use the interface type in type annotations
   - Follow import boundaries from ARCHITECTURE.md

5. **Verify** — all tests pass
   ```bash
   // turbo
   make test
   ```

6. **Check architecture** — verify import boundaries
   ```bash
   // turbo
   make check-architecture
   ```

## Anti-Patterns to Avoid

- **Writing implementation before interface**: You'll end up shaping the
  interface around implementation details instead of user needs.
- **Testing implementation details**: Tests should verify behavior, not
  internal method calls or private state.
- **Skipping the failing test step**: If tests pass before implementation,
  they're testing nothing.
