---
description: How to fix a bug using 5-WHYs root cause analysis
---

# Fix Bug Workflow

This workflow forces root-cause analysis before writing any fix code.
The key principle: **fix the disease, not the symptom**.

## Steps

1. **Reproduce** — write a failing test that demonstrates the bug end-to-end
Use the user description of the bug to write an end-to-end test [required]
Isolate failing behavior using integration test [required]
Narrow down to a failing unit test [optional]


2. **Root Cause Analysis** — create a temporary RCA document
   ```bash
   # Create tmp/rca_<issue>.md with the following structure:
   ```

   ```markdown
   # RCA: <brief description of bug>

   ## Symptom
   <What the user saw or what broke>

   ## Why 1: Why did this happen?
   <Direct cause>

   ## Why 2: Why did [Why 1] happen?
   <Deeper cause>

   ## Why 3: Why did [Why 2] happen?
   <Even deeper>

   ## Why 4: Why did [Why 3] happen?
   <Approaching root cause>

   ## Why 5: Why did [Why 4] happen?
   <Root cause — usually "a test was missing" or "a design assumption was wrong">

   ## Root Cause
   <One-line summary of the actual root cause>

   ## Fix Plan
   <What to change, in which files>
   ```

3. **Fix the root cause** — implement the fix identified in the RCA
   - Fix the ROOT CAUSE from the RCA, NOT the surface symptom
   - If the root cause is a design issue, propose a fundamental change to design
   - If the root cause is "missing validation", add validation
   - If the root cause is "missing test", add the test AND the fix

4. **Verify** — all tests pass, including regression

5. **Cleanup** — delete the RCA document

## Why This Matters

Without RCA, agents tend to:
- Add null checks that mask the real problem
- Catch exceptions too broadly
- Fix one code path but leave the root cause to break another path

The 5-WHYs forces tracing causality before coding. The RCA document is
disposable — its value is in the thinking process, not the artifact.
