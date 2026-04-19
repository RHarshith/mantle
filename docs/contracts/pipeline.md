# Contract Pipeline: Capture to UI

Status: active
Version: v1

## Purpose

This document is the index and transformation map across all layer contracts.

## Layer Map

1. Kernel probe stream contract
   - File: `docs/contracts/kernel-bpftrace-probe-contract.md`
   - Boundary: bpftrace stdout `EVT|...` -> parser

2. eBPF JSONL contract
   - File: `docs/contracts/ebpf-jsonl-contract.md`
   - Boundary: parser output JSONL -> strict ingest normalization

3. Post-processing and correlation contract
   - File: `docs/contracts/post-processing-correlation-contract.md`
   - Boundary: ebpf/events/mitm -> turns/tool calls -> SQLite

4. Downstream analysis/API contract
   - File: `docs/contracts/downstream-analysis-contract.md`
   - Boundary: correlated model + DB -> API responses

5. Frontend rendering contract
   - File: `docs/contracts/frontend-rendering-contract.md`
   - Boundary: API payloads -> visible dashboard behavior

## Transformation Chain

```text
Kernel tracepoints (bpftrace)
  -> EVT text lines
  -> normalized eBPF JSONL events
  -> correlated sys + agent events
  -> turns + tool call pairs
  -> SQLite canonical tables (event/turns/tool_calls)
  -> replay and analysis API payloads
  -> dashboard UI rendering (overview, replay, state diff, source popups)
```

## Boundary Contracts and Failure Semantics

- L1 -> L2:
  - malformed/non-EVT lines are dropped at parser level
  - delimiter/positional changes are breaking

- L2 -> L3:
  - strict JSON object + supported type validation
  - violations raise runtime failure (no silent failure)

- L3 -> L4:
  - canonical correlated turn semantics and tier metadata
  - SQLite columns are stable query surface; `payload` is extension bucket

- L4 -> L5:
  - frontend assumes specific key names and nested shapes
  - payload shape changes require same-PR frontend updates

## Confidence Tier Carry-through

Network destination confidence must remain explicit end-to-end:

- `tier1_payload_exact`
- `tier2_payload_mapped`
- `tier3_network_only`

These labels may not be collapsed or reworded without updating all dependent layers.

## Required Change Workflow

When changing any layer contract:

1. Update the impacted contract file in this folder.
2. Update adjacent layer contracts if boundary shape changes.
3. Update implementation and tests in same change.
4. Record the decision in `docs/micro-decisions.md`.
5. Validate e2e behavior for replay/dashboard flow.

## Pull Request Checklist

- [ ] Which layer(s) changed?
- [ ] Which contract file(s) were updated?
- [ ] Was cross-layer compatibility verified?
- [ ] Were tests added/updated for the changed boundary?
- [ ] Were confidence tiers and source metadata preserved?
