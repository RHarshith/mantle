# Agent Guide: Mantle

Mantle is a framework for deploying secure and observable AI agents. This guide outlines the development rules and best practices for contributing to the Mantle codebase.

# Development Principles
Security and performance are top priorities. Follow these principles:
- **Test Before Ship**: Every feature must have an automated end-to-end test that involves running the mantle_agent with a sample prompt. Browser automation tests are ideal (actually check if buttons and user flows work), but if that's not feasible, at least have an integration test that runs the cli_agent with a prompt and checks outputs.

- **No Silent Failures**: If something can fail, it should raise an exception. Don't catch exceptions unless you can handle them meaningfully. This ensures issues are visible and can be fixed. If any exceptions are being handled, ensure they are clearly logged and visible.


# Mandatory Delivery Protocol

All non-trivial work must follow this sequence:

1. **Alignment Gate (required before coding)**
	- Confirm user goals, constraints, deadlines, and non-goals.
	- Define explicit acceptance criteria.
	- If assumptions are unresolved, ask questions before implementation.

2. **Contract Gate (required before modifying behavior)**
	- Identify impacted boundaries:
	  - frontend <-> API
	  - API <-> store
	  - store <-> capture ingestion
	  - userspace capture <-> kernel event ABI
	- Document expected request/response and event schema shape changes.

3. **Implementation Gate**
	- Implement the smallest coherent slice that satisfies one acceptance criterion.
	- Avoid speculative feature additions outside agreed scope.

4. **Verification Gate (required before claiming done)**
	- Run relevant unit/integration/e2e tests.
	- Provide concrete evidence from test output.
	- Report residual risks and unsupported cases explicitly.

5. **Documentation Gate**
	- Update docs for operator-facing behavior changes.
	- Log micro decisions in docs/micro-decisions.md.


# Role-Based Agent Handoff

Use these specialized agents for complex work:

- **advisor-orchestrator**: planning, scope control, acceptance criteria.
- **contract-guardian**: interface/schema stability and error semantics.
- **tracing-specialist**: MITM/eBPF fidelity, endpoint inference, replay extraction.
- **test-architect**: journey-level test strategy and regression hardening.

Default order for large changes:
advisor-orchestrator -> contract-guardian -> tracing-specialist -> test-architect -> implementation.


# Demo Mode Acceptance Matrix

For demo-readiness changes, the default runtime matrix is:

- openai codex (latest)
- github copilot cli
- mantle_agent with custom OpenAI-compatible endpoint

A demo change is not complete unless all required runtimes pass agreed acceptance checks.


# API Tracing Confidence Rules

Use and preserve tier labels for capture confidence:

- `tier1_payload_exact`: payload extracted and endpoint matched exactly.
- `tier2_payload_mapped`: payload extracted but endpoint inferred heuristically or via manual mapping.
- `tier3_network_only`: only baseline network endpoint telemetry is available.

Rules:
- Never present inferred endpoint data as certain without tier/source metadata.
- Never silently suppress degraded capture states.
- Always document limitations when changing inference behavior.







