# Agent Guide: Mantle

Mantle is a framework for deploying secure and observable AI agents. This guide outlines the development rules and best practices for contributing to the Mantle codebase.


# Passworless SUDO available
This system has passwordless sudo enabled for testing. Exercise caution when running commands with sudo, as they will execute without a password prompt.

# Development Principles
Security and performance are top priorities. Follow these principles:
- **Test Before Ship**: Every feature must have an automated end-to-end test that involves running the mantle_agent with a sample prompt. Browser automation tests are ideal (actually check if buttons and user flows work), but if that's not feasible, at least have an integration test that runs the cli_agent with a prompt and checks outputs.

- **No Silent Failures**: If something can fail, it should raise an exception. Don't catch exceptions unless you can handle them meaningfully. This ensures issues are visible and can be fixed. If any exceptions are being handled, ensure they are clearly logged and visible.

- **No legacy code**: Avoid adding new code that supports legacy behavior or deprecated features. If a feature is no longer needed, remove it instead of adding new code to support it.

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








