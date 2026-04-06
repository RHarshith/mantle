# Agent Guide: Mantle

Mantle is a framework for deploying secure and observable AI agents. This guide outlines the development rules and best practices for contributing to the Mantle codebase.

# Development Principles
Security and performance are top priorities. Follow these principles:
- **Test Before Ship**: Every feature must have an automated end-to-end test that involves running the mantle_agent with a sample prompt. Browser automation tests are ideal (actually check if buttons and user flows work), but if that's not feasible, at least have an integration test that runs the agent code and checks outputs.

- **No Silent Failures**: If something can fail, it should raise an exception. Don't catch exceptions unless you can handle them meaningfully. This ensures issues are visible and can be fixed. If any exceptions are being handled, ensure they are clearly logged and visible.







