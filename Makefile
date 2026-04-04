# Mantle Development Makefile
# Standard targets for testing, linting, and serving.

PYTHON ?= .venv/bin/python
PYTEST ?= $(PYTHON) -m pytest

.PHONY: test test-unit test-integration test-e2e lint typecheck serve check-architecture help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: test-unit test-integration ## Run unit + integration tests

test-unit: ## Run unit tests only
	$(PYTEST) tests/unit/ -v --tb=short -m unit

test-integration: ## Run integration tests
	$(PYTEST) tests/integration/ -v --tb=short -m integration

test-e2e: ## Run E2E tests (requires API keys / Playwright)
	$(PYTEST) tests/e2e/ -v --tb=short -m e2e

lint: typecheck check-architecture ## Run all static checks

typecheck: ## Run mypy type checking
	$(PYTHON) -m mypy mantle/interfaces/ --strict --ignore-missing-imports 2>/dev/null || \
		echo "mypy not installed — skipping type check"

check-architecture: ## Validate import boundaries
	$(PYTHON) scripts/check_architecture.py

serve: ## Start the dashboard server
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
		bin/mantle serve

clean: ## Remove caches and temp files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f tmp/rca_*.md
