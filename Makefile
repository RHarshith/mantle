# Mantle Development Makefile
# Standard targets for testing, linting, and serving.

SHELL := /usr/bin/env bash

REPO_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
VENV_PATH ?= $(REPO_ROOT)/.venv
PYTHON_BIN := $(VENV_PATH)/bin/python
PIP_BIN := $(VENV_PATH)/bin/pip

REQUIRED_APT_PACKAGES := bpftrace iptables ca-certificates python3-venv python3-pip

.PHONY: test test-unit test-integration test-e2e lint typecheck serve proxy check-architecture \
	help build preflight-sudo preflight-foundation install-system-deps \
	install-python-deps verify-mantle clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: preflight-sudo preflight-foundation install-system-deps install-python-deps verify-mantle ## Demo-ready setup for Mantle (run with sudo)

preflight-sudo: ## Fail unless make is running as root via sudo
	@set -euo pipefail; \
	if [[ "$$EUID" -ne 0 ]]; then \
		echo "Error: run with sudo, for example: sudo make build" >&2; \
		exit 1; \
	fi; \
	echo "[ok] Running as root (sudo context confirmed)."

preflight-foundation: ## Validate Linux and Python foundations that must already exist
	@set -euo pipefail; \
	if [[ "$$EUID" -ne 0 ]]; then \
		echo "Error: run with sudo, for example: sudo make build" >&2; \
		exit 1; \
	fi; \
	if [[ "$$(uname -s)" != "Linux" ]]; then \
		echo "Error: Mantle demo setup currently supports Linux only." >&2; \
		exit 1; \
	fi; \
	if [[ ! -r /proc/version ]]; then \
		echo "Error: Linux kernel information is unavailable; verify kernel support manually." >&2; \
		exit 1; \
	fi; \
	echo "[ok] Kernel: $$(uname -r)"; \
	if ! command -v python3 >/dev/null 2>&1; then \
		echo "Error: python3 is not installed. Install Python 3.11+ first, then rerun make build." >&2; \
		exit 1; \
	fi; \
	if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then \
		echo "Error: Python 3.11+ is required (see pyproject requires-python)." >&2; \
		exit 1; \
	fi; \
	echo "[ok] python3: $$(python3 --version)"

install-system-deps: ## Install missing system dependencies required by Mantle runtime
	@set -euo pipefail; \
	if ! command -v apt-get >/dev/null 2>&1; then \
		echo "Error: apt-get not found. Install these packages manually: $(REQUIRED_APT_PACKAGES)" >&2; \
		exit 1; \
	fi; \
	missing_pkgs=""; \
	for pkg in $(REQUIRED_APT_PACKAGES); do \
		if dpkg -s "$$pkg" >/dev/null 2>&1; then \
			echo "[ok] apt package present: $$pkg"; \
		else \
			missing_pkgs="$$missing_pkgs $$pkg"; \
		fi; \
	done; \
	if [[ -n "$$missing_pkgs" ]]; then \
		echo "[*] Installing missing apt packages:$$missing_pkgs"; \
		apt-get update; \
		DEBIAN_FRONTEND=noninteractive apt-get install -y $$missing_pkgs; \
	else \
		echo "[ok] All required apt packages are already installed."; \
	fi

install-python-deps: ## Create venv and install Python dependencies only when needed
	@set -euo pipefail; \
	mkdir -p "$(REPO_ROOT)"; \
	if [[ ! -x "$(PYTHON_BIN)" ]]; then \
		echo "[*] Creating virtualenv at $(VENV_PATH)"; \
		python3 -m venv "$(VENV_PATH)"; \
	else \
		echo "[ok] Virtualenv already exists at $(VENV_PATH)"; \
	fi; \
	if [[ ! -x "$(PIP_BIN)" ]]; then \
		echo "Error: pip not found in virtualenv: $(PIP_BIN)" >&2; \
		exit 1; \
	fi; \
	state_file="$(VENV_PATH)/.mantle_runtime_deps.sha256"; \
	current_hash="$$(cat "$(REPO_ROOT)/requirements.runtime.txt" "$(REPO_ROOT)/pyproject.toml" | sha256sum | awk '{print $$1}')"; \
	deps_ok=0; \
	if [[ -f "$$state_file" ]] && [[ "$$(cat "$$state_file")" == "$$current_hash" ]]; then \
		if "$(PYTHON_BIN)" -c "import fastapi, uvicorn, mitmproxy, mantle" >/dev/null 2>&1; then \
			deps_ok=1; \
		fi; \
	fi; \
	if [[ "$$deps_ok" -eq 1 ]]; then \
		echo "[ok] Python dependencies already installed for current requirement set."; \
	else \
		echo "[*] Installing Python runtime dependencies"; \
		"$(PYTHON_BIN)" -m pip install --upgrade pip; \
		"$(PIP_BIN)" install -r "$(REPO_ROOT)/requirements.runtime.txt"; \
		"$(PIP_BIN)" install -e "$(REPO_ROOT)"; \
		echo "$$current_hash" > "$$state_file"; \
		echo "[ok] Python dependencies installed."; \
	fi

verify-mantle: ## Verify that bin/mantle is now functional
	@set -euo pipefail; \
	if [[ ! -x "$(REPO_ROOT)/bin/mantle" ]]; then \
		echo "Error: missing executable: $(REPO_ROOT)/bin/mantle" >&2; \
		exit 1; \
	fi; \
	if [[ ! -x "$(VENV_PATH)/bin/mitmdump" ]]; then \
		echo "Error: mitmdump not available in venv after setup." >&2; \
		exit 1; \
	fi; \
	MANTLE_VENV="$(VENV_PATH)" "$(REPO_ROOT)/bin/mantle" serve --help >/dev/null; \
	echo "[ok] bin/mantle is functional (serve command resolved)."

serve: ## Start the dashboard server
	@set -euo pipefail; \
	cd $(REPO_ROOT); \
	echo "Checking for process on port 8099..."; \
	if ss -ltn "sport = :8099" | tail -n +2 | grep -q .; then \
	  echo "Stopping process on port 8099..."; \
	  user_pids="$$(lsof -nP -iTCP:8099 -sTCP:LISTEN -u "$$USER" -t 2>/dev/null || true)"; \
	  if [[ -n "$$user_pids" ]]; then kill $$user_pids; fi; \
	  sleep 1; \
	else \
	  echo "No process running on port 8099."; \
	fi; \
	if ss -ltn "sport = :8099" | tail -n +2 | grep -q .; then \
	  remaining_pids="$$(lsof -nP -iTCP:8099 -sTCP:LISTEN -t 2>/dev/null || true)"; \
	  if [[ -n "$$remaining_pids" ]]; then \
	    echo "Error: port 8099 is still in use by PID(s): $$remaining_pids" >&2; \
	  else \
	    echo "Error: port 8099 is still in use (process owner may be hidden or owned by another user)." >&2; \
	  fi; \
	  exit 1; \
	fi; \
	bin/mantle serve

proxy: ## Start LiteLLM proxy on port 4000 (stops existing server first)
	@set -euo pipefail; \
	cd $(REPO_ROOT); \
	echo "Checking for process on port 4000..."; \
	if ss -ltn "sport = :4000" | tail -n +2 | grep -q .; then \
	  echo "Stopping process on port 4000..."; \
	  user_pids="$$(lsof -nP -iTCP:4000 -sTCP:LISTEN -u "$$USER" -t 2>/dev/null || true)"; \
	  if [[ -n "$$user_pids" ]]; then kill $$user_pids; fi; \
	  sleep 1; \
	else \
	  echo "No process running on port 4000."; \
	fi; \
	if ss -ltn "sport = :4000" | tail -n +2 | grep -q .; then \
	  remaining_pids="$$(lsof -nP -iTCP:4000 -sTCP:LISTEN -t 2>/dev/null || true)"; \
	  if [[ -n "$$remaining_pids" ]]; then \
	    echo "Error: port 4000 is still in use by PID(s): $$remaining_pids" >&2; \
	  else \
	    echo "Error: port 4000 is still in use (process owner may be hidden or owned by another user)." >&2; \
	  fi; \
	  exit 1; \
	fi; \
	cd $(REPO_ROOT)/litellm_proxy; \
	$(PYTHON_BIN) -m uvicorn proxy:app --host 0.0.0.0 --port 4000

clean: ## Remove caches and temp files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f tmp/rca_*.md
