# Mantle Development Makefile
# Standard targets for testing, linting, and serving.

SHELL := /usr/bin/env bash

REPO_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
COMPOSE_FILE := $(REPO_ROOT)/docker-compose.yml
DOCKER_COMPOSE_API_VERSION ?= 1.44
COMPOSE_CMD := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "DOCKER_API_VERSION=$(DOCKER_COMPOSE_API_VERSION) docker-compose"; fi)
MANTLE_HOST_HOME := $(shell if [ -n "$$MANTLE_HOST_HOME" ]; then echo "$$MANTLE_HOST_HOME"; elif [ -n "$$SUDO_USER" ]; then h="$$(getent passwd "$$SUDO_USER" 2>/dev/null | cut -d: -f6)"; if [ -n "$$h" ]; then echo "$$h"; else echo "$$HOME"; fi; else echo "$$HOME"; fi)
COMPOSE_RUN := MANTLE_HOST_HOME="$(MANTLE_HOST_HOME)" $(COMPOSE_CMD)

.PHONY: serve proxy check-architecture \
	help build down clean daemon-start daemon-stop daemon-status ensure-compose ensure-docker-access ensure-repo-mountpoint

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

ensure-compose: ## Ensure docker compose is installed (plugin or standalone)
	@set -euo pipefail; \
	if [[ -z "$(COMPOSE_CMD)" ]]; then \
		echo "Error: Docker Compose is not available." >&2; \
		echo "Install either the docker compose plugin or docker-compose binary." >&2; \
		exit 1; \
	fi

ensure-docker-access: ## Ensure current user can reach Docker daemon
	@set -euo pipefail; \
	if ! docker info >/dev/null 2>&1; then \
		echo "Error: cannot access Docker daemon." >&2; \
		echo "Run with sudo (for example: sudo make build) or add this user to the docker group." >&2; \
		exit 1; \
	fi

ensure-repo-mountpoint: ## Ensure nested /app/.mantle bind target exists inside repo mount
	@set -euo pipefail; \
	mkdir -p "$(REPO_ROOT)/.mantle"

build: ensure-compose ensure-docker-access ensure-repo-mountpoint ## Build and start Mantle services via docker compose
	@echo "[mantle] Building and starting docker compose services..."
	@set -euo pipefail; \
	if [[ "$(COMPOSE_CMD)" == *"docker-compose"* ]]; then \
		echo "[mantle] docker-compose v1 detected; resetting stack to avoid ContainerConfig recreate bug..."; \
		$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" down --remove-orphans || true; \
	fi; \
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" up -d --build

down: ensure-compose ensure-docker-access ## Stop Mantle docker compose services
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" down

serve: ensure-compose ensure-docker-access ensure-repo-mountpoint ## Start the dashboard server (via docker compose)
	@set -euo pipefail; \
	if [[ "$(COMPOSE_CMD)" == *"docker-compose"* ]]; then \
		$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" rm -fs server >/dev/null 2>&1 || true; \
	fi; \
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" up -d server

proxy: ensure-compose ensure-docker-access ensure-repo-mountpoint ## Start LiteLLM proxy (via docker compose)
	@set -euo pipefail; \
	if [[ "$(COMPOSE_CMD)" == *"docker-compose"* ]]; then \
		$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" rm -fs proxy >/dev/null 2>&1 || true; \
	fi; \
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" up -d proxy

daemon-start: ensure-compose ensure-docker-access ensure-repo-mountpoint ## Start the eBPF tracing daemon (via docker compose)
	@set -euo pipefail; \
	if [[ "$(COMPOSE_CMD)" == *"docker-compose"* ]]; then \
		$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" rm -fs daemon >/dev/null 2>&1 || true; \
	fi; \
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" up -d daemon

daemon-stop: ensure-compose ensure-docker-access ## Stop the eBPF tracing daemon
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" exec -T daemon python3 -m mantle.daemon.client shutdown

daemon-status: ensure-compose ensure-docker-access ## Show daemon health and active traces
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" exec -T daemon python3 -m mantle.daemon.client status

clean: ensure-compose ensure-docker-access ## Remove caches, temp files, and docker containers
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f tmp/rca_*.md
	$(COMPOSE_RUN) -f "$(COMPOSE_FILE)" down -v --remove-orphans
