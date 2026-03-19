#!/usr/bin/env bash
# Idempotent cleanup for the taint analysis test scenario.
set -euo pipefail

SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Stopping taint analysis test services..."
docker compose -f "$SCENARIO_DIR/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true

echo "==> Cleanup complete."
