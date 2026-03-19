#!/usr/bin/env bash
# Idempotent setup for the taint analysis test scenario.
# Starts containerized test services via docker-compose.
set -euo pipefail

SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Starting taint analysis test services..."
docker compose -f "$SCENARIO_DIR/docker-compose.yml" up -d --build

echo "==> Waiting for services to become healthy..."
for svc in taint-test-vuln-app taint-test-mock-mcp; do
    retries=20
    while [ $retries -gt 0 ]; do
        status=$(docker inspect --format='{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "missing")
        if [ "$status" = "healthy" ]; then
            echo "    $svc is healthy"
            break
        fi
        retries=$((retries - 1))
        sleep 1
    done
    if [ $retries -eq 0 ]; then
        echo "ERROR: $svc did not become healthy in time" >&2
        docker compose -f "$SCENARIO_DIR/docker-compose.yml" logs "$svc"
        exit 1
    fi
done

echo "==> Setup complete."
