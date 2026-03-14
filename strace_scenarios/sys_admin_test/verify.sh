#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "$0")" && pwd)"
REDIS_PORT=6380
API_PORT=18080

if ! redis_cli_out="$(redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>/dev/null)"; then
    echo "[verify] Redis is not reachable on :$REDIS_PORT" >&2
    exit 1
fi

if [[ "$redis_cli_out" != "PONG" ]]; then
    echo "[verify] Unexpected Redis ping response: $redis_cli_out" >&2
    exit 1
fi

api_status="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$API_PORT/health" || true)"
if [[ "$api_status" != "500" ]]; then
    echo "[verify] Expected API to be faulted (500), got: $api_status" >&2
    exit 1
fi

echo "[verify] Scenario preconditions validated"
echo "[verify] Redis: PONG"
echo "[verify] API /health: 500 (fault active)"
