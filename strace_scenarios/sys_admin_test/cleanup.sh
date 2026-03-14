#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="$SUITE_DIR/.runtime"
REDIS_PID_FILE="$RUNTIME_DIR/redis.pid"
API_PID_FILE="$RUNTIME_DIR/faulty_api.pid"

stop_pidfile() {
    local pid_file="$1"
    if [[ ! -f "$pid_file" ]]; then
        return
    fi

    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            sleep 0.2
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi

    rm -f "$pid_file"
}

stop_pidfile "$API_PID_FILE"
stop_pidfile "$REDIS_PID_FILE"

echo "[cleanup] Scenario services stopped"
