#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIME_DIR="$SUITE_DIR/.runtime"
LOG_DIR="$RUNTIME_DIR/logs"
REDIS_PORT=6380
API_PORT=18080
REDIS_PID_FILE="$RUNTIME_DIR/redis.pid"
API_PID_FILE="$RUNTIME_DIR/faulty_api.pid"
REDIS_CONF="$RUNTIME_DIR/redis.conf"
STATE_FILE="$RUNTIME_DIR/fault_state.json"

mkdir -p "$RUNTIME_DIR" "$LOG_DIR"

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_if_missing() {
    local bin="$1"
    local pkg="$2"
    if command_exists "$bin"; then
        return
    fi

    if ! command_exists apt-get; then
        echo "[setup] Missing required binary '$bin' and apt-get is unavailable." >&2
        echo "[setup] Run this scenario in the Ubuntu Docker container, or preinstall '$pkg'." >&2
        exit 1
    fi

    echo "[setup] Installing missing package: $pkg"
    apt-get update -y >/dev/null
    apt-get install -y "$pkg" >/dev/null
}

is_pid_alive() {
    local pid="$1"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

cleanup_stale_pidfile() {
    local pid_file="$1"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file" 2>/dev/null || true)"
        if ! is_pid_alive "$pid"; then
            rm -f "$pid_file"
        fi
    fi
}

install_if_missing redis-server redis-server
install_if_missing redis-cli redis-tools
install_if_missing curl curl
install_if_missing lsof lsof

cleanup_stale_pidfile "$REDIS_PID_FILE"
cleanup_stale_pidfile "$API_PID_FILE"

if redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    echo "[setup] Redis already running on :$REDIS_PORT"
else
    cat > "$REDIS_CONF" <<EOF
bind 127.0.0.1
port $REDIS_PORT
daemonize yes
pidfile $REDIS_PID_FILE
dir $RUNTIME_DIR
save ""
appendonly no
logfile $LOG_DIR/redis.log
EOF
    redis-server "$REDIS_CONF"

    for _ in {1..20}; do
        if redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null 2>&1; then
            echo "[setup] Redis started on :$REDIS_PORT"
            break
        fi
        sleep 0.2
    done
fi

if [[ ! -f "$STATE_FILE" ]]; then
    cat > "$STATE_FILE" <<EOF
{"force_unhealthy": true}
EOF
fi

if [[ -f "$API_PID_FILE" ]]; then
    api_pid="$(cat "$API_PID_FILE" 2>/dev/null || true)"
else
    api_pid=""
fi

if is_pid_alive "$api_pid"; then
    echo "[setup] Faulty API already running on :$API_PORT"
else
    nohup python3 "$SUITE_DIR/services/faulty_api.py" \
        --host 127.0.0.1 \
        --port "$API_PORT" \
        --state-file "$STATE_FILE" \
        > "$LOG_DIR/faulty_api.log" 2>&1 &
    echo $! > "$API_PID_FILE"
    echo "[setup] Faulty API started on :$API_PORT"
fi

for _ in {1..20}; do
    if curl -fsS "http://127.0.0.1:$API_PORT/admin/state" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

# Force fault state each time so the scenario is reproducible.
curl -fsS -X POST "http://127.0.0.1:$API_PORT/admin/toggle-health?healthy=0" >/dev/null

echo "[setup] Scenario initialized"
echo "[setup] Redis health: $(redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping 2>/dev/null || echo fail)"
echo "[setup] API /health status: $(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$API_PORT/health" || echo fail)"
