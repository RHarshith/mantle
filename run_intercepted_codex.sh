#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run codex (or any external agent) with mitmproxy API interception
# and optional strace syscall tracing.
#
# Usage:
#   ./run_intercepted_codex.sh "List files in the home directory"
#   ./run_intercepted_codex.sh                    # interactive (no task)
#   ./run_intercepted_codex.sh --no-strace "Explain this repo"
#   ./run_intercepted_codex.sh --agent "aider" "Fix the bug"
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

USE_STRACE=true
TRACE_ID=""
MITM_PORT=8899
AGENT_BIN="codex"
TASK=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-strace)   USE_STRACE=false; shift ;;
        --trace-id)    TRACE_ID="$2"; shift 2 ;;
        --port)        MITM_PORT="$2"; shift 2 ;;
        --agent)       AGENT_BIN="$2"; shift 2 ;;
        -*)            echo "Unknown flag: $1" >&2; exit 1 ;;
        *)             TASK="$1"; shift; break ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_ROOT="${AGENT_OBS_ROOT:-$SCRIPT_DIR/obs}"
[ -z "$TRACE_ID" ] && TRACE_ID="${AGENT_BIN}_$(date +%Y%m%d_%H%M%S).strace.log"

mkdir -p "$OBS_ROOT/traces" "$OBS_ROOT/events" "$OBS_ROOT/mitm"

MITM_JSONL="$OBS_ROOT/mitm/${TRACE_ID%.strace.log}.mitm.jsonl"
STRACE_FILE="$OBS_ROOT/traces/$TRACE_ID"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"

# Find mitmdump
MITMDUMP="$(command -v mitmdump 2>/dev/null || echo "$HOME/.local/bin/mitmdump")"
[ -x "$MITMDUMP" ] || { echo "Error: mitmdump not found. Install with: pipx install mitmproxy" >&2; exit 1; }
[ -f "$MITM_CA" ]   || { echo "Error: mitmproxy CA cert not found. Run 'mitmdump' once to generate it." >&2; exit 1; }

command -v "$AGENT_BIN" >/dev/null 2>&1 || { echo "Error: '$AGENT_BIN' not found in PATH" >&2; exit 1; }

echo "═══════════════════════════════════════════════════════════"
echo "  Intercepted External Agent"
echo "═══════════════════════════════════════════════════════════"
echo "  Agent:       $AGENT_BIN"
echo "  Task:        ${TASK:-<interactive>}"
echo "  Trace ID:    $TRACE_ID"
echo "  MITM proxy:  localhost:$MITM_PORT"
echo "  MITM log:    $MITM_JSONL"
echo "  Strace:      $USE_STRACE"
$USE_STRACE && echo "  Strace file: $STRACE_FILE"
echo "═══════════════════════════════════════════════════════════"

# Start mitmdump
export MITM_CAPTURE_FILE="$MITM_JSONL"
"$MITMDUMP" -p "$MITM_PORT" --ssl-insecure \
    -s "$SCRIPT_DIR/mitm_capture.py" \
    --set capture_file="$MITM_JSONL" -q &
MITM_PID=$!
sleep 2
kill -0 "$MITM_PID" 2>/dev/null || { echo "Error: mitmdump failed to start" >&2; exit 1; }
echo "[*] mitmdump started (PID $MITM_PID)"

# Proxy + TLS env vars
# IMPORTANT: Rust's reqwest uses LOWERCASE env vars, Node.js uses UPPERCASE.
# We export both to cover all runtimes (Python, Node.js, Rust, Go, curl).
export HTTPS_PROXY="http://127.0.0.1:$MITM_PORT"
export HTTP_PROXY="http://127.0.0.1:$MITM_PORT"
export https_proxy="http://127.0.0.1:$MITM_PORT"
export http_proxy="http://127.0.0.1:$MITM_PORT"
export SSL_CERT_FILE="$MITM_CA"
export REQUESTS_CA_BUNDLE="$MITM_CA"
export NODE_EXTRA_CA_CERTS="$MITM_CA"
export NODE_TLS_REJECT_UNAUTHORIZED=0

cleanup() {
    echo ""
    echo "[*] Stopping mitmdump (PID $MITM_PID)..."
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
    echo "[*] Done. Captured data:"
    [ -f "$MITM_JSONL" ] && echo "    MITM log:   $MITM_JSONL ($(wc -l < "$MITM_JSONL") lines)"
    $USE_STRACE && [ -f "$STRACE_FILE" ] && echo "    Strace log: $STRACE_FILE ($(wc -l < "$STRACE_FILE") lines)"
}
trap cleanup EXIT

# Build the agent command args
AGENT_ARGS=()
[ -n "$TASK" ] && AGENT_ARGS+=("$TASK")

if $USE_STRACE; then
    echo "[*] Running $AGENT_BIN with strace..."
    strace -f -e trace=process,file,network -o "$STRACE_FILE" "$AGENT_BIN" "${AGENT_ARGS[@]+"${AGENT_ARGS[@]}"}"
else
    echo "[*] Running $AGENT_BIN..."
    touch "$STRACE_FILE"
    "$AGENT_BIN" "${AGENT_ARGS[@]+"${AGENT_ARGS[@]}"}"
fi

echo "[*] $AGENT_BIN finished."
