#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run the simple agent in INTERACTIVE mode with mitmproxy interception.
#
# Usage:
#   ./run_interactive_intercepted.sh                  # with manual approval
#   ./run_interactive_intercepted.sh --auto           # auto-approve tool calls
#   ./run_interactive_intercepted.sh --auto --strace  # also capture strace
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

AUTO_FLAG=""
USE_STRACE=false
MITM_PORT=8899

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto)    AUTO_FLAG="--auto"; shift ;;
        --strace)  USE_STRACE=true; shift ;;
        --port)    MITM_PORT="$2"; shift 2 ;;
        *)         echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_ROOT="${AGENT_OBS_ROOT:-$SCRIPT_DIR/obs}"
TRACE_ID="trace_$(date +%Y%m%d_%H%M%S).strace.log"

mkdir -p "$OBS_ROOT/traces" "$OBS_ROOT/events" "$OBS_ROOT/mitm"

MITM_JSONL="$OBS_ROOT/mitm/${TRACE_ID%.strace.log}.mitm.jsonl"
STRACE_FILE="$OBS_ROOT/traces/$TRACE_ID"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"

# Find Python
PYTHON_BIN="${AGENT_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
    if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
        PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    else
        echo "Error: no Python found" >&2; exit 1
    fi
fi

# Find mitmdump
MITMDUMP="$(command -v mitmdump 2>/dev/null || echo "$HOME/.local/bin/mitmdump")"
[ -x "$MITMDUMP" ] || { echo "Error: mitmdump not found" >&2; exit 1; }
[ -f "$MITM_CA" ]   || { echo "Error: mitmproxy CA cert not found at $MITM_CA" >&2; exit 1; }

echo "═══════════════════════════════════════════════════════════"
echo "  Interactive Intercepted Agent"
echo "═══════════════════════════════════════════════════════════"
echo "  Trace ID:    $TRACE_ID"
echo "  MITM proxy:  localhost:$MITM_PORT"
echo "  MITM log:    $MITM_JSONL"
echo "  Auto-approve: ${AUTO_FLAG:-off}"
echo "  Strace:      $USE_STRACE"
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

# Proxy env
export HTTPS_PROXY="http://127.0.0.1:$MITM_PORT"
export HTTP_PROXY="http://127.0.0.1:$MITM_PORT"
export SSL_CERT_FILE="$MITM_CA"
export REQUESTS_CA_BUNDLE="$MITM_CA"
export AGENT_TRACE_ID="$TRACE_ID"
export AGENT_OBS_ROOT="$OBS_ROOT"

cleanup() {
    echo ""
    echo "[*] Stopping mitmdump (PID $MITM_PID)..."
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
    [ -f "$MITM_JSONL" ] && echo "    MITM log: $MITM_JSONL ($(wc -l < "$MITM_JSONL") lines)"
    $USE_STRACE && [ -f "$STRACE_FILE" ] && echo "    Strace:   $STRACE_FILE ($(wc -l < "$STRACE_FILE") lines)"
}
trap cleanup EXIT

echo "[*] Starting interactive agent (Ctrl+C/Ctrl+D to exit)..."
echo ""

if $USE_STRACE; then
    strace -f -e trace=process,file,network -o "$STRACE_FILE" \
        $PYTHON_BIN "$SCRIPT_DIR/simple_agent/cli_agent.py" $AUTO_FLAG --verbose
else
    $PYTHON_BIN "$SCRIPT_DIR/simple_agent/cli_agent.py" $AUTO_FLAG --verbose
fi
