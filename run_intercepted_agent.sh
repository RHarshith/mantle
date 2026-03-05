#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run the simple agent with mitmproxy interception + optional strace.
#
# Usage:
#   ./run_intercepted_agent.sh --task "List files in the home directory"
#   ./run_intercepted_agent.sh --task "Create a hello.py file" --strace
#   ./run_intercepted_agent.sh --task "..." --trace-id my_custom_id
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

TASK=""
USE_STRACE=false
TRACE_ID=""
MITM_PORT=8899

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --task)
            TASK="$2"
            shift 2
            ;;
        --strace)
            USE_STRACE=true
            shift
            ;;
        --trace-id)
            TRACE_ID="$2"
            shift 2
            ;;
        --port)
            MITM_PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$TASK" ]; then
    echo "Usage: $0 --task \"<task description>\" [--strace] [--trace-id <id>] [--port <mitm_port>]" >&2
    exit 1
fi

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ORIG_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    ORIG_HOME="$(eval echo "~$SUDO_USER")"
fi

OBS_ROOT="${AGENT_OBS_ROOT:-$ORIG_HOME/shared/simple_agent/obs}"
TRACE_DIR="$OBS_ROOT/traces"
EVENT_DIR="$OBS_ROOT/events"
MITM_DIR="$OBS_ROOT/mitm"
mkdir -p "$TRACE_DIR" "$EVENT_DIR" "$MITM_DIR"

# Generate trace ID if not provided
if [ -z "$TRACE_ID" ]; then
    TRACE_ID="trace_$(date +%Y%m%d_%H%M%S).strace.log"
fi

MITM_JSONL="$MITM_DIR/${TRACE_ID%.strace.log}.mitm.jsonl"
STRACE_FILE="$TRACE_DIR/$TRACE_ID"

# Find Python
PYTHON_BIN="${AGENT_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
    if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
        PYTHON_BIN="$VIRTUAL_ENV/bin/python"
    elif [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
        PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
    elif [ -x "$PWD/.venv/bin/python" ]; then
        PYTHON_BIN="$PWD/.venv/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v python3)"
    else
        echo "Error: could not find a Python interpreter." >&2
        exit 1
    fi
fi

# Find mitmproxy CA cert
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
if [ ! -f "$MITM_CA" ]; then
    echo "Error: mitmproxy CA cert not found at $MITM_CA" >&2
    echo "Run 'mitmdump' once to generate it." >&2
    exit 1
fi

# Find mitmdump
MITMDUMP="$(command -v mitmdump 2>/dev/null || echo "$HOME/.local/bin/mitmdump")"
if [ ! -x "$MITMDUMP" ]; then
    echo "Error: mitmdump not found" >&2
    exit 1
fi

echo "═══════════════════════════════════════════════════════════"
echo "  Intercepted Agent Run"
echo "═══════════════════════════════════════════════════════════"
echo "  Trace ID:    $TRACE_ID"
echo "  Task:        $TASK"
echo "  MITM proxy:  localhost:$MITM_PORT"
echo "  MITM log:    $MITM_JSONL"
echo "  Strace:      $USE_STRACE"
if $USE_STRACE; then
echo "  Strace file: $STRACE_FILE"
fi
echo "  Python:      $PYTHON_BIN"
echo "═══════════════════════════════════════════════════════════"

# Start mitmdump in background
export MITM_CAPTURE_FILE="$MITM_JSONL"
"$MITMDUMP" \
    -p "$MITM_PORT" \
    --ssl-insecure \
    -s "$SCRIPT_DIR/mitm_capture.py" \
    --set capture_file="$MITM_JSONL" \
    -q &
MITM_PID=$!

# Give mitmdump time to start
sleep 2

# Verify mitmdump is running
if ! kill -0 "$MITM_PID" 2>/dev/null; then
    echo "Error: mitmdump failed to start" >&2
    exit 1
fi
echo "[*] mitmdump started (PID $MITM_PID)"

# Set up environment for the agent
export HTTPS_PROXY="http://127.0.0.1:$MITM_PORT"
export HTTP_PROXY="http://127.0.0.1:$MITM_PORT"
export SSL_CERT_FILE="$MITM_CA"
export REQUESTS_CA_BUNDLE="$MITM_CA"
export NODE_EXTRA_CA_CERTS="$MITM_CA"
export AGENT_TRACE_ID="$TRACE_ID"
export AGENT_OBS_ROOT="$OBS_ROOT"
export AGENT_AUTO_APPROVE="1"

cleanup() {
    echo ""
    echo "[*] Stopping mitmdump (PID $MITM_PID)..."
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
    echo "[*] Done. Captured data:"
    if [ -f "$MITM_JSONL" ]; then
        LINES=$(wc -l < "$MITM_JSONL")
        echo "    MITM log:   $MITM_JSONL ($LINES lines)"
    fi
    if $USE_STRACE && [ -f "$STRACE_FILE" ]; then
        SLINES=$(wc -l < "$STRACE_FILE")
        echo "    Strace log: $STRACE_FILE ($SLINES lines)"
    fi
}
trap cleanup EXIT

# Build agent command
AGENT_CMD="$PYTHON_BIN $SCRIPT_DIR/simple_agent/cli_agent.py --auto --verbose --task \"$TASK\""

if $USE_STRACE; then
    echo "[*] Running agent with strace..."
    strace -f -e trace=process,file,network -o "$STRACE_FILE" \
        $PYTHON_BIN "$SCRIPT_DIR/simple_agent/cli_agent.py" --auto --verbose --task "$TASK"
else
    echo "[*] Running agent..."
    $PYTHON_BIN "$SCRIPT_DIR/simple_agent/cli_agent.py" --auto --verbose --task "$TASK"
fi

echo "[*] Agent finished."
