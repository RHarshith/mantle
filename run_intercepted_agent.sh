#!/usr/bin/env bash
# Run an external agent with Rust MITM capture + Rust eBPF capture.
set -euo pipefail

TRACE_ID=""
MITM_REV_PORT=8898
AGENT_BIN="codex"
TASK=()
INTERCEPT_MODE="${MANTLE_INTERCEPT_MODE:-${RTRACE_INTERCEPT_MODE:-proxy}}"
AGENT_TAG="agent"
ENABLE_EBPF=true
INTERACTIVE_EBPF=false
USE_PTY_WRAPPER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trace-id) TRACE_ID="$2"; shift 2 ;;
        --port) MITM_REV_PORT="$2"; shift 2 ;;
        --mode) INTERCEPT_MODE="$2"; shift 2 ;;
        --agent) AGENT_BIN="$2"; shift 2 ;;
        --no-ebpf) ENABLE_EBPF=false; shift ;;
        --interactive-ebpf) INTERACTIVE_EBPF=true; shift ;;
        --) shift; TASK=("$@"); break ;;
        -*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *) TASK=("$@"); break ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_ROOT_DEFAULT="$SCRIPT_DIR/obs"
OBS_ROOT_ENV="${AGENT_OBS_ROOT:-}"
OBS_ROOT="$OBS_ROOT_DEFAULT"

if [[ -n "$OBS_ROOT_ENV" ]]; then
    env_score=0
    repo_score=0
    if [[ -d "$OBS_ROOT_ENV/traces" ]]; then
        env_score=$((env_score + $(find "$OBS_ROOT_ENV/traces" -maxdepth 1 -type f -name '*.ebpf.jsonl' 2>/dev/null | wc -l)))
    fi
    if [[ -d "$OBS_ROOT_ENV/events" ]]; then
        env_score=$((env_score + $(find "$OBS_ROOT_ENV/events" -maxdepth 1 -type f -name '*.events.jsonl' 2>/dev/null | wc -l)))
    fi
    if [[ -d "$OBS_ROOT_DEFAULT/traces" ]]; then
        repo_score=$((repo_score + $(find "$OBS_ROOT_DEFAULT/traces" -maxdepth 1 -type f -name '*.ebpf.jsonl' 2>/dev/null | wc -l)))
    fi
    if [[ -d "$OBS_ROOT_DEFAULT/events" ]]; then
        repo_score=$((repo_score + $(find "$OBS_ROOT_DEFAULT/events" -maxdepth 1 -type f -name '*.events.jsonl' 2>/dev/null | wc -l)))
    fi

    if [[ "$env_score" -eq 0 && "$repo_score" -gt 0 ]]; then
        OBS_ROOT="$OBS_ROOT_DEFAULT"
        echo "[mantle] AGENT_OBS_ROOT has no logs; using repo obs root: $OBS_ROOT" >&2
    else
        OBS_ROOT="$OBS_ROOT_ENV"
    fi
fi

AGENT_TAG="$(basename "$AGENT_BIN")"
[ -z "$TRACE_ID" ] && TRACE_ID="${AGENT_TAG}_$(date +%Y%m%d_%H%M%S).ebpf.jsonl"

if [[ ${#TASK[@]} -eq 0 ]]; then
    if $INTERACTIVE_EBPF; then
        if command -v script >/dev/null 2>&1; then
            ENABLE_EBPF=true
            USE_PTY_WRAPPER=true
        else
            ENABLE_EBPF=false
            echo "[mantle] --interactive-ebpf requested, but 'script' is unavailable; running without eBPF." >&2
        fi
    else
        ENABLE_EBPF=false
    fi
fi

if [[ "$INTERCEPT_MODE" != "proxy" && "$INTERCEPT_MODE" != "transparent" ]]; then
    echo "Error: --mode must be 'proxy' or 'transparent'" >&2
    exit 1
fi
if [[ "$INTERCEPT_MODE" == "transparent" ]]; then
    echo "[mantle] transparent mode is mapped to reverse-proxy mode for Rust MITM capture." >&2
fi

mkdir -p "$OBS_ROOT/traces" "$OBS_ROOT/events" "$OBS_ROOT/mitm"

TRACE_BASENAME="${TRACE_ID%.ebpf.jsonl}"
MITM_JSONL="$OBS_ROOT/mitm/${TRACE_BASENAME}.mitm.jsonl"
EBPF_FILE="$OBS_ROOT/traces/$TRACE_ID"
ROOT_PID_FILE="$OBS_ROOT/mitm/${TRACE_BASENAME}.root.pid"
PID_WRAPPER_SCRIPT=""

MITM_CAPTURE_BIN="${MANTLE_CAPTURE_MITM_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_capture_mitm_proxy}"
EBPF_CAPTURE_BIN="${MANTLE_CAPTURE_EBPF_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_capture_ebpf}"

if [[ ! -x "$MITM_CAPTURE_BIN" ]]; then
    echo "Error: MITM Rust binary not found or not executable: $MITM_CAPTURE_BIN" >&2
    echo "Build it first: mantle/capture/rust/scripts/build_capture_rust.sh" >&2
    exit 1
fi
if [[ ! -x "$EBPF_CAPTURE_BIN" ]]; then
    echo "Error: eBPF Rust binary not found or not executable: $EBPF_CAPTURE_BIN" >&2
    echo "Build it first: mantle/capture/rust/scripts/build_capture_rust.sh" >&2
    exit 1
fi

export AGENT_TRACE_ID="$TRACE_BASENAME"
export MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE"
rm -f "$ROOT_PID_FILE"

command -v "$AGENT_BIN" >/dev/null 2>&1 || { echo "Error: '$AGENT_BIN' not found in PATH" >&2; exit 1; }
AGENT_BIN_PATH="$(command -v "$AGENT_BIN")"

if [[ "$(basename "$AGENT_BIN_PATH")" == "codex" ]]; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        echo "Error: OPENAI_API_KEY is not set in environment." >&2
        exit 1
    fi
    if ! printf '%s' "$OPENAI_API_KEY" | codex login --with-api-key >/dev/null 2>&1; then
        echo "Error: failed to initialize Codex auth from OPENAI_API_KEY." >&2
        exit 1
    fi
fi

echo "═══════════════════════════════════════════════════════════"
echo "  Intercepted External Agent"
echo "═══════════════════════════════════════════════════════════"
echo "  Agent:       $AGENT_BIN"
echo "  Task:        ${TASK[*]:-<interactive>}"
echo "  Trace ID:    $TRACE_ID"
echo "  MITM mode:   reverse"
echo "  MITM proxy:  localhost:$MITM_REV_PORT"
echo "  MITM log:    $MITM_JSONL"
echo "  eBPF trace:  $ENABLE_EBPF"
echo "  eBPF file:   $EBPF_FILE"
echo "═══════════════════════════════════════════════════════════"

MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE" \
    "$MITM_CAPTURE_BIN" \
    --listen-port "$MITM_REV_PORT" \
    --capture-file "$MITM_JSONL" \
    --upstream-base "https://api.openai.com" &
MITM_PID=$!
sleep 1
kill -0 "$MITM_PID" 2>/dev/null || { echo "Error: Rust MITM proxy failed to start" >&2; exit 1; }
echo "[*] Rust MITM proxy started (PID $MITM_PID)"

# Route OpenAI-compatible clients through local Rust reverse endpoint.
export OPENAI_API_BASE="http://127.0.0.1:$MITM_REV_PORT/v1"
export OPENAI_BASE_URL="http://127.0.0.1:$MITM_REV_PORT/v1"
echo "[*] Forced OPENAI_BASE_URL/OPENAI_API_BASE to Rust reverse endpoint"

cleanup() {
    echo ""
    echo "[*] Stopping Rust MITM proxy (PID $MITM_PID)..."
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
    echo "[*] Done. Captured data:"
    [ -f "$MITM_JSONL" ] && echo "    MITM log:   $MITM_JSONL ($(wc -l < "$MITM_JSONL") lines)"
    [ -f "$EBPF_FILE" ] && echo "    eBPF log:   $EBPF_FILE ($(wc -l < "$EBPF_FILE") lines)"
    [ -n "$PID_WRAPPER_SCRIPT" ] && rm -f "$PID_WRAPPER_SCRIPT"
    rm -f "$ROOT_PID_FILE"
}
trap cleanup EXIT

AGENT_ARGS=("${TASK[@]}")
make_pid_wrapper() {
    local wrapper
    wrapper="$(mktemp /tmp/mantle-agent-launch.XXXXXX.sh)"
    {
        echo "#!/usr/bin/env bash"
        echo "set -euo pipefail"
        echo "echo \"\$\$\" > $(printf '%q' "$ROOT_PID_FILE")"
        printf "exec "
        printf "%q " "$AGENT_BIN_PATH" "${AGENT_ARGS[@]}"
        echo
    } > "$wrapper"
    chmod 700 "$wrapper"
    PID_WRAPPER_SCRIPT="$wrapper"
}
make_pid_wrapper

if ! $ENABLE_EBPF; then
    echo "[*] Running $AGENT_BIN interactively (eBPF disabled to preserve TTY)..."
    "$PID_WRAPPER_SCRIPT"
    echo "[*] $AGENT_BIN finished."
    exit 0
fi

CAPTURE_CMD=("$PID_WRAPPER_SCRIPT")
if $USE_PTY_WRAPPER; then
    printf -v PTY_AGENT_CMD '%q ' "$AGENT_BIN_PATH" "${AGENT_ARGS[@]+"${AGENT_ARGS[@]}"}"
    CAPTURE_CMD=(script -qefc "$PTY_AGENT_CMD" /dev/null)
    echo "[*] Interactive PTY wrapper enabled for eBPF capture."
fi

if ! command -v bpftrace >/dev/null 2>&1; then
    echo "Error: bpftrace is required for BPF tracing but was not found in PATH." >&2
    exit 1
fi

echo "[*] Running $AGENT_BIN with eBPF capture..."
"$EBPF_CAPTURE_BIN" --output "$EBPF_FILE" -- "${CAPTURE_CMD[@]}"

echo "[*] $AGENT_BIN finished."
