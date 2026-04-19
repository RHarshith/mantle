#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run an external agent with eBPF syscall tracing only.
#
# MITM interception is intentionally disabled so captured BPF network events
# preserve real destination IP/port data points.
#
# Usage:
#   ./run_intercepted_agent.sh --agent "codex" -- "exec do something"
#   ./run_intercepted_agent.sh --trace-id "my_trace.ebpf.jsonl" --agent "aider"
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

TRACE_ID=""
AGENT_BIN="aider"
TASK=()
INTERCEPT_MODE="${MANTLE_INTERCEPT_MODE:-${RTRACE_INTERCEPT_MODE:-none}}"
AGENT_TAG="agent"
ENABLE_EBPF=true
INTERACTIVE_EBPF=false
USE_PTY_WRAPPER=false
RUN_AS_USER=""
RUN_AS_HOME=""
PROXY_LOG_DIR=""
PROXY_CONTROL_URL=""

# Keep BPF capture under root, but execute the target agent as the invoking
# user so user-scoped CLI auth/config (for example ~/.codex/config.toml)
# remains effective under `mantle watch`.
if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    RUN_AS_USER="${SUDO_USER}"
    RUN_AS_HOME="$(getent passwd "${RUN_AS_USER}" | cut -d: -f6 || true)"
fi

is_likely_interactive_agent() {
    local base
    base="$(basename "$AGENT_BIN")"
    case "$base" in
        aider|codex|copilot|mantlecli)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trace-id)    TRACE_ID="$2"; shift 2 ;;
        --mode)        INTERCEPT_MODE="$2"; shift 2 ;;
        --port)        echo "Error: --port is unavailable because MITM interception is disabled." >&2; exit 1 ;;
        --agent)       AGENT_BIN="$2"; shift 2 ;;
        --no-ebpf)     ENABLE_EBPF=false; shift ;;
        --interactive-ebpf) INTERACTIVE_EBPF=true; shift ;;
        --)            shift; TASK=("$@"); break ;;
        -*)            echo "Unknown flag: $1" >&2; exit 1 ;;
        *)             TASK=("$@"); break ;;
    esac
done

if [[ "$INTERCEPT_MODE" != "none" ]]; then
    echo "Error: MITM interception is disabled. Only --mode none is supported." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOGS_ROOT="$SCRIPT_DIR/.mantle/logs"
OBS_ROOT="$SCRIPT_DIR/.mantle/obs"
CONFIG_ROOT="$SCRIPT_DIR/.mantle/config"
RUNTIME_ROOT="$LOGS_ROOT/runtime"
PROXY_LOG_DIR="$OBS_ROOT/proxy"
MANTLE_BPF_RUNTIME_DIR="${MANTLE_BPF_RUNTIME_DIR:-$RUNTIME_ROOT/bpf_collector}"
PROXY_CONTROL_URL="${MANTLE_PROXY_CONTROL_URL:-http://127.0.0.1:4000/mantle/active-trace}"

AGENT_TAG="$(basename "$AGENT_BIN")"
[[ -z "$TRACE_ID" ]] && TRACE_ID="${AGENT_TAG}_$(date +%Y%m%d_%H%M%S).ebpf.jsonl"

# No-task flows are often interactive for agent CLIs (aider/codex shell modes),
# but script executables (for example ./run_codex.sh) should still be traced.
if [[ ${#TASK[@]} -eq 0 ]]; then
    if $INTERACTIVE_EBPF; then
        if command -v script >/dev/null 2>&1; then
            ENABLE_EBPF=true
            USE_PTY_WRAPPER=true
        else
            ENABLE_EBPF=false
            echo "[mantle] --interactive-ebpf requested, but 'script' is unavailable; running without eBPF." >&2
        fi
    elif is_likely_interactive_agent; then
        ENABLE_EBPF=false
        echo "[mantle] No task provided for interactive agent '$AGENT_BIN'; running without eBPF to preserve TTY." >&2
    else
        ENABLE_EBPF=true
    fi
fi

mkdir -p "$OBS_ROOT/traces" "$OBS_ROOT/events" "$OBS_ROOT/mitm" "$PROXY_LOG_DIR" "$MANTLE_BPF_RUNTIME_DIR" "$CONFIG_ROOT"

export MANTLE_LOGS_DIR="$LOGS_ROOT"
export MANTLE_CONFIG_DIR="$CONFIG_ROOT"
export MANTLE_PROXY_LOG_DIR="$PROXY_LOG_DIR"
export AGENT_OBS_ROOT="$OBS_ROOT"
export OBS_TRACE_DIR="$OBS_ROOT/traces"
export OBS_EVENTS_DIR="$OBS_ROOT/events"

TRACE_BASENAME="${TRACE_ID%.ebpf.jsonl}"
EBPF_FILE="$OBS_ROOT/traces/$TRACE_ID"
ROOT_PID_FILE="$OBS_ROOT/mitm/${TRACE_BASENAME}.root.pid"
PID_WRAPPER_SCRIPT=""
RUNTIME_LOG_FILE="$MANTLE_BPF_RUNTIME_DIR/${TRACE_BASENAME}.log"

# Capture watch runner lifecycle logs in runtime/bpf_collector.
exec > >(tee -a "$RUNTIME_LOG_FILE") 2>&1

EBPF_CAPTURE_SCRIPT="$SCRIPT_DIR/mantle/capture/ebpf.py"
if [[ ! -f "$EBPF_CAPTURE_SCRIPT" ]]; then
    EBPF_CAPTURE_SCRIPT="$SCRIPT_DIR/mantle/ebpf_capture.py"
fi
if [[ ! -f "$EBPF_CAPTURE_SCRIPT" ]]; then
    echo "Error: eBPF capture wrapper script not found" >&2
    exit 1
fi

# Correlate native agent events with the same trace identifier used by eBPF.
export AGENT_TRACE_ID="$TRACE_BASENAME"
export MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE"
rm -f "$ROOT_PID_FILE"

make_pid_wrapper() {
    local wrapper
    local preserve_env
    wrapper="$(mktemp /tmp/mantle-agent-launch.XXXXXX.sh)"
    preserve_env="PATH,OPENAI_API_KEY,OAK1,OPENAI_BASE_URL,OPENAI_MODEL,AGENT_TRACE_ID,AGENT_OBS_ENABLED,AGENT_OBS_ROOT,OBS_TRACE_DIR,OBS_EVENTS_DIR,MANTLE_LOGS_DIR,MANTLE_CONFIG_DIR,MANTLE_PROXY_LOG_DIR,RTRACE_VENV,RTRACE_INTERCEPT_MODE,RTRACE_FORCE_OPENAI_BASE,MANTLE_VENV,MANTLE_INTERCEPT_MODE,MANTLE_FORCE_OPENAI_BASE,XDG_CONFIG_HOME,XDG_STATE_HOME,XDG_CACHE_HOME,XDG_DATA_HOME,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,GITHUB_TOKEN,GH_TOKEN,GITHUB_COPILOT_TOKEN,COPILOT_TOKEN"
    {
        echo "#!/usr/bin/env bash"
        echo "set -euo pipefail"
        echo "echo \"\$\$\" > $(printf '%q' "$ROOT_PID_FILE")"
        if [[ -n "$RUN_AS_USER" ]]; then
            if [[ -n "$RUN_AS_HOME" ]]; then
                printf "export HOME=%q\\n" "$RUN_AS_HOME"
            fi
            printf "exec sudo -H -u %q --preserve-env=%q " "$RUN_AS_USER" "$preserve_env"
        else
            printf "exec "
        fi
        printf "%q " "$AGENT_BIN_PATH" "${AGENT_ARGS[@]}"
        echo
    } > "$wrapper"
    chmod 700 "$wrapper"
    PID_WRAPPER_SCRIPT="$wrapper"
}

set_proxy_active_trace() {
    local trace_file="$1"
    local payload_file
    payload_file="$(mktemp /tmp/mantle-proxy-control.XXXXXX.json)"

    if [[ "$trace_file" == "__NONE__" ]]; then
        printf '{"trace_file": null}\n' > "$payload_file"
    else
        python3 - "$trace_file" "$payload_file" <<'PY'
import json
import os
import sys

trace_file, payload_path = sys.argv[1], sys.argv[2]
base = os.path.basename(trace_file)
if base != trace_file or base in {"", ".", ".."}:
    raise SystemExit("trace_file must be a basename")
with open(payload_path, "w", encoding="utf-8") as fh:
    json.dump({"trace_file": base}, fh)
PY
    fi

    if ! python3 - "$PROXY_CONTROL_URL" "$payload_file" <<'PY'
import sys
import urllib.error
import urllib.request

url, payload_path = sys.argv[1], sys.argv[2]
with open(payload_path, "rb") as fh:
    data = fh.read()
req = urllib.request.Request(
    url,
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=2.0) as resp:
    if resp.status < 200 or resp.status >= 300:
        raise RuntimeError(f"unexpected status: {resp.status}")
PY
    then
        rm -f "$payload_file"
        return 1
    fi

    rm -f "$payload_file"
    return 0
}

command -v "$AGENT_BIN" >/dev/null 2>&1 || { echo "Error: '$AGENT_BIN' not found in PATH" >&2; exit 1; }
AGENT_BIN_PATH="$(command -v "$AGENT_BIN")"

if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    echo "[*] OPENAI_API_KEY is not set. External agents that require API access may fail." >&2
fi

echo "═══════════════════════════════════════════════════════════"
echo "  External Agent (eBPF only)"
echo "═══════════════════════════════════════════════════════════"
echo "  Agent:       $AGENT_BIN"
echo "  Task:        ${TASK[*]:-<interactive>}"
echo "  Trace ID:    $TRACE_ID"
echo "  MITM:        disabled"
echo "  eBPF trace:  $ENABLE_EBPF"
echo "  eBPF file:   $EBPF_FILE"
if [[ -n "$RUN_AS_USER" ]]; then
    echo "  Run as user: $RUN_AS_USER"
fi
echo "═══════════════════════════════════════════════════════════"

# Ensure no inherited proxy vars accidentally reintroduce interception.
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy ALL_PROXY all_proxy

cleanup() {
    if ! set_proxy_active_trace "__NONE__"; then
        echo "[mantle] Warning: failed to clear active trace on proxy control endpoint: $PROXY_CONTROL_URL" >&2
    fi
    echo ""
    echo "[*] Done. Captured data:"
    [[ -f "$EBPF_FILE" ]] && echo "    eBPF log:   $EBPF_FILE ($(wc -l < "$EBPF_FILE") lines)"
    if [[ -f "$PROXY_LOG_DIR/$TRACE_ID" ]]; then
        echo "    Proxy log:  $PROXY_LOG_DIR/$TRACE_ID ($(wc -l < "$PROXY_LOG_DIR/$TRACE_ID") lines)"
    fi
    [[ -n "$PID_WRAPPER_SCRIPT" ]] && rm -f "$PID_WRAPPER_SCRIPT"
    rm -f "$ROOT_PID_FILE"
}
trap cleanup EXIT

# Build the agent command args
AGENT_ARGS=("${TASK[@]}")
make_pid_wrapper

if ! set_proxy_active_trace "$TRACE_ID"; then
    echo "Error: could not set active trace file on proxy endpoint: $PROXY_CONTROL_URL" >&2
    echo "Hint: start proxy with 'make proxy' or override MANTLE_PROXY_CONTROL_URL." >&2
    exit 1
fi

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
if [[ ! -f "$EBPF_CAPTURE_SCRIPT" ]]; then
    echo "Error: eBPF capture wrapper not found at $EBPF_CAPTURE_SCRIPT" >&2
    exit 1
fi

echo "[*] Running $AGENT_BIN with eBPF capture..."
python3 "$EBPF_CAPTURE_SCRIPT" --output "$EBPF_FILE" -- "${CAPTURE_CMD[@]}"

echo "[*] $AGENT_BIN finished."
