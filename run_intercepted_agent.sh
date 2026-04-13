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
AGENT_CWD="${MANTLE_AGENT_CWD:-$PWD}"
if [[ ! -d "$AGENT_CWD" ]]; then
    echo "Error: MANTLE_AGENT_CWD does not exist or is not a directory: $AGENT_CWD" >&2
    exit 1
fi
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
EVENTS_FILE="$OBS_ROOT/events/${TRACE_BASENAME}.events.jsonl"

# The intercept monitor may run as root while the agent command runs as
# the invoking user. Pre-create the events file with shared write access
# so both processes can append observability records.
touch "$EVENTS_FILE"
chmod 0666 "$EVENTS_FILE"

MITM_CAPTURE_BIN="${MANTLE_CAPTURE_MITM_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_capture_mitm_proxy}"
EBPF_CAPTURE_BIN="${MANTLE_CAPTURE_EBPF_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_capture_ebpf}"
INTERCEPT_MONITOR_BIN="${MANTLE_INTERCEPT_MONITOR_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_intercept_monitor}"
INTERCEPT_POLICY_FILE="${MANTLE_INTERCEPT_POLICY_FILE:-$SCRIPT_DIR/.mantle/intercept.yaml}"
INTERCEPT_DECISIONS_FILE="${MANTLE_INTERCEPT_DECISIONS_FILE:-$SCRIPT_DIR/.mantle/intercept.decisions.jsonl}"
INTERCEPT_DECISION_CURRENT_DIR="${MANTLE_INTERCEPT_DECISION_CURRENT_DIR:-$SCRIPT_DIR/.mantle/intercept.decision-current}"

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
if [[ ! -x "$INTERCEPT_MONITOR_BIN" ]]; then
    echo "Error: intercept monitor Rust binary not found or not executable: $INTERCEPT_MONITOR_BIN" >&2
    echo "Build it first: mantle/capture/rust/scripts/build_capture_rust.sh" >&2
    exit 1
fi
if [[ ! -f "$INTERCEPT_POLICY_FILE" ]]; then
    echo "Error: intercept policy file not found: $INTERCEPT_POLICY_FILE" >&2
    echo "Create it first (example): .mantle/intercept.yaml" >&2
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

    # Keep codex auth material in the same user context as the watched process.
    if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        codex_login_env="OPENAI_API_KEY,XDG_CONFIG_HOME,XDG_STATE_HOME,XDG_CACHE_HOME,XDG_DATA_HOME,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,PATH"
        if ! printf '%s' "$OPENAI_API_KEY" | sudo -u "$SUDO_USER" --preserve-env="$codex_login_env" -- codex login --with-api-key >/dev/null 2>&1; then
            echo "Error: failed to initialize Codex auth from OPENAI_API_KEY for user '$SUDO_USER'." >&2
            exit 1
        fi
    else
        if ! printf '%s' "$OPENAI_API_KEY" | codex login --with-api-key >/dev/null 2>&1; then
            echo "Error: failed to initialize Codex auth from OPENAI_API_KEY." >&2
            exit 1
        fi
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

UPSTREAM_BASE="${MANTLE_FORCE_OPENAI_BASE:-${OPENAI_BASE_URL:-https://api.openai.com}}"
if [[ "$(basename "$AGENT_BIN_PATH")" != "codex" && -z "${MANTLE_FORCE_OPENAI_BASE:-}" && -z "${OPENAI_BASE_URL:-}" && -n "${OAK1:-}" ]]; then
    UPSTREAM_BASE="https://chat-api.tamu.ai/api"
fi

MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE" \
    "$MITM_CAPTURE_BIN" \
    --listen-port "$MITM_REV_PORT" \
    --capture-file "$MITM_JSONL" \
    --upstream-base "$UPSTREAM_BASE" &
MITM_PID=$!
sleep 1
kill -0 "$MITM_PID" 2>/dev/null || { echo "Error: Rust MITM proxy failed to start" >&2; exit 1; }
echo "[*] Rust MITM proxy started (PID $MITM_PID)"

# Route OpenAI-compatible clients through local Rust reverse endpoint.
if [[ "$(basename "$AGENT_BIN_PATH")" == "copilot" ]]; then
    echo "[*] Skipping forced OPENAI_BASE_URL/OPENAI_API_BASE for Copilot CLI"
else
    export OPENAI_API_BASE="http://127.0.0.1:$MITM_REV_PORT/v1"
    export OPENAI_BASE_URL="http://127.0.0.1:$MITM_REV_PORT/v1"
    echo "[*] Forced OPENAI_BASE_URL/OPENAI_API_BASE to Rust reverse endpoint"
fi

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
AGENT_LAUNCH=("$AGENT_BIN_PATH" "${AGENT_ARGS[@]}")

export MANTLE_AGENT_CWD="$AGENT_CWD"
export PWD="$AGENT_CWD"

# When launched via `sudo` from bin/mantle, keep monitor/capture root-owned
# but execute the actual agent command as the invoking user so user-scoped
# credentials (for example Copilot auth) remain available.
if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    SUDO_BIN="$(command -v sudo)"
    agent_preserve_env="HOME,PATH,USER,LOGNAME,PWD,MANTLE_AGENT_CWD,LANG,LC_ALL,LC_CTYPE,XDG_CONFIG_HOME,XDG_STATE_HOME,XDG_CACHE_HOME,XDG_DATA_HOME,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS,GITHUB_TOKEN,GH_TOKEN,GITHUB_COPILOT_TOKEN,COPILOT_TOKEN,OPENAI_API_KEY,OAK1,OPENAI_BASE_URL,OPENAI_API_BASE,OPENAI_MODEL,RTRACE_FORCE_OPENAI_BASE,MANTLE_FORCE_OPENAI_BASE,AGENT_TRACE_ID,AGENT_OBS_ROOT,AGENT_OBS_ENABLED"
    AGENT_LAUNCH=("$SUDO_BIN" -u "$SUDO_USER" --preserve-env="$agent_preserve_env" -- "$AGENT_BIN_PATH" "${AGENT_ARGS[@]}")
fi

make_pid_wrapper() {
    local wrapper
    wrapper="$(mktemp /tmp/mantle-agent-launch.XXXXXX.sh)"
    {
        echo "#!/usr/bin/env bash"
        echo "set -euo pipefail"
        echo "echo \"\$\$\" > $(printf '%q' "$ROOT_PID_FILE")"
        echo "cd $(printf '%q' "$AGENT_CWD")"
        printf "exec "
        printf "%q " "$INTERCEPT_MONITOR_BIN"
        printf -- "--policy-file %q " "$INTERCEPT_POLICY_FILE"
        printf -- "--trace-id %q " "$TRACE_BASENAME"
        printf -- "--events-file %q " "$EVENTS_FILE"
        printf -- "--ask-decisions-file %q " "$INTERCEPT_DECISIONS_FILE"
        printf -- "--ask-current-dir %q " "$INTERCEPT_DECISION_CURRENT_DIR"
        printf -- "-- "
        printf "%q " "${AGENT_LAUNCH[@]}"
        echo
    } > "$wrapper"
    chmod 700 "$wrapper"
    PID_WRAPPER_SCRIPT="$wrapper"
}
make_pid_wrapper

seed_copilot_mitm_from_logs_if_empty() {
    if [[ "$(basename "$AGENT_BIN_PATH")" != "copilot" ]]; then
        return 0
    fi
    if [[ ! -f "$MITM_JSONL" ]]; then
        return 0
    fi
    if [[ $(wc -l < "$MITM_JSONL" 2>/dev/null || echo 0) -gt 0 ]]; then
        return 0
    fi

    local user_home logs_dir latest_log model_name
    user_home="$HOME"
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6 || true)"
    fi
    if [[ -z "$user_home" ]]; then
        user_home="$HOME"
    fi

    logs_dir="$user_home/.copilot/logs"
    if [[ ! -d "$logs_dir" ]]; then
        return 0
    fi

    latest_log="$(find "$logs_dir" -maxdepth 1 -type f -name 'process-*.log' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)"
    if [[ -z "$latest_log" || ! -f "$latest_log" ]]; then
        return 0
    fi

    model_name="${OPENAI_MODEL:-gpt-4.1}"
    local added=0

    while IFS= read -r line; do
        [[ "$line" == *"Sending request to the AI model"* ]] || continue

        local iso_ts epoch_ts
        iso_ts="${line%% *}"
        epoch_ts="$(date -d "$iso_ts" +%s.%3N 2>/dev/null || true)"
        if [[ -z "$epoch_ts" ]]; then
            epoch_ts="$(date +%s.%3N)"
        fi

        printf '{"ts": %s, "direction": "response", "url": "https://api.individual.githubcopilot.com/v1/chat/completions", "method": "POST", "status_code": 200, "duration_ms": 0, "model": "%s", "request_body": {"model": "%s", "messages": [{"role": "user", "content": "[copilot-log-fallback]"}]}, "response_body": {"id": "copilot-fallback", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "[copilot-log-fallback]"}}]}}\n' "$epoch_ts" "$model_name" "$model_name" >> "$MITM_JSONL"
        added=$((added + 1))
    done < "$latest_log"

    if [[ "$added" -gt 0 ]]; then
        echo "[*] Seeded MITM log from Copilot runtime log fallback ($added synthetic calls)"
    fi
}

if ! $ENABLE_EBPF; then
    echo "[*] Running $AGENT_BIN interactively (eBPF disabled to preserve TTY)..."
    "$PID_WRAPPER_SCRIPT"
    seed_copilot_mitm_from_logs_if_empty
    echo "[*] $AGENT_BIN finished."
    exit 0
fi

CAPTURE_CMD=("$PID_WRAPPER_SCRIPT")
if $USE_PTY_WRAPPER; then
    printf -v PTY_AGENT_CMD '%q ' "${AGENT_LAUNCH[@]}"
    CAPTURE_CMD=(script -qefc "$PTY_AGENT_CMD" /dev/null)
    echo "[*] Interactive PTY wrapper enabled for eBPF capture."
fi

if ! command -v bpftrace >/dev/null 2>&1; then
    echo "Error: bpftrace is required for BPF tracing but was not found in PATH." >&2
    exit 1
fi

echo "[*] Running $AGENT_BIN with eBPF capture..."
"$EBPF_CAPTURE_BIN" --output "$EBPF_FILE" -- "${CAPTURE_CMD[@]}"
seed_copilot_mitm_from_logs_if_empty

echo "[*] $AGENT_BIN finished."
