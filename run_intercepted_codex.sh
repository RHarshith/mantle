#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run codex (or any external agent) with mitmproxy API interception
# and optional eBPF syscall tracing.
#
# Uses iptables transparent redirect to force ALL HTTPS traffic
# through mitmproxy — works even for binaries that ignore proxy
# env vars (e.g. statically-linked Rust binaries).
#
# Requires: root, iptables, mitmproxy, mitmproxyuser system account
#
# Usage:
#   ./run_intercepted_codex.sh "List files in the home directory"
#   ./run_intercepted_codex.sh                    # interactive (no task)
#   ./run_intercepted_codex.sh --agent "aider" "Fix the bug"
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

TRACE_ID=""
MITM_PORT=8899
MITM_REV_PORT=8898
AGENT_BIN="codex"
TASK=()
MITM_USER="mitmproxyuser"
INTERCEPT_MODE="${MANTLE_INTERCEPT_MODE:-${RTRACE_INTERCEPT_MODE:-proxy}}"
AGENT_TAG="codex"
ENABLE_EBPF=true
INTERACTIVE_EBPF=false
USE_PTY_WRAPPER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trace-id)    TRACE_ID="$2"; shift 2 ;;
        --port)        MITM_PORT="$2"; shift 2 ;;
        --mode)        INTERCEPT_MODE="$2"; shift 2 ;;
        --agent)       AGENT_BIN="$2"; shift 2 ;;
        --no-ebpf)     ENABLE_EBPF=false; shift ;;
        --interactive-ebpf) INTERACTIVE_EBPF=true; shift ;;
        --)            shift; TASK=("$@"); break ;;
        -*)            echo "Unknown flag: $1" >&2; exit 1 ;;
        *)             TASK=("$@"); break ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_ROOT_DEFAULT="$SCRIPT_DIR/obs"
OBS_ROOT_ENV="${AGENT_OBS_ROOT:-}"
OBS_ROOT="$OBS_ROOT_DEFAULT"

# If AGENT_OBS_ROOT is set but points to stale/empty data while this repo has
# logs, prefer the repo-local obs folder to avoid silent trace loss after renames.
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

# Interactive CLI flows require a real TTY. When no task is provided, launch
# the agent directly (still under MITM capture) instead of piping through
# bpftrace output capture, which forces stdout/stderr to non-TTY pipes.
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

# Resolve runtime venv path (allows consistent tool discovery under sudo).
RUNTIME_VENV="${MANTLE_VENV:-${RTRACE_VENV:-$SCRIPT_DIR/.venv}}"

mkdir -p "$OBS_ROOT/traces" "$OBS_ROOT/events" "$OBS_ROOT/mitm"

TRACE_BASENAME="$TRACE_ID"
TRACE_BASENAME="${TRACE_BASENAME%.ebpf.jsonl}"
MITM_JSONL="$OBS_ROOT/mitm/${TRACE_BASENAME}.mitm.jsonl"
EBPF_FILE="$OBS_ROOT/traces/$TRACE_ID"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
EBPF_CAPTURE_BIN="${MANTLE_CAPTURE_EBPF_BIN:-$SCRIPT_DIR/mantle/capture/rust/target/release/mantle_capture_ebpf}"
if [[ ! -x "$EBPF_CAPTURE_BIN" ]]; then
    echo "Error: eBPF Rust binary not found or not executable: $EBPF_CAPTURE_BIN" >&2
    echo "Build it first: mantle/capture/rust/scripts/build_capture_rust.sh" >&2
    exit 1
fi
MITM_CAPTURE_SCRIPT="$SCRIPT_DIR/mantle/capture/mitm.py"
if [[ ! -f "$MITM_CAPTURE_SCRIPT" ]]; then
    MITM_CAPTURE_SCRIPT="$SCRIPT_DIR/mantle/mitm_capture.py"
fi
if [[ ! -f "$MITM_CAPTURE_SCRIPT" ]]; then
    echo "Error: mitm capture addon script not found" >&2
    exit 1
fi
ROOT_PID_FILE="$OBS_ROOT/mitm/${TRACE_BASENAME}.root.pid"
PID_WRAPPER_SCRIPT=""

# Correlate native agent events with the same trace identifier used by eBPF/mitm.
export AGENT_TRACE_ID="$TRACE_BASENAME"
export MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE"
rm -f "$ROOT_PID_FILE"

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

# Find mitmdump
MITMDUMP=""
MITMDUMP_LAUNCH=()
if [ -x "$RUNTIME_VENV/bin/mitmdump" ]; then
    MITMDUMP="$RUNTIME_VENV/bin/mitmdump"
elif [ -x "$SCRIPT_DIR/.venv/bin/mitmdump" ]; then
    MITMDUMP="$SCRIPT_DIR/.venv/bin/mitmdump"
elif command -v mitmdump >/dev/null 2>&1; then
    MITMDUMP="$(command -v mitmdump)"
elif [ -x "$HOME/.local/bin/mitmdump" ]; then
    MITMDUMP="$HOME/.local/bin/mitmdump"
fi

[ -n "$MITMDUMP" ] || {
    echo "Error: mitmdump not found. Run scripts/install_mantle.sh or install with: pipx install mitmproxy" >&2
    exit 1
}

# Handle stale shebangs after repo renames by invoking script via Python.
if [ -x "$RUNTIME_VENV/bin/python" ] && [ -f "$MITMDUMP" ]; then
    first_line="$(head -n 1 "$MITMDUMP" 2>/dev/null || true)"
    if [[ "$first_line" == '#!'* ]]; then
        shebang_path="${first_line#\#!}"
        shebang_path="${shebang_path%% *}"
        if [ -n "$shebang_path" ] && [ ! -x "$shebang_path" ]; then
            MITMDUMP_LAUNCH=("$RUNTIME_VENV/bin/python" "$MITMDUMP")
        fi
    fi
fi
if [ ${#MITMDUMP_LAUNCH[@]} -eq 0 ]; then
    MITMDUMP_LAUNCH=("$MITMDUMP")
fi

# First-run bootstrap: generate mitmproxy CA material if missing.
if [ ! -f "$MITM_CA" ]; then
    echo "[*] mitmproxy CA cert not found. Bootstrapping mitmproxy config..."
    if command -v timeout >/dev/null 2>&1; then
        timeout 2 "${MITMDUMP_LAUNCH[@]}" -q >/dev/null 2>&1 || true
    else
        "${MITMDUMP_LAUNCH[@]}" -q >/dev/null 2>&1 &
        TMP_MITM_PID=$!
        sleep 2
        kill "$TMP_MITM_PID" >/dev/null 2>&1 || true
        wait "$TMP_MITM_PID" >/dev/null 2>&1 || true
    fi
fi
[ -f "$MITM_CA" ] || { echo "Error: mitmproxy CA cert not found after bootstrap at $MITM_CA" >&2; exit 1; }

command -v "$AGENT_BIN" >/dev/null 2>&1 || { echo "Error: '$AGENT_BIN' not found in PATH" >&2; exit 1; }
AGENT_BIN_PATH="$(command -v "$AGENT_BIN")"

# Ensure Codex auth is initialized from current environment key for this run.
if [[ "$(basename "$AGENT_BIN_PATH")" == "codex" ]]; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        echo "Error: OPENAI_API_KEY is not set in container environment." >&2
        echo "Export OPENAI_API_KEY on host and recreate container, then retry." >&2
        exit 1
    fi
    if ! printf '%s' "$OPENAI_API_KEY" | codex login --with-api-key >/dev/null 2>&1; then
        echo "Error: failed to initialize Codex auth from OPENAI_API_KEY." >&2
        echo "Verify your key and retry." >&2
        exit 1
    fi
fi

if [[ "$INTERCEPT_MODE" != "proxy" && "$INTERCEPT_MODE" != "transparent" ]]; then
    echo "Error: --mode must be 'proxy' or 'transparent'" >&2
    exit 1
fi

if [[ "$INTERCEPT_MODE" == "transparent" ]]; then
    # Ensure mitmproxyuser exists
    if ! id "$MITM_USER" >/dev/null 2>&1; then
        useradd -r -s /bin/false "$MITM_USER"
        echo "[*] Created system user: $MITM_USER"
    fi
fi

echo "═══════════════════════════════════════════════════════════"
echo "  Intercepted External Agent"
echo "═══════════════════════════════════════════════════════════"
echo "  Agent:       $AGENT_BIN"
echo "  Task:        ${TASK[*]:-<interactive>}"
echo "  Trace ID:    $TRACE_ID"
echo "  MITM mode:   $INTERCEPT_MODE"
echo "  MITM proxy:  localhost:$MITM_PORT"
echo "  MITM log:    $MITM_JSONL"
echo "  eBPF trace:  $ENABLE_EBPF"
echo "  eBPF file:   $EBPF_FILE"
echo "═══════════════════════════════════════════════════════════"

export MITM_CAPTURE_FILE="$MITM_JSONL"
if [[ "$INTERCEPT_MODE" == "transparent" ]]; then
    # Make capture directory writable by mitmproxyuser
    chmod 777 "$OBS_ROOT/mitm"
    # Copy CA cert so mitmproxyuser can read it
    MITM_USER_HOME="$(eval echo ~$MITM_USER)"
    mkdir -p "$MITM_USER_HOME/.mitmproxy"
    cp "$MITM_CA" "$MITM_USER_HOME/.mitmproxy/"
    cp "${MITM_CA%.pem}-ca.pem" "$MITM_USER_HOME/.mitmproxy/" 2>/dev/null || true
    cp "$HOME/.mitmproxy/mitmproxy-ca.pem" "$MITM_USER_HOME/.mitmproxy/" 2>/dev/null || true
    cp "$HOME/.mitmproxy/mitmproxy-ca-cert.cer" "$MITM_USER_HOME/.mitmproxy/" 2>/dev/null || true
    # Copy the full mitmproxy config directory for key material
    cp -r "$HOME/.mitmproxy/"* "$MITM_USER_HOME/.mitmproxy/" 2>/dev/null || true
    chown -R "$MITM_USER":"$MITM_USER" "$MITM_USER_HOME/.mitmproxy"

    # Start mitmdump in transparent mode, running as mitmproxyuser
    # so its own outbound traffic is excluded from iptables redirect.
    sudo -u "$MITM_USER" \
        MITM_CAPTURE_FILE="$MITM_JSONL" \
        MANTLE_AGENT_ROOT_PID_FILE="$ROOT_PID_FILE" \
        HOME="$MITM_USER_HOME" \
        "${MITMDUMP_LAUNCH[@]}" \
            --mode transparent@"$MITM_PORT" \
            --mode reverse:https://api.openai.com@"$MITM_REV_PORT" \
            --ssl-insecure \
            --set connection_strategy=lazy \
            -s "$MITM_CAPTURE_SCRIPT" \
            --set capture_file="$MITM_JSONL" \
            -q &
    MITM_PID=$!
    sleep 2
    kill -0 "$MITM_PID" 2>/dev/null || { echo "Error: mitmdump failed to start" >&2; exit 1; }
    echo "[*] mitmdump started as $MITM_USER (PID $MITM_PID)"
else
    # Stable default for containerized codex: explicit proxy mode.
    "${MITMDUMP_LAUNCH[@]}" \
        -p "$MITM_PORT" \
        --ssl-insecure \
        -s "$MITM_CAPTURE_SCRIPT" \
        --set capture_file="$MITM_JSONL" \
        -q &
    MITM_PID=$!
    sleep 2
    kill -0 "$MITM_PID" 2>/dev/null || { echo "Error: mitmdump failed to start" >&2; exit 1; }
    echo "[*] mitmdump started in proxy mode (PID $MITM_PID)"
fi

IPTABLES_SETUP=false
IP6TABLES_SETUP=false
if [[ "$INTERCEPT_MODE" == "transparent" ]]; then
    # Redirect all HTTPS traffic through mitmproxy in transparent mode.
    if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -A OUTPUT -p tcp --dport 443 \
            -m owner ! --uid-owner "$MITM_USER" \
            -j REDIRECT --to-port "$MITM_PORT" 2>/dev/null && IPTABLES_SETUP=true
        if $IPTABLES_SETUP; then
            echo "[*] iptables redirect: port 443 → $MITM_PORT (excluding $MITM_USER)"
        else
            echo "[!] iptables redirect failed (need root?), falling back to env vars"
        fi
    else
        echo "[!] iptables not available, falling back to env vars"
    fi

    if command -v ip6tables >/dev/null 2>&1; then
        # Reject IPv6 traffic to force fallback to IPv4 (which is correctly proxied)
        ip6tables -A OUTPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null && IP6TABLES_SETUP=true
        if $IP6TABLES_SETUP; then
            echo "[*] ip6tables reject: port 443 (forcing IPv4 fallback)"
        fi
    fi
fi

# Install mitmproxy CA to system trust store (important for Rust binaries ignoring env vars)
if [ -d "/usr/local/share/ca-certificates" ]; then
    if [ -w "/usr/local/share/ca-certificates" ]; then
        cp "$MITM_CA" /usr/local/share/ca-certificates/mitmproxy.crt
        update-ca-certificates >/dev/null 2>&1 || true
        echo "[*] Installed mitmproxy CA to system trust store."
    else
        echo "[*] Skipping system CA install (no write permission); using env-based CA bundle."
    fi
fi

# Create a combined CA bundle: system CAs + mitmproxy CA
# Rust's rustls reads SSL_CERT_FILE but needs ALL CAs (not just mitmproxy)
COMBINED_CA="$(mktemp /tmp/mantle-ca-bundle.XXXXXX.crt)"
cat /etc/ssl/certs/ca-certificates.crt "$MITM_CA" > "$COMBINED_CA" 2>/dev/null || \
    cp "$MITM_CA" "$COMBINED_CA"
echo "[*] Combined CA bundle: $COMBINED_CA"

# Also set proxy env vars as fallback (for agents that DO respect them)
export HTTPS_PROXY="http://127.0.0.1:$MITM_PORT"
export HTTP_PROXY="http://127.0.0.1:$MITM_PORT"
export https_proxy="http://127.0.0.1:$MITM_PORT"
export http_proxy="http://127.0.0.1:$MITM_PORT"
export ALL_PROXY="http://127.0.0.1:$MITM_PORT"
export all_proxy="http://127.0.0.1:$MITM_PORT"
# Keep bypasses configurable instead of hard-coding localhost exclusions.
# Empty by default so local traffic (for example curl localhost:8080) is proxied and captured.
NO_PROXY_VALUE="${MANTLE_NO_PROXY:-${RTRACE_NO_PROXY:-}}"
export NO_PROXY="$NO_PROXY_VALUE"
export no_proxy="$NO_PROXY_VALUE"
export SSL_CERT_FILE="$COMBINED_CA"
export REQUESTS_CA_BUNDLE="$COMBINED_CA"
export NODE_EXTRA_CA_CERTS="$COMBINED_CA"
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Newer Codex versions may drop auth headers for plaintext http base URLs.
# Transparent iptables interception is sufficient, so do NOT override base URL
# by default. Allow opt-in for debugging compatibility.
if [[ "${MANTLE_FORCE_OPENAI_BASE:-${RTRACE_FORCE_OPENAI_BASE:-0}}" == "1" ]]; then
    export OPENAI_API_BASE="http://127.0.0.1:$MITM_REV_PORT/v1"
    export OPENAI_BASE_URL="http://127.0.0.1:$MITM_REV_PORT/v1"
    echo "[*] Forced OPENAI_BASE_URL/OPENAI_API_BASE to local reverse endpoint"
fi

cleanup() {
    echo ""
    # Remove iptables rule first
    if $IPTABLES_SETUP; then
        iptables -t nat -D OUTPUT -p tcp --dport 443 \
            -m owner ! --uid-owner "$MITM_USER" \
            -j REDIRECT --to-port "$MITM_PORT" 2>/dev/null || true
        echo "[*] iptables redirect removed"
    fi
    if $IP6TABLES_SETUP; then
        ip6tables -D OUTPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null || true
        echo "[*] ip6tables reject removed"
    fi
    if [ -f "/usr/local/share/ca-certificates/mitmproxy.crt" ]; then
        rm -f "/usr/local/share/ca-certificates/mitmproxy.crt"
        update-ca-certificates >/dev/null 2>&1
    fi
    echo "[*] Stopping mitmdump (PID $MITM_PID)..."
    kill "$MITM_PID" 2>/dev/null || true
    wait "$MITM_PID" 2>/dev/null || true
    echo "[*] Done. Captured data:"
    [ -f "$MITM_JSONL" ] && echo "    MITM log:   $MITM_JSONL ($(wc -l < "$MITM_JSONL") lines)"
    [ -f "$EBPF_FILE" ] && echo "    eBPF log:   $EBPF_FILE ($(wc -l < "$EBPF_FILE") lines)"
    [ -n "$PID_WRAPPER_SCRIPT" ] && rm -f "$PID_WRAPPER_SCRIPT"
    [ -n "${COMBINED_CA:-}" ] && rm -f "$COMBINED_CA"
    rm -f "$ROOT_PID_FILE"
}
trap cleanup EXIT

# Build the agent command args
AGENT_ARGS=("${TASK[@]}")
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
