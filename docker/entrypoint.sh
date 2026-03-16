#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${MANTLE_REPO_ROOT:-${RTRACE_REPO_ROOT:-/workspace/mantle}}"

export PATH="/usr/local/bin:${PATH}"
export AGENT_OBS_ROOT="${AGENT_OBS_ROOT:-$REPO_ROOT/obs}"
export MANTLE_VENV="${MANTLE_VENV:-${RTRACE_VENV:-/opt/mantle-venv}}"
export MANTLE_AGENT_SETUP_CONFIG="${MANTLE_AGENT_SETUP_CONFIG:-${RTRACE_AGENT_SETUP_CONFIG:-$REPO_ROOT/agent_setup/setup.yml}}"
export RTRACE_VENV="$MANTLE_VENV"
export RTRACE_AGENT_SETUP_CONFIG="$MANTLE_AGENT_SETUP_CONFIG"

mkdir -p "$AGENT_OBS_ROOT/traces" "$AGENT_OBS_ROOT/events" "$AGENT_OBS_ROOT/mitm"

SETUP_RUNNER="$REPO_ROOT/scripts/agent_setup/run_setup_scripts.sh"
if [[ -x "$SETUP_RUNNER" ]]; then
    "$SETUP_RUNNER" "$MANTLE_AGENT_SETUP_CONFIG" || echo "[entrypoint] Agent setup runner failed (continuing)."
fi

if [[ $# -eq 0 ]]; then
    exec bash
fi

exec "$@"
