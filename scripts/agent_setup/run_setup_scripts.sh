#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${MANTLE_REPO_ROOT:-${RTRACE_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}}"
CONFIG_PATH="${1:-${MANTLE_AGENT_SETUP_CONFIG:-${RTRACE_AGENT_SETUP_CONFIG:-$REPO_ROOT/agent_setup/setup.yml}}}"

if [[ "${MANTLE_SKIP_AGENT_SETUP:-${RTRACE_SKIP_AGENT_SETUP:-0}}" == "1" ]]; then
    echo "[agent-setup] Skipped (MANTLE_SKIP_AGENT_SETUP=1)"
    exit 0
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "[agent-setup] Config not found at $CONFIG_PATH (skipping)"
    exit 0
fi

echo "[agent-setup] Using config: $CONFIG_PATH"

script_count=0
while IFS= read -r line; do
    script_rel="$(printf '%s' "$line" | sed -n 's/^[[:space:]]*-[[:space:]]*//p')"
    if [[ -z "$script_rel" ]]; then
        continue
    fi

    script_path="$script_rel"
    if [[ "$script_path" != /* ]]; then
        script_path="$REPO_ROOT/$script_path"
    fi

    if [[ ! -x "$script_path" ]]; then
        echo "[agent-setup] Warning: script not executable or missing: $script_path"
        continue
    fi

    echo "[agent-setup] Running: $script_path"
    "$script_path"
    script_count=$((script_count + 1))
done < "$CONFIG_PATH"

echo "[agent-setup] Completed. Scripts executed: $script_count"
