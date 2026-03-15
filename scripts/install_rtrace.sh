#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_PATH="${RTRACE_VENV:-$REPO_ROOT/.venv}"
LOCAL_BIN="${HOME}/.local/bin"

echo "[rtrace-install] Repo: $REPO_ROOT"
echo "[rtrace-install] Venv: $VENV_PATH"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/python" -m pip install --upgrade pip
"$VENV_PATH/bin/python" -m pip install -r "$REPO_ROOT/requirements.runtime.txt"

mkdir -p "$LOCAL_BIN"
ln -sf "$REPO_ROOT/bin/rtrace" "$LOCAL_BIN/rtrace"
ln -sf "$REPO_ROOT/bin/rtrace_monitor" "$LOCAL_BIN/rtrace_monitor"
ln -sf "$REPO_ROOT/bin/rtrace_test" "$LOCAL_BIN/rtrace_test"
rm -f "$LOCAL_BIN/strace_test"

echo ""
echo "[rtrace-install] Installed commands:"
echo "  $LOCAL_BIN/rtrace"
echo "  $LOCAL_BIN/rtrace_monitor"
echo "  $LOCAL_BIN/rtrace_test"
echo ""
echo "If they are not found, add this to your shell profile and reload:"
echo "  export PATH=\"$HOME/.local/bin:$PATH\""
echo ""
echo "Quick test:"
echo "  rtrace_monitor --help"
echo "  rtrace codex --help"
echo "  rtrace_test --list"
