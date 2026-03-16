#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_PATH="${MANTLE_VENV:-${RTRACE_VENV:-$REPO_ROOT/.venv}}"
LOCAL_BIN="${HOME}/.local/bin"

echo "[mantle-install] Repo: $REPO_ROOT"
echo "[mantle-install] Venv: $VENV_PATH"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required." >&2
    exit 1
fi

python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/python" -m pip install --upgrade pip
"$VENV_PATH/bin/python" -m pip install -r "$REPO_ROOT/requirements.runtime.txt"

mkdir -p "$LOCAL_BIN"
ln -sf "$REPO_ROOT/bin/mantle" "$LOCAL_BIN/mantle"
rm -f "$LOCAL_BIN/rtrace" "$LOCAL_BIN/rtrace_monitor" "$LOCAL_BIN/rtrace_test" "$LOCAL_BIN/strace_test"

echo ""
echo "[mantle-install] Installed command:"
echo "  $LOCAL_BIN/mantle"
echo ""
echo "If it is not found, add this to your shell profile and reload:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo ""
echo "Quick test:"
echo "  mantle --help"
echo "  mantle serve --help"
echo "  mantle watch --help"
