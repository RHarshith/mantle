#!/usr/bin/env bash

if [ -z "${BASH_VERSION:-}" ]; then
	exec /usr/bin/env bash "$0" "$@"
fi

set -euo pipefail

TRACE_ID="${1:-trace_$(date +%Y%m%d_%H%M%S).strace.log}"

ORIG_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
	ORIG_HOME="$(eval echo "~$SUDO_USER")"
fi

OBS_ROOT="${AGENT_OBS_ROOT:-$ORIG_HOME/shared/simple_agent/obs}"
TRACE_DIR="$OBS_ROOT/traces"
EVENT_DIR="$OBS_ROOT/events"

PYTHON_BIN="${AGENT_PYTHON:-}"
if [ -z "$PYTHON_BIN" ]; then
	if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
		PYTHON_BIN="$VIRTUAL_ENV/bin/python"
	elif [ -x "$PWD/.venv/bin/python" ]; then
		PYTHON_BIN="$PWD/.venv/bin/python"
	elif [ -n "${SUDO_USER:-}" ] && [ -x "/home/$SUDO_USER/.venv/bin/python" ]; then
		PYTHON_BIN="/home/$SUDO_USER/.venv/bin/python"
	elif command -v python3 >/dev/null 2>&1; then
		PYTHON_BIN="$(command -v python3)"
	elif command -v python >/dev/null 2>&1; then
		PYTHON_BIN="$(command -v python)"
	else
		echo "Error: could not find a Python interpreter. Set AGENT_PYTHON explicitly." >&2
		exit 1
	fi
fi

mkdir -p "$TRACE_DIR" "$EVENT_DIR"

echo "Trace ID: $TRACE_ID"
echo "Trace file: $TRACE_DIR/$TRACE_ID"
echo "Event file: $EVENT_DIR/$TRACE_ID.events.jsonl"
echo "Python: $PYTHON_BIN"

export AGENT_TRACE_ID="$TRACE_ID"
export AGENT_OBS_ROOT="$OBS_ROOT"

strace -f -e trace=process,file -o "$TRACE_DIR/$TRACE_ID" "$PYTHON_BIN" simple_agent/cli_agent.py
