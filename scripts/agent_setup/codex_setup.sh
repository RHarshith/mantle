#!/usr/bin/env bash
set -euo pipefail

ENV_DIR="/root/.config/rtrace/agent-env"
ENV_FILE="$ENV_DIR/codex.env"
BASHRC="/root/.bashrc"
MARKER_START="# >>> rtrace-agent-env >>>"
MARKER_END="# <<< rtrace-agent-env <<<"

mkdir -p "$ENV_DIR"

if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    umask 077
    cat > "$ENV_FILE" <<EOF
export OPENAI_API_KEY='${OPENAI_API_KEY}'
EOF
    chmod 600 "$ENV_FILE"

    # Initialize Codex CLI auth store so it works in non-interactive runs.
    if command -v codex >/dev/null 2>&1; then
        if printf '%s' "$OPENAI_API_KEY" | codex login --with-api-key >/dev/null 2>&1; then
            echo "[codex-setup] Codex login initialized from OPENAI_API_KEY."
        else
            echo "[codex-setup] Warning: codex login initialization failed (env file still written)."
        fi
    fi

    echo "[codex-setup] OPENAI_API_KEY synced to container runtime env file."
else
    echo "[codex-setup] OPENAI_API_KEY not present in environment; skipping key sync."
fi

if [[ -f "$BASHRC" ]]; then
    if ! grep -q "$MARKER_START" "$BASHRC"; then
        cat >> "$BASHRC" <<'EOF'
# >>> rtrace-agent-env >>>
if [ -d /root/.config/rtrace/agent-env ]; then
  for _envf in /root/.config/rtrace/agent-env/*.env; do
    [ -f "$_envf" ] && . "$_envf"
  done
fi
# <<< rtrace-agent-env <<<
EOF
    fi
fi
