#!/usr/bin/env bash
set -euo pipefail

ENV_DIR="/root/.config/mantle/agent-env"
ENV_FILE="$ENV_DIR/openai.env"
BASHRC="/root/.bashrc"
MARKER_START="# >>> mantle-agent-env >>>"
MARKER_END="# <<< mantle-agent-env <<<"

mkdir -p "$ENV_DIR"

if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    umask 077
    cat > "$ENV_FILE" <<EOF
export OPENAI_API_KEY='${OPENAI_API_KEY}'
EOF
    chmod 600 "$ENV_FILE"

    echo "[agent-env-setup] OPENAI_API_KEY synced to runtime env file."
else
    echo "[agent-env-setup] OPENAI_API_KEY not present in environment; skipping key sync."
fi

if [[ -f "$BASHRC" ]]; then
    if ! grep -q "$MARKER_START" "$BASHRC"; then
        cat >> "$BASHRC" <<'EOF'
# >>> mantle-agent-env >>>
if [ -d /root/.config/mantle/agent-env ]; then
    for _envf in /root/.config/mantle/agent-env/*.env; do
    [ -f "$_envf" ] && . "$_envf"
  done
fi
# <<< mantle-agent-env <<<
EOF
    fi
fi
