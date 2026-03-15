#!/usr/bin/env bash
set -euo pipefail

# Idempotent Ubuntu bootstrap for this repository.
# Assumes you run this script from inside the cloned repo.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$REPO_ROOT/requirements.runtime.txt" ]]; then
  echo "Error: requirements.runtime.txt not found. Run from inside the repo." >&2
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Error: unable to detect OS." >&2
  exit 1
fi

# shellcheck source=/dev/null
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "Warning: this script is designed for Ubuntu. Detected: ${ID:-unknown}" >&2
fi

if command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

apt_install() {
  local pkg
  local to_install=()
  for pkg in "$@"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      continue
    fi
    to_install+=("$pkg")
  done

  if [[ ${#to_install[@]} -eq 0 ]]; then
    echo "[bootstrap] apt packages already installed"
    return 0
  fi

  echo "[bootstrap] installing apt packages: ${to_install[*]}"
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y "${to_install[@]}"
}

echo "[bootstrap] repo: $REPO_ROOT"
echo "[bootstrap] updating apt cache"
$SUDO apt-get update -y

apt_install \
  bash \
  ca-certificates \
  curl \
  git \
  iproute2 \
  iptables \
  iputils-ping \
  lsof \
  npm \
  openssh-client \
  python3 \
  python3-pip \
  python3-venv \
  sudo \
  bpftrace

if ! command -v codex >/dev/null 2>&1; then
  echo "[bootstrap] installing Codex CLI"
  $SUDO npm install -g @openai/codex
else
  echo "[bootstrap] Codex CLI already installed"
fi

# Ensure local bin PATH wiring in common shells (idempotent append).
append_once() {
  local file="$1"
  local line="$2"
  [[ -f "$file" ]] || touch "$file"
  if grep -Fqx "$line" "$file"; then
    return 0
  fi
  echo "$line" >> "$file"
}

append_once "$HOME/.bashrc" 'export PATH="$HOME/.local/bin:$PATH"'
append_once "$HOME/.zshrc" 'export PATH="$HOME/.local/bin:$PATH"'
append_once "$HOME/.bashrc" "export AGENT_OBS_ROOT=\"$REPO_ROOT/obs\""
append_once "$HOME/.zshrc" "export AGENT_OBS_ROOT=\"$REPO_ROOT/obs\""

cd "$REPO_ROOT"
echo "[bootstrap] installing python runtime + repo commands"
bash "$REPO_ROOT/scripts/install_rtrace.sh"

echo "[bootstrap] done"
echo ""
echo "Next steps:"
echo "  1) reload your shell: source ~/.bashrc  (or source ~/.zshrc)"
echo "  2) set key for current shell: export OPENAI_API_KEY=YOUR_KEY"
echo "  3) verify commands: rtrace_monitor --help && rtrace codex --help && rtrace_test --list"
