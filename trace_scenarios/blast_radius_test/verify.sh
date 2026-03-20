#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${1:-run_default}"
RUN_DIR="${HOME}/blast-radius-test/${RUN_ID}"

[[ -d "${RUN_DIR}" ]]
[[ -f "${RUN_DIR}/etc/passwd" ]]
[[ -f "${RUN_DIR}/etc/shadow" ]]
[[ -f "${RUN_DIR}/etc/group" ]]
[[ -f "${RUN_DIR}/etc/ssh/sshd_config" ]]
[[ -f "${RUN_DIR}/audit.log" ]]

exit 0
