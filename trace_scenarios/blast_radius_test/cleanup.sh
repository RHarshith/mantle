#!/usr/bin/env bash
# Cleanup for blast radius SSH onboarding sandbox.
set -euo pipefail

RUN_ID="${1:-}"
BASE_DIR="${HOME}/blast-radius-test"

if [[ -n "${RUN_ID}" ]]; then
    rm -rf "${BASE_DIR}/${RUN_ID}" 2>/dev/null || true
else
    rm -rf "${BASE_DIR}" 2>/dev/null || true
fi
