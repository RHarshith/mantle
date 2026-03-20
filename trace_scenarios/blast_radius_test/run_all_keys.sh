#!/usr/bin/env bash
# Run blast-radius scenarios from scenarios.json.
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
while [[ -h "$SOURCE" ]]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    TARGET="$(readlink "$SOURCE")"
    if [[ "$TARGET" != /* ]]; then
        SOURCE="$DIR/$TARGET"
    else
        SOURCE="$TARGET"
    fi
done

SCENARIO_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
REPO_ROOT="$(cd "$SCENARIO_DIR/../.." && pwd)"
MANTLE_BIN="${REPO_ROOT}/bin/mantle"
PROMPT_TEMPLATE="${SCENARIO_DIR}/prompt.txt"
SCENARIO_JSON="${SCENARIO_DIR}/scenarios.json"
KEY_GENERATOR="${SCENARIO_DIR}/generate_valid_keys.sh"
VENV_PATH="${MANTLE_VENV:-$REPO_ROOT/.venv}"
PYTHON_BIN="$VENV_PATH/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
    PYTHON_BIN="$(command -v python3)"
fi

if [[ ! -f "$SCENARIO_JSON" ]]; then
    echo "Missing scenarios file: $SCENARIO_JSON" >&2
    exit 1
fi

if [[ ! -x "$MANTLE_BIN" ]]; then
    echo "Missing mantle runner: $MANTLE_BIN" >&2
    exit 1
fi

if [[ ! -x "$KEY_GENERATOR" ]]; then
    chmod +x "$KEY_GENERATOR"
fi
bash "$KEY_GENERATOR"

scenario_rows=()
while IFS= read -r line; do
    scenario_rows+=("$line")
done < <("$PYTHON_BIN" - <<PY
import json
from pathlib import Path

path = Path(${SCENARIO_JSON@Q})
items = json.loads(path.read_text(encoding="utf-8"))
for it in items:
    if not isinstance(it, dict):
        continue
    if it.get("enabled", True) is False:
        continue
    sid = str(it.get("id") or "").strip()
    key = str(it.get("user_pub_key") or "").strip()
    username = str(it.get("username") or "").strip()
    expected = str(it.get("expected") or "").strip()
    if sid and key and username:
        print("\t".join([sid, key, username, expected]))
PY
)

if [[ ${#scenario_rows[@]} -eq 0 ]]; then
    echo "No enabled scenarios found in $SCENARIO_JSON"
    exit 0
fi

failed=()

for row in "${scenario_rows[@]}"; do
    IFS=$'\t' read -r scenario_id key_rel username expected <<< "$row"

    key_file="${SCENARIO_DIR}/${key_rel}"
    if [[ ! -f "$key_file" ]]; then
        echo "Skipping ${scenario_id}: key file not found at ${key_file}" >&2
        continue
    fi

    key_name="$(basename "$key_file")"
    run_id="blast_$(date +%Y%m%d_%H%M%S)_${scenario_id}"
    run_root="${HOME}/blast-radius-test/${run_id}"

    echo ""
    echo "==> Running fixture: ${scenario_id} (${key_name})"
    bash "$SCENARIO_DIR/setup.sh" "$run_id"

    cp "$key_file" "$run_root/home/user_pub_keys/${key_name}"

    prompt="$(sed "s/{run_id}/${run_id}/g" "$PROMPT_TEMPLATE")"
    prompt="$prompt

Use this key file: $run_root/home/user_pub_keys/${key_name}
Target username: ${username}
Expected behavior: ${expected}"

    trace_id="blast_radius_${scenario_id}_$(date +%H%M%S).ebpf.jsonl"
    echo "    trace_id: ${trace_id}"

    # Route output to repo-local obs and execute under mantle watch so eBPF
    # traces are produced (dashboard trace list depends on *.ebpf.jsonl).
    export AGENT_OBS_ROOT="${REPO_ROOT}/obs"
    if ! AGENT_OBS_ENABLED=1 \
        AGENT_AUTO_APPROVE=1 \
        "$MANTLE_BIN" watch --trace-id "$trace_id" -- "$PYTHON_BIN" -m mantle_agent.cli_agent --auto --task "$prompt"; then
        echo "    ERROR: scenario failed: ${scenario_id}" >&2
        failed+=("$scenario_id")
    fi

    bash "$SCENARIO_DIR/cleanup.sh" "$run_id"
done

echo ""
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "==> Completed with failures: ${failed[*]}" >&2
    exit 1
fi
echo "==> Completed all key fixtures"
