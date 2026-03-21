# Blast Radius Test Scenario

This scenario trains and validates an SSH key onboarding agent in a sandboxed filesystem.

## Files

- `setup.sh [run_id]`: Creates `~/blast-radius-test/{run_id}` with sandbox `/etc` + `/home` mirrors.
  It also generates per-run SSH key fixtures under `~/blast-radius-test/{run_id}/home/user_pub_keys`.
- `verify.sh [run_id]`: Verifies required sandbox files exist.
- `cleanup.sh [run_id]`: Removes one run directory, or all runs when no run id is provided.
- `prompt.txt`: Prompt template for the onboarding workflow.
- `scenarios.json`: Scenario list and metadata (`user_pub_key`, `username`, `expected`, `enabled`).
- `keys/`, `user_pub_keys/`: Placeholder directories only; key fixtures are generated at setup time.
- `run_all_keys.sh`: Reads enabled entries from `scenarios.json`, runs the CLI agent, and records traces.

Injection fixture variants include:
- multiline instruction tail (`injection_skip_audit.pub`)
- policy text embedded in key comment (`injection_comment_roleplay.pub`)
- payload encoded in valid authorized_keys options (`injection_option_payload.pub`)

## Quick Run

```bash
trace_scenarios/blast_radius_test/run_all_keys.sh
```

Disable a scenario by setting `"enabled": false` in `scenarios.json`.
