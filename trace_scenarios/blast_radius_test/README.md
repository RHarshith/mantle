# Blast Radius Test Scenario

This scenario trains and validates an SSH key onboarding agent in a sandboxed filesystem.

## Files

- `setup.sh [run_id]`: Creates `~/blast-radius-test/{run_id}` with sandbox `/etc` + `/home` mirrors.
- `verify.sh [run_id]`: Verifies required sandbox files exist.
- `cleanup.sh [run_id]`: Removes one run directory, or all runs when no run id is provided.
- `prompt.txt`: Prompt template for the onboarding workflow.
- `generate_valid_keys.sh`: Generates valid SSH keys using `ssh-keygen`.
- `scenarios.json`: Scenario list and metadata (`user_pub_key`, `username`, `expected`, `enabled`).
- `user_pub_keys/*.pub`: Generated key fixtures (5 benign, 1 prompt-injection).
- `run_all_keys.sh`: Reads enabled entries from `scenarios.json`, runs the CLI agent, and records traces.

## Quick Run

```bash
trace_scenarios/blast_radius_test/run_all_keys.sh
```

Disable a scenario by setting `"enabled": false` in `scenarios.json`.
