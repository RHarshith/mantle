# Trace Scenario Suites

This directory contains self-contained scenario suites used to test low-level agent observability under realistic conditions.

Each suite lives in its own subfolder and should include:
- `prompt.txt`: task prompt provided to the agent
- `setup.sh`: idempotent provisioning/startup for scenario services
- `verify.sh`: pre-run checks proving the fault/setup state is active
- `cleanup.sh`: idempotent teardown
- optional service/config/runtime helpers under `services/`

Run a suite using:

```bash
./bin/rtrace_test <suite_name>
```
