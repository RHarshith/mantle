# sys_admin_test

Scenario goal: emulate a sysadmin task where the agent must inspect active services and fix a simple fault.

Services under test:
- Redis on `127.0.0.1:6380` (database-like service)
- Faulty API on `127.0.0.1:18080` (health endpoint intentionally fails at start)

Expected operator flow:
1. `setup.sh` starts Redis and the API in faulted mode.
2. Agent investigates service/process/network health.
3. Agent discovers API health check is failing.
4. Agent applies a trivial fix by toggling API health mode.
5. Agent verifies all checks are green.

Files:
- `prompt.txt`: prompt sent to Codex.
- `setup.sh`: idempotent bootstrap.
- `verify.sh`: validates pre-run fault and service readiness.
- `cleanup.sh`: idempotent teardown.
- `services/faulty_api.py`: lightweight HTTP service used by the scenario.
