# Mantle

Mantle provides a non-invasive ecosystem for deploying verifiable, secure and capable AI agents.

Mantle's core value is about bridging the gap between semantic decisions and the ground-truth of the system- it captures what an AI agent sees (the context), the actions it performs (reasoning, responses and tool calls) and the side-effects on the system (files read/written, API calls made, etc), all of which are combined to form a unified trajectory of the agent's interactions with the system.

It does all of this without requiring any instrumentation of the agent- simply install mantle and run your agent of choice like you always do.


## Why This Project Exists

AI agents are powerful, but most teams still treat their behavior as a black box. Mantle was built to answer practical engineering and security questions.

### Correctness
- Did the agent solve the task correctly, given a reference solution?
- Did the agent follow the *right* steps to achieve its goal?

### Safety
- Did the agent receive the right privileges to do the task efficiently *and* securely?
- Did any of the agent's actions result in an unexpected side-effect on the system?
- Did any sensitive information leak into the agent's context?

### Efficiency
- Relative to a baseline, how efficiently did the agent finish the task? This could include token usage, number of tool calls, system resource utilization and more.
- Did the agent ingest redundant information already in the context, or did it perform an action with the same side-effect on the system multiple times?
- How can we compare different agents and models to determine the best combination for our specific needs?

The above questions are a small subset of many interesting usecases that mantle can solve. This is why mantle exists as a **extensible platform** that supports the development of such usecases by providing a robust infrastructure to **monitor** and **guardrail** agents.

## Core Capabilities

### Semantic and ground truth correlation
Mantle links each system call (the ground truth) to its corresponding high level action that the agent took (the tool call). Today most monitoring tools exist to either monitor the semantic layer (langsmith, langfuse), or the system layer (Tetragon). Mantle bridges the gap.

### Zero-instrumentation operations
All of mantle's features rely on observing the agent from its system boundaries- its network interactions and system calls. network interactions allows us to capture the model's context and actions, whereas system calls allow us to capture the side-effects.

### State reconstruction and replay
Snapshots of the system resources(files) at tool call boundaries allows us to reconstruct the agent's past execution to debug wrong behavior and optimize tool usage.

### Sandboxing [Upcoming]
Most agents have their own sandboxes with primitive exclusion policies. Mantle's unified sandbox allows teams to switch agents on the fly and provides a rich policy language that dynamically switches policies based on task requirements.


## Quickstart

### System Requirements

Mantle currently requires a **Linux** environment (kernel version >= 5.15 recommended for eBPF observability features).

Please ensure you have the following prerequisite tools installed on your system:
- **git**
- **make**
- **docker**
- **docker compose v2 plugin** (recommended) or **docker-compose v1** (supported fallback)
- **systemd user session support** (`systemd-run --user`) for eBPF watch mode
- **codex CLI** (current Mantle flow expects `codex exec ...`)

On Ubuntu/Debian, you can install these requirements by running:

```bash
sudo apt-get update
sudo apt-get install -y git make docker.io docker-compose-v2 systemd
```

If your distro does not provide `docker-compose-v2`, Mantle can use the
standalone `docker-compose` binary (v1) as a fallback.

Quick verification checklist:

```bash
docker --version
docker compose version || docker-compose --version
systemd-run --user --scope -q true
codex --version
```

If you see Docker daemon permission errors, either run with `sudo` or add your user
to the `docker` group.

To use OpenAI through Mantle's proxy, ensure your API key is exported:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

### Step-by-Step Guide

**1. Clone the repository**

```bash
git clone https://github.com/RHarshith/mantle
cd mantle
```

**2. Configure your coding agent**

**Note**: Current version only supports OpenAI codex.
Update its `config.toml` proxy settings to point to Mantle's proxy service:

```toml
model = "gpt-5.4-nano"
model_reasoning_effort = "low"
model_provider = "litellm-proxy"

[model_providers.litellm-proxy]
name = "Mantle Proxy"
base_url = "http://127.0.0.1:4000/v1"
env_key = "OPENAI_API_KEY" # Ensure this is set in your ENV
wire_api = "responses"
requires_openai_auth = false
```

If `codex` is not yet installed, install and authenticate it before continuing.

**3. Build**

Build and provision the containerized background services:

```bash
sudo make build
```
Mantle automatically prefers `docker compose` (v2) and falls back to `docker-compose` (v1) when needed.

**4. Run**

`make build` automatically starts the daemon, proxy, and server in the background. To run an agent with tracing enabled, you can run the `watch` command (you can optionally add `bin` to your `$PATH`):

```bash
bin/mantle watch codex exec "task here" --sandbox danger-full-access
```

**Note**: The `--sandbox` flag is optional. You can configure codex sandbox policy as required.
If your environment does not support `systemd-run --user`, eBPF watch mode will not work.

You can view the live trace dashboard by opening `http://127.0.0.1:8099` in your browser.

**5. Clean up**

To stop all background services and clean up the containers:

```bash
make down
make clean
```


