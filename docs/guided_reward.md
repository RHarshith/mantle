Let's pick **"add a new API endpoint to an existing codebase"** as the scenario. It's well-scoped, has clear intermediate steps, and the BPF events are predictable.

---

### What the Human Does Once

The human simply implements the endpoint themselves in their normal workflow. Nothing special — they open files, write code, run tests. Mantle records the session. That's the entire human input.

From that session, Mantle extracts the trace automatically:

```
[observable_env] → [action] → [bpf_events]
[observable_env] → [action] → [bpf_events]
...
```

---

### What the Checkpoints Look Like

For "add a GET /users/{id} endpoint" the human trace might look like:

```
Step 1: Read routes.py
         → action: read_file("routes.py")  
         → bpf: openat(routes.py, O_RDONLY)

Step 2: Write new route definition
         → action: write_file("routes.py", ...)
         → bpf: openat(routes.py, O_WRONLY), write(routes.py)

Step 3: Read models.py (understanding existing schema)
         → action: read_file("models.py")
         → bpf: openat(models.py, O_RDONLY)

Step 4: Write handler function
         → action: write_file("handlers/user.py", ...)
         → bpf: openat(handlers/user.py, O_CREAT|O_WRONLY), write(...)

Step 5: Run tests
         → action: run_command("pytest tests/test_users.py")
         → bpf: execve(pytest), openat(test_users.py), 
                network(127.0.0.1:5000), exit_code(0)
```

From this, Mantle extracts **checkpoints** — not the specific file contents, but the **structural BPF predicates** that must hold:

```python
checkpoints = [
    C1: openat("routes.py", O_WRONLY)       # routes were modified
    C2: openat("handlers/*.py", O_CREAT)    # a new handler file was created
    C3: execve("pytest")                    # tests were run
    C4: exit_code(pytest) == 0              # tests passed
    C5: network(localhost:PORT)             # server was reachable
]
```

These are **structurally abstracted** from the human trace — file names are generalized where possible, exact content is ignored, order is partially relaxed (C1 before C4, but C2 and C3 can be unordered).

---

### Reward Calculation

Simple potential-based shaping. At each agent step, reward is:

```python
def calculate_reward(bpf_events_so_far, checkpoints, terminal=False):
    
    # How many checkpoints satisfied so far
    satisfied = [c for c in checkpoints if c.evaluate(bpf_events_so_far)]
    progress = len(satisfied) / len(checkpoints)
    
    # Step penalty to discourage unnecessary actions
    step_cost = -0.01
    
    # Shaped reward: progress delta since last step
    shaped_reward = (progress - prev_progress) * 10
    
    # Terminal bonus: only if all checkpoints satisfied
    terminal_bonus = 10.0 if terminal and progress == 1.0 else 0.0
    
    return shaped_reward + step_cost + terminal_bonus
```

Concretely for the scenario:

```
Agent creates handler file         → C2 satisfied → reward +2.0
Agent modifies routes.py           → C1 satisfied → reward +2.0
Agent runs pytest, fails           → C3 satisfied → reward +2.0, C4 not → no bonus
Agent fixes bug, reruns pytest     → C4 satisfied → reward +2.0
Server responds on localhost       → C5 satisfied → reward +2.0 + terminal +10.0
```

---

### The Dummy Logic You Can Run

Here's a minimal self-contained implementation to validate the concept:

```python
from dataclasses import dataclass, field
from typing import List, Callable
import re

# ── data structures ──────────────────────────────────────────────

@dataclass
class BPFEvent:
    syscall: str      # "openat", "execve", "exit_group", "connect"
    args: dict        # e.g. {"path": "routes.py", "flags": "O_WRONLY"}
    exit_code: int = 0

@dataclass  
class Checkpoint:
    name: str
    predicate: Callable[[List[BPFEvent]], bool]
    satisfied: bool = False

# ── checkpoint definitions for "add API endpoint" ────────────────

def make_checkpoints():
    return [
        Checkpoint(
            name="routes_modified",
            predicate=lambda events: any(
                e.syscall == "openat" and 
                "route" in e.args.get("path", "") and 
                "W" in e.args.get("flags", "")
                for e in events
            )
        ),
        Checkpoint(
            name="handler_created",
            predicate=lambda events: any(
                e.syscall == "openat" and
                "handler" in e.args.get("path", "") and
                "CREAT" in e.args.get("flags", "")
                for e in events
            )
        ),
        Checkpoint(
            name="tests_run",
            predicate=lambda events: any(
                e.syscall == "execve" and
                "pytest" in e.args.get("cmd", "")
                for e in events
            )
        ),
        Checkpoint(
            name="tests_passed",
            predicate=lambda events: any(
                e.syscall == "execve" and
                "pytest" in e.args.get("cmd", "") and
                e.exit_code == 0
                for e in events
            )
        ),
        Checkpoint(
            name="server_reachable",
            predicate=lambda events: any(
                e.syscall == "connect" and
                "127.0.0.1" in e.args.get("addr", "")
                for e in events
            )
        ),
    ]

# ── reward engine ─────────────────────────────────────────────────

class RewardEngine:
    def __init__(self, checkpoints: List[Checkpoint]):
        self.checkpoints = checkpoints
        self.prev_progress = 0.0
        self.all_events: List[BPFEvent] = []
        self.step_cost = -0.01

    def step(self, new_events: List[BPFEvent], terminal=False) -> float:
        self.all_events.extend(new_events)

        for c in self.checkpoints:
            if not c.satisfied:
                c.satisfied = c.predicate(self.all_events)

        progress = sum(c.satisfied for c in self.checkpoints) / len(self.checkpoints)
        shaped = (progress - self.prev_progress) * 10
        self.prev_progress = progress

        terminal_bonus = 10.0 if terminal and progress == 1.0 else 0.0
        reward = shaped + self.step_cost + terminal_bonus

        # debug
        satisfied_names = [c.name for c in self.checkpoints if c.satisfied]
        print(f"  progress={progress:.2f} reward={reward:.3f} "
              f"satisfied={satisfied_names}")
        return reward

# ── simulate an agent run ─────────────────────────────────────────

if __name__ == "__main__":
    engine = RewardEngine(make_checkpoints())

    print("=== Agent Run Simulation ===\n")

    # agent reads existing routes
    print("Step 1: agent reads routes.py")
    engine.step([BPFEvent("openat", {"path": "routes.py", "flags": "O_RDONLY"})])

    # agent writes new route
    print("Step 2: agent writes routes.py")
    engine.step([BPFEvent("openat", {"path": "routes.py", "flags": "O_WRONLY"})])

    # agent creates handler
    print("Step 3: agent creates handler file")
    engine.step([BPFEvent("openat", {"path": "handlers/user.py", 
                                      "flags": "O_CREAT|O_WRONLY"})])

    # agent runs tests — fail first
    print("Step 4: agent runs pytest (fails)")
    engine.step([BPFEvent("execve", {"cmd": "pytest tests/"}, exit_code=1)])

    # agent fixes and reruns
    print("Step 5: agent reruns pytest (passes)")
    engine.step([BPFEvent("execve", {"cmd": "pytest tests/"}, exit_code=0)])

    # server comes up
    print("Step 6: server reachable")
    engine.step([
        BPFEvent("connect", {"addr": "127.0.0.1:5000"})
    ], terminal=True)
```

---

### What to Validate

When you run this against an actual coding agent, the hypothesis is:

1. **An agent receiving these shaped rewards completes the task in fewer steps** than one receiving only terminal reward (tests pass / don't pass)
2. **The agent reaches partial completion more reliably** — it doesn't spin on one file forever because intermediate checkpoints reward forward progress
3. **The checkpoints extracted from one human trace generalize** to different valid implementations of the same task type

The third point is the most important one to stress-test. Try the human trace on a Flask app, then see if the extracted checkpoints correctly reward an agent solving the same task on a FastAPI app. If they do, the structural abstraction is working.