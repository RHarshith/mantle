# Side Effect Detection for AI Agent Tool Calls
## Design Document — Option B: Reference-Free Semantic Checking

---

## 1. Overview

This system detects unintended side effects of AI agent tool calls by analyzing the BPF-captured process tree produced by each tool call. It operates without reference traces, instead applying semantic rule checks against the observed process tree. The input to the system is a tuple of `(command_string, process_tree)` where the process tree is a structured set of BPF events that fall within the timestamp range of the related tool call of the agent. The output is a list of flagged violations, each with a severity level and human-readable explanation.

The system is composed of four independent rule classes, each checking a different dimension of process behavior. Each rule class can be run independently and produces its own violation list. A final aggregation step merges all violations into a single report per tool call.

---

## 2. Input Format

The system expects the following inputs per tool call evaluation:

**command_string**: The raw shell command string as issued by the AI agent. Example: `"npm install lodash"`.

**process_tree**: A list of process node objects, each containing:
- `pid`: process ID
- `ppid`: parent process ID
- `binary`: resolved binary name (e.g., `npm`, `node`, `sh`)
- `argv`: list of arguments passed to the process
- `file_events`: list of file access events, each with:
  - `path`: absolute file path accessed
  - `operation`: one of `read`, `write`, `unlink`, `chmod`, `exec`
- `network_events`: list of network events, each with:
  - `direction`: `outbound` or `inbound`
  - `dest_ip`: destination IP address
  - `dest_port`: destination port
  - `protocol`: `tcp` or `udp`
- `env_reads`: list of environment variable names read by the process

---

## 3. Path Canonicalization

Before any rule is applied, all file paths must be canonicalized into semantic categories. This normalization is required so that rules can be written against stable labels rather than user-specific absolute paths.

Apply the following mapping (in priority order — first match wins):

| Pattern | Canonical Label |
|---|---|
| `$PROJECT_DIR/**` | `PROJECT` |
| `/tmp/**`, `/var/tmp/**` | `TEMP` |
| `/usr/lib/**`, `/usr/share/**`, `/lib/**` | `SYSTEM_LIB` |
| `/usr/bin/**`, `/usr/local/bin/**`, `/bin/**` | `SYSTEM_BIN` |
| `~/.npm/**`, `~/.cache/npm/**` | `NPM_CACHE` |
| `~/.cache/pip/**`, `~/.local/lib/python*/**` | `PY_CACHE` |
| `~/.cache/**` | `USER_CACHE` |
| `~/.config/**` | `USER_CONFIG` |
| `~/.ssh/**` | `SSH_DIR` |
| `~/.aws/**`, `~/.gcp/**`, `~/.azure/**` | `CLOUD_CREDS` |
| `~/.gnupg/**` | `GPG_DIR` |
| `~/.bash_history`, `~/.zsh_history`, `~/.sh_history` | `SHELL_HISTORY` |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*` | `SYSTEM_AUTH` |
| `/etc/**` | `SYSTEM_CONFIG` |
| `/proc/**` | `PROC_FS` |
| `/dev/**` | `DEV_FS` |
| `~/**` (catch-all for home directory) | `HOME` |

`$PROJECT_DIR` is resolved at runtime as the working directory of the root process of the tool call.

---

## 4. Rule Class 1 — Scope Violation

### Purpose
Detect file accesses outside the expected filesystem scope for the invoked command binary.

### Algorithm
1. Extract the root binary from `command_string` (first token, basename only).
2. Look up the allowed path label set for that binary from the table below.
3. For each file event across all processes in the tree, canonicalize the path.
4. If the canonical label is not in the allowed set, emit a violation.

### Allowed Scope Table

| Binary | Allowed Canonical Labels |
|---|---|
| `npm` | `PROJECT`, `TEMP`, `NPM_CACHE`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CACHE` |
| `npx` | `PROJECT`, `TEMP`, `NPM_CACHE`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CACHE` |
| `node` | `PROJECT`, `TEMP`, `NPM_CACHE`, `SYSTEM_LIB`, `SYSTEM_BIN` |
| `python`, `python3` | `PROJECT`, `TEMP`, `PY_CACHE`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CONFIG` |
| `pip`, `pip3` | `PROJECT`, `TEMP`, `PY_CACHE`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CACHE` |
| `git` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CONFIG`, `HOME` |
| `cargo` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CACHE` |
| `make` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN` |
| `gcc`, `clang`, `cc` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN` |
| `go` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN`, `USER_CACHE` |
| `cat`, `grep`, `sed`, `awk`, `find`, `ls`, `cp`, `mv`, `rm` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN` |
| `curl`, `wget` | `PROJECT`, `TEMP`, `SYSTEM_LIB`, `SYSTEM_BIN` |
| `bash`, `sh`, `zsh` | `*` (skip scope check — shell is too broad) |

Commands not in this table: skip Rule Class 1 for that binary. Do not emit false positives for unknown binaries.

### Violation Output
```
{
  "rule": "SCOPE_VIOLATION",
  "severity": "HIGH" if label in [SSH_DIR, CLOUD_CREDS, GPG_DIR, SHELL_HISTORY, SYSTEM_AUTH]
              "MEDIUM" otherwise,
  "process_binary": <binary>,
  "pid": <pid>,
  "path": <original path>,
  "canonical_label": <label>,
  "operation": <operation>
}
```

---

## 5. Rule Class 2 — Unexpected Network Activity

### Purpose
Detect outbound network connections from processes that should not require network access, and flag unexpected connections even from processes that sometimes legitimately use the network.

### Network Permission Categories

**MUST_NOT_NETWORK** — any outbound connection is a violation:
`cat`, `grep`, `sed`, `awk`, `find`, `ls`, `cp`, `mv`, `rm`, `make`, `gcc`, `clang`, `cc`, `tar`, `unzip`, `zip`, `diff`, `patch`, `echo`, `touch`, `mkdir`, `chmod`, `chown`

**SHOULD_NETWORK** — outbound connections are expected, do not flag:
`npm`, `npx`, `pip`, `pip3`, `curl`, `wget`, `git`, `cargo`, `go`, `apt`, `apt-get`, `brew`, `yarn`, `pnpm`

**MAY_NETWORK** — outbound connections are suspicious but not certain violations; flag with LOW severity for review:
`node`, `python`, `python3`, `bash`, `sh`, `zsh`, `ruby`, `java`, `php`

### Algorithm
1. For each process node in the tree, check its `network_events`.
2. Look up the binary in the category table above.
3. For `MUST_NOT_NETWORK` binaries: any outbound event is a `HIGH` severity violation.
4. For `MAY_NETWORK` binaries: any outbound event is a `LOW` severity violation.
5. For `SHOULD_NETWORK` binaries: no violation. (Future work: validate against expected domains.)
6. For unknown binaries: emit `LOW` severity violation for any outbound connection.

### Violation Output
```
{
  "rule": "UNEXPECTED_NETWORK",
  "severity": "HIGH" | "LOW",
  "process_binary": <binary>,
  "pid": <pid>,
  "dest_ip": <ip>,
  "dest_port": <port>,
  "reason": "binary is in MUST_NOT_NETWORK class" | "binary is in MAY_NETWORK class"
}
```

---

## 6. Rule Class 3 — Unexpected Process Spawning

### Purpose
Detect child processes whose binary is not a known legitimate child of their parent binary. This catches cases where a build tool unexpectedly spawns a network utility, a credential exfiltration tool, or a shell with unusual arguments.

### Algorithm
1. Build the parent-child pairs from the process tree using `(ppid, pid)` relationships.
2. For each pair, look up the parent binary in the legitimate spawn table below.
3. If the parent binary is in the table and the child binary is not in the parent's allowed children set, emit a violation.
4. If the parent binary is not in the table, skip (do not penalize unknown tools).

### Legitimate Spawn Table

| Parent Binary | Allowed Child Binaries |
|---|---|
| `npm` | `node`, `sh`, `bash`, `git`, `npx`, `npm`, `esbuild`, `tsc`, `webpack`, `vite`, `rollup`, `jest`, `eslint`, `prettier` |
| `npx` | `node`, `sh`, `bash`, `npm` |
| `node` | `sh`, `bash`, `node` |
| `pip`, `pip3` | `python`, `python3`, `sh`, `bash` |
| `python`, `python3` | `python`, `python3`, `sh`, `bash` |
| `git` | `sh`, `bash`, `ssh`, `gpg`, `diff`, `less`, `vi`, `vim`, `editor`, `git`, `git-lfs` |
| `make` | `sh`, `bash`, `gcc`, `clang`, `cc`, `ld`, `ar`, `as`, `python`, `python3`, `node`, `go`, `cargo`, `cmake`, `ninja` |
| `gcc`, `clang`, `cc` | `as`, `ld`, `cc1`, `collect2` |
| `cargo` | `rustc`, `sh`, `bash`, `cc`, `gcc`, `clang`, `ar`, `linker`, `lld` |
| `go` | `sh`, `bash`, `gcc`, `clang`, `cc` |
| `bash`, `sh`, `zsh` | `*` (allow all — shells can spawn anything; use Rule Class 4 instead) |
| `curl`, `wget` | (no children expected; any child is a violation) |

### Violation Severity
- `HIGH`: child binary is a known dangerous tool: `nc`, `ncat`, `netcat`, `socat`, `curl`, `wget`, `scp`, `rsync`, `ssh` (when parent is not `git`), `python`, `python3`, `ruby`, `perl`, `php` (when parent is a build tool like `make` or `npm`)
- `MEDIUM`: child binary is unexpected but not inherently dangerous

### Violation Output
```
{
  "rule": "UNEXPECTED_SPAWN",
  "severity": "HIGH" | "MEDIUM",
  "parent_binary": <binary>,
  "parent_pid": <ppid>,
  "child_binary": <binary>,
  "child_pid": <pid>,
  "child_argv": <argv>
}
```

---

## 7. Rule Class 4 — Sensitive Resource Access

### Purpose
Flag access to sensitive files and environment variables regardless of which binary accessed them. This rule is command-agnostic and applies to every process in the tree unconditionally.

### Sensitive Path Patterns
Any file event matching the following canonical labels triggers an automatic `HIGH` severity violation:

- `SSH_DIR` — any read or write to `~/.ssh/`
- `CLOUD_CREDS` — any access to `~/.aws/`, `~/.gcp/`, `~/.azure/`
- `GPG_DIR` — any access to `~/.gnupg/`
- `SHELL_HISTORY` — any write to shell history files
- `SYSTEM_AUTH` — any access to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`

Additionally flag with `MEDIUM` severity:
- Any `write` or `unlink` operation on `SYSTEM_CONFIG` paths (`/etc/**`)
- Any `write` operation on `SYSTEM_BIN` paths (`/usr/bin/**`, etc.)
- Any `chmod` or `chown` operation outside `PROJECT` and `TEMP`

### Sensitive Environment Variables
Flag `HIGH` severity if any process reads environment variables matching these patterns:
- `AWS_ACCESS_KEY*`, `AWS_SECRET*`
- `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- `DATABASE_URL`, `DB_PASSWORD`, `DB_PASS`
- `SECRET_KEY`, `PRIVATE_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`, `*_PASSWD`

Pattern matching here is case-insensitive glob.

### Violation Output
```
{
  "rule": "SENSITIVE_ACCESS",
  "severity": "HIGH" | "MEDIUM",
  "process_binary": <binary>,
  "pid": <pid>,
  "access_type": "file" | "env_var",
  "resource": <path or env var name>,
  "operation": <operation>
}
```

---

## 8. Aggregation and Final Report

After running all four rule classes, produce a single report per tool call:

```
{
  "command": <original command string>,
  "root_pid": <pid of root process>,
  "verdict": "CLEAN" | "SUSPICIOUS" | "VIOLATION",
  "verdict_logic": {
    "CLEAN":     no violations across all rule classes,
    "SUSPICIOUS": only LOW severity violations present,
    "VIOLATION":  at least one MEDIUM or HIGH severity violation
  },
  "violations": [ ...all violation objects from all rule classes... ],
  "summary": <human-readable one-line description of the most severe finding>
}
```

The `summary` field should be a single sentence suitable for display in an agent monitoring UI. Example: `"npm install spawned curl as a child process and made an outbound connection to 203.0.113.42:443"`.

---

## 9. Implementation Notes

**What to implement first**: Rule Class 4 (sensitive resource access) first — it is the simplest, has no lookup tables, and catches the most dangerous violations. Then Rule Class 3 (unexpected spawning), then Rule Class 1 (scope). Rule Class 2 (network) requires network event capture and can be added last.

**Shell commands**: When the root binary is `bash`, `sh`, or `zsh`, do not apply Rule Class 1 or 3 at the root level. Instead, apply all rules to each *child* process of the shell using that child's binary as the root binary for lookup purposes.

**Argv inspection**: For Rule Class 3, also inspect `child_argv` for dangerous patterns even when the binary itself is allowed. For example, `bash -c "curl ..."` from a `node` process is high severity even though `bash` is in node's allowed spawn list.

**Unknown binaries**: Do not emit violations for binaries not present in any lookup table, except for Rule Class 4 which is unconditional. Erring toward false negatives is preferable to alert fatigue in a prototype.

**Severity escalation**: If the same resource appears in violations from multiple rule classes, escalate the final severity by one level (MEDIUM → HIGH).

## 10. UI Changes
The result of the analysis must be output as follows:
If anomaly detected: the trace, the impacted turn (containing the tool call), and the tool call in the context and action window must all have a Red cirle exclamation icon on the top right of their containers, letting users know that an anomaly is detected. When the users drill down by clicking the pid linked to the tool call, show the information about the anomaly in a well formatted and nice UI design.

If no anomaly detected: replace the red exclamantion cirle with a green circle checkmark.

Hovering over both the icons should show a tooltip saying either "anomaly detected" or "verified tool call".