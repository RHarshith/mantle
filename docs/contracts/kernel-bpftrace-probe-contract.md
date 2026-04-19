# Contract: Kernel bpftrace Probe Stream

Status: active
Version: v1
Owner: mantle/capture/ebpf.py
Boundary: kernel/user tracing probes -> Python parser (_event_from_line)

## Purpose

Define the exact line protocol emitted by the in-process bpftrace program and consumed by the Python parser. This is the first contract boundary in the observability pipeline.

## Transport Contract

- Medium: stdout text lines from bpftrace process
- Encoding: UTF-8 compatible text
- Record model: one event per line
- Event prefix: every parseable event line MUST start with `EVT|`
- Non-EVT lines: allowed as passthrough target-process output, ignored by parser

## Line Grammar

```text
event-line := "EVT|" ns "|" kind ("|" field)*
ns         := uint64 (monotonic nanoseconds from bpftrace nsecs)
kind       := one of the kinds listed below
field      := raw token (no escaping; split by '|')
```

## Event Kinds and Positional Fields

```text
root          EVT|<ns>|root|<cpid>|0|start
fork          EVT|<ns>|fork|<parent_pid>|<child_pid>|<comm>
exec          EVT|<ns>|exec|<pid>|<ppid>|<comm>|<filename>
exit          EVT|<ns>|exit|<pid>|<ppid>|<comm>

openat        EVT|<ns>|openat|<pid>|<path>|<flags>
openat_ret    EVT|<ns>|openat_ret|<pid>|<ret_fd>
unlinkat      EVT|<ns>|unlinkat|<pid>|<path>
renameat      EVT|<ns>|renameat|<pid>|<old_path>|<new_path>
renameat_ret  EVT|<ns>|renameat_ret|<pid>|<ret>
renameat2     EVT|<ns>|renameat2|<pid>|<old_path>|<new_path>
renameat2_ret EVT|<ns>|renameat2_ret|<pid>|<ret>

connect       EVT|<ns>|connect|<pid>|<fd>
sendto        EVT|<ns>|sendto|<pid>|<fd>|<len>
recvfrom      EVT|<ns>|recvfrom|<pid>|<fd>|<size>

write         EVT|<ns>|write|<pid>|<fd>|<count>
write_ret     EVT|<ns>|write_ret|<pid>|<ret>
close         EVT|<ns>|close|<pid>|<fd>
```

## Parser Mapping Contract

The parser in mantle/capture/ebpf.py maps kind -> normalized `type` as follows:

```text
fork            -> process_spawn
exec            -> command_exec
exit            -> process_exit
openat          -> file_read | file_write (derived from flags)
openat_ret      -> fd_open
unlinkat        -> file_delete
renameat*       -> file_rename
renameat*_ret   -> file_rename_ret
connect         -> net_connect
sendto          -> net_send
recvfrom        -> net_recv
write           -> fd_write
write_ret       -> fd_write_ret
close           -> fd_close
```

## Required Invariants

- `ns`, `pid`, and numeric fields are parsed with integer fallback behavior (`_safe_int`).
- Timestamp conversion to epoch seconds is:
  - `ts = (ns / 1_000_000_000) + time_offset`
- Sequence number (`line_no`) is assigned by parser order, not kernel timestamp order.
- Resolver side effects are allowed at this layer:
  - socket fd -> destination enrichment
  - command line reconstruction from `/proc/<pid>/cmdline`

## Compatibility Notes

- `root` lines are emitted by bpftrace but not converted to JSON events.
- Unknown or malformed kinds are ignored (line dropped).
- `renameat_ret` and `renameat2_ret` map to `file_rename_ret`, which is currently not part of strict ingest-supported types in mantle/capture/events_model.py. Treat this as a cross-layer compatibility risk and update both contracts together when changing rename return behavior.

## Violation Policy

- Any producer change to field order, delimiter, or kind names is a breaking change.
- Breaking changes require:
  - parser update in mantle/capture/ebpf.py
  - ingest validator update in mantle/capture/events_model.py (if event types change)
  - corresponding test updates in tests/unit/test_ebpf_event_parsing.py
