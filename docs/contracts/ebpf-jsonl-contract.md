# Contract: eBPF JSONL Events

Status: active
Version: v1
Owner: mantle/capture/ebpf.py + mantle/capture/events_model.py
Boundary: ebpf parser/writer -> ingest tailer (_tail_ebpf_events)

## Purpose

Define the line-by-line JSON schema written to `.mantle/obs/traces/<trace_id>.ebpf.jsonl` and strictly validated during ingestion.

## File Contract

- Path convention: `.mantle/obs/traces/<trace_id>.ebpf.jsonl`
- Encoding: UTF-8 JSONL
- One JSON object per line
- Writer: `json.dumps(..., ensure_ascii=False)`

## Canonical Base Shape

```json
{
  "ts": 1776182077.3540726,
  "line_no": 25,
  "type": "command_exec",
  "pid": 522158,
  "label": "exec /bin/bash /tmp/tmp55y0k9zd.sh"
}
```

Required base keys (all events):

- `ts`: number (epoch seconds)
- `line_no`: integer sequence number
- `type`: string
- `pid`: integer
- `label`: string (human summary)

## Event Type Schemas

Ingest validator (RawBpfEvent + transform_bpf_record) currently supports the following `type` values:

```text
process_spawn
command_exec
process_exit
file_read
file_write
fd_open
file_delete
file_rename
file_snapshot
fd_write
fd_write_ret
fd_close
net_connect
net_send
net_recv
```

Per-type required fields:

```text
process_spawn  : child_pid:int
command_exec   : exec_path:str
file_read      : path:str (empty string allowed)
file_write     : path:str (empty string allowed)
file_delete    : path:str (empty string allowed)
file_rename    : src:str (empty allowed), path:str (empty allowed)
file_snapshot  : path:str (non-empty)
net_connect    : dest:str
net_send       : dest:str
net_recv       : dest:str
```

Common optional keys by event type (as emitted today):

- `command_exec`: `ppid`, `exec_path`, `argv`, `command`
- `file_read`/`file_write`: `flags`
- `fd_open`: `fd`, optional `path`
- `fd_write`: `fd`, `requested_bytes`, optional `path`
- `fd_write_ret`: `written_bytes`, `ok`, optional `path`
- `fd_close`: `fd`
- `file_snapshot`: `snapshot_phase`, `trigger`, `exists`, `size`, `truncated`, `binary`, `content`
- `net_*`: `fd`, `bytes` (send/recv), `transport`, `family`, `ok`

## Strict Validation Rules

At ingest (`TraceStore._tail_ebpf_events`):

- invalid JSON line -> hard failure (`RuntimeError`)
- non-object JSON value -> hard failure (`RuntimeError`)
- missing required base keys -> hard failure
- unsupported `type` -> hard failure
- malformed required field type -> hard failure

No silent failure policy applies here.

## Producer/Consumer Compatibility

- Producer currently can emit `file_rename_ret` events from rename return probes.
- Consumer strict type set does not currently include `file_rename_ret`.
- Contract rule:
  - either producer MUST stop emitting `file_rename_ret`
  - or consumer type set MUST be updated in the same change
- This mismatch is a breaking contract risk and must be resolved atomically.

## Downstream Transformation Contract

After validation, event is transformed into abstract shape:

```json
{
  "ts": 1776182077.3540726,
  "line_no": 25,
  "type": "command_exec",
  "pid": 522158,
  "source": "bpftrace",
  "label": "exec /bin/bash /tmp/tmp55y0k9zd.sh",
  "payload": {"original": "record"}
}
```

Mapped canonical keys may include `ppid`, `path`, `src`, `dest`, `bytes`, `exec_path`, `command`, `argv`.
