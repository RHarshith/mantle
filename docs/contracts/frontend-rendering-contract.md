# Contract: Frontend Rendering Behavior

Status: active
Version: v1
Owner: mantle/server/static/app.js + mantle/server/static/index.html
Boundary: API payloads -> visible dashboard state

## Purpose

Define exactly what the frontend must render, what it must not render, and which payload keys are required for stable behavior.

## Primary Runtime Modes

- Overview mode (no selected trace):
  - process-grouped trace list
  - correctness/safety/efficiency summary cards
- Replay mode (selected trace):
  - replay turn list
  - replay detail pane (Context / Action / Summary)
  - state diff explorer

## Trace List Contract

Required `GET /api/traces` fields per trace row:

- `trace_id`
- `status` (`active` or `completed`)
- `agent_event_count`
- `sys_event_count`

UI behavior:

- every trace row shows trace id and status badge
- traces are grouped by process buckets stored in localStorage
- delete button calls `DELETE /api/traces/{trace_id}`

## Replay Overview Contract

Required from `GET /api/traces/{trace_id}/replay-turns`:

- top-level: `trace_id`, `turns[]`
- per turn item:
  - `turn_id`, `label`, `tool_call_count`, `context_section_count`, `action_section_count`

Rendered output:

- left panel turn button text:
  - title: `label || turn_id`
  - metadata: `ctx <count> · act <count>`
  - tools badge: `<tool_call_count> tools`

## Replay Turn Detail Contract

Required from `GET /api/traces/{trace_id}/replay-turns/{turn_id}`:

- `context.sections[]`
- `action.sections[]`
- `summary`
- `tool_call_response_pairs[]`

Replay detail tabs must include:

- `Context`
- `Action`
- `Summary`
- `Raw Events`

### Context tab

Render rules:

- render all `context.sections` as expandable cards
- each card header: `section.label` and value count
- values rendered as text pre blocks (JSON pretty-print for non-strings)
- default card state: open

Source rules:

- source links are shown only for sections with `style == "tool_output"`
- preferred source for each value:
  - `section.sources[idx]` if provided
  - fallback source inference by tool_call_id/result text maps
- source display text:
  - matched pid: `source: pid<id>` as clickable button
  - missing source: `source: not found` as non-clickable text

### Action tab

Render rules:

- filter out generic action section where `id == "tool_calls"` (not shown as normal section card)
- render remaining action sections as cards
- render dedicated tool response cards from `tool_call_response_pairs`

Each tool pair card must show:

- tool name and tool_call_id
- arguments JSON
- response preview (truncated, expandable)
- source link if `source.pid > 0`, else source missing text

### Summary tab

Render from `summary` keys:

- `tool_calls`
- `context_tokens`
- `files_read`, `files_written`
- `subprocesses_spawned`
- `network_calls`
- `context_sections`, `action_sections`

Interactive summary metric behavior:

- `tool_calls` click -> modal listing `summary.tool_call_pairs`
- `files_rw` click -> modal tree from `summary.file_activity.tree`
- `subprocesses` click -> modal list from `summary.subprocesses`

### Raw Events tab

Render contract:

- uses unified renderer `display_trace(pid=None, start_timestamp=None, end_timestamp=None)`
- initial call uses selected replay turn `[start_ts, end_ts]` with `pid=None`
- includes a compact/detailed switch for trace rows
- default mode is compact (`Detailed: Off`)
- compact mode hides event types from a configurable hidden-event list (default: `fd_open`, `fd_close`, `fd_write`, `fd_write_ret`)
- hidden-event list is editable from the UI and persisted in browser localStorage
- consecutive file-system groups in the same process scope are coalesced into a single folder tree row
- each rendered timeline row exposes a `Debug Info` button that opens a formatted JSON popup for that rendered event payload
- show direct-vs-nested syscall metrics for files/network/spawns
- process groups list child pids as recursive drilldown actions
- clicking child pid re-calls `display_trace` with same timestamp window and `pid=<child>`
- back navigation restores previous pid scope without changing turn selection

## Source Process Popup Contract

Clicking source pid buttons calls:

- `GET /api/traces/{trace_id}/display-trace?pid=<pid>[&start_timestamp=<ts>&end_timestamp=<ts>]`

Popup must show:

- process id, parent, lifecycle mode
- grouped timeline rows for process/file/network activity
- recursive child-pid drilldown via the same renderer function
- the same compact/detailed switch and hidden-event filtering behavior as Raw Events tab

## State Diff Contract

State diff entry point:

- replay left panel button `View state diff`

Required payloads:

- `GET /api/traces/{trace_id}/replay-state-diff`
- `GET /api/traces/{trace_id}/replay-state-diff/file`

Rendered behavior:

- left pane:
  - turn-range selectors (`from`, `to`)
  - files tree with file stats
- right pane:
  - unified diff for selected file
  - stats pills (`+added`, `-removed`, `delta`)

Selection behavior:

- on load, auto-select first file when available
- changing range resets selected file and reloads tree

## Visibility / Hidden Constraints

- Do not render replay source links for non-tool-output values.
- Do not show generic `tool_calls` action section card.
- Do not leave replay pane blank when no sections:
  - show explicit empty-state text
- Do not drop assistant final text when missing from action sections:
  - backend injects fallback `assistant_text` section and frontend must display it

## Breakage Conditions

These are frontend-breaking API changes unless UI is updated in same change:

- rename/removal of `context.sections`, `action.sections`, or `summary` keys
- change to `tool_call_response_pairs` shape
- change to source object shape (`status`, `pid`)
- change to state diff `tree`/`files`/`diff` keys
