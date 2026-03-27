# Mantle CLI

The CLI provides a terminal-first way to inspect observability traces.

## Modes

- Interactive: `mantle cli --interactive` or `mantlecli --interactive`
- Non-interactive route mode: `mantlecli <route>`

## Common Routes

- `traces`
- `<trace_id>/summary`
- `<trace_id>/summary/metric/<metric_name>`
- `<trace_id>/replay`
- `<trace_id>/replay/<turn_id>/summary`
- `<trace_id>/replay/<turn_id>/summary/metric/<metric_name>`
- `<trace_id>/replay/<turn_id>/context/<section_id>/<message_index>`
- `<trace_id>/replay/<turn_id>/action/<section_id>/<message_index>`
- `<trace_id>/replay/<turn_id>/files`
- `<trace_id>/replay/<turn_id>/files/node/<node_id>`
- `<trace_id>/replay/<turn_id>/pids`
- `<trace_id>/replay/<turn_id>/pids/<pid>`
- `objects/files`
- `objects/files/node/<node_id>`
- `objects/files/trace/<trace_id>`
- `objects/files/trace/<trace_id>/node/<node_id>`
- `objects/files/trace/<trace_id>/turn/<turn_id>`
- `objects/files/trace/<trace_id>/turn/<turn_id>/node/<node_id>`
- `objects/pids`
- `objects/pids/trace/<trace_id>`
- `objects/pids/<pid>`

Summary routes only show compact metrics. Use metric and folder-node routes to drill down incrementally.

Run `mantlecli help` for full route list.
