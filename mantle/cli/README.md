# Mantle CLI

The CLI provides a terminal-first way to inspect observability traces.

## Modes

- Interactive: `mantle cli --interactive` or `mantlecli --interactive`
- Non-interactive route mode: `mantlecli <route>`

## Common Routes

- `traces`
- `<trace_id>/trace`
- `<trace_id>/trace/<turn_id>/summary`
- `<trace_id>/trace/<turn_id>/timeline/<index>`
- `<trace_id>/replay`
- `<trace_id>/replay/<turn_id>/summary`
- `<trace_id>/replay/<turn_id>/context/<section_id>/<message_index>`
- `<trace_id>/replay/<turn_id>/action/<section_id>/<message_index>`

Run `mantlecli help` for full route list.
