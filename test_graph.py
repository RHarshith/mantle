import asyncio
from mantle.dashboard.app import store, _resolve_paths

async def main():
    trace_dir, events_dir = _resolve_paths()
    print("Trace dir:", trace_dir)
    await store.poll_once()
    print("Traces loaded:", list(store.traces.keys()))
    if "python_20260317_012745.ebpf.jsonl" in store.traces:
        graph = store.high_level_graph("python_20260317_012745.ebpf.jsonl")
        kinds = [n.get("kind") for n in graph.get("nodes", [])]
        print([k for k in kinds if 'tool' in k or 'api' in k])

asyncio.run(main())
