"""FastAPI entrypoint for mantle dashboard HTTP/WebSocket interfaces."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from mantle.ingest.config import resolve_observability_paths
from mantle.errors import log_exception
from mantle.ingest.store import TraceStore


app = FastAPI(title="Agent System Observability Dashboard")


@app.middleware("http")
async def disable_frontend_cache(request: Request, call_next):
	"""Disable browser caching for root and static assets during active development."""
	response = await call_next(request)
	path = request.url.path
	if path == "/" or path.startswith("/static/"):
		response.headers["Cache-Control"] = "no-store, max-age=0"
		response.headers["Pragma"] = "no-cache"
		response.headers["Expires"] = "0"
	return response


def _resolve_paths() -> tuple[Path, Path]:
	"""Resolve trace and events directories for dashboard runtime."""
	return resolve_observability_paths()


WATCH_DIR, EVENTS_DIR = _resolve_paths()
MITM_DIR = WATCH_DIR.parent / "mitm" if WATCH_DIR else None

store = TraceStore(trace_dir=WATCH_DIR, events_dir=EVENTS_DIR, mitm_dir=MITM_DIR)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
async def startup() -> None:
	"""Start background trace polling loop."""
	stop_event = asyncio.Event()
	app.state.poll_stop_event = stop_event

	async def _poll_loop() -> None:
		while not stop_event.is_set():
			try:
				await store.poll_once()
			except asyncio.CancelledError:
				raise
			except Exception:
				log_exception("Dashboard poll loop failed")

			try:
				await asyncio.wait_for(stop_event.wait(), timeout=1.0)
			except asyncio.TimeoutError:
				continue

	app.state.poll_task = asyncio.create_task(_poll_loop(), name="mantle-dashboard-poll")


@app.on_event("shutdown")
async def shutdown() -> None:
	"""Stop background polling task gracefully."""
	stop_event = getattr(app.state, "poll_stop_event", None)
	poll_task = getattr(app.state, "poll_task", None)

	if stop_event is not None:
		stop_event.set()

	if poll_task is not None and not poll_task.done():
		poll_task.cancel()
		try:
			await poll_task
		except asyncio.CancelledError:
			pass


@app.get("/")
def index() -> FileResponse:
	"""Serve the dashboard SPA entrypoint."""
	return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/traces")
def list_traces() -> dict[str, Any]:
	"""Return available trace metadata and current store version."""
	return {"traces": store.list_traces(), "version": store.version}


@app.delete("/api/traces/{trace_id}")
async def delete_trace(trace_id: str) -> dict[str, Any]:
	"""Delete a trace and all associated files by id."""
	try:
		return await store.delete_trace(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/config")
def config() -> dict[str, Any]:
	"""Expose effective dashboard backend configuration."""
	return {
		"watch_dir": str(WATCH_DIR),
		"events_dir": str(EVENTS_DIR),
		"trace_count": len(store.traces),
	}


@app.get("/api/settings/llm-schemas")
def get_llm_schemas() -> dict[str, Any]:
	"""Return configured LLM schema parsing rules."""
	return store.list_llm_api_schemas()


@app.post("/api/settings/llm-schemas")
def set_llm_schemas(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
	"""Update LLM schema parsing rules used for MITM trace interpretation."""
	schemas = payload.get("schemas") if isinstance(payload, dict) else []
	if not isinstance(schemas, list):
		raise HTTPException(status_code=400, detail="schemas must be a list")
	return store.set_llm_api_schemas(schemas)


@app.get("/api/traces/{trace_id}/high-level-graph")
def high_level_graph(trace_id: str) -> dict[str, Any]:
	"""Build high-level trace graph for a specific trace id."""
	try:
		return store.high_level_graph(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/turns")
def turns_overview(trace_id: str) -> dict[str, Any]:
	"""Return conversation/tool turns summary for a trace."""
	try:
		return store.turns_overview(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/replay-turns")
def replay_turns_overview(trace_id: str) -> dict[str, Any]:
	"""Return replay-oriented turn list for debugger-style trace playback."""
	try:
		return store.replay_turns_overview(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/turns/{turn_id}")
def turn_detail(trace_id: str, turn_id: str) -> dict[str, Any]:
	"""Return detailed timeline/context for a single turn."""
	try:
		return store.turn_detail(trace_id, turn_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace turn not found")


@app.get("/api/traces/{trace_id}/replay-turns/{turn_id}")
def replay_turn_detail(trace_id: str, turn_id: str) -> dict[str, Any]:
	"""Return structured context/action panes for one replay turn."""
	try:
		return store.replay_turn_detail(trace_id, turn_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace turn not found")


@app.get("/api/traces/{trace_id}/replay-state-diff")
def replay_state_diff(trace_id: str, from_turn_id: str | None = None, to_turn_id: str | None = None) -> dict[str, Any]:
	"""Return folder-tree state diff summary between two selected replay turns."""
	try:
		return store.replay_state_diff(trace_id, from_turn_id=from_turn_id, to_turn_id=to_turn_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/replay-state-diff/file")
def replay_state_diff_file(trace_id: str, path: str, from_turn_id: str | None = None, to_turn_id: str | None = None) -> dict[str, Any]:
	"""Return unified diff for one file between two selected replay turns."""
	if not path:
		raise HTTPException(status_code=400, detail="path is required")
	try:
		return store.replay_state_diff_file(trace_id, path=path, from_turn_id=from_turn_id, to_turn_id=to_turn_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace or file diff not found")


@app.get("/api/traces/{trace_id}/process-subtrace/{turn_id}/{pid}")
def process_subtrace(trace_id: str, turn_id: str, pid: int, full_lifecycle: bool = False) -> dict[str, Any]:
	"""Return a focused sub-trace for one process within a turn."""
	try:
		return store.process_subtrace(trace_id, turn_id, pid, full_lifecycle=full_lifecycle)
	except KeyError:
		raise HTTPException(status_code=404, detail="Process sub-trace not found")


@app.get("/api/traces/{trace_id}/raw-resource-events")
def raw_resource_events(trace_id: str, turn_id: str, resource_type: str, resource_key: str) -> dict[str, Any]:
	"""Return raw syscall events for a specific file or network resource."""
	if resource_type not in {"file", "network"}:
		raise HTTPException(status_code=400, detail="resource_type must be 'file' or 'network'")
	try:
		return store.raw_resource_events(trace_id, turn_id, resource_type, resource_key)
	except KeyError:
		raise HTTPException(status_code=404, detail="Resource events not found")


@app.get("/api/traces/{trace_id}/process-graph/{pid}")
def process_graph(trace_id: str, pid: int) -> dict[str, Any]:
	"""Build process-centric graph view rooted at a pid."""
	try:
		return store.process_graph(trace_id, pid)
	except KeyError as exc:
		# Only treat missing trace-id lookups as 404. Other KeyErrors are
		# internal issues and should not be masked as "trace not found".
		if exc.args and str(exc.args[0]) == trace_id:
			raise HTTPException(status_code=404, detail="trace not found")
		raise HTTPException(status_code=500, detail="process graph build failed")


@app.get("/api/traces/{trace_id}/internal-graph/{line_start}/{line_end}")
def internal_graph(trace_id: str, line_start: int, line_end: int) -> dict[str, Any]:
	"""Build internal graph for a selected syscall line range."""
	try:
		return store.internal_graph(trace_id, line_start, line_end)
	except KeyError:
		raise HTTPException(status_code=404, detail="trace not found")


@app.get("/api/traces/{trace_id}/tool-graph/{tool_call_id}")
def tool_graph(trace_id: str, tool_call_id: str) -> dict[str, Any]:
	"""Build tool-call-centric graph for a specific tool invocation."""
	try:
		return store.tool_graph(trace_id, tool_call_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace or tool call not found")


@app.get("/api/traces/{trace_id}/summary")
def trace_summary(trace_id: str) -> dict[str, Any]:
	"""Return summary metrics and grouped behavior for a trace."""
	try:
		return store.trace_summary(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/traces/{trace_id}/dimension-metrics")
def trace_dimension_metrics(trace_id: str) -> dict[str, Any]:
	"""Return correctness/safety/efficiency heuristic metrics for one trace."""
	try:
		return store.trace_dimension_metrics(trace_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace not found")


@app.get("/api/dimensions/metrics")
def all_dimension_metrics() -> dict[str, Any]:
	"""Return dimension metrics for all traces."""
	return store.all_trace_dimension_metrics()


@app.get("/api/traces/{trace_id}/tool-summary/{tool_call_id}")
def tool_summary(trace_id: str, tool_call_id: str) -> dict[str, Any]:
	"""Return summarized insights for one tool call."""
	try:
		return store.tool_summary(trace_id, tool_call_id)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace or tool call not found")


@app.websocket("/ws")
async def ws_updates(websocket: WebSocket) -> None:
	"""Push store version updates to connected websocket clients."""
	await websocket.accept()
	last_version = -1
	try:
		while True:
			version = store.version
			if version != last_version:
				await websocket.send_json({"type": "version", "version": version})
				last_version = version
			await asyncio.sleep(1.0)
	except WebSocketDisconnect:
		return

