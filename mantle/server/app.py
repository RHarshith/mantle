"""FastAPI entrypoint for mantle dashboard HTTP/WebSocket interfaces."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any
import uuid

from fastapi import Body, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from mantle.ingest.config import resolve_observability_paths
from mantle.errors import log_exception
from mantle.ingest.store import TraceStore
from mantle.runtime.bootstrap import bootstrap_runtime
from mantle.runtime.logging import bind_correlation, get_component_logger


app = FastAPI(title="Agent System Observability Dashboard")

_RUNTIME_ENV, _RUNTIME_LAYOUT = bootstrap_runtime("server")
SERVER_LOGGER = get_component_logger("server", layout=_RUNTIME_LAYOUT)
FRONTEND_LOGGER = get_component_logger("frontend", layout=_RUNTIME_LAYOUT)


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
_DEFAULT_PROXY_DIR = _RUNTIME_LAYOUT.proxy_obs_dir
LLM_CAPTURE_SOURCE = str(os.getenv("MANTLE_LLM_CAPTURE_SOURCE", "proxy")).strip().lower() or "proxy"
PROXY_DIR = _DEFAULT_PROXY_DIR
PROXY_LOG_FILE = None

store = TraceStore(
	trace_dir=WATCH_DIR,
	events_dir=EVENTS_DIR,
	proxy_dir=PROXY_DIR,
	llm_capture_source=LLM_CAPTURE_SOURCE,
	proxy_log_file=PROXY_LOG_FILE,
)

SERVER_LOGGER.info(
	"server runtime initialized",
	extra={
		"watch_dir": str(WATCH_DIR),
		"events_dir": str(EVENTS_DIR),
		"proxy_dir": str(PROXY_DIR) if PROXY_DIR else "",
		"logs_root": str(_RUNTIME_LAYOUT.logs_root),
	},
)

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
				bind_correlation(correlation_id=str(uuid.uuid4()))
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


# ── Process lifecycle ──────────────────────────────────────────────

@app.post("/api/processes")
def create_process(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
	"""Create a named process grouping (idempotent)."""
	name = str(payload.get("name") or "").strip()
	if not name:
		raise HTTPException(status_code=400, detail="name is required")
	return store.create_process(name)


@app.get("/api/processes")
def list_processes() -> dict[str, Any]:
	"""Return all processes."""
	return {"processes": store.list_processes()}


@app.delete("/api/processes/{process_name}")
def delete_process(process_name: str) -> dict[str, Any]:
	"""Delete a process."""
	store.delete_process(process_name)
	return {"ok": True}


@app.post("/api/processes/{process_name}/traces")
def assign_trace_to_process(
	process_name: str,
	payload: dict[str, Any] = Body(default={}),
) -> dict[str, Any]:
	"""Register / assign a trace to a process."""
	trace_id = str(payload.get("trace_id") or "").strip()
	if not trace_id:
		raise HTTPException(status_code=400, detail="trace_id is required")
	# Ensure process exists (idempotent) and trace row exists, then explicitly assign.
	store.create_process(process_name)
	store.sqlite_store.register_trace(trace_id=trace_id, file_name=trace_id)
	store.assign_trace_to_process(trace_id, process_name)
	return {"ok": True, "trace_id": trace_id, "process_name": process_name}


@app.post("/api/traces/{trace_id}/set-guide")
def set_guide_trace(trace_id: str) -> dict[str, Any]:
	"""Mark a trace as the guide for its process."""
	info = store.sqlite_store.get_trace_info(trace_id)
	if info is None:
		raise HTTPException(status_code=404, detail="Trace not registered")
	process_name = info.get("process_name")
	if not process_name:
		raise HTTPException(
			status_code=400,
			detail="Trace is not assigned to a process",
		)
	store.set_guide_trace(process_name, trace_id)
	return {"ok": True, "guide_trace_id": trace_id, "process_name": process_name}


@app.get("/api/traces/{trace_id}/reward-status")
def reward_status(trace_id: str) -> dict[str, Any]:
	"""Compute and return reward status for a trace against its process guide."""
	from mantle.reward.engine import compute_reward_status
	info = store.sqlite_store.get_trace_info(trace_id)
	if info is None:
		raise HTTPException(status_code=404, detail="Trace not registered")
	process_name = info.get("process_name")
	if not process_name:
		return {"error": "trace_not_in_process", "progress": 0, "satisfied": [], "pending": []}
	guide_trace_id = store.get_guide_trace(process_name)
	if not guide_trace_id:
		return {"error": "no_guide_trace", "progress": 0, "satisfied": [], "pending": []}
	if guide_trace_id == trace_id:
		return {"error": "trace_is_guide", "progress": 1.0, "satisfied": [], "pending": []}
	return compute_reward_status(
		guide_trace_id=guide_trace_id,
		active_trace_id=trace_id,
		process_name=process_name,
		sqlite_store=store.sqlite_store,
	)


@app.get("/api/config")
def config() -> dict[str, Any]:
	"""Expose effective dashboard backend configuration."""
	return {
		"watch_dir": str(WATCH_DIR),
		"events_dir": str(EVENTS_DIR),
		"runtime_logs_root": str(_RUNTIME_LAYOUT.runtime_root),
		"trace_count": len(store.traces),
	}


@app.post("/api/frontend-log")
def frontend_log(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
	"""Persist browser runtime errors into frontend runtime logs."""
	correlation_id = str(payload.get("correlation_id") or uuid.uuid4())
	bind_correlation(correlation_id=correlation_id, request_id=str(payload.get("request_id") or ""))
	message = str(payload.get("message") or "frontend runtime event")
	level = str(payload.get("level") or "error").strip().lower()
	if level == "warning":
		FRONTEND_LOGGER.warning(message, extra={"frontend_payload": payload})
	else:
		FRONTEND_LOGGER.error(message, extra={"frontend_payload": payload})
	return {"ok": True, "correlation_id": correlation_id}


@app.get("/api/settings/llm-schemas")
def get_llm_schemas() -> dict[str, Any]:
	"""Return configured LLM schema parsing rules."""
	return store.list_llm_api_schemas()


@app.post("/api/settings/llm-schemas")
def set_llm_schemas(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
	"""Update LLM schema parsing rules used for proxy-capture interpretation."""
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


@app.get("/api/traces/{trace_id}/turns/{turn_id}/raw-events")
def turn_raw_events(trace_id: str, turn_id: str) -> dict[str, Any]:
	"""Return raw capture events in the selected turn timestamp range."""
	try:
		return store.raw_events_for_turn(trace_id, turn_id)
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


@app.get("/api/traces/{trace_id}/display-trace")
def display_trace(
	trace_id: str,
	pid: int | None = None,
	start_timestamp: float | None = None,
	end_timestamp: float | None = None,
) -> dict[str, Any]:
	"""Return a unified event-view payload scoped by optional pid and timestamp window."""
	try:
		return store.display_trace(
			trace_id,
			pid=pid,
			start_timestamp=start_timestamp,
			end_timestamp=end_timestamp,
		)
	except KeyError:
		raise HTTPException(status_code=404, detail="Trace or pid not found")


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


@app.get("/api/traces/{trace_id}/capture-quality")
def trace_capture_quality(trace_id: str) -> dict[str, Any]:
	"""Return tiered capture confidence metadata for a trace."""
	try:
		return store.trace_capture_quality(trace_id)
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

