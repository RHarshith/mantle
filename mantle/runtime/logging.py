"""Structured runtime logging helpers for Mantle components."""

from __future__ import annotations

import contextvars
from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from .paths import RuntimeLayout, ensure_runtime_layout, resolve_runtime_layout


CORRELATION_ID = contextvars.ContextVar("mantle_correlation_id", default="")
TRACE_ID = contextvars.ContextVar("mantle_trace_id", default="")
REQUEST_ID = contextvars.ContextVar("mantle_request_id", default="")


class JsonLogFormatter(logging.Formatter):
    """Emit structured JSON logs with consistent fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "component": getattr(record, "component", "unknown"),
        }

        correlation_id = CORRELATION_ID.get()
        trace_id = TRACE_ID.get()
        request_id = REQUEST_ID.get()
        if correlation_id:
            payload["correlation_id"] = correlation_id
        if trace_id:
            payload["trace_id"] = trace_id
        if request_id:
            payload["request_id"] = request_id

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True)


def bind_correlation(correlation_id: str | None = None, trace_id: str | None = None, request_id: str | None = None) -> None:
    """Bind correlation fields for subsequent log records in this context."""
    if correlation_id is not None:
        CORRELATION_ID.set(str(correlation_id))
    if trace_id is not None:
        TRACE_ID.set(str(trace_id))
    if request_id is not None:
        REQUEST_ID.set(str(request_id))


def _handler_for_file(path: Path, formatter: logging.Formatter) -> logging.Handler:
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(formatter)
    return handler


def _stream_handler(formatter: logging.Formatter) -> logging.Handler:
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    return handler


def get_component_logger(component: str, layout: RuntimeLayout | None = None, level: str | None = None) -> logging.LoggerAdapter:
    """Return a component logger writing to runtime/<component>/runtime.log."""
    resolved_layout = resolve_runtime_layout() if layout is None else layout
    ensure_runtime_layout(resolved_layout, require_writable=True)
    if component not in resolved_layout.runtime_dirs:
        component_dir = resolved_layout.runtime_root / component
        component_dir.mkdir(parents=True, exist_ok=True)
    else:
        component_dir = resolved_layout.runtime_dirs[component]

    logger = logging.getLogger(f"mantle.{component}")
    logger.setLevel(getattr(logging, (level or "INFO").upper(), logging.INFO))
    logger.propagate = False

    formatter = JsonLogFormatter()
    log_path = component_dir / "runtime.log"
    existing_files = {
        getattr(handler, "baseFilename", "")
        for handler in logger.handlers
        if isinstance(handler, logging.FileHandler)
    }
    if str(log_path) not in existing_files:
        logger.addHandler(_handler_for_file(log_path, formatter))
    if not any(isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler) for handler in logger.handlers):
        logger.addHandler(_stream_handler(formatter))

    return logging.LoggerAdapter(logger, {"component": component})


def configure_root_logger(component: str, layout: RuntimeLayout | None = None, level: str | None = None) -> logging.Logger:
    """Configure mantle root logger to mirror logs into the selected component file."""
    resolved_layout = resolve_runtime_layout() if layout is None else layout
    logger_adapter = get_component_logger(component=component, layout=resolved_layout, level=level)
    component_logger = logger_adapter.logger  # type: ignore[attr-defined]
    mantle_root = logging.getLogger("mantle")
    mantle_root.handlers = component_logger.handlers[:]
    mantle_root.setLevel(component_logger.level)
    mantle_root.propagate = False
    return mantle_root
