"""Canonical exception hierarchy for Mantle.

All modules should raise from these types instead of bare KeyError/RuntimeError.
This gives callers a stable contract for error handling and prevents ad-hoc
exception types from proliferating.
"""

from __future__ import annotations


class MantleError(Exception):
    """Base class for all Mantle-specific errors."""


class TraceNotFoundError(MantleError, KeyError):
    """Raised when a trace_id does not exist in the store.

    Inherits from KeyError for backward compatibility with existing handlers
    that catch KeyError (e.g. FastAPI route handlers in app.py).
    """

    def __init__(self, trace_id: str) -> None:
        self.trace_id = trace_id
        super().__init__(trace_id)


class TurnNotFoundError(MantleError, KeyError):
    """Raised when a turn_id does not exist within a trace."""

    def __init__(self, trace_id: str, turn_id: str) -> None:
        self.trace_id = trace_id
        self.turn_id = turn_id
        super().__init__(f"{trace_id}/{turn_id}")


class ParseError(MantleError):
    """Raised when trace data, MITM logs, or EBPF output cannot be parsed."""


class CaptureError(MantleError):
    """Raised when a capture backend (eBPF, MITM) fails to start or run."""


# ── Shared Logging ───────────────────────────────────────────────

import logging

LOGGER = logging.getLogger("mantle")


def log_exception(message: str) -> None:
    """Log the active exception with stack trace using the mantle logger."""
    LOGGER.exception(message)
