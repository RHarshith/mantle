"""Shared logging helpers for dashboard runtime error handling."""

from __future__ import annotations

import logging


LOGGER = logging.getLogger("mantle.dashboard")


def log_exception(message: str) -> None:
    """Log the active exception with stack trace using dashboard logger."""
    LOGGER.exception(message)
