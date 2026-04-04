"""Server logging utilities.

Re-exports log_exception from mantle.errors for backward compatibility.
"""

from mantle.errors import LOGGER, log_exception  # noqa: F401

__all__ = ["LOGGER", "log_exception"]
