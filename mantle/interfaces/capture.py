"""Protocol for capture backends (eBPF, future alternatives).

Abstracts the syscall/network tracing layer so the implementation language
can be swapped without changing consumers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ICapture(Protocol):
    """Contract for system-level capture backends."""

    def run_capture(self, output_file: Path, command: list[str]) -> int:
        """Run a command under observation, writing events to output_file.

        Returns the exit code of the traced command.
        """
        ...

    def event_from_line(
        self,
        raw: str,
        seq: int,
        cmdline_cache: dict[int, str],
        socket_cache: dict[tuple[int, int], dict[str, Any]],
        time_offset: float,
    ) -> dict[str, Any] | None:
        """Parse a single raw trace line into a structured event dict.

        Returns None if the line is not a recognized event.
        """
        ...
