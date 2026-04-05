"""Interface contracts for capture backends.

These protocols define stable contracts so the Python server can keep using
`mantle.capture` while backend implementations move to Rust.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class EbpfCaptureEngine(Protocol):
    """Run command execution tracing and write JSONL trace events."""

    def run_capture(self, output_file: Path, command: list[str]) -> int:
        ...


class MitmRecordEngine(Protocol):
    """Build request/response capture records from network flow metadata."""

    def build_record(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        ...
