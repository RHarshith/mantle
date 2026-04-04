from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class EventSink(Protocol):
    """Contract for emitting structured agent observability events."""
    trace_id: str
    session_id: str

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        ...

    def close(self) -> None:
        ...


class NullEventSink:
    trace_id = "disabled"
    session_id = "disabled"

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        return

    def close(self) -> None:
        return


@dataclass
class JsonlEventSink:
    trace_id: str
    session_id: str
    output_path: Path

    def __post_init__(self) -> None:
        self._seq = 0
        self._lock = threading.Lock()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.output_path.open("a", encoding="utf-8")

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        payload = payload or {}
        with self._lock:
            self._seq += 1
            record = {
                "ts": time.time(),
                "monotonic_ns": time.monotonic_ns(),
                "trace_id": self.trace_id,
                "session_id": self.session_id,
                "seq": self._seq,
                "event_type": event_type,
                "payload": payload,
            }
            self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def build_event_sink() -> EventSink:
    enabled = os.getenv("AGENT_OBS_ENABLED", "1").strip().lower() not in {"0", "false", "off", "no"}
    if not enabled:
        return NullEventSink()

    trace_id = os.getenv("AGENT_TRACE_ID", "").strip()
    if not trace_id:
        trace_id = f"trace-{int(time.time())}-{os.getpid()}"

    session_id = str(uuid.uuid4())

    root = os.getenv("AGENT_OBS_ROOT", "~/shared/mantle/obs").strip()
    root_path = Path(root).expanduser()

    output_path = root_path / "events" / f"{trace_id}.events.jsonl"
    return JsonlEventSink(trace_id=trace_id, session_id=session_id, output_path=output_path)
