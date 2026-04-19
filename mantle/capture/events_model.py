from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_SUPPORTED_EVENT_TYPES = {
    "process_spawn",
    "command_exec",
    "process_exit",
    "file_read",
    "file_write",
    "fd_open",
    "file_delete",
    "file_rename",
    "file_rename_ret",
    "file_snapshot",
    "fd_write",
    "fd_write_ret",
    "fd_close",
    "net_connect",
    "net_send",
    "net_recv",
}


def _require_int(record: dict[str, Any], key: str) -> int:
    if key not in record:
        raise ValueError(f"missing required key: {key}")
    try:
        return int(record[key])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid integer for key '{key}': {record.get(key)!r}") from exc


def _require_str(record: dict[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = record.get(key)
    if not isinstance(value, str):
        raise ValueError(f"missing or invalid string key: {key}")
    if not allow_empty and not value.strip():
        raise ValueError(f"missing or invalid string key: {key}")
    return value


def _validate_type_requirements(event_type: str, record: dict[str, Any]) -> None:
    if event_type in {"process_spawn"}:
        _require_int(record, "child_pid")
    elif event_type in {"command_exec"}:
        _require_str(record, "exec_path")
    elif event_type in {"file_read", "file_write", "file_delete"}:
        _require_str(record, "path", allow_empty=True)
    elif event_type == "file_rename":
        _require_str(record, "src", allow_empty=True)
        _require_str(record, "path", allow_empty=True)
    elif event_type == "file_rename_ret":
        # Result-only rename events may not include path/src fields.
        return
    elif event_type == "file_snapshot":
        _require_str(record, "path")
    elif event_type in {"net_connect", "net_send", "net_recv"}:
        _require_str(record, "dest")


@dataclass(slots=True)
class RawBpfEvent:
    """Strict representation of a low-level BPF capture event."""

    ts: float
    line_no: int
    event_type: str
    pid: int
    raw_payload: dict[str, Any]

    @classmethod
    def from_record(cls, record: dict[str, Any], fallback_line_no: int) -> "RawBpfEvent":
        event_type = str(record.get("type") or "").strip()
        if not event_type:
            raise ValueError("missing event type")
        if event_type not in _SUPPORTED_EVENT_TYPES:
            raise ValueError(f"unsupported event type: {event_type}")

        if "ts" not in record:
            raise ValueError("missing required key: ts")
        try:
            ts = float(record["ts"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid timestamp: {record.get('ts')!r}") from exc

        pid = _require_int(record, "pid")
        _validate_type_requirements(event_type, record)

        line_no = int(record.get("line_no") or fallback_line_no)
        return cls(
            ts=ts,
            line_no=line_no,
            event_type=event_type,
            pid=pid,
            raw_payload=dict(record),
        )


@dataclass(slots=True)
class AbstractEvent:
    """Capture-agnostic event model consumed by downstream ingestion code."""

    timestamp_s: float
    line_no: int
    event_type: str
    pid: int
    trace_source: str
    label: str
    ppid: int | None = None
    path: str | None = None
    src: str | None = None
    dest: str | None = None
    bytes_count: int | None = None
    exec_path: str | None = None
    command: str | None = None
    argv: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ts": self.timestamp_s,
            "line_no": self.line_no,
            "type": self.event_type,
            "pid": self.pid,
            "source": self.trace_source,
            "label": self.label,
            "payload": self.payload,
        }
        if self.ppid is not None:
            data["ppid"] = self.ppid
        if self.path:
            data["path"] = self.path
        if self.src:
            data["src"] = self.src
        if self.dest:
            data["dest"] = self.dest
        if self.bytes_count is not None:
            data["bytes"] = self.bytes_count
        if self.exec_path:
            data["exec_path"] = self.exec_path
        if self.command:
            data["command"] = self.command
        if self.argv:
            data["argv"] = self.argv
        return data


def transform_bpf_record(record: dict[str, Any], fallback_line_no: int) -> dict[str, Any]:
    """Transform a strict raw BPF event into the domain event shape consumed by pipelines."""
    raw = RawBpfEvent.from_record(record, fallback_line_no=fallback_line_no)

    event = AbstractEvent(
        timestamp_s=raw.ts,
        line_no=raw.line_no,
        event_type=raw.event_type,
        pid=raw.pid,
        trace_source=str(raw.raw_payload.get("source") or "bpftrace"),
        label=str(raw.raw_payload.get("label") or raw.event_type.replace("_", " ")),
        ppid=int(raw.raw_payload.get("ppid")) if raw.raw_payload.get("ppid") is not None else None,
        path=str(raw.raw_payload.get("path")) if raw.raw_payload.get("path") is not None else None,
        src=str(raw.raw_payload.get("src")) if raw.raw_payload.get("src") is not None else None,
        dest=str(raw.raw_payload.get("dest")) if raw.raw_payload.get("dest") is not None else None,
        bytes_count=int(raw.raw_payload.get("bytes")) if raw.raw_payload.get("bytes") is not None else None,
        exec_path=str(raw.raw_payload.get("exec_path")) if raw.raw_payload.get("exec_path") is not None else None,
        command=str(raw.raw_payload.get("command")) if raw.raw_payload.get("command") is not None else None,
        argv=[str(x) for x in (raw.raw_payload.get("argv") or [])],
        payload=raw.raw_payload,
    )
    return event.to_dict()
