from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class SQLiteTraceStore:
    """Persists raw events plus semantic overlays into a local SQLite database."""

    def __init__(self, db_path: Path, schema_path: Path):
        self.db_path = db_path
        self.schema_path = schema_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        schema_sql = self.schema_path.read_text(encoding="utf-8")
        with self._connect() as conn:
            try:
                conn.executescript(schema_sql)
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if "no such column" in message and "event_kind" in message:
                    self._recreate_event_table(conn)
                    conn.executescript(schema_sql)
                else:
                    raise
            self._ensure_event_schema(conn)

    def _recreate_event_table(self, conn: sqlite3.Connection) -> None:
        conn.execute("DROP TABLE IF EXISTS event")

    def _ensure_event_schema(self, conn: sqlite3.Connection) -> None:
        required_columns = {
            "id",
            "trace_id",
            "timestamp_ns",
            "source",
            "event_kind",
            "event_type",
            "line_no",
            "pid",
            "ppid",
            "child_pid",
            "path",
            "src",
            "dest",
            "bytes_count",
            "exec_path",
            "command",
            "argv_json",
            "label",
            "payload",
        }
        cols = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(event)")
        }
        if required_columns.issubset(cols):
            return

        # Event rows are a derived cache from JSONL traces. Recreate when schema
        # shape changes so downstream readers always see canonical columns.
        conn.execute("DROP TABLE IF EXISTS event")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS event (
                id INTEGER PRIMARY KEY,
                trace_id TEXT NOT NULL,
                timestamp_ns BIGINT NOT NULL,
                source TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                event_type TEXT NOT NULL,
                line_no INTEGER,
                pid INTEGER,
                ppid INTEGER,
                child_pid INTEGER,
                path TEXT,
                src TEXT,
                dest TEXT,
                bytes_count BIGINT,
                exec_path TEXT,
                command TEXT,
                argv_json JSON,
                label TEXT,
                payload JSON NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_trace_id ON event(trace_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_trace_time ON event(trace_id, timestamp_ns)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_trace_kind_type ON event(trace_id, event_kind, event_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_trace_path ON event(trace_id, path)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_event_trace_pid ON event(trace_id, pid)")

    @staticmethod
    def _ts_ns(value: Any) -> int:
        try:
            return int(float(value) * 1_000_000_000)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _int_or_none(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _string_or_none(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        if not text:
            return None
        return text

    @staticmethod
    def _extract_extra_payload(
        event: dict[str, Any],
        *,
        mapped_keys: set[str],
    ) -> dict[str, Any]:
        raw_payload = event.get("payload")
        extras: dict[str, Any]
        if isinstance(raw_payload, dict):
            extras = dict(raw_payload)
        else:
            extras = {}
            if raw_payload not in (None, "", [], {}):
                extras["_payload"] = raw_payload

        for key in mapped_keys:
            extras.pop(key, None)
        return extras

    @staticmethod
    def _turn_seq(turn: dict[str, Any], fallback: int) -> int:
        raw = turn.get("index")
        if isinstance(raw, int):
            return raw
        turn_id = str(turn.get("turn_id") or "")
        if turn_id.startswith("turn_"):
            try:
                return int(turn_id.split("_", 1)[1])
            except ValueError:
                pass
        return fallback

    def replace_trace_payload(
        self,
        *,
        trace_id: str,
        sys_events: list[dict[str, Any]],
        agent_events: list[dict[str, Any]],
        turns: list[dict[str, Any]],
    ) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM tool_calls WHERE trace_id = ?", (trace_id,))
            conn.execute("DELETE FROM turns WHERE trace_id = ?", (trace_id,))
            conn.execute("DELETE FROM event WHERE trace_id = ?", (trace_id,))

            for event in sys_events:
                ts_ns = self._ts_ns(event.get("ts"))
                source = str(event.get("source") or "bpftrace")
                event_type = str(event.get("type") or "unknown")
                line_no = self._int_or_none(event.get("line_no"))
                pid = self._int_or_none(event.get("pid"))
                ppid = self._int_or_none(event.get("ppid"))
                child_pid = self._int_or_none(event.get("child_pid"))
                path = self._string_or_none(event.get("path"))
                src = self._string_or_none(event.get("src"))
                dest = self._string_or_none(event.get("dest"))
                bytes_count = self._int_or_none(event.get("bytes"))
                exec_path = self._string_or_none(event.get("exec_path"))
                command = self._string_or_none(event.get("command"))
                argv = event.get("argv") if isinstance(event.get("argv"), list) else []
                label = self._string_or_none(event.get("label"))
                extras = self._extract_extra_payload(
                    event,
                    mapped_keys={
                        "ts",
                        "line_no",
                        "type",
                        "pid",
                        "source",
                        "label",
                        "ppid",
                        "child_pid",
                        "path",
                        "src",
                        "dest",
                        "bytes",
                        "exec_path",
                        "command",
                        "argv",
                    },
                )
                conn.execute(
                    """
                    INSERT INTO event(
                        trace_id, timestamp_ns, source, event_kind, event_type,
                        line_no, pid, ppid, child_pid,
                        path, src, dest, bytes_count,
                        exec_path, command, argv_json, label, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trace_id,
                        ts_ns,
                        source,
                        "sys",
                        event_type,
                        line_no,
                        pid,
                        ppid,
                        child_pid,
                        path,
                        src,
                        dest,
                        bytes_count,
                        exec_path,
                        command,
                        self._json(argv),
                        label,
                        self._json(extras),
                    ),
                )

            for event in agent_events:
                ts_ns = self._ts_ns(event.get("ts"))
                source = str(event.get("_source") or event.get("source") or "mitmproxy")
                event_type = str(event.get("event_type") or event.get("type") or "agent_event")
                line_no = self._int_or_none(event.get("line_no"))
                pid = self._int_or_none(event.get("pid"))
                ppid = self._int_or_none(event.get("ppid"))
                child_pid = self._int_or_none(event.get("child_pid"))
                path = self._string_or_none(event.get("path"))
                src = self._string_or_none(event.get("src"))
                dest = self._string_or_none(event.get("dest"))
                bytes_count = self._int_or_none(event.get("bytes"))
                exec_path = self._string_or_none(event.get("exec_path"))
                command = self._string_or_none(event.get("command"))
                argv = event.get("argv") if isinstance(event.get("argv"), list) else []
                label = self._string_or_none(event.get("label"))
                conn.execute(
                    """
                    INSERT INTO event(
                        trace_id, timestamp_ns, source, event_kind, event_type,
                        line_no, pid, ppid, child_pid,
                        path, src, dest, bytes_count,
                        exec_path, command, argv_json, label, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trace_id,
                        ts_ns,
                        source,
                        "agent",
                        event_type,
                        line_no,
                        pid,
                        ppid,
                        child_pid,
                        path,
                        src,
                        dest,
                        bytes_count,
                        exec_path,
                        command,
                        self._json(argv),
                        label,
                        self._json(event),
                    ),
                )

            for i, turn in enumerate(turns, start=1):
                turn_seq = self._turn_seq(turn, fallback=i)
                start_ns = self._ts_ns(turn.get("start_ts"))
                end_ns = self._ts_ns(turn.get("end_ts"))
                if end_ns <= start_ns:
                    end_ns = start_ns + 1

                conn.execute(
                    "INSERT INTO turns(trace_id, turn_id, start_ts_ns, end_ts_ns, prompt, metadata) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        trace_id,
                        turn_seq,
                        start_ns,
                        end_ns,
                        str(turn.get("prompt_text") or ""),
                        self._json(turn),
                    ),
                )

                tool_pairs = turn.get("_tool_pairs") or []
                for tool_index, pair in enumerate(tool_pairs):
                    if not isinstance(pair, dict):
                        continue
                    call = pair.get("call") or {}
                    result = pair.get("result") or {}
                    tool_name = str(call.get("payload", {}).get("tool_name") or "unknown")
                    tool_start = self._ts_ns(call.get("ts") or turn.get("start_ts"))
                    tool_end = self._ts_ns(result.get("ts") or call.get("ts") or turn.get("end_ts"))
                    if tool_end <= tool_start:
                        tool_end = tool_start + 1
                    conn.execute(
                        "INSERT INTO tool_calls(trace_id, turn_id, tool_index, tool_name, start_ts_ns, end_ts_ns, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            trace_id,
                            turn_seq,
                            tool_index,
                            tool_name,
                            tool_start,
                            tool_end,
                            self._json(pair),
                        ),
                    )

    def list_turns(self, trace_id: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return list(
                conn.execute(
                    "SELECT turn_id, start_ts_ns, end_ts_ns, prompt, metadata FROM turns WHERE trace_id = ? ORDER BY turn_id",
                    (trace_id,),
                )
            )

    def turn_window(self, trace_id: str, turn_id: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT turn_id, start_ts_ns, end_ts_ns, prompt, metadata FROM turns WHERE trace_id = ? AND turn_id = ?",
                (trace_id, turn_id),
            ).fetchone()

    def count_event_type_in_window(self, trace_id: str, start_ts_ns: int, end_ts_ns: int, event_type: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM event WHERE trace_id = ? AND event_kind = 'sys' AND timestamp_ns >= ? AND timestamp_ns <= ? AND event_type = ?",
                (trace_id, start_ts_ns, end_ts_ns, event_type),
            ).fetchone()
        return int(row["c"] if row else 0)

    def unique_paths_in_window(self, trace_id: str, start_ts_ns: int, end_ts_ns: int, event_types: list[str]) -> int:
        if not event_types:
            return 0
        placeholders = ",".join(["?"] * len(event_types))
        sql = (
            "SELECT path, src FROM event "
            "WHERE trace_id = ? AND timestamp_ns >= ? AND timestamp_ns <= ? "
            f"AND event_kind = 'sys' AND event_type IN ({placeholders})"
        )
        with self._connect() as conn:
            rows = list(conn.execute(sql, (trace_id, start_ts_ns, end_ts_ns, *event_types)))

        paths: set[str] = set()
        for row in rows:
            path = str(row["path"] or "").strip()
            if path:
                paths.add(path)
            src = str(row["src"] or "").strip()
            if src:
                paths.add(src)
        return len(paths)

    def tool_calls_for_turn(self, trace_id: str, turn_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return list(
                conn.execute(
                    "SELECT tool_index, tool_name, start_ts_ns, end_ts_ns, metadata FROM tool_calls WHERE trace_id = ? AND turn_id = ? ORDER BY tool_index",
                    (trace_id, turn_id),
                )
            )

    def events_for_window(self, trace_id: str, start_ts_ns: int, end_ts_ns: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = list(
                conn.execute(
                    """
                    SELECT
                        id, timestamp_ns, source, event_kind, event_type,
                        line_no, pid, ppid, child_pid,
                        path, src, dest, bytes_count,
                        exec_path, command, argv_json, label, payload
                    FROM event
                    WHERE trace_id = ? AND timestamp_ns >= ? AND timestamp_ns <= ?
                    ORDER BY timestamp_ns, id
                    """,
                    (trace_id, start_ts_ns, end_ts_ns),
                )
            )

        out: list[dict[str, Any]] = []
        for row in rows:
            payload: Any
            try:
                payload = json.loads(str(row["payload"] or "{}"))
            except json.JSONDecodeError:
                payload = {"_raw": str(row["payload"] or "")}

            argv: list[str] = []
            try:
                parsed_argv = json.loads(str(row["argv_json"] or "[]"))
                if isinstance(parsed_argv, list):
                    argv = [str(item) for item in parsed_argv]
            except json.JSONDecodeError:
                argv = []

            out.append(
                {
                    "id": int(row["id"]),
                    "timestamp_ns": int(row["timestamp_ns"]),
                    "source": str(row["source"]),
                    "event_kind": str(row["event_kind"]),
                    "event_type": str(row["event_type"]),
                    "line_no": self._int_or_none(row["line_no"]),
                    "pid": self._int_or_none(row["pid"]),
                    "ppid": self._int_or_none(row["ppid"]),
                    "child_pid": self._int_or_none(row["child_pid"]),
                    "path": self._string_or_none(row["path"]),
                    "src": self._string_or_none(row["src"]),
                    "dest": self._string_or_none(row["dest"]),
                    "bytes_count": self._int_or_none(row["bytes_count"]),
                    "exec_path": self._string_or_none(row["exec_path"]),
                    "command": self._string_or_none(row["command"]),
                    "argv": argv,
                    "label": self._string_or_none(row["label"]),
                    "payload": payload,
                }
            )
        return out
