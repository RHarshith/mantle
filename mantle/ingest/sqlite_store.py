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
                source = str(event.get("_source") or event.get("source") or "proxy")
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
                    tool_name = str(
                        call.get("payload", {}).get("tool_name")
                        or pair.get("tool_name")
                        or "unknown"
                    )
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

    # ── turn_computed persistence ─────────────────────────────────────

    def replace_turn_computed(
        self,
        trace_id: str,
        computed_turns: list[dict[str, Any]],
    ) -> None:
        """Bulk upsert pre-computed turn metrics.

        Called during _sync_trace_to_sqlite() to persist all computed turn data
        so that API endpoints become pure DB reads.
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM turn_computed WHERE trace_id = ?", (trace_id,))
            for turn in computed_turns:
                conn.execute(
                    """
                    INSERT INTO turn_computed(
                        trace_id, turn_id, turn_index,
                        tool_call_count, files_read_count, files_written_count,
                        network_call_count, subprocess_direct_count,
                        label, tags, dominant_summary,
                        prompt_text, response_text,
                        prompt_sections, response_sections,
                        replay_context_sections, replay_action_sections,
                        anomaly, raw_events_anomaly, raw_events_has_anomaly,
                        pre_tool_counts, first_tool_ts,
                        tool_pairs, tool_anomalies,
                        start_ts, end_ts
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trace_id,
                        str(turn.get("turn_id") or ""),
                        int(turn.get("index") or 0),
                        int(turn.get("tool_call_count") or 0),
                        int(turn.get("files_read_count") or 0),
                        int(turn.get("files_written_count") or 0),
                        int(turn.get("network_call_count") or 0),
                        int(turn.get("subprocess_direct_count") or 0),
                        str(turn.get("label") or ""),
                        self._json(turn.get("tags") or []),
                        str(turn.get("dominant_summary") or ""),
                        str(turn.get("prompt_text") or ""),
                        str(turn.get("response_text") or ""),
                        self._json(turn.get("prompt_sections") or []),
                        self._json(turn.get("response_sections") or []),
                        self._json(turn.get("replay_context_sections") or []),
                        self._json(turn.get("replay_action_sections") or []),
                        self._json(turn.get("anomaly") or {}),
                        self._json(turn.get("raw_events_anomaly") or turn.get("_outside_tool_anomaly") or {}),
                        1 if turn.get("raw_events_has_anomaly") else 0,
                        self._json(turn.get("pre_tool_counts") or {}),
                        float(turn["first_tool_ts"]) if turn.get("first_tool_ts") is not None else None,
                        self._json(self._strip_internal_fields(turn.get("_tool_pairs") or [])),
                        self._json(turn.get("_tool_anomalies") or []),
                        float(turn["start_ts"]) if turn.get("start_ts") is not None else None,
                        float(turn["end_ts"]) if turn.get("end_ts") is not None else None,
                    ),
                )

    @staticmethod
    def _strip_internal_fields(tool_pairs: list[Any]) -> list[dict[str, Any]]:
        """Remove non-serializable internal fields from tool_pairs before DB storage."""
        out: list[dict[str, Any]] = []
        for pair in tool_pairs:
            if not isinstance(pair, dict):
                continue
            clean = {k: v for k, v in pair.items() if not k.startswith("_")}
            out.append(clean)
        return out

    def get_turns_computed(self, trace_id: str) -> list[dict[str, Any]]:
        """Read all pre-computed turn data for a trace. Used by turns_overview and related endpoints."""
        with self._connect() as conn:
            rows = list(
                conn.execute(
                    """
                    SELECT * FROM turn_computed
                    WHERE trace_id = ?
                    ORDER BY turn_index
                    """,
                    (trace_id,),
                )
            )
        return [self._turn_computed_row_to_dict(row) for row in rows]

    def get_turn_computed(self, trace_id: str, turn_id: str) -> dict[str, Any] | None:
        """Read pre-computed data for a single turn."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM turn_computed
                WHERE trace_id = ? AND turn_id = ?
                """,
                (trace_id, turn_id),
            ).fetchone()
        if row is None:
            return None
        return self._turn_computed_row_to_dict(row)

    def _turn_computed_row_to_dict(self, row: Any) -> dict[str, Any]:
        """Convert a turn_computed Row into a plain dict with parsed JSON fields."""
        def _parse_json(raw: Any, default: Any = None) -> Any:
            if raw is None:
                return default if default is not None else {}
            try:
                return json.loads(str(raw))
            except (json.JSONDecodeError, TypeError):
                return default if default is not None else {}

        return {
            "turn_id": str(row["turn_id"]),
            "index": int(row["turn_index"]),
            "tool_call_count": int(row["tool_call_count"]),
            "files_read_count": int(row["files_read_count"]),
            "files_written_count": int(row["files_written_count"]),
            "network_call_count": int(row["network_call_count"]),
            "subprocess_direct_count": int(row["subprocess_direct_count"]),
            "label": str(row["label"]),
            "tags": _parse_json(row["tags"], []),
            "dominant_summary": str(row["dominant_summary"]),
            "prompt_text": str(row["prompt_text"]),
            "response_text": str(row["response_text"]),
            "prompt_sections": _parse_json(row["prompt_sections"], []),
            "response_sections": _parse_json(row["response_sections"], []),
            "replay_context_sections": _parse_json(row["replay_context_sections"], []),
            "replay_action_sections": _parse_json(row["replay_action_sections"], []),
            "anomaly": _parse_json(row["anomaly"], {}),
            "raw_events_anomaly": _parse_json(row["raw_events_anomaly"], {}),
            "raw_events_has_anomaly": bool(row["raw_events_has_anomaly"]),
            "pre_tool_counts": _parse_json(row["pre_tool_counts"], {}),
            "first_tool_ts": float(row["first_tool_ts"]) if row["first_tool_ts"] is not None else None,
            "tool_pairs": _parse_json(row["tool_pairs"], []),
            "tool_anomalies": _parse_json(row["tool_anomalies"], []),
            "start_ts": float(row["start_ts"]) if row["start_ts"] is not None else None,
            "end_ts": float(row["end_ts"]) if row["end_ts"] is not None else None,
        }

    def sys_events_for_turn_window(
        self,
        trace_id: str,
        start_ts_ns: int,
        end_ts_ns: int,
    ) -> list[dict[str, Any]]:
        """Retrieve sys events within a turn's time window. More targeted than events_for_window
        because it filters to event_kind='sys' only."""
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
                    WHERE trace_id = ? AND event_kind = 'sys'
                      AND timestamp_ns >= ? AND timestamp_ns <= ?
                    ORDER BY timestamp_ns, id
                    """,
                    (trace_id, start_ts_ns, end_ts_ns),
                )
            )

        return self._rows_to_sys_events(rows)

    def sys_events_by_pid_in_window(
        self,
        trace_id: str,
        pid: int,
        start_ts_ns: int,
        end_ts_ns: int,
    ) -> list[dict[str, Any]]:
        """Retrieve sys events for a specific PID within a time window."""
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
                    WHERE trace_id = ? AND event_kind = 'sys'
                      AND pid = ?
                      AND timestamp_ns >= ? AND timestamp_ns <= ?
                    ORDER BY timestamp_ns, id
                    """,
                    (trace_id, pid, start_ts_ns, end_ts_ns),
                )
            )

        return self._rows_to_sys_events(rows)

    def _rows_to_sys_events(self, rows: list[Any]) -> list[dict[str, Any]]:
        """Convert raw SQLite rows into the dict format expected by store.py processing."""
        out: list[dict[str, Any]] = []
        for row in rows:
            payload: Any
            try:
                payload = json.loads(str(row["payload"] or "{}"))
            except json.JSONDecodeError:
                payload = {}

            argv: list[str] = []
            try:
                parsed_argv = json.loads(str(row["argv_json"] or "[]"))
                if isinstance(parsed_argv, list):
                    argv = [str(item) for item in parsed_argv]
            except json.JSONDecodeError:
                argv = []

            # Reconstruct the in-memory event dict format used by store.py
            ts_ns = int(row["timestamp_ns"])
            ts_sec = ts_ns / 1_000_000_000 if ts_ns > 0 else 0.0

            event: dict[str, Any] = {
                "ts": ts_sec,
                "type": str(row["event_type"]),
                "source": str(row["source"]),
                "line_no": self._int_or_none(row["line_no"]),
                "pid": self._int_or_none(row["pid"]),
                "ppid": self._int_or_none(row["ppid"]),
                "child_pid": self._int_or_none(row["child_pid"]),
                "path": self._string_or_none(row["path"]),
                "src": self._string_or_none(row["src"]),
                "dest": self._string_or_none(row["dest"]),
                "bytes": self._int_or_none(row["bytes_count"]),
                "exec_path": self._string_or_none(row["exec_path"]),
                "command": self._string_or_none(row["command"]),
                "argv": argv,
                "label": self._string_or_none(row["label"]),
            }
            # Merge any extra payload fields
            if isinstance(payload, dict):
                for k, v in payload.items():
                    if k not in event:
                        event[k] = v

            out.append(event)
        return out

    # ── token_profile persistence ─────────────────────────────────────

    def replace_token_profile(
        self,
        trace_id: str,
        profile_rows: list[dict[str, Any]],
    ) -> None:
        """Bulk upsert pre-computed token byte metrics for the profiler view.

        Called during _sync_trace_to_sqlite() alongside turn_computed persistence.
        """
        with self._connect() as conn:
            conn.execute("DELETE FROM token_profile WHERE trace_id = ?", (trace_id,))
            for row in profile_rows:
                conn.execute(
                    """
                    INSERT INTO token_profile(
                        trace_id, turn_index,
                        request_bytes, response_bytes, delta_bytes
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        trace_id,
                        int(row.get("turn_index") or 0),
                        int(row.get("request_bytes") or 0),
                        int(row.get("response_bytes") or 0),
                        int(row.get("delta_bytes") or 0),
                    ),
                )

    def get_token_profile(self, trace_id: str) -> list[dict[str, Any]]:
        """Read stored token profile for a trace. Used by the profiler API endpoint."""
        with self._connect() as conn:
            rows = list(
                conn.execute(
                    """
                    SELECT turn_index, request_bytes, response_bytes, delta_bytes
                    FROM token_profile
                    WHERE trace_id = ?
                    ORDER BY turn_index
                    """,
                    (trace_id,),
                )
            )
        return [
            {
                "turn_index": int(row["turn_index"]),
                "request_bytes": int(row["request_bytes"]),
                "response_bytes": int(row["response_bytes"]),
                "delta_bytes": int(row["delta_bytes"]),
            }
            for row in rows
        ]

