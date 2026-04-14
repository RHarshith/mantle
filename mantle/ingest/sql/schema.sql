PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

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
);

CREATE INDEX IF NOT EXISTS idx_event_trace_id ON event(trace_id);
CREATE INDEX IF NOT EXISTS idx_event_trace_time ON event(trace_id, timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_event_trace_kind_type ON event(trace_id, event_kind, event_type);
CREATE INDEX IF NOT EXISTS idx_event_trace_path ON event(trace_id, path);
CREATE INDEX IF NOT EXISTS idx_event_trace_pid ON event(trace_id, pid);

CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY,
    trace_id TEXT NOT NULL,
    turn_id INTEGER NOT NULL,
    start_ts_ns BIGINT NOT NULL,
    end_ts_ns BIGINT NOT NULL,
    prompt TEXT,
    metadata JSON NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_turns_trace_turn ON turns(trace_id, turn_id);
CREATE INDEX IF NOT EXISTS idx_turns_trace_id ON turns(trace_id);
CREATE INDEX IF NOT EXISTS idx_turns_trace_time ON turns(trace_id, start_ts_ns, end_ts_ns);

CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY,
    trace_id TEXT NOT NULL,
    turn_id INTEGER NOT NULL,
    tool_index INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    start_ts_ns BIGINT NOT NULL,
    end_ts_ns BIGINT NOT NULL,
    metadata JSON NOT NULL,
    FOREIGN KEY(trace_id, turn_id) REFERENCES turns(trace_id, turn_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_trace_id ON tool_calls(trace_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_trace_turn ON tool_calls(trace_id, turn_id);
