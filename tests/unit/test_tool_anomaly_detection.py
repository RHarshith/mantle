"""Unit tests for tool side-effect anomaly detection rules."""

from __future__ import annotations

from pathlib import Path

from mantle.analysis.tool_anomaly import ToolAnomalyDetector


def _event(line_no: int, event_type: str, **kwargs):
    return {
        "line_no": line_no,
        "ts": float(line_no),
        "type": event_type,
        **kwargs,
    }


def test_sensitive_file_access_is_high_severity() -> None:
    detector = ToolAnomalyDetector()
    events = [
        _event(1, "command_exec", pid=101, ppid=1, exec_path="/usr/bin/npm", argv=["npm", "install"], command="npm install"),
        _event(2, "file_read", pid=101, path=str(Path.home() / ".ssh" / "id_rsa")),
    ]

    report = detector.analyze("npm install", events, {101: 1})
    sensitive = [v for v in report["violations"] if v.get("rule") == "SENSITIVE_ACCESS"]

    assert report["verdict"] == "VIOLATION"
    assert sensitive
    assert sensitive[0]["severity"] == "HIGH"


def test_unknown_network_binary_is_skipped() -> None:
    detector = ToolAnomalyDetector(skip_unknown_network_binaries=True)
    events = [
        _event(1, "command_exec", pid=201, ppid=1, exec_path="/usr/local/bin/custom_tool", argv=["custom_tool", "run"], command="custom_tool run"),
        _event(2, "net_connect", pid=201, dest="203.0.113.42:443", transport="tcp"),
    ]

    report = detector.analyze("custom_tool run", events, {201: 1})

    assert report["verdict"] == "CLEAN"
    assert not any(v.get("rule") == "UNEXPECTED_NETWORK" for v in report["violations"])


def test_must_not_network_binary_is_high_violation() -> None:
    detector = ToolAnomalyDetector()
    events = [
        _event(1, "command_exec", pid=301, ppid=1, exec_path="/bin/cat", argv=["cat", "README.md"], command="cat README.md"),
        _event(2, "net_connect", pid=301, dest="198.51.100.20:443", transport="tcp"),
    ]

    report = detector.analyze("cat README.md", events, {301: 1})
    network = [v for v in report["violations"] if v.get("rule") == "UNEXPECTED_NETWORK"]

    assert report["verdict"] == "VIOLATION"
    assert network
    assert network[0]["severity"] == "HIGH"


def test_shell_root_uses_child_binary_for_scope_checks() -> None:
    detector = ToolAnomalyDetector()
    events = [
        _event(1, "command_exec", pid=401, ppid=1, exec_path="/bin/bash", argv=["bash", "-lc", "npm install"], command="bash -lc npm install"),
        _event(2, "command_exec", pid=402, ppid=401, exec_path="/usr/bin/npm", argv=["npm", "install"], command="npm install"),
        _event(3, "file_read", pid=402, path=str(Path.home() / ".ssh" / "config")),
    ]

    report = detector.analyze("bash -lc npm install", events, {401: 1, 402: 401}, root_pid=401)

    assert any(v.get("rule") == "SCOPE_VIOLATION" for v in report["violations"])


def test_low_only_violations_are_suspicious() -> None:
    detector = ToolAnomalyDetector()
    events = [
        _event(1, "command_exec", pid=501, ppid=1, exec_path="/usr/bin/python3", argv=["python3", "script.py"], command="python3 script.py"),
        _event(2, "net_connect", pid=501, dest="192.0.2.10:443", transport="tcp"),
    ]

    report = detector.analyze("python3 script.py", events, {501: 1})

    assert report["verdict"] == "SUSPICIOUS"
    assert report["severity_counts"]["LOW"] >= 1
    assert report["severity_counts"]["MEDIUM"] == 0
    assert report["severity_counts"]["HIGH"] == 0


def test_parent_process_map_enrichment_does_not_mutate_iteration() -> None:
    detector = ToolAnomalyDetector()
    events = [
        _event(1, "command_exec", pid=601, ppid=6010, exec_path="/usr/bin/python3", argv=["python3", "script.py"], command="python3 script.py"),
    ]

    report = detector.analyze("python3 script.py", events, {601: 6010})

    assert report["command"] == "python3 script.py"
    assert report["root_pid"] == 601
