"""Unit tests for eBPF event parsing functions in mantle.ebpf_capture."""

import pytest

from mantle.capture.ebpf import (
    _command_for_bpftrace,
    _decode_ipv4,
    _decode_ipv6,
    _event_from_line,
    _safe_int,
)


@pytest.mark.unit
class TestSafeInt:
    def test_valid_int(self):
        assert _safe_int("42") == 42

    def test_zero(self):
        assert _safe_int("0") == 0

    def test_negative(self):
        assert _safe_int("-1") == -1

    def test_invalid(self):
        assert _safe_int("abc") == 0

    def test_invalid_with_default(self):
        assert _safe_int("abc", -1) == -1

    def test_none(self):
        assert _safe_int(None) == 0

    def test_empty_string(self):
        assert _safe_int("") == 0


@pytest.mark.unit
class TestDecodeIPv4:
    def test_localhost(self):
        # 127.0.0.1 in little-endian hex is 0100007F
        result = _decode_ipv4("0100007F")
        assert result == "127.0.0.1"

    def test_invalid(self):
        result = _decode_ipv4("invalid")
        assert result == "unknown"


@pytest.mark.unit
class TestDecodeIPv6:
    def test_loopback(self):
        # ::1 in /proc/net/tcp6 format
        result = _decode_ipv6("00000000000000000000000001000000")
        assert result != "unknown"

    def test_invalid(self):
        result = _decode_ipv6("invalid")
        assert result == "unknown"


@pytest.mark.unit
class TestEventFromLine:
    """Test _event_from_line with synthesized EVT| lines."""

    def _parse(self, line: str, seq: int = 1) -> dict | None:
        return _event_from_line(line, seq, {}, {}, 0.0)

    def test_fork_event(self):
        event = self._parse("EVT|1000000000|fork|100|200|bash")
        assert event is not None
        assert event["type"] == "process_spawn"
        assert event["pid"] == 100
        assert event["child_pid"] == 200

    def test_exec_event(self):
        event = self._parse("EVT|1000000000|exec|200|100|bash|/usr/bin/bash")
        assert event is not None
        assert event["type"] == "command_exec"
        assert event["pid"] == 200
        assert event["ppid"] == 100

    def test_exit_event(self):
        event = self._parse("EVT|1000000000|exit|200|100|bash")
        assert event is not None
        assert event["type"] == "process_exit"
        assert event["pid"] == 200

    def test_openat_read(self):
        event = self._parse("EVT|1000000000|openat|200|/etc/passwd|0")
        assert event is not None
        assert event["type"] == "file_read"
        assert event["path"] == "/etc/passwd"

    def test_openat_write(self):
        # O_WRONLY | O_CREAT = 0x41 = 65
        event = self._parse("EVT|1000000000|openat|200|/tmp/out.txt|65")
        assert event is not None
        assert event["type"] == "file_write"

    def test_unlinkat(self):
        event = self._parse("EVT|1000000000|unlinkat|200|/tmp/old.txt")
        assert event is not None
        assert event["type"] == "file_delete"

    def test_renameat(self):
        event = self._parse("EVT|1000000000|renameat|200|/tmp/a.txt|/tmp/b.txt")
        assert event is not None
        assert event["type"] == "file_rename"
        assert event["src"] == "/tmp/a.txt"
        assert event["path"] == "/tmp/b.txt"

    def test_write_event(self):
        event = self._parse("EVT|1000000000|write|200|3|1024")
        assert event is not None
        assert event["type"] == "fd_write"
        assert event["fd"] == 3

    def test_close_event(self):
        event = self._parse("EVT|1000000000|close|200|3")
        assert event is not None
        assert event["type"] == "fd_close"

    def test_non_evt_line(self):
        assert self._parse("some random output") is None

    def test_short_line(self):
        assert self._parse("EVT|123") is None

    def test_unknown_kind(self):
        assert self._parse("EVT|1000000000|unknown_kind|200") is None

    def test_timestamp_calculation(self):
        event = self._parse("EVT|2000000000|exit|100|0|bash")
        assert event is not None
        # With time_offset=0.0, ts should be 2.0
        assert event["ts"] == pytest.approx(2.0, abs=0.01)

    def test_openat_ret(self):
        event = self._parse("EVT|1000000000|openat_ret|200|5")
        assert event is not None
        assert event["type"] == "fd_open"
        assert event["fd"] == 5


@pytest.mark.unit
class TestCommandForBpftrace:
    def test_empty_command(self):
        assert _command_for_bpftrace([]) == []

    def test_nonexistent_binary(self):
        cmd = ["/nonexistent/binary", "--arg"]
        assert _command_for_bpftrace(cmd) == cmd

    def test_native_elf_unchanged(self, tmp_path):
        binary = tmp_path / "test_bin"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        cmd = [str(binary), "--flag"]
        assert _command_for_bpftrace(cmd) == cmd

    def test_shebang_script(self, tmp_path):
        script = tmp_path / "test_script"
        script.write_text("#!/usr/bin/env python3\nprint('hello')\n")
        script.chmod(0o755)
        result = _command_for_bpftrace([str(script)])
        assert result[0] == "/usr/bin/env"
        assert result[1] == "python3"
        assert str(script) in result
