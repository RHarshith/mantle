"""Unit tests for strict BPF event normalization."""

import pytest

from mantle.capture.events_model import transform_bpf_record


@pytest.mark.unit
def test_transform_allows_file_rename_ret() -> None:
    record = {
        "ts": 1776540069.8888168,
        "line_no": 8639,
        "type": "file_rename_ret",
        "pid": 19040,
        "ok": True,
        "ret": 0,
        "label": "rename ret=0",
    }

    normalized = transform_bpf_record(record, fallback_line_no=1)

    assert normalized["type"] == "file_rename_ret"
    assert normalized["pid"] == 19040
    assert normalized["payload"]["ret"] == 0
