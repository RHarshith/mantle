"""E2E regression: copilot watch runs should produce replay-turn API capture evidence."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from mantle.ingest.store import TraceStore

pytestmark = pytest.mark.e2e


def _has_copilot_watch_requirements() -> bool:
    return (
        shutil.which("sudo") is not None
        and Path("bin/mantle").exists()
        and shutil.which("copilot") is not None
    )


@pytest.mark.skipif(not _has_copilot_watch_requirements(), reason="sudo/bin-mantle/copilot unavailable")
def test_watch_copilot_emits_mitm_and_replay_turns(tmp_path):
    """Copilot watch run should produce MITM evidence and at least one non-setup replay turn."""
    obs_root = tmp_path / "obs"
    (obs_root / "traces").mkdir(parents=True, exist_ok=True)
    (obs_root / "events").mkdir(parents=True, exist_ok=True)
    (obs_root / "mitm").mkdir(parents=True, exist_ok=True)
    # Launcher prefers repo obs when AGENT_OBS_ROOT appears empty.
    (obs_root / "traces" / ".seed.ebpf.jsonl").write_text("", encoding="utf-8")
    (obs_root / "events" / ".seed.events.jsonl").write_text("", encoding="utf-8")

    trace_id = "copilot_capture_case.ebpf.jsonl"
    trace_base = trace_id.removesuffix(".ebpf.jsonl")

    cmd = [
        "bin/mantle",
        "watch",
        "--trace-id",
        trace_id,
        "copilot",
        "-p",
        "reply with exactly hello",
        "--yolo",
        "--model",
        "gpt-4.1",
    ]

    env = os.environ.copy()
    env["AGENT_OBS_ROOT"] = str(obs_root)

    proc = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
    )

    output = f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}"
    assert proc.returncode == 0, output

    mitm_file = obs_root / "mitm" / f"{trace_base}.mitm.jsonl"
    assert mitm_file.exists(), output
    mitm_lines = [line for line in mitm_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    assert len(mitm_lines) > 0, output

    store = TraceStore(
        trace_dir=obs_root / "traces",
        events_dir=obs_root / "events",
        mitm_dir=obs_root / "mitm",
    )
    asyncio.run(store.poll_once())

    replay = store.replay_turns_overview(trace_id)
    turn_ids = [str(t.get("turn_id") or "") for t in list(replay.get("turns") or [])]
    assert any(tid != "setup" for tid in turn_ids), replay
