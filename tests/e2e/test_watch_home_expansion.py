"""E2E regression: mantle watch should keep user HOME for tilde expansion."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e


def _has_required_binaries() -> bool:
    return shutil.which("sudo") is not None and Path("bin/mantle").exists()


@pytest.mark.skipif(not _has_required_binaries(), reason="sudo or bin/mantle unavailable")
def test_watch_preserves_user_home_for_tilde_expansion():
    """Watch runs should preserve HOME so `~` points to invoking user's directory."""
    expected_home = str(Path.home())

    cmd = [
        "bin/mantle",
        "watch",
        "--interactive-ebpf",
        "bash",
        "-lc",
        "echo MANTLE_HOME=$HOME",
    ]

    proc = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parents[2],
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=180,
    )

    out = f"{proc.stdout}\n{proc.stderr}"
    assert proc.returncode == 0, out
    assert f"MANTLE_HOME={expected_home}" in out, out
