"""E2E regression: mantle watch should keep user HOME for tilde expansion."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
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


@pytest.mark.skipif(not _has_required_binaries(), reason="sudo or bin/mantle unavailable")
def test_watch_preserves_copilot_auth_env_context():
    """Watch runs should preserve Copilot auth env context across sudo."""
    expected_xdg = str(Path.home() / ".config")
    expected_token = "mantle-test-gh-token"
    expected_runtime = "/tmp/mantle-xdg-runtime"
    expected_dbus = "unix:path=/tmp/mantle-dbus-sock"

    cmd = [
        "bin/mantle",
        "watch",
        "--interactive-ebpf",
        "bash",
        "-lc",
        "echo MANTLE_XDG_CONFIG_HOME=$XDG_CONFIG_HOME && echo MANTLE_GITHUB_TOKEN=$GITHUB_TOKEN && echo MANTLE_XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR && echo MANTLE_DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS",
    ]

    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = expected_xdg
    env["GITHUB_TOKEN"] = expected_token
    env["XDG_RUNTIME_DIR"] = expected_runtime
    env["DBUS_SESSION_BUS_ADDRESS"] = expected_dbus

    proc = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )

    out = f"{proc.stdout}\n{proc.stderr}"
    assert proc.returncode == 0, out
    assert f"MANTLE_XDG_CONFIG_HOME={expected_xdg}" in out, out
    assert f"MANTLE_GITHUB_TOKEN={expected_token}" in out, out
    assert f"MANTLE_XDG_RUNTIME_DIR={expected_runtime}" in out, out
    assert f"MANTLE_DBUS_SESSION_BUS_ADDRESS={expected_dbus}" in out, out


@pytest.mark.skipif(not _has_required_binaries(), reason="sudo or bin/mantle unavailable")
def test_watch_runs_agent_as_invoking_user_not_root():
    """Watch runs should execute the agent command as the calling user."""
    expected_user = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()

    cmd = [
        "bin/mantle",
        "watch",
        "--interactive-ebpf",
        "bash",
        "-lc",
        "echo MANTLE_WATCH_USER=$(id -un)",
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
    assert f"MANTLE_WATCH_USER={expected_user}" in out, out


@pytest.mark.skipif(not _has_required_binaries(), reason="sudo or bin/mantle unavailable")
def test_watch_does_not_force_openai_base_for_copilot_binary_name():
    """Copilot binary should keep its default auth/provider discovery mode."""
    with tempfile.TemporaryDirectory(prefix="mantle-copilot-probe-") as tmpdir:
        probe = Path(tmpdir) / "copilot"
        probe.write_text("#!/usr/bin/env bash\necho MANTLE_OPENAI_BASE_URL=${OPENAI_BASE_URL:-}\n", encoding="utf-8")
        probe.chmod(0o755)

        cmd = [
            "bin/mantle",
            "watch",
            "--interactive-ebpf",
            str(probe),
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
        assert "MANTLE_OPENAI_BASE_URL=" in out, out
        assert "MANTLE_OPENAI_BASE_URL=http://127.0.0.1:" not in out, out
