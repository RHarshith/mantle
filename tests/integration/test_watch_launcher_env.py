"""Integration regression tests for watch launcher environment propagation."""

from pathlib import Path

import pytest


@pytest.mark.integration
def test_watch_sudo_preserve_env_includes_home():
    """`mantle watch` should preserve HOME when escalating via sudo."""
    script = Path("bin/mantle").read_text(encoding="utf-8")
    assert "--preserve-env=" in script
    assert "HOME" in script
