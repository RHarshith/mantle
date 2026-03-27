"""Shared pager utilities for long-form CLI output."""

from __future__ import annotations

import os
import pydoc
import shutil
import subprocess
from typing import Optional


def show_text(text: str, title: Optional[str] = None) -> None:
    """Render text via less when available, with a pydoc fallback."""
    payload = str(text or "")
    if title:
        payload = f"{title}\n{'=' * len(title)}\n\n{payload}"

    less_path = shutil.which("less")
    if less_path and os.isatty(0) and os.isatty(1):
        env = dict(os.environ)
        env.setdefault("LESS", "-R")
        subprocess.run([less_path], input=payload.encode("utf-8"), env=env, check=False)
        return

    pydoc.pager(payload)
