"""Environment schema parsing and validation for Mantle runtime."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping


@dataclass(frozen=True)
class RuntimeEnv:
    openai_model: str | None
    openai_base_url: str | None
    oak1: str | None


def load_runtime_env(environ: Mapping[str, str] | None = None) -> RuntimeEnv:
    """Load and validate Mantle runtime environment configuration."""
    env = dict(os.environ if environ is None else environ)

    return RuntimeEnv(
        openai_model=(env.get("OPENAI_MODEL") or "").strip() or None,
        openai_base_url=(env.get("OPENAI_BASE_URL") or "").strip() or None,
        oak1=(env.get("OAK1") or "").strip() or None,
    )
