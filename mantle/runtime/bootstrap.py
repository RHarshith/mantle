"""Startup bootstrap for Mantle runtime processes."""

from __future__ import annotations

from .env_schema import RuntimeEnv, load_runtime_env
from .logging import configure_root_logger
from .paths import RuntimeLayout, ensure_runtime_config_scaffold, ensure_runtime_layout, resolve_runtime_layout


def bootstrap_runtime(component: str, *, log_level: str | None = None) -> tuple[RuntimeEnv, RuntimeLayout]:
    """Validate environment, prepare directories/config, and initialize logging."""
    runtime_env = load_runtime_env()
    layout = resolve_runtime_layout(runtime_env)
    ensure_runtime_layout(layout, require_writable=True)
    ensure_runtime_config_scaffold(layout)
    configure_root_logger(component=component, layout=layout, level=log_level)
    return runtime_env, layout
