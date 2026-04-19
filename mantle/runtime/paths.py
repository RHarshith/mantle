"""Filesystem layout resolution for Mantle runtime paths."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .env_schema import RuntimeEnv, load_runtime_env


RUNTIME_COMPONENTS = (
    "bpf_collector",
    "proxy",
    "post_processing",
    "server",
    "frontend",
    "agent",
)


@dataclass(frozen=True)
class RuntimeLayout:
    repo_root: Path
    logs_root: Path
    obs_root: Path
    runtime_root: Path
    traces_dir: Path
    events_dir: Path
    mitm_dir: Path
    proxy_obs_dir: Path
    runtime_dirs: dict[str, Path]
    config_root: Path
    proxy_config_path: Path
    runtime_config_path: Path


def _repo_root() -> Path:
    # paths.py lives at <repo>/mantle/runtime/paths.py.
    return Path(__file__).resolve().parents[2]


def resolve_runtime_layout(env: RuntimeEnv | None = None) -> RuntimeLayout:
    """Resolve all runtime directories under the fixed repo-local .mantle root."""
    _ = load_runtime_env() if env is None else env
    repo_root = _repo_root()
    mantle_root = repo_root / ".mantle"
    logs_root = mantle_root / "logs"
    obs_root = mantle_root / "obs"
    runtime_root = logs_root / "runtime"
    config_root = mantle_root / "config"

    runtime_dirs = {component: runtime_root / component for component in RUNTIME_COMPONENTS}
    return RuntimeLayout(
        repo_root=repo_root,
        logs_root=logs_root,
        obs_root=obs_root,
        runtime_root=runtime_root,
        traces_dir=obs_root / "traces",
        events_dir=obs_root / "events",
        mitm_dir=obs_root / "mitm",
        proxy_obs_dir=obs_root / "proxy",
        runtime_dirs=runtime_dirs,
        config_root=config_root,
        proxy_config_path=config_root / "litellm_proxy.config.yaml",
        runtime_config_path=config_root / "runtime.defaults.json",
    )


def ensure_runtime_layout(layout: RuntimeLayout, require_writable: bool = True) -> None:
    """Create required runtime directories and optionally verify write permissions."""
    required_dirs = [
        layout.logs_root,
        layout.obs_root,
        layout.traces_dir,
        layout.events_dir,
        layout.mitm_dir,
        layout.proxy_obs_dir,
        layout.runtime_root,
        *layout.runtime_dirs.values(),
        layout.config_root,
    ]

    for directory in required_dirs:
        directory.mkdir(parents=True, exist_ok=True)

    if not require_writable:
        return

    for directory in required_dirs:
        probe = directory / ".mantle.write_check"
        try:
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            raise RuntimeError(f"Path is not writable: {directory}") from exc


def ensure_runtime_config_scaffold(layout: RuntimeLayout) -> None:
    """Create baseline runtime config scaffolding if absent."""
    if layout.runtime_config_path.exists():
        return
    payload = {
        "description": "Generated defaults scaffold for Mantle runtime.",
        "notes": [
            "Runtime paths are fixed to repo-local .mantle/{obs,config,logs}.",
            "Do not rely on env folder overrides for capture/runtime directories.",
        ],
        "paths": {
            "logs_root": str(layout.logs_root),
            "obs_root": str(layout.obs_root),
            "runtime_root": str(layout.runtime_root),
            "config_root": str(layout.config_root),
        },
    }
    layout.runtime_config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
