"""Cgroup v2 utility functions for Mantle daemon."""

from __future__ import annotations

import os
from pathlib import Path


CGROUP_FS_ROOT = "/sys/fs/cgroup"


def get_cgroup_id(cgroup_path: str) -> int:
    """Return the kernel cgroup ID (inode number) for a cgroup directory.

    This matches what bpftrace's ``cgroup`` builtin returns for processes
    inside the cgroup.
    """
    p = Path(cgroup_path)
    if not p.is_dir():
        raise FileNotFoundError(f"cgroup path does not exist: {cgroup_path}")
    return os.stat(cgroup_path).st_ino


def validate_cgroup_path(cgroup_path: str) -> bool:
    """Verify that *cgroup_path* is a valid cgroup v2 directory."""
    p = Path(cgroup_path)
    if not p.is_dir():
        return False
    try:
        resolved = str(p.resolve())
    except OSError:
        return False
    if not resolved.startswith(CGROUP_FS_ROOT):
        return False
    # Must contain the standard cgroup interface file.
    return (p / "cgroup.procs").exists()


def is_cgroup_alive(cgroup_path: str) -> bool:
    """Return True if the cgroup directory still exists on the filesystem."""
    return Path(cgroup_path).is_dir()


def read_self_cgroup_path() -> str:
    """Return the absolute sysfs path of the calling process's cgroup."""
    cgroup_rel = Path("/proc/self/cgroup").read_text().strip().split(":")[2]
    return f"{CGROUP_FS_ROOT}{cgroup_rel}"
