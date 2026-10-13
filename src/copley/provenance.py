"""Run provenance: git revision, dirty status, dependency-lock digest."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def git_revision() -> tuple[str | None, bool | None]:
    root = _repo_root()
    try:
        # Fixed git argv, no shell, no untrusted input.
        rev = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if rev.returncode != 0:
            return None, None
        status = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), "status", "--porcelain"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        dirty = bool(status.stdout.strip())
        return rev.stdout.strip(), dirty
    except (OSError, subprocess.SubprocessError):
        return None, None


def lock_digest() -> str | None:
    lock = _repo_root() / "uv.lock"
    if not lock.exists():
        return None
    return "sha256:" + hashlib.sha256(lock.read_bytes()).hexdigest()[:16]
