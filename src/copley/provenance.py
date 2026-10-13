"""Run provenance: git revision, dirty status, dependency-lock digest, dataset digests,
and a per-run metadata record (handoff §9)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from copley.schemas import LabeledWindow


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


def dataset_digest(records: list[LabeledWindow]) -> str:
    """Order-independent content digest of a set of labeled windows.

    Uses each window's serialized model input plus its label, so the digest is stable under
    reordering but changes if evidence or labels change. Used to record source/split hashes.
    """
    from copley.data.serialize import serialize

    parts: list[str] = []
    for rec in records:
        ser = serialize(rec.evidence)
        basis = ser.text if ser.text is not None else rec.evidence.window_id
        parts.append(f"{rec.annotation.label.value}|{basis}")
    joined = "\n".join(sorted(parts)).encode("utf-8")
    return "sha256:" + hashlib.sha256(joined).hexdigest()


def run_record(
    *,
    kind: str,
    config: dict[str, Any],
    seed: int,
    source_digests: dict[str, str] | None = None,
    split_digests: dict[str, str] | None = None,
    artifact_digests: dict[str, str] | None = None,
    elapsed_seconds: float | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rev, dirty = git_revision()
    return {
        "kind": kind,
        "created_at": datetime.now(UTC).isoformat(),
        "config": config,
        "seed": seed,
        "git_revision": rev,
        "git_dirty": dirty,
        "lock_digest": lock_digest(),
        "source_digests": source_digests or {},
        "split_digests": split_digests or {},
        "artifact_digests": artifact_digests or {},
        "elapsed_seconds": elapsed_seconds,
        "extra": extra or {},
    }


def write_run_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
