"""Manifest-driven, opt-in data fetcher with a dry-run plan.

Safety rules enforced here:
* Dry-run (default in the CLI) performs no network access and prints the plan.
* Disabled sources are never fetched.
* We refuse Git LFS pointer files masquerading as data (size/content sniff).
* We never execute repository scripts or any command found in telemetry.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"


@dataclass
class FilePlan:
    path: str
    sha256: str | None
    size: int | None


@dataclass
class SourcePlan:
    id: str
    enabled: bool
    acquisition: str
    repo: str | None
    revision: str | None
    license: str | None
    redistribution: str | None
    label_availability: str | None
    adapter: str | None
    files: list[FilePlan]
    action: str  # "skip_disabled" | "would_fetch" | "unsupported"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["files"] = [asdict(f) for f in self.files]
        return d


def load_source_manifest(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def plan_fetch(manifest: dict) -> list[SourcePlan]:
    plans: list[SourcePlan] = []
    for src in manifest.get("sources", []):
        files = [
            FilePlan(path=f["path"], sha256=f.get("sha256"), size=f.get("size"))
            for f in src.get("files", [])
        ]
        if not src.get("enabled", False):
            action = "skip_disabled"
        elif src.get("acquisition") == "git_lfs":
            action = "would_fetch"
        else:
            action = "unsupported"
        plans.append(
            SourcePlan(
                id=src["id"],
                enabled=bool(src.get("enabled", False)),
                acquisition=src.get("acquisition", "unknown"),
                repo=src.get("repo"),
                revision=src.get("revision"),
                license=src.get("license"),
                redistribution=src.get("redistribution"),
                label_availability=src.get("label_availability"),
                adapter=src.get("adapter"),
                files=files,
                action=action,
            )
        )
    return plans


def is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX
    except OSError:
        return False


class FetchError(RuntimeError):
    pass


def ensure_not_pointer(path: Path) -> None:
    if is_lfs_pointer(path):
        raise FetchError(
            f"{path} is a Git LFS pointer, not real data. Run `git lfs pull --include=...` "
            "for this file, or acquire it through the documented manual step."
        )
