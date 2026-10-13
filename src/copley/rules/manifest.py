"""Load and hash-verify the pinned Sigma rule subset."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

_LIBRARY = Path(__file__).parent / "library"


@dataclass(frozen=True)
class RuleEntry:
    set_name: str
    path: Path
    sha256: str
    license: str


class RuleManifestError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rule_manifest(manifest_path: Path) -> list[RuleEntry]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    sigmahq_license = data.get("sigmahq_source", {}).get("license", "DRL-1.1")
    entries: list[RuleEntry] = []
    for item in data.get("rules", []):
        set_name = item["set"]
        path = _LIBRARY / set_name / item["file"]
        if not path.exists():
            raise RuleManifestError(f"rule file missing: {path}")
        actual = _sha256(path)
        if actual != item["sha256"]:
            raise RuleManifestError(
                f"sha256 mismatch for {path.name}: manifest {item['sha256']} != actual {actual}"
            )
        license_name = "Apache-2.0" if set_name == "local" else sigmahq_license
        entries.append(RuleEntry(set_name, path, actual, license_name))
    return entries


def default_manifest_path() -> Path:
    # Repo-root manifests/rules.yaml, resolved relative to the installed package when present.
    candidates = [
        Path.cwd() / "manifests" / "rules.yaml",
        Path(__file__).resolve().parents[3] / "manifests" / "rules.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise RuleManifestError("could not locate manifests/rules.yaml")
