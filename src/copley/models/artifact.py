"""Artifact metadata and the shared predictor interface.

An artifact is a directory containing `metadata.json`, a weights file, and optionally a
calibration file. Loading is restricted to local directories we wrote; there is no
arbitrary pickle/model upload path. The randomly initialized neural smoke artifact is
marked `artifact_kind=test_only` and `fixture_trained=true`, so it can never be presented
as a deployable detector.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from copley.schemas import (
    ArtifactKind,
    CalibrationStatus,
    EvidenceWindow,
    Prediction,
)

METADATA_FILENAME = "metadata.json"


class CalibrationInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: CalibrationStatus = CalibrationStatus.uncalibrated
    artifact_id: str | None = None
    population: str | None = None
    method: str | None = None


class ArtifactMetadata(BaseModel):
    """Serialized description of a trained (or test) artifact."""

    model_config = ConfigDict(extra="forbid")

    model_id: str
    model_type: str  # "linear" | "modernbert"
    artifact_kind: ArtifactKind
    fixture_trained: bool
    task_id: str
    schema_version: str = "copley.artifact/v1"
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    weights_file: str
    weights_sha256: str
    preprocessing_version: str
    serializer_version: str
    label_mapping: dict[str, int]
    positive_label: str = "malicious"

    threshold: float | None = None
    threshold_basis: str | None = None
    calibration: CalibrationInfo = Field(default_factory=CalibrationInfo)

    # Provenance
    git_revision: str | None = None
    git_dirty: bool | None = None
    lock_digest: str | None = None
    train_counts: dict[str, int] = Field(default_factory=dict)
    base_model: str | None = None
    base_model_revision: str | None = None
    extra: dict = Field(default_factory=dict)

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / METADATA_FILENAME).write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path) -> ArtifactMetadata:
        path = directory / METADATA_FILENAME
        if not path.exists():
            raise ArtifactError(f"no {METADATA_FILENAME} in {directory}")
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class ArtifactError(RuntimeError):
    """Raised for missing, invalid, or tampered artifacts. Never a benign prediction."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_weights(directory: Path, metadata: ArtifactMetadata) -> Path:
    weights = directory / metadata.weights_file
    if not weights.exists():
        raise ArtifactError(f"weights file missing: {weights}")
    actual = sha256_file(weights)
    if actual != metadata.weights_sha256:
        raise ArtifactError(
            f"weights digest mismatch: metadata {metadata.weights_sha256} != actual {actual}"
        )
    return weights


class Predictor(Protocol):
    """Shared interface. Implementations receive EvidenceWindow ONLY."""

    metadata: ArtifactMetadata

    def predict(self, window: EvidenceWindow) -> Prediction: ...


def load_calibration(directory: Path) -> dict | None:
    path = directory / "calibration.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
