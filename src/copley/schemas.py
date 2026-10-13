"""Typed data contract for Copley.

Three families of models live here and must stay separate:

* Evidence (`ProcessEvent`, `EvidenceWindow`): the only thing a predictor may receive.
* Annotations/provenance (`Annotation`, `Provenance`, `Grouping`): training/evaluation
  metadata that must never reach feature extraction or tokenization.
* Outputs (`Prediction`).

`LabeledWindow` pairs one evidence window with its annotation for datasets on disk.
"""

from __future__ import annotations

import math
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION: Final = "copley.evidence/v1"
PREDICTION_SCHEMA_VERSION: Final = "copley.prediction/v1"
TASK_PROCESS_EXECUTION = "process_execution.suspicious.v1"
SUPPORTED_TASKS = frozenset({TASK_PROCESS_EXECUTION})

# Payload bounds enforced at validation time. The serializer applies tighter,
# model-specific bounds and abstains rather than truncating.
MAX_FIELD_CHARS = 32_768
MAX_EVENTS_PER_WINDOW = 64
MAX_ID_CHARS = 256

Ident = Annotated[str, Field(min_length=1, max_length=MAX_ID_CHARS)]
FieldText = Annotated[str, Field(max_length=MAX_FIELD_CHARS)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)


def _require_tz(value: datetime | None, name: str) -> datetime | None:
    if value is not None and value.tzinfo is None:
        raise ValueError(f"{name} must include a timezone offset")
    return value


# --------------------------------------------------------------------------- evidence

PROCESS_FIELDS: tuple[str, ...] = (
    "image",
    "original_file_name",
    "command_line",
    "current_directory",
    "integrity_level",
    "user",
    "process_id",
    "parent_image",
    "parent_command_line",
    "parent_process_id",
)


class ProcessEvent(_Strict):
    """One Windows process-creation event (Sysmon EID 1 / Security 4688 shaped)."""

    event_id: Ident
    event_type: Literal["process_creation"] = "process_creation"
    timestamp: datetime | None = None
    observed_at: datetime | None = Field(
        default=None,
        description="Ingestion/observation time when the source records it; null if unknown.",
    )
    host: FieldText | None = None
    image: FieldText | None = None
    original_file_name: FieldText | None = None
    command_line: FieldText | None = None
    current_directory: FieldText | None = None
    integrity_level: FieldText | None = None
    user: FieldText | None = None
    process_id: FieldText | None = None
    parent_image: FieldText | None = None
    parent_command_line: FieldText | None = None
    parent_process_id: FieldText | None = None
    source_truncated_fields: tuple[str, ...] = Field(
        default=(),
        description="Fields the upstream source itself marked or is known to have truncated.",
    )

    @field_validator("timestamp", "observed_at")
    @classmethod
    def _tz(cls, v: datetime | None, info: object) -> datetime | None:
        return _require_tz(v, getattr(info, "field_name", "timestamp"))

    @field_validator("source_truncated_fields")
    @classmethod
    def _known_fields(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(v) - set(PROCESS_FIELDS))
        if unknown:
            raise ValueError(f"unknown truncated fields: {unknown}")
        return v

    @property
    def missing_fields(self) -> tuple[str, ...]:
        return tuple(f for f in PROCESS_FIELDS if getattr(self, f) in (None, ""))


class ContextInfo(_Strict):
    """What context was available to and supplied with the window."""

    policy: Literal["anchor_only", "parent_chain", "host_time_window"] = "anchor_only"
    related_events_available: bool | None = Field(
        default=None, description="Whether the source could supply related events; null if unknown."
    )
    related_events_omitted: int = Field(
        default=0, ge=0, description="Related events known to exist but not included."
    )
    notes: Annotated[str, Field(max_length=1024)] | None = None


class EvidenceWindow(_Strict):
    """Bounded snapshot of telemetry available at decision time. Predictor input only."""

    schema_version: Literal["copley.evidence/v1"] = SCHEMA_VERSION
    window_id: Ident
    task_id: str
    as_of: datetime
    anchor_event_id: Ident
    events: Annotated[list[ProcessEvent], Field(min_length=1, max_length=MAX_EVENTS_PER_WINDOW)]
    context: ContextInfo = Field(default_factory=ContextInfo)

    @field_validator("task_id")
    @classmethod
    def _supported_task(cls, v: str) -> str:
        if v not in SUPPORTED_TASKS:
            raise ValueError(f"unsupported task_id {v!r}; supported: {sorted(SUPPORTED_TASKS)}")
        return v

    @field_validator("as_of")
    @classmethod
    def _as_of_tz(cls, v: datetime) -> datetime:
        _require_tz(v, "as_of")
        return v

    @model_validator(mode="after")
    def _consistency(self) -> EvidenceWindow:
        ids = [e.event_id for e in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("event_id values must be unique within a window")
        if self.anchor_event_id not in ids:
            raise ValueError("anchor_event_id does not match any supplied event")
        for e in self.events:
            if e.timestamp is not None and e.timestamp > self.as_of:
                raise ValueError(f"event {e.event_id} timestamp is after as_of (future evidence)")
            if e.observed_at is not None and e.observed_at > self.as_of:
                raise ValueError(f"event {e.event_id} was not observed until after as_of")
        return self

    @property
    def anchor(self) -> ProcessEvent:
        return next(e for e in self.events if e.event_id == self.anchor_event_id)

    @property
    def related(self) -> list[ProcessEvent]:
        return [e for e in self.events if e.event_id != self.anchor_event_id]

    @property
    def evidence_profile(self) -> str:
        """Slice label derived from evidence structure only."""
        a = self.anchor
        if self.related:
            return "with_related_events"
        present = set(PROCESS_FIELDS) - set(a.missing_fields)
        if present <= {"command_line"}:
            return "command_line_only"
        if a.parent_image or a.parent_command_line:
            return "process_with_parent"
        return "process_without_parent"


# ------------------------------------------------------------------ annotations


class Label(StrEnum):
    benign = "benign"
    malicious = "malicious"
    unlabeled = "unlabeled"


class LabelSource(StrEnum):
    reviewed_evidence = "reviewed_evidence"
    known_controlled_execution = "known_controlled_execution"
    weak_rule_label = "weak_rule_label"
    synthetic_fixture = "synthetic_fixture"
    none = "none"


class ReviewStatus(StrEnum):
    unreviewed = "unreviewed"
    reviewed = "reviewed"
    disputed = "disputed"
    not_applicable = "not_applicable"


class ProvenanceCategory(StrEnum):
    synthetic_fixture = "synthetic_fixture"
    controlled_attack_execution = "controlled_attack_execution"
    real_intrusion = "real_intrusion"
    benign_operations = "benign_operations"
    unknown = "unknown"


class Provenance(_Strict):
    dataset_id: Ident
    source_id: Ident
    category: ProvenanceCategory
    upstream_url: str | None = None
    upstream_revision: str | None = None
    original_file: str | None = None
    content_sha256: str | None = None
    license: str | None = None
    redistribution: Literal["allowed", "not_allowed", "unknown"] = "unknown"
    preprocessing_version: str


class Grouping(_Strict):
    """Identifiers used to keep correlated examples on one side of a split."""

    run_id: str | None = None
    incident_id: str | None = None
    scenario_id: str | None = None
    host_id: str | None = None
    template_id: str | None = None

    def keys(self) -> list[str]:
        return [f"{k}:{v}" for k, v in self.model_dump().items() if v]


class Annotation(_Strict):
    label: Label
    label_source: LabelSource
    review_status: ReviewStatus = ReviewStatus.unreviewed
    reviewer: str | None = None
    notes: Annotated[str, Field(max_length=4096)] | None = None
    provenance: Provenance
    grouping: Grouping = Field(default_factory=Grouping)

    @model_validator(mode="after")
    def _label_consistency(self) -> Annotation:
        if self.label is Label.unlabeled and self.label_source is not LabelSource.none:
            raise ValueError("unlabeled records must use label_source 'none'")
        if self.label is not Label.unlabeled and self.label_source is LabelSource.none:
            raise ValueError("labeled records need a label_source")
        return self


class LabeledWindow(_Strict):
    """Dataset record: evidence plus annotation. Never pass this to a predictor."""

    evidence: EvidenceWindow
    annotation: Annotation


# ------------------------------------------------------------------- prediction


class Assessment(StrEnum):
    likely_benign = "likely_benign"
    suspicious = "suspicious"
    abstain = "abstain"


class ArtifactKind(StrEnum):
    fixture_baseline = "fixture_baseline"
    research_candidate = "research_candidate"
    test_only = "test_only"


class CalibrationStatus(StrEnum):
    uncalibrated = "uncalibrated"
    uncalibrated_insufficient_data = "uncalibrated_insufficient_data"
    calibrated = "calibrated"


class Prediction(_Strict):
    schema_version: Literal["copley.prediction/v1"] = PREDICTION_SCHEMA_VERSION
    task_id: str
    window_id: str
    assessment: Assessment
    score: float | None = Field(
        description=(
            "Uncalibrated model score in [0, 1]; higher means more suspicious. "
            "Not a probability. Null when the model abstains before scoring."
        )
    )
    score_scale: str = "uncalibrated_model_output_0_1"
    threshold: float | None = None
    probability: float | None = Field(
        default=None, description="Only set when a calibration artifact is attached."
    )
    calibration_status: CalibrationStatus
    calibration_artifact_id: str | None = None
    calibration_population: str | None = None
    model_id: str
    weights_sha256: str
    preprocessing_version: str
    artifact_kind: ArtifactKind
    fixture_trained: bool
    input_event_ids: list[str]
    quality_warnings: list[str] = Field(default_factory=list)
    abstention_reason: str | None = None

    @field_validator("score", "probability")
    @classmethod
    def _finite(cls, v: float | None) -> float | None:
        if v is not None and not math.isfinite(v):
            raise ValueError("score/probability must be finite")
        return v

    @model_validator(mode="after")
    def _abstain_reason(self) -> Prediction:
        if self.assessment is Assessment.abstain and not self.abstention_reason:
            raise ValueError("abstentions must state a reason")
        if (
            self.probability is not None
            and self.calibration_status is not CalibrationStatus.calibrated
        ):
            raise ValueError("probability requires a calibration artifact")
        return self
