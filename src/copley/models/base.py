"""Shared prediction flow used by every learned predictor.

Subclasses only implement `_score_text(text) -> float` (probability of the positive
class in [0, 1]). This base class owns evidence serialization, the abstention policy,
threshold application, calibration attachment, and typed output construction, so the CLI
and API get identical behavior regardless of backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from copley.data.serialize import DEFAULT_MAX_BYTES, DEFAULT_MAX_EVENTS, serialize
from copley.models.artifact import ArtifactMetadata
from copley.schemas import (
    SUPPORTED_TASKS,
    Assessment,
    CalibrationStatus,
    EvidenceWindow,
    Prediction,
)


class BasePredictor(ABC):
    def __init__(
        self,
        metadata: ArtifactMetadata,
        *,
        calibration: dict | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_events: int = DEFAULT_MAX_EVENTS,
    ) -> None:
        self.metadata = metadata
        self.calibration = calibration
        self.max_bytes = max_bytes
        self.max_events = max_events

    @abstractmethod
    def _score_text(self, text: str) -> float:
        """Return P(positive) in [0, 1] for a serialized window."""

    def _apply_calibration(self, score: float) -> float | None:
        if (
            not self.calibration
            or self.metadata.calibration.status is not CalibrationStatus.calibrated
        ):
            return None
        # Isotonic-style step mapping stored as sorted (x, y) knots.
        knots = self.calibration.get("knots")
        if not knots:
            return None
        prob = knots[0][1]
        for x, y in knots:
            if score >= x:
                prob = y
            else:
                break
        return float(min(1.0, max(0.0, prob)))

    def predict(self, window: EvidenceWindow) -> Prediction:
        if not isinstance(window, EvidenceWindow):
            raise TypeError("predict() requires an EvidenceWindow")

        base = dict(
            task_id=window.task_id,
            window_id=window.window_id,
            model_id=self.metadata.model_id,
            weights_sha256=self.metadata.weights_sha256,
            preprocessing_version=self.metadata.preprocessing_version,
            artifact_kind=self.metadata.artifact_kind,
            fixture_trained=self.metadata.fixture_trained,
            calibration_status=self.metadata.calibration.status,
            calibration_artifact_id=self.metadata.calibration.artifact_id,
            calibration_population=self.metadata.calibration.population,
            threshold=self.metadata.threshold,
        )

        if window.task_id not in SUPPORTED_TASKS:
            # Should be caught at schema validation, but never classify an unsupported task.
            raise ValueError(f"unsupported task_id: {window.task_id}")
        if window.task_id != self.metadata.task_id:
            raise ValueError(f"artifact trained for {self.metadata.task_id}, got {window.task_id}")

        ser = serialize(window, max_bytes=self.max_bytes, max_events=self.max_events)
        if not ser.usable:
            reason = ser.insufficient_reason or ser.overflow_reason or "insufficient evidence"
            return Prediction(
                assessment=Assessment.abstain,
                score=None,
                input_event_ids=ser.input_event_ids,
                quality_warnings=ser.warnings,
                abstention_reason=reason,
                **base,
            )

        if ser.text is None:  # unreachable given ser.usable, but keeps types/guards explicit
            raise RuntimeError("serializer returned no text for a usable window")
        score = float(self._score_text(ser.text))
        probability = self._apply_calibration(score)
        threshold = self.metadata.threshold if self.metadata.threshold is not None else 0.5
        assessment = Assessment.suspicious if score >= threshold else Assessment.likely_benign
        return Prediction(
            assessment=assessment,
            score=score,
            probability=probability,
            input_event_ids=ser.input_event_ids,
            quality_warnings=ser.warnings,
            **base,
        )

    def score_batch(self, windows: list[EvidenceWindow]) -> list[Prediction]:
        return [self.predict(w) for w in windows]
