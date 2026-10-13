"""Linear training, artifact integrity, abstention, and missing-artifact errors."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from copley.models.artifact import ArtifactError
from copley.models.linear import LinearPredictor, train_linear
from copley.models.loader import load_predictor
from copley.schemas import (
    TASK_PROCESS_EXECUTION,
    Assessment,
    CalibrationStatus,
    EvidenceWindow,
    ProcessEvent,
)

_T = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def linear_dir(tmp_path, split_result):
    d = tmp_path / "linear"
    train_linear(split_result.partitions["train"], d, model_id="test-linear")
    return d


def test_train_and_load(linear_dir):
    pred = LinearPredictor.load(linear_dir)
    assert pred.metadata.model_type == "linear"
    assert pred.metadata.fixture_trained is True


def test_missing_artifact_errors(tmp_path):
    with pytest.raises(ArtifactError):
        LinearPredictor.load(tmp_path / "nope")


def test_tampered_weights_detected(linear_dir):
    (linear_dir / "model.joblib").write_bytes(b"corrupted")
    with pytest.raises(ArtifactError, match="digest mismatch"):
        LinearPredictor.load(linear_dir)


def test_single_class_training_errors(tmp_path, fixtures):
    benign_only = [r for r in fixtures if r.annotation.label.value == "benign"]
    with pytest.raises(ArtifactError, match="both classes"):
        train_linear(benign_only, tmp_path / "x", model_id="bad")


def test_prediction_is_typed_and_finite(linear_dir, split_result):
    pred = LinearPredictor.load(linear_dir)
    for rec in split_result.partitions["test"]:
        out = pred.predict(rec.evidence)
        assert out.task_id == TASK_PROCESS_EXECUTION
        assert out.score is None or 0.0 <= out.score <= 1.0
        assert out.probability is None  # uncalibrated by default
        assert out.fixture_trained is True
        assert out.artifact_kind.value == "fixture_baseline"


def test_abstains_on_empty_evidence(linear_dir):
    pred = LinearPredictor.load(linear_dir)
    ev = ProcessEvent(
        event_id="e0", timestamp=_T, observed_at=_T, image=None, command_line=None, parent_image="p"
    )
    w = EvidenceWindow(
        window_id="w", task_id=TASK_PROCESS_EXECUTION, as_of=_T, anchor_event_id="e0", events=[ev]
    )
    out = pred.predict(w)
    assert out.assessment is Assessment.abstain
    assert out.abstention_reason
    assert out.score is None


def test_loader_dispatches_linear(linear_dir):
    pred = load_predictor(linear_dir)
    assert pred.metadata.model_type == "linear"


def test_probability_requires_calibration():
    # Prediction schema should reject a probability without calibrated status.
    from copley.schemas import ArtifactKind, Prediction

    with pytest.raises(Exception, match="calibration"):
        Prediction(
            task_id=TASK_PROCESS_EXECUTION,
            window_id="w",
            assessment=Assessment.suspicious,
            score=0.9,
            probability=0.9,
            calibration_status=CalibrationStatus.uncalibrated,
            model_id="m",
            weights_sha256="x",
            preprocessing_version="v",
            artifact_kind=ArtifactKind.fixture_baseline,
            fixture_trained=True,
            input_event_ids=["e0"],
        )
