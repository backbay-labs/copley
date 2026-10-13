"""Offline tiny neural forward/backward/save/reload. Requires the `train` extra.

Skipped automatically when torch is not installed, so the core test suite needs no GPU,
credentials, or model downloads.
"""

from __future__ import annotations

import pytest

pytest.importorskip("torch")
pytest.importorskip("transformers")

from copley.training.config import TrainingConfig  # noqa: E402
from copley.training.neural import dry_run, train  # noqa: E402

pytestmark = pytest.mark.neural


def _cfg(tmp_path):
    return TrainingConfig(
        mode="tiny",
        epochs=2,
        batch_size=4,
        gradient_accumulation_steps=1,
        max_length=64,
        device="cpu",
        dtype="float32",
        output_dir=tmp_path / "neural",
        tiny_vocab_size=256,
        tiny_max_position=64,
        max_steps=10,
    )


def test_tiny_forward_backward_save_reload(tmp_path, split_result):
    import os

    os.environ["HF_HUB_OFFLINE"] = "1"
    from copley.models.neural import NeuralPredictor

    cfg = _cfg(tmp_path)
    outcome = train(cfg, split_result.partitions["train"], split_result.partitions["validation"])
    assert outcome.steps > 0
    assert outcome.final_train_loss == outcome.final_train_loss  # finite (not NaN)
    assert outcome.metadata.artifact_kind.value == "test_only"
    assert outcome.metadata.fixture_trained is True

    # Reload and verify deterministic inference parity.
    w = split_result.partitions["test"][0].evidence
    p1 = NeuralPredictor.load(cfg.output_dir)
    p2 = NeuralPredictor.load(cfg.output_dir)
    pred1 = p1.predict(w)
    pred2 = p2.predict(w)
    assert pred1.score == pred2.score
    assert pred1.artifact_kind.value == "test_only"


def test_test_only_artifact_cannot_masquerade(tmp_path, split_result):
    cfg = _cfg(tmp_path)
    outcome = train(cfg, split_result.partitions["train"], split_result.partitions["validation"])
    md = outcome.metadata
    # A deployable-looking kind must never attach to a fixture-trained smoke artifact.
    assert md.artifact_kind.value == "test_only"
    assert md.fixture_trained is True
    assert md.base_model is None  # tiny mode never claims a real backbone


def test_dry_run_reports_download_requirement(tmp_path, split_result):
    real = TrainingConfig(mode="real", output_dir=tmp_path / "r")
    plan = dry_run(real, split_result.partitions["train"])
    assert plan["requires_model_download"] is True
    assert plan["expected_artifact_kind"] == "research_candidate"
    assert plan["estimated_cost_usd"].startswith("unknown")
