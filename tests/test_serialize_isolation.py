"""Annotation-feature isolation and deterministic serialization."""

from __future__ import annotations

import pytest

from copley.data.serialize import (
    MODEL_INPUT_ALLOWLIST,
    WITHHELD_FROM_MODEL,
    serialize,
)
from copley.schemas import Label


def test_serialize_rejects_labeled_window(fixtures):
    rec = fixtures[0]
    with pytest.raises(TypeError, match="EvidenceWindow only"):
        serialize(rec)  # passing LabeledWindow must fail


def test_annotation_text_never_in_serialization(fixtures):
    for rec in fixtures:
        text = serialize(rec.evidence).text or ""
        # Label words and provenance must not leak into model input.
        assert (
            rec.annotation.label.value not in text.lower()
            or rec.annotation.label is Label.unlabeled
        )
        assert rec.annotation.provenance.category.value not in text
        assert rec.annotation.provenance.dataset_id not in text
        if rec.annotation.notes:
            assert rec.annotation.notes not in text


def test_withheld_fields_absent(fixtures):
    rec = fixtures[0]
    text = serialize(rec.evidence).text
    # Host, user, pids, raw timestamps are withheld from the model.
    assert rec.evidence.anchor.host not in text
    assert rec.evidence.anchor.user not in text
    assert "host=" not in text and "user=" not in text
    for field in WITHHELD_FROM_MODEL:
        assert f"\n{field}=" not in text


def test_allowlist_is_closed():
    assert not (set(MODEL_INPUT_ALLOWLIST) & set(WITHHELD_FROM_MODEL))


def test_serialization_deterministic(fixtures):
    for rec in fixtures:
        a = serialize(rec.evidence).text
        b = serialize(rec.evidence).text
        assert a == b


def test_overflow_abstains_not_truncates(fixtures):
    rec = fixtures[0]
    out = serialize(rec.evidence, max_bytes=20)
    assert out.text is None
    assert out.overflow_reason is not None
    assert "limit" in out.overflow_reason
