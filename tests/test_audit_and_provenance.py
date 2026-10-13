"""Source/label correlation audit and per-run provenance record."""

from __future__ import annotations

from copley.data.audit import audit_source_label_correlation
from copley.data.fixtures import build_fixtures
from copley.provenance import dataset_digest, run_record
from copley.schemas import Label


def test_fixtures_have_both_classes_per_source(fixtures):
    # Synthetic fixtures use one source id but carry both classes, so not source-disjoint.
    audit = audit_source_label_correlation(fixtures)
    assert audit.sources_with_both_classes >= 1
    assert audit.class_disjoint_sources is False


def test_class_disjoint_sources_flagged():
    fixtures = build_fixtures()
    # Rewrite provenance so benign and malicious come from disjoint sources.
    forged = []
    for rec in fixtures:
        src = "lab_malware" if rec.annotation.label is Label.malicious else "lab_benign"
        prov = rec.annotation.provenance.model_copy(update={"source_id": src})
        ann = rec.annotation.model_copy(update={"provenance": prov})
        forged.append(rec.model_copy(update={"annotation": ann}))
    audit = audit_source_label_correlation(forged)
    assert audit.class_disjoint_sources is True
    assert audit.exploratory_only is True
    assert any("source" in r.lower() for r in audit.reasons)


def test_single_source_is_exploratory_for_cross_source():
    # One labeled source -> cross-source generalization unassessed -> exploratory only.
    fixtures = build_fixtures()
    audit = audit_source_label_correlation(fixtures)
    assert audit.total_sources == 1
    assert audit.exploratory_only is True


def test_dataset_digest_order_independent(fixtures):
    a = dataset_digest(fixtures)
    b = dataset_digest(list(reversed(fixtures)))
    assert a == b
    assert a.startswith("sha256:")


def test_dataset_digest_changes_with_label(fixtures):
    base = dataset_digest(fixtures)
    flipped = [fixtures[0].model_copy(deep=True), *fixtures[1:]]
    other_label = (
        Label.benign if fixtures[0].annotation.label is Label.malicious else Label.malicious
    )
    ann = flipped[0].annotation.model_copy(update={"label": other_label})
    flipped[0] = flipped[0].model_copy(update={"annotation": ann})
    assert dataset_digest(flipped) != base


def test_run_record_shape():
    rec = run_record(
        kind="test",
        config={"a": 1},
        seed=42,
        source_digests={"s": "sha256:x"},
        split_digests={"train": "sha256:y"},
        artifact_digests={"linear": "deadbeef"},
        elapsed_seconds=1.23,
    )
    assert rec["kind"] == "test"
    assert rec["seed"] == 42
    assert "lock_digest" in rec
    assert rec["source_digests"] == {"s": "sha256:x"}
    assert rec["elapsed_seconds"] == 1.23
