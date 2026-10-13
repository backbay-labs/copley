"""End-to-end orchestration shared by the CLI and tests.

`run_smoke` performs the full vertical slice on synthetic fixtures:
fixtures -> validation -> grouped split -> real linear training -> Sigma execution ->
evaluation -> artifact reload -> typed prediction. It never downloads weights, contacts
a network service, or needs a GPU, and it fails loudly on any broken stage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from copley.data.fixtures import build_fixtures
from copley.data.io import load_labeled, write_labeled
from copley.data.split import SplitResult, split
from copley.data.validate import account_split, validate_records
from copley.evaluation.evaluate import evaluate
from copley.evaluation.report import write_reports
from copley.models.calibration import (
    fit_calibration,
    reliability_table,
    select_threshold,
    write_calibration,
)
from copley.models.linear import LinearPredictor, train_linear
from copley.rules.engine import compile_rules, run_rules
from copley.rules.manifest import default_manifest_path, load_rule_manifest
from copley.schemas import ArtifactKind, CalibrationStatus, Label


@dataclass
class SmokeResult:
    out_dir: Path
    fixtures_path: Path
    linear_dir: Path
    report_paths: dict[str, Path]
    split_counts: dict[str, int]
    sigma_ok: int
    sigma_failed: int
    example_prediction: dict


def _score_split(predictor: LinearPredictor, records) -> tuple[list[float], list[int]]:
    scores: list[float] = []
    labels: list[int] = []
    for r in records:
        if r.annotation.label is Label.unlabeled:
            continue
        p = predictor.predict(r.evidence)
        if p.score is None:
            continue
        scores.append(p.score)
        labels.append(1 if r.annotation.label is Label.malicious else 0)
    return scores, labels


def run_smoke(out_dir: Path, *, seed: int = 42) -> SmokeResult:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. fixtures -> disk
    fixtures = build_fixtures()
    fixtures_path = out_dir / "fixtures.jsonl"
    write_labeled(fixtures_path, fixtures)

    # 2. validation (reload from disk to exercise IO + schema)
    loaded = load_labeled(fixtures_path)
    if not loaded.ok:
        raise RuntimeError(f"fixture validation failed: {loaded.errors}")
    summary = validate_records(loaded.records, loaded.errors)
    (out_dir / "validation.json").write_text(
        json.dumps(summary.to_dict(), indent=2), encoding="utf-8"
    )

    # 3. grouped split
    sr: SplitResult = split(loaded.records, seed=seed)
    if not sr.ok:
        raise RuntimeError(f"split failed: {sr.reason}")
    acc = account_split(sr)
    if acc.group_leakage:
        raise RuntimeError(f"group leakage detected across splits: {acc.group_leakage}")
    (out_dir / "split.json").write_text(json.dumps(acc.to_dict(), indent=2), encoding="utf-8")

    # 4. real linear training (train split only)
    linear_dir = out_dir / "linear"
    train_linear(
        sr.partitions["train"],
        linear_dir,
        model_id="copley-process-linear-fixture-smoke",
        artifact_kind=ArtifactKind.fixture_baseline,
        fixture_trained=True,
        seed=seed,
    )

    # 5. threshold on validation, calibration on calibration split
    predictor = LinearPredictor.load(linear_dir)
    val_scores, val_labels = _score_split(predictor, sr.partitions["validation"])
    choice = select_threshold(val_scores, val_labels, target_fpr=0.0)
    cal_scores, cal_labels = _score_split(predictor, sr.partitions["calibration"])
    cal_status, cal_payload = fit_calibration(cal_scores, cal_labels)
    md = predictor.metadata
    md.threshold = choice.threshold
    md.threshold_basis = choice.basis
    md.calibration.status = cal_status
    if cal_status is CalibrationStatus.calibrated and cal_payload:
        md.calibration.artifact_id = "calibration.json"
        md.calibration.population = "synthetic fixture calibration split"
        md.calibration.method = cal_payload.get("method")
        write_calibration(linear_dir, cal_payload)
    md.extra["reliability_calibration_split"] = reliability_table(cal_scores, cal_labels)
    md.save(linear_dir)

    # 6. Sigma execution
    entries = load_rule_manifest(default_manifest_path())
    compiled = compile_rules([e.path for e in entries])
    sigma = run_rules([r.evidence for r in sr.partitions["test"]], compiled)

    # 7. evaluation on frozen test split + artifact reload
    predictor = LinearPredictor.load(linear_dir)  # reload to prove save/reload parity
    result = evaluate(
        sr.partitions["test"],
        sigma,
        linear=predictor,
        dataset_label="synthetic-fixtures-test-split",
        synthetic_fixture=True,
    )
    report_paths = write_reports(result.to_dict(), out_dir / "report")

    # 8. typed prediction on a single held-out example
    example = sr.partitions["test"][0]
    prediction = predictor.predict(example.evidence)

    return SmokeResult(
        out_dir=out_dir,
        fixtures_path=fixtures_path,
        linear_dir=linear_dir,
        report_paths=report_paths,
        split_counts=sr.counts(),
        sigma_ok=len(sigma.ok_rules),
        sigma_failed=len(sigma.failed_rules),
        example_prediction=prediction.model_dump(mode="json"),
    )
