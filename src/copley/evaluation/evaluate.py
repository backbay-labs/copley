"""Evaluate detectors on a held-out split and emit machine-readable metrics.

Produces, for each detector (Sigma, linear, neural if available, and Sigma+model union):
denominators, confusion counts, precision/recall, average precision for scored models,
false-positive count/rate on the benign sample, abstentions, errors, and recall over ALL
labeled positives (including abstained/missed). Also records per-example results and the
disagreement matrix. Nothing here invents numbers; metrics that do not apply are null.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np

from copley.models.base import BasePredictor
from copley.rules.engine import SigmaRunResult
from copley.schemas import Assessment, Label, LabeledWindow


@dataclass
class DetectorMetrics:
    detector: str
    kind: str  # "rules" | "scored" | "union"
    total_windows: int
    labeled_positives: int
    labeled_negatives: int
    scored: int
    abstentions: int
    errors: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall_scored: float | None
    recall_all_positives: float | None
    false_positives: int
    benign_evaluated: int
    fp_per_10k_benign: float | None
    average_precision: float | None
    abstention_rate: float | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_div(a: float, b: float) -> float | None:
    return (a / b) if b else None


def _scored_metrics(
    detector: str,
    y_true: list[int],
    decisions: list[int | None],
    scores: list[float | None],
    *,
    total: int,
    errors: int,
) -> DetectorMetrics:
    pos = sum(1 for y in y_true if y == 1)
    neg = sum(1 for y in y_true if y == 0)
    tp = fp = tn = fn = 0
    scored = 0
    abst = 0
    for y, d in zip(y_true, decisions, strict=True):
        if d is None:
            abst += 1
            continue
        scored += 1
        if y == 1 and d == 1:
            tp += 1
        elif y == 1 and d == 0:
            fn += 1
        elif y == 0 and d == 1:
            fp += 1
        else:
            tn += 1
    benign_eval = tn + fp
    ap = _average_precision(y_true, scores)
    return DetectorMetrics(
        detector=detector,
        kind="scored",
        total_windows=total,
        labeled_positives=pos,
        labeled_negatives=neg,
        scored=scored,
        abstentions=abst,
        errors=errors,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=_safe_div(tp, tp + fp),
        recall_scored=_safe_div(tp, tp + fn),
        recall_all_positives=_safe_div(tp, pos),
        false_positives=fp,
        benign_evaluated=benign_eval,
        fp_per_10k_benign=(fp / benign_eval * 10_000) if benign_eval else None,
        average_precision=ap,
        abstention_rate=_safe_div(abst, len(y_true)),
    )


def _average_precision(y_true: list[int], scores: list[float | None]) -> float | None:
    pairs = [(s, y) for s, y in zip(scores, y_true, strict=True) if s is not None]
    if not pairs or len({y for _, y in pairs}) < 2:
        return None
    from sklearn.metrics import average_precision_score

    s = np.array([p[0] for p in pairs])
    y = np.array([p[1] for p in pairs])
    return float(average_precision_score(y, s))


@dataclass
class EvaluationResult:
    dataset_label: str
    synthetic_fixture: bool
    denominators: dict
    metrics: list[dict]
    per_example: list[dict]
    disagreements: dict
    thresholds: dict

    def to_dict(self) -> dict:
        return asdict(self)


def evaluate(
    records: list[LabeledWindow],
    sigma_result: SigmaRunResult,
    *,
    linear: BasePredictor | None = None,
    neural: BasePredictor | None = None,
    dataset_label: str = "fixtures",
    synthetic_fixture: bool = True,
) -> EvaluationResult:
    labeled = [r for r in records if r.annotation.label is not Label.unlabeled]
    y_true = [1 if r.annotation.label is Label.malicious else 0 for r in labeled]
    total = len(labeled)

    # Sigma decisions: match -> 1, else 0. Conversion failures counted separately as errors.
    sigma_dec = [1 if sigma_result.matched(r.evidence.window_id) else 0 for r in labeled]
    sigma_errors = len(sigma_result.failed_rules)

    detectors: list[DetectorMetrics] = []
    sigma_m = _scored_metrics(
        "sigma",
        y_true,
        [int(d) for d in sigma_dec],
        [None] * total,
        total=total,
        errors=sigma_errors,
    )
    sigma_m.kind = "rules"
    sigma_m.average_precision = None
    sigma_m.notes.append(
        f"selected subset of {len(sigma_result.ok_rules)} compiled rules; "
        f"{sigma_errors} unsupported/failed (not counted as negatives)"
    )
    detectors.append(sigma_m)

    linear_dec: list[int | None] = [None] * total
    linear_scores: list[float | None] = [None] * total
    if linear is not None:
        for i, r in enumerate(labeled):
            p = linear.predict(r.evidence)
            linear_scores[i] = p.score
            linear_dec[i] = (
                None
                if p.assessment is Assessment.abstain
                else (1 if p.assessment is Assessment.suspicious else 0)
            )
        detectors.append(
            _scored_metrics("linear", y_true, linear_dec, linear_scores, total=total, errors=0)
        )

    neural_dec: list[int | None] = [None] * total
    neural_scores: list[float | None] = [None] * total
    if neural is not None:
        for i, r in enumerate(labeled):
            p = neural.predict(r.evidence)
            neural_scores[i] = p.score
            neural_dec[i] = (
                None
                if p.assessment is Assessment.abstain
                else (1 if p.assessment is Assessment.suspicious else 0)
            )
        nm = _scored_metrics("neural", y_true, neural_dec, neural_scores, total=total, errors=0)
        nm.notes.append(
            "randomly initialized smoke artifact; not a trained detector"
            if neural.metadata.artifact_kind.value == "test_only"
            else ""
        )
        detectors.append(nm)

    # Union: Sigma OR the primary learned model (linear if present else neural).
    primary = linear_dec if linear is not None else (neural_dec if neural is not None else None)
    if primary is not None:
        union_dec = [
            1
            if (sigma_dec[i] == 1 or primary[i] == 1)
            else (None if primary[i] is None and sigma_dec[i] == 0 else 0)
            for i in range(total)
        ]
        um = _scored_metrics(
            "sigma_union_model", y_true, union_dec, [None] * total, total=total, errors=0
        )
        um.kind = "union"
        um.average_precision = None
        um.notes.append("Sigma OR primary learned model; may raise recall and false positives")
        detectors.append(um)

    per_example = []
    for i, r in enumerate(labeled):
        per_example.append(
            {
                "window_id": r.evidence.window_id,
                "label": r.annotation.label.value,
                "provenance": r.annotation.provenance.category.value,
                "evidence_profile": r.evidence.evidence_profile,
                "sigma_match": bool(sigma_dec[i]),
                "sigma_rules": sigma_result.window_matched.get(r.evidence.window_id, []),
                "linear_score": linear_scores[i],
                "linear_decision": linear_dec[i],
                "neural_score": neural_scores[i],
                "neural_decision": neural_dec[i],
            }
        )

    disagreements = _disagreements(labeled, sigma_dec, primary) if primary is not None else {}

    return EvaluationResult(
        dataset_label=dataset_label,
        synthetic_fixture=synthetic_fixture,
        denominators={
            "total_labeled_windows": total,
            "labeled_positives": sum(y_true),
            "labeled_negatives": total - sum(y_true),
            "independent_groups": len({_gk(r) for r in labeled}),
            "unsupported_rules": sigma_errors,
        },
        metrics=[d.to_dict() for d in detectors],
        per_example=per_example,
        disagreements=disagreements,
        thresholds={
            "linear": linear.metadata.threshold if linear else None,
            "neural": neural.metadata.threshold if neural else None,
        },
    )


def _gk(r: LabeledWindow) -> str:
    from copley.data.split import group_key

    return group_key(r)


def _disagreements(
    labeled: list[LabeledWindow], sigma_dec: list[int], model_dec: list[int | None]
) -> dict:
    buckets: dict[str, list[str]] = {"rules_only": [], "model_only": [], "both": [], "neither": []}
    for i, r in enumerate(labeled):
        s = sigma_dec[i] == 1
        m = model_dec[i] == 1
        wid = r.evidence.window_id
        if s and m:
            buckets["both"].append(wid)
        elif s and not m:
            buckets["rules_only"].append(wid)
        elif m and not s:
            buckets["model_only"].append(wid)
        else:
            buckets["neither"].append(wid)
    return {k: {"count": len(v), "window_ids": v} for k, v in buckets.items()}
