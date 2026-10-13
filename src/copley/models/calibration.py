"""Threshold selection and post-hoc calibration.

Thresholds are chosen on the validation split and frozen before test evaluation.
Calibration is fit on the separate calibration split using isotonic regression, and only
when there is enough data in both classes; otherwise probability stays null and the status
is `uncalibrated_insufficient_data`. A sigmoid/softmax is never assumed to be calibrated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.isotonic import IsotonicRegression

from copley.schemas import CalibrationStatus

MIN_PER_CLASS_FOR_CALIBRATION = 10


@dataclass
class ThresholdChoice:
    threshold: float
    basis: str
    achieved_fpr: float | None
    achieved_recall: float | None


def select_threshold(
    scores: list[float],
    labels: list[int],
    *,
    target_fpr: float | None = None,
) -> ThresholdChoice:
    """Pick a threshold on validation scores.

    With a `target_fpr` and enough benign examples, choose the lowest threshold whose
    benign false-positive rate is <= target. Otherwise fall back to the F1-optimal
    threshold over candidate scores and say so, rather than manufacturing an FP claim.
    """
    s = np.asarray(scores, dtype=float)
    y = np.asarray(labels, dtype=int)
    if s.size == 0 or len(set(labels)) < 2:
        return ThresholdChoice(0.5, "default_no_validation_signal", None, None)

    candidates = sorted(set(s.tolist()) | {0.5})
    neg = s[y == 0]
    pos = s[y == 1]

    if target_fpr is not None and neg.size >= 5:
        best: ThresholdChoice | None = None
        for t in candidates:
            fpr = float((neg >= t).mean())
            recall = float((pos >= t).mean()) if pos.size else None
            if fpr <= target_fpr:
                best = ThresholdChoice(float(t), f"validation_fpr<={target_fpr}", fpr, recall)
                break
        if best is not None:
            return best
        # Could not meet target; report the strictest available operating point.
        t = float(max(candidates))
        return ThresholdChoice(
            t,
            f"validation_fpr_target_{target_fpr}_unreachable",
            float((neg >= t).mean()),
            float((pos >= t).mean()) if pos.size else None,
        )

    # F1-optimal fallback.
    best_t, best_f1 = 0.5, -1.0
    for t in candidates:
        tp = float((pos >= t).sum())
        fp = float((neg >= t).sum())
        fn = float((pos < t).sum())
        denom = 2 * tp + fp + fn
        f1 = (2 * tp / denom) if denom else 0.0
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    recall_f: float | None = float((pos >= best_t).mean()) if pos.size else None
    fpr_f: float | None = float((neg >= best_t).mean()) if neg.size else None
    return ThresholdChoice(best_t, "validation_f1_optimal", fpr_f, recall_f)


def fit_calibration(
    scores: list[float], labels: list[int]
) -> tuple[CalibrationStatus, dict | None]:
    y = np.asarray(labels, dtype=int)
    pos = int((y == 1).sum())
    neg = int((y == 0).sum())
    if pos < MIN_PER_CLASS_FOR_CALIBRATION or neg < MIN_PER_CLASS_FOR_CALIBRATION:
        return CalibrationStatus.uncalibrated_insufficient_data, {
            "reason": f"need >= {MIN_PER_CLASS_FOR_CALIBRATION} per class; have pos={pos} neg={neg}",
            "positive": pos,
            "negative": neg,
        }
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    s = np.asarray(scores, dtype=float)
    iso.fit(s, y)
    xs = np.unique(s)
    ys = iso.predict(xs)
    knots = [[float(x), float(v)] for x, v in zip(xs, ys, strict=True)]
    return CalibrationStatus.calibrated, {
        "method": "isotonic",
        "knots": knots,
        "positive": pos,
        "negative": neg,
    }


def reliability_table(scores: list[float], labels: list[int], *, bins: int = 5) -> list[dict]:
    """Coarse reliability diagnostic: observed positive rate per score bin."""
    s = np.asarray(scores, dtype=float)
    y = np.asarray(labels, dtype=int)
    out: list[dict] = []
    edges = np.linspace(0.0, 1.0, bins + 1)
    for i in range(bins):
        lo, hi = edges[i], edges[i + 1]
        mask = (s >= lo) & (s < hi if i < bins - 1 else s <= hi)
        n = int(mask.sum())
        out.append(
            {
                "bin": f"[{lo:.2f},{hi:.2f}{']' if i == bins - 1 else ')'}",
                "n": n,
                "mean_score": float(s[mask].mean()) if n else None,
                "observed_positive_rate": float(y[mask].mean()) if n else None,
            }
        )
    return out


def write_calibration(directory: Path, payload: dict) -> None:
    (directory / "calibration.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
