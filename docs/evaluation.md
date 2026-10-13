# Evaluation

`copley evaluate` (and `run_smoke`) compare four detectors on a held-out split: **Sigma**, the
**linear** baseline, the **neural** candidate (when available), and a **Sigma + model union**.
Reports are generated from the metrics JSON only (`evaluation/report.py`).

## What is reported

- **Denominators**: total labeled windows, labeled positives/negatives, independent groups,
  unsupported/failed rules.
- Per detector: confusion counts (tp/fp/tn/fn), precision, recall over scored examples, recall
  over **all** labeled positives (including abstained/missed), average precision (scored models
  only), abstentions and abstention rate, false-positive count, and false positives per 10,000
  **evaluated benign windows** (with the raw count alongside).
- **Disagreements**: rules-only, model-only, both, neither.
- **Thresholds**: the frozen operating point and how it was chosen.

## Honesty rules baked in

- Metrics that do not apply to a rule-only output (e.g., average precision) are `null`, not
  fabricated.
- FP-per-10k is derived from the actual evaluated benign count; **zero observed false positives
  is not a zero false-positive rate.** We do not project production alerts/day without
  representative traffic.
- Uncertainty intervals are not manufactured. With grouped/correlated observations and tiny
  samples, uncertainty is left unassessed rather than invented.
- An all-abstain model cannot look successful: recall over all labeled positives is always shown.
- Thresholds are frozen on validation before test evaluation. When a validation FP target
  cannot be meaningfully estimated, that is stated (`threshold_basis`), not papered over.

## Current synthetic smoke result (illustrative of wiring, not performance)

From `copley smoke` on the synthetic fixtures **test split** (6 windows, 2 independent groups):

| detector | tp | fp | tn | fn | precision | recall | AP |
|---|---|---|---|---|---|---|---|
| sigma | 3 | 0 | 3 | 0 | 1.00 | 1.00 | n/a (rules) |
| linear | 3 | 3 | 0 | 0 | 0.50 | 1.00 | 1.00 |
| sigma ∪ linear | 3 | 3 | 0 | 0 | 0.50 | 1.00 | n/a |

**Interpretation:** Sigma looks perfect only because the malicious fixtures were authored to
match the selected rules — this is circular by construction and says nothing about real
detection. The linear model, trained on 6 examples from 2 groups, labels everything suspicious
(precision 0.50); that is a tiny-data artifact. **These numbers measure plumbing, not cyber
capability.** Negative/weak results are kept on purpose. The point is a reproducible comparison.

## Latency

Not advertised. Measure locally with hardware, batch size, input length, warm/cold status, and
whether preprocessing is included before quoting any number.
