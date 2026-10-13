# Model card — Copley process-execution detector

> **This card describes software scaffolding, not a trained detector.** The only artifacts
> that exist today are a linear baseline and a neural model trained on **synthetic fixtures**
> for wiring tests. They are not fit for detection use.

## Overview

- **Project:** Copley (Backbay Industries).
- **Task:** `process_execution.suspicious.v1` — score one anchor Windows process-creation event
  (with optional genuinely-available related events) and emit `likely_benign` / `suspicious` /
  `abstain`.
- **Internal artifact name (until a real checkpoint exists):** `copley-process-modernbert-base`.
- **Artifact kinds:** `fixture_baseline` (linear, fixture-trained), `test_only` (tiny neural
  smoke), `research_candidate` (real neural run — not yet produced).

## Artifacts that exist now

| Artifact | Type | Trained on | Kind | Fit for detection? |
|---|---|---|---|---|
| `copley-process-linear-fixture-smoke` | TF-IDF + logistic regression | synthetic fixtures | `fixture_baseline` | **No** |
| `copley-process-modernbert-tiny-smoke` | randomly initialized tiny ModernBERT | synthetic fixtures | `test_only` | **No** |

Every prediction carries `fixture_trained=true` and the artifact kind, so consumers can see the
fixture status. Randomly initialized test artifacts are marked `test_only` and never load as
normal deployable detectors.

## Inputs and outputs

- **Input:** an `EvidenceWindow` (see `docs/architecture.md`). Only allowlisted process fields
  reach the model (image, original file name, command line, current directory, integrity level,
  parent image, parent command line). Host, user, PIDs, and raw timestamps are withheld.
- **Output:** a typed `Prediction` with an **uncalibrated** score in [0, 1] (higher = more
  suspicious), assessment, threshold, calibration status, model id + weights digest,
  preprocessing version, the supplied `input_event_ids`, quality warnings, and an abstention
  reason when applicable. `probability` is null unless a calibration artifact is attached.

## Metrics

- Real-world detection metrics: **unknown / unmeasured.** No evaluation on real telemetry has
  been performed.
- Synthetic-fixture smoke metrics exist only to prove the comparison runs; see
  `docs/evaluation.md`. They are **not** performance evidence.

## Intended use and out-of-scope

- **Intended (eventually):** reproducible research comparison of learned detection vs. a
  selected Sigma subset on Windows process execution.
- **Out of scope / not supported:** authorization decisions, intent attribution, full ATT&CK
  technique labeling, arbitrary NL questions, autonomous response, production telemetry
  ingestion, full Sigma coverage. A low score is not a safety guarantee.

## Limitations

- Trained only on tiny synthetic data; no generalization claim.
- Sigma comparison uses a **selected pinned subset**, not full Sigma.
- Scores are uncalibrated unless a calibration artifact is attached.
- Explanations: `input_event_ids` lists evidence supplied, not a causal explanation. Matched
  Sigma conditions are attributed to the rules engine, separately.

## Ethical / safety notes

Do not present fixture-trained output as detection capability. Do not expose the demo server
publicly without authentication and operational controls.
