# Architecture

Copley is a small Python package (`src/copley/`) with a thin Typer CLI and an optional FastAPI
app. Everything flows through one typed data contract.

## Modules

```
copley/
  schemas.py          Typed contract: EvidenceWindow (model input), Annotation/Provenance
                      (never model input), Prediction (output).
  data/
    serialize.py      Deterministic allowlist serializer (EvidenceWindow -> text).
    fixtures.py       Original synthetic fixtures (benign + controlled-exec templates).
    io.py             JSONL load/write with per-record error reporting.
    split.py          Group-aware split + dedup; visible insufficient_data result.
    validate.py       Dataset + split accounting (labels, groups, leakage, future events).
    fetch.py          Manifest-driven opt-in fetcher with dry-run; refuses LFS pointers.
    adapters.py       Sysmon XML -> unlabeled evidence windows.
  rules/
    manifest.py       Load + sha256-verify the pinned rule subset.
    engine.py         pySigma SQLite compilation + execution against in-memory SQLite.
    library/          sigmahq/ (DRL-1.1, vendored) and local/ (Apache-2.0, original).
  models/
    artifact.py       ArtifactMetadata + Predictor protocol + digest verification.
    base.py           Shared predict() flow: serialize -> abstain policy -> threshold.
    linear.py         TF-IDF + logistic regression train/load.
    neural.py         ModernBERT predictor (lazy torch import).
    calibration.py    Threshold selection (validation) + isotonic calibration (calibration).
    loader.py         Dispatch artifact loading by model_type.
  training/
    config.py         Pydantic TrainingConfig (import-safe without torch).
    neural.py         Tiny + real training loop, dry-run, save/reload.
    tokenizer.py      char_hash (offline tiny) and hf (real) tokenizers.
  evaluation/
    evaluate.py       Compare Sigma / linear / neural / union; honest denominators.
    report.py         Markdown + HTML from metrics JSON only.
  pipeline.py         run_smoke(): the full vertical slice used by CLI + tests.
  cli.py              Typer CLI.
  api.py              FastAPI app (serve extra).
  web/page.py         Minimal server-rendered demo page.
```

## The three detection paths

- **A. Sigma** — pinned rule subset compiled through pySigma's SQLite backend and executed
  against the same normalized evidence the models see. Conversion failures are recorded, never
  treated as negative matches. Event matches aggregate to the window via a documented rule
  (`anchor_match`).
- **B. Linear baseline** — a real trained+persisted scikit-learn pipeline. Train and inference
  share the exact serializer and vectorizer.
- **C. Neural candidate** — ModernBERT sequence classification behind the `train` extra. A tiny
  randomly initialized configuration is used for offline smoke tests; the pretrained backbone
  is used only for real experiments (not run here).

## Abstention and error policy

- Unsupported `task_id` → schema validation error (never a prediction).
- Missing/invalid/tampered artifact or incompatible schema → explicit error, never a benign
  prediction or a silent backend switch.
- Valid but insufficient evidence (e.g., empty anchor, overflow) → `abstain` with a reason.
- A low score means "less suspicious by this model," never authorization or safety.

## Typed contract invariant

`serialize()` and every predictor accept `EvidenceWindow` only and raise `TypeError` on a
`LabeledWindow`. The model-input allowlist is closed and disjoint from the withheld set
(host/user/pids/raw timestamps). Tests assert annotation text never appears in serialized
input.
