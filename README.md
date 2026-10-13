# Copley

**Copley is an open research project for small cyber decision models.** Its first
experiment scores Windows process activity and compares learned detection with a selected
set of Sigma rules. Copley is a project of **Backbay Industries**.

> **Status: scaffold complete; model not trained; not release ready.** Everything in this
> repository runs on *synthetic fixtures* for wiring tests. Synthetic-fixture results are
> smoke tests, **not** detection-performance evidence. No pretrained model has been trained
> or evaluated on real telemetry.

Copley turns a bounded snapshot of process-execution telemetry into a typed assessment
(`likely_benign`, `suspicious`, or `abstain`) for one fixed task:
`process_execution.suspicious.v1`. It is a small supervised detector, not a general
question-answering system and not an authorization decision.

## What works today

- A runnable local vertical slice: fixtures → validation → group-aware split → **real Sigma
  execution** → **real linear training** → evaluation → artifact reload → typed prediction.
- A reproducible **offline neural smoke test**: a tiny randomly initialized ModernBERT does
  forward/backward/save/reload through the real training path, producing a `test_only`
  artifact that can never masquerade as a trained detector.
- A CLI and a FastAPI app that produce identical predictions for the same artifact, plus a
  minimal same-origin demo page.
- Honest evaluation reports (JSON + Markdown + HTML) with denominators, abstentions, errors,
  and disagreement buckets, always labeled as a synthetic smoke test.

See [`HANDOFF.md`](HANDOFF.md) for the full status, verified commands, and limitations.

## Requirements

- Python 3.12 (`.python-version` pins it) and [uv](https://docs.astral.sh/uv/).
- Installing the core CLI does **not** require CUDA, FlashAttention, torch, or network
  access. Neural training is an optional extra.

## Quickstart (core, offline)

```bash
uv sync --locked --group dev
uv run --locked copley doctor
uv run --locked copley smoke --out artifacts/smoke
uv run --locked copley data validate --input examples/fixtures.jsonl
uv run --locked copley data fetch --manifest manifests/sources.yaml --dry-run
uv run --locked copley predict --artifact artifacts/smoke/linear --input examples/decision-request.json
```

`copley smoke` runs the whole vertical slice and writes a report to `artifacts/smoke/report/`.
It needs no GPU, no credentials, and downloads nothing.

## Neural path (optional `train` extra, offline smoke)

```bash
uv sync --locked --extra train
HF_HUB_OFFLINE=1 uv run --locked --extra train copley train --config configs/train-smoke.yaml
# Real training is NOT run here. Inspect its plan and prerequisites:
uv run --locked --extra train copley train --config configs/modernbert-base.yaml --dry-run
```

## Serving + demo (optional `serve` extra)

```bash
uv sync --locked --extra serve
uv run --locked --extra serve copley serve --artifact artifacts/smoke/linear --host 127.0.0.1
# then open http://127.0.0.1:8000/
```

The server binds to localhost, requires explicit artifact configuration, validates bounded
payloads, does not log raw telemetry, and never fabricates output when a model is
unavailable. **Public exposure requires additional authentication and operational controls.**

## Licensing

Copley's own code is Apache-2.0. Bundled SigmaHQ rules are under the Detection Rule License
(DRL) 1.1, original Copley rules are Apache-2.0, and external data/models stay under their own
terms. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Documentation

`docs/research.md`, `docs/architecture.md`, `docs/data-plan.md`, `docs/evaluation.md`,
`docs/training.md`, `docs/budget.md`, plus [`MODEL_CARD.md`](MODEL_CARD.md) and
[`DATA_CARD.md`](DATA_CARD.md).
