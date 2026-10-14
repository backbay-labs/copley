<p align="center">
  <img src="docs/copley-hero.png" alt="Copley: small, open cyber decision models. Built by Backbay Industries." width="100%">
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/copley/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/copley/ci.yml?branch=main&amp;label=CI&amp;style=flat&amp;labelColor=30363d" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-007ec6?style=flat&amp;labelColor=30363d" alt="Code license: Apache-2.0"></a>
  <a href="MODEL_CARD.md"><img src="https://img.shields.io/badge/Stage-Research-d97706?style=flat&amp;labelColor=30363d" alt="Stage: research"></a>
  <a href="https://pytorch.org/"><img src="https://img.shields.io/badge/Training-PyTorch-EE4C2C?style=flat&amp;logo=pytorch&amp;logoColor=EE4C2C&amp;labelColor=30363d" alt="Neural training: PyTorch"></a>
</p>

Copley develops **small, open cyber decision models**. Each model maps a bounded window of
security telemetry to `likely_benign`, `suspicious`, or `abstain`. The project centers on
local inference, reproducible evaluation, and models that defenders can inspect and retrain.

## Research

**Rule-miss recovery at a fixed false-positive budget.** The research objective is to measure
the fraction of attack executions missed by a pinned rule baseline that a learned model
detects, alongside the additional false-positive decisions per million benign windows.

The first task is suspicious Windows process execution (`process_execution.suspicious.v1`).
The comparison uses a pinned Sigma rule subset, a character TF-IDF / logistic-regression
baseline, and a planned ModernBERT-base fine-tune on the same normalized telemetry, with
group-disjoint evaluation splits.

- **Input isolation.** Labels and provenance are excluded from model inputs.
- **Abstention.** Insufficient evidence can produce `abstain`.
- **Evaluation accounting.** Reports retain denominators, abstentions, and errors.

## Quickstart

Python 3.12 + [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run --locked copley smoke --out artifacts/smoke
```

Inspect the report at `artifacts/smoke/report/`.

> **Early research.** The pipeline runs on synthetic fixtures: smoke tests, not detection
> results. No real-telemetry training or evaluation yet. The next milestone is a reviewed real
> corpus and the first held-out comparison.

Contributions are welcome in source-balanced telemetry, reviewed labels, and independent
evaluation.

## Documentation

[Architecture](docs/architecture.md) · [Data plan](docs/data-plan.md) ·
[Evaluation](docs/evaluation.md) · [Training](docs/training.md)

Code: [Apache-2.0](LICENSE). Bundled SigmaHQ rules: DRL 1.1. External data and models retain
their own terms. [Third-party notices](THIRD_PARTY_NOTICES.md).
