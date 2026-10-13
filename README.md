<p align="center">
  <img src="docs/copley-hero.png" alt="Copley: small, open cyber decision models. Built by Backbay Industries." width="100%">
</p>

# Copley

**Cyber defense you can own.**

Copley develops **small, open cyber decision models**. Each model maps a bounded window of
security telemetry to a typed assessment:

```text
likely_benign  |  suspicious  |  abstain
```

The project centers on local inference, reproducible evaluation, and task-specific models
that defenders can inspect and retrain.

Built by **Backbay Industries**.

## Process execution

The first task is suspicious Windows process execution (`process_execution.suspicious.v1`).
The comparison uses a pinned **Sigma rule subset**, a **character TF-IDF / logistic-regression
baseline**, and a planned **ModernBERT-base fine-tune** on the same normalized telemetry.

Evaluation examines detection coverage, false positives, and rule–model disagreements under
group-disjoint splits.

## Method

- **Input isolation.** Labels and provenance are excluded from model inputs.
- **Abstention.** Insufficient evidence can produce `abstain`.
- **Evaluation accounting.** Reports retain denominators, abstentions, and errors.

## Development

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

---

[Architecture](docs/architecture.md) · [Data plan](docs/data-plan.md) ·
[Evaluation](docs/evaluation.md) · [Training](docs/training.md)

Code: [Apache-2.0](LICENSE). Bundled SigmaHQ rules: DRL 1.1. External data and models retain
their own terms. [Third-party notices](THIRD_PARTY_NOTICES.md).
