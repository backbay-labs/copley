<p align="center">
  <img src="docs/copley-hero.png" alt="Copley: small, open cyber decision models. Built by Backbay Industries." width="100%">
</p>

# Copley

**Cyber defense you can own.**

Copley is building **small, open cyber decision models** for the systems defenders actually run.
Each model answers one security question from a bounded window of evidence.

```text
likely_benign  |  suspicious  |  abstain
```

Keep inference beside your telemetry. Inspect the weights. Reproduce the evaluation.
Retrain for your environment.

Progress means a model another defender can run, a result they can reproduce, and a failure
they can learn from.

Built by **Backbay Industries**.

## The first bet

**Can a compact learned model catch suspicious process activity that established rules miss?**

We're starting with Windows process execution: a pinned **Sigma rule subset**, a **linear
baseline**, and a planned **ModernBERT fine-tune**, evaluated against the same normalized
evidence. We'll measure where learned detection adds value—and where the rules win.

## Built to be challenged

- **Evidence only.** Labels and provenance stay outside model inputs.
- **Abstention is part of the contract.** Insufficient evidence can produce `abstain`.
- **Show the failures.** Evaluation reports include errors, abstentions, and rule–model
  disagreements.

## Run the scaffold

Python 3.12 + [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --group dev
uv run --locked copley smoke --out artifacts/smoke
```

Inspect the report at `artifacts/smoke/report/`.

> **Early research.** The pipeline runs on synthetic fixtures: smoke tests, not detection
> results. No real-telemetry training or evaluation yet. The next milestone is a reviewed real
> corpus and the first held-out comparison.

**Help build the evidence:** reviewed telemetry, detection expertise, and evaluation critique
are the highest-value contributions.

---

[Architecture](docs/architecture.md) · [Data plan](docs/data-plan.md) ·
[Evaluation](docs/evaluation.md) · [Training](docs/training.md)

Code: [Apache-2.0](LICENSE). Bundled SigmaHQ rules: DRL 1.1. External data and models retain
their own terms. [Third-party notices](THIRD_PARTY_NOTICES.md).
