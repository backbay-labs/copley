<p align="center">
  <img src="docs/copley-hero.png" alt="Copley: small, open cyber decision models. Built by Backbay Industries." width="100%">
</p>

# Copley

**Cyber defense you can own.**

Copley is building a family of **small, open cyber decision models**—with the ambition to put
detection capability in the hands of every defender.

Models you can run locally. Inspect. Retrain. Build into your own systems.

**One model. One defined job. Evidence in, decision out.**

```text
likely_benign  |  suspicious  |  abstain
```

The ambition is an open library of security decisions: specialized models, reproducible
evaluations, and published failures that the whole field can learn from.

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
> corpus and the first held-out comparison. [Current status](HANDOFF.md).

**Help build the evidence:** reviewed telemetry, detection expertise, and evaluation critique
are the highest-value contributions.

---

[Architecture](docs/architecture.md) · [Data plan](docs/data-plan.md) ·
[Evaluation](docs/evaluation.md) · [Training](docs/training.md) · [Project status](HANDOFF.md)

Code: [Apache-2.0](LICENSE). Bundled SigmaHQ rules: DRL 1.1. External data and models retain
their own terms. [Third-party notices](THIRD_PARTY_NOTICES.md).
