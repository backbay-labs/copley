# AGENTS.md

Guidance for automated agents working in the Copley repository.

Copley is a small, self-contained Python research project. It is developed independently of
the surrounding Backbay multi-repo workspace: it has its own `pyproject.toml` and `uv.lock`
and is **not** a member of the root `backbay-workspace` uv workspace. Run all commands from
this directory (`ml/copley`).

## Golden rules

- **Do not invent results.** Synthetic-fixture output is a smoke test, never a benchmark.
  Never fill cards/docs with plausible-looking invented metrics, calibrated probabilities,
  dataset labels, or completed integrations. Mark unknowns as `unknown`.
- **No paid resources, no publishing, no remote pushes, no real training runs** without
  explicit human authorization. Existing credentials are not permission.
- **Preserve the typed data contract**: predictors receive `EvidenceWindow` only.
  Annotations/provenance must never reach serialization, features, or tokenization. There
  are tests enforcing this (`tests/test_serialize_isolation.py`); keep them passing.
- **Fixture-trained artifacts must stay visibly labeled** (`fixture_trained=true`,
  `artifact_kind` of `fixture_baseline`/`test_only`). They must never load as deployable
  detectors.
- **Do not weaken tests to get green.** Do not disable failing tests or leave placeholders
  on a claimed-complete path.

## Commands

```bash
uv sync --locked --group dev                 # core dev env (no torch/fastapi)
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked --all-extras mypy
uv run --locked --no-default-groups --group dev pytest -q      # core tests
HF_HUB_OFFLINE=1 uv run --locked --extra train --extra serve pytest -q   # full tests
```

## Style

- Ruff + Ruff format (line length 100). Python 3.12 typing. mypy must pass on `src/copley`.
- Pydantic v2 models; `snake_case` modules; keep modules small and cohesive.
- Keep the core install free of CUDA/torch/FlashAttention requirements.

Project intent and current status live in `README.md`; technical contracts live in `docs/`.
Keep them current when status changes.
