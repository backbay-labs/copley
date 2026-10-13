# Training

Neural training lives behind the optional `train` extra (`torch`, `transformers`,
`safetensors`). Installing the core CLI never pulls these.

## Two modes

- **tiny** (`configs/train-smoke.yaml`): a small randomly initialized ModernBERT with a
  self-contained char tokenizer. Fully offline and CPU-safe. Produces a `test_only` artifact
  with `fixture_trained=true`. Used for the forward/backward/save/reload smoke test.
- **real** (`configs/modernbert-base.yaml`): the pretrained `answerdotai/ModernBERT-base` at a
  pinned revision. Requires a model download (unless cached). Produces a `research_candidate`
  artifact. **Not run during the scaffold task** ($0 authorized).

## What was verified (offline)

- Tiny model: forward + backward (finite loss), AdamW steps with gradient accumulation,
  validation-based checkpoint selection, safetensors save, reload, and deterministic inference
  parity. Ran on CPU and MPS on the dev host.
- Config validation and the `--dry-run` plan for the real config (reports dataset counts, input
  limits, planned optimizer steps, expected artifact location, and that a model download is
  required).
- `transformers.ModernBertForSequenceClassification` imports at the pinned library version.

## What was NOT tested

- Loading/fine-tuning the **full pretrained ModernBERT-base** backbone (requires a network
  download; not authorized).
- Any **GPU/CUDA** execution (the dev host has no CUDA; MPS and CPU only).

## Running the tiny smoke test

```bash
uv sync --locked --extra train
HF_HUB_OFFLINE=1 uv run --locked --extra train copley train --config configs/train-smoke.yaml
```

## Preparing a real run (do not execute without authorization)

1. Verify the base-model revision in `configs/modernbert-base.yaml` against Hugging Face
   (recorded: `8949b909ec900327062f0ebf497f51aef5e6f0c8`, 2026-10-13). Do not use a fabricated
   SHA.
2. Point `data_path` at a reviewed, labeled JSONL corpus (see `docs/data-plan.md`). Do not train
   on the final test split.
3. Inspect the plan: `uv run --locked --extra train copley train --config configs/modernbert-base.yaml --dry-run`.
4. Choose device/dtype: `cuda` + `bfloat16` for GPU; FlashAttention is optional and never
   required (`attn_implementation: sdpa` is the default and CPU-safe).
5. Set `max_steps` / `max_wall_seconds` guards. **A local timeout does not deallocate a rented
   GPU** — see `docs/budget.md` for termination/cleanup responsibilities.
6. After training, calibrate on a separate calibration split and report reliability; leave
   `probability` null if evidence is too sparse (`calibration_status` makes this explicit).

## Starting hyperparameters (hypotheses, not promises)

`base_model=answerdotai/ModernBERT-base`, `max_length=512`, `num_labels=2`, `lr=2e-5`,
`epochs=3`, `batch_size=8`, `gradient_accumulation_steps=4`, `seed=42`. Adjust in config.
