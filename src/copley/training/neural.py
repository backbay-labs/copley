"""ModernBERT sequence-classification training.

Works in two modes (see `TrainingConfig.mode`):

* `tiny`: a small randomly initialized ModernBERT + a self-contained char tokenizer.
  Fully offline, CPU-safe, used for the forward/backward/save/reload smoke test. Writes a
  `test_only` artifact that can never load as a deployable detector.
* `real`: the pretrained backbone at a pinned revision. Requires a model download unless
  cached. Writes a `research_candidate` artifact.

The training loop is a small, explicit torch loop (no Trainer) so behavior, guards, and
device/dtype choices are visible. Validation loss selects the saved checkpoint. Test data
is never read during training.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from copley.data.serialize import SERIALIZER_VERSION, serialize
from copley.models.artifact import ArtifactKind, ArtifactMetadata, sha256_file
from copley.provenance import git_revision, lock_digest
from copley.schemas import TASK_PROCESS_EXECUTION, Label, LabeledWindow
from copley.training.config import TrainingConfig
from copley.training.tokenizer import CharHashTokenizer, HFTokenizerWrapper

LABEL_MAPPING = {Label.benign.value: 0, Label.malicious.value: 1}
WEIGHTS_FILE = "model.safetensors"
PREPROCESSING_VERSION = "neural-modernbert-v1"


@dataclass
class TrainOutcome:
    metadata: ArtifactMetadata
    steps: int
    final_train_loss: float
    best_val_loss: float | None
    wall_seconds: float
    device: str


def _resolve_device(choice: str) -> str:
    import torch

    if choice != "auto":
        return choice
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def _dataset(records: list[LabeledWindow]) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    for r in records:
        if r.annotation.label is Label.unlabeled:
            continue
        ser = serialize(r.evidence)
        if ser.text is None:
            continue
        texts.append(ser.text)
        labels.append(LABEL_MAPPING[r.annotation.label.value])
    return texts, labels


def build_model(config: TrainingConfig) -> tuple[Any, CharHashTokenizer | HFTokenizerWrapper]:
    """Return (model, tokenizer). Imports torch/transformers lazily."""
    import torch
    from transformers import ModernBertConfig, ModernBertForSequenceClassification

    torch.manual_seed(config.seed)
    tok: CharHashTokenizer | HFTokenizerWrapper
    if config.mode == "tiny":
        tok = CharHashTokenizer(vocab_size=config.tiny_vocab_size)
        mc = ModernBertConfig(  # type: ignore[call-arg]
            vocab_size=config.tiny_vocab_size,
            hidden_size=config.tiny_hidden_size,
            intermediate_size=config.tiny_hidden_size * 2,
            num_hidden_layers=config.tiny_layers,
            num_attention_heads=config.tiny_heads,
            max_position_embeddings=config.tiny_max_position,
            num_labels=config.num_labels,
            pad_token_id=0,
            bos_token_id=1,
            eos_token_id=2,
            cls_token_id=1,
            sep_token_id=2,
            local_attention=16,
            global_attn_every_n_layers=1,
        )
        mc._attn_implementation = config.attn_implementation
        model = ModernBertForSequenceClassification(mc)
        return model, tok

    tok = HFTokenizerWrapper.from_pretrained(config.base_model, config.base_model_revision)
    model = ModernBertForSequenceClassification.from_pretrained(
        config.base_model,
        revision=config.base_model_revision,  # type: ignore[arg-type]
        num_labels=config.num_labels,
        trust_remote_code=config.trust_remote_code,
        attn_implementation=config.attn_implementation,
    )
    return model, tok


def train(
    config: TrainingConfig,
    records: list[LabeledWindow],
    val_records: list[LabeledWindow] | None = None,
) -> TrainOutcome:
    import torch
    from torch.optim import AdamW

    start = time.monotonic()
    device = _resolve_device(config.device)
    dtype = {"float32": torch.float32, "bfloat16": torch.bfloat16, "float16": torch.float16}[
        config.dtype
    ]

    texts, labels = _dataset(records)
    if len(set(labels)) < 2:
        raise ValueError(f"training needs both classes; got {sorted(set(labels))}")

    model, tok = build_model(config)
    model.to(device)
    if dtype != torch.float32 and device != "cpu":
        model = model.to(dtype)

    input_ids, attn = tok.encode_batch(texts, config.max_length)
    x = torch.tensor(input_ids, dtype=torch.long, device=device)
    m = torch.tensor(attn, dtype=torch.long, device=device)
    y = torch.tensor(labels, dtype=torch.long, device=device)

    val_xy = None
    if val_records:
        vt, vl = _dataset(val_records)
        if vt and len(set(vl)) >= 1:
            vi, va = tok.encode_batch(vt, config.max_length)
            val_xy = (
                torch.tensor(vi, dtype=torch.long, device=device),
                torch.tensor(va, dtype=torch.long, device=device),
                torch.tensor(vl, dtype=torch.long, device=device),
            )

    opt = AdamW(model.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay)
    n = x.shape[0]
    bs = config.batch_size

    model.train()
    step = 0
    final_loss = float("nan")
    best_val = None
    best_state = None
    for _epoch in range(config.epochs):
        perm = torch.randperm(n, device=device)
        for i in range(0, n, bs):
            idx = perm[i : i + bs]
            out = model(input_ids=x[idx], attention_mask=m[idx], labels=y[idx])
            loss = out.loss
            if not torch.isfinite(loss):
                raise RuntimeError(f"non-finite training loss at step {step}: {loss.item()}")
            (loss / config.gradient_accumulation_steps).backward()
            if (step + 1) % config.gradient_accumulation_steps == 0:
                opt.step()
                opt.zero_grad()
            final_loss = float(loss.item())
            step += 1
            if config.max_steps and step >= config.max_steps:
                break
            if config.max_wall_seconds and (time.monotonic() - start) > config.max_wall_seconds:
                break
        else:
            # validation-based checkpoint selection at epoch end
            if val_xy is not None:
                model.eval()
                with torch.no_grad():
                    vout = model(input_ids=val_xy[0], attention_mask=val_xy[1], labels=val_xy[2])
                vloss = float(vout.loss.item())
                if best_val is None or vloss < best_val:
                    best_val = vloss
                    best_state = {
                        k: v.detach().cpu().clone() for k, v in model.state_dict().items()
                    }
                model.train()
            continue
        break

    if best_state is not None:
        model.load_state_dict(best_state)

    metadata = _save(model, tok, config, labels, device)
    return TrainOutcome(
        metadata=metadata,
        steps=step,
        final_train_loss=final_loss,
        best_val_loss=best_val,
        wall_seconds=time.monotonic() - start,
        device=device,
    )


def _save(model, tok, config: TrainingConfig, labels: list[int], device: str) -> ArtifactMetadata:
    from safetensors.torch import save_model

    out = Path(config.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    model.eval()
    model.to("cpu")
    model.config.save_pretrained(str(out))
    save_model(model, str(out / WEIGHTS_FILE))
    tok.save(out)

    is_tiny = config.mode == "tiny"
    rev, dirty = git_revision()
    metadata = ArtifactMetadata(
        model_id=config.run_name + ("-tiny-smoke" if is_tiny else ""),
        model_type="modernbert",
        artifact_kind=ArtifactKind.test_only if is_tiny else ArtifactKind.research_candidate,
        fixture_trained=is_tiny,
        task_id=TASK_PROCESS_EXECUTION,
        weights_file=WEIGHTS_FILE,
        weights_sha256=sha256_file(out / WEIGHTS_FILE),
        preprocessing_version=PREPROCESSING_VERSION,
        serializer_version=SERIALIZER_VERSION,
        label_mapping=LABEL_MAPPING,
        git_revision=rev,
        git_dirty=dirty,
        lock_digest=lock_digest(),
        base_model=None if is_tiny else config.base_model,
        base_model_revision=None if is_tiny else config.base_model_revision,
        train_counts={"train_scored": len(labels), "train_positive": sum(labels)},
        extra={
            "mode": config.mode,
            "tokenizer_type": tok.tokenizer_type,
            "max_length": config.max_length,
            "device_trained": device,
            "dtype": config.dtype,
            "attn_implementation": config.attn_implementation,
        },
    )
    metadata.save(out)
    return metadata


def dry_run(config: TrainingConfig, records: list[LabeledWindow]) -> dict:
    """Describe the planned run without loading a model or downloading weights."""
    texts, labels = _dataset(records)
    n = len(texts)
    bs = config.batch_size
    steps_per_epoch = max(1, (n + bs - 1) // bs)
    planned_steps = steps_per_epoch * config.epochs
    if config.max_steps:
        planned_steps = min(planned_steps, config.max_steps)
    requires_download = config.mode == "real"
    return {
        "run_name": config.run_name,
        "mode": config.mode,
        "base_model": config.base_model if requires_download else None,
        "base_model_revision": config.base_model_revision if requires_download else None,
        "requires_model_download": requires_download,
        "dataset_windows": n,
        "positives": sum(labels),
        "negatives": len(labels) - sum(labels),
        "max_length": config.max_length,
        "batch_size": bs,
        "gradient_accumulation_steps": config.gradient_accumulation_steps,
        "effective_batch_size": bs * config.gradient_accumulation_steps,
        "epochs": config.epochs,
        "steps_per_epoch": steps_per_epoch,
        "planned_optimizer_steps": planned_steps,
        "max_steps_guard": config.max_steps,
        "max_wall_seconds_guard": config.max_wall_seconds,
        "output_dir": str(config.output_dir),
        "expected_artifact_kind": "test_only" if config.mode == "tiny" else "research_candidate",
        "device": config.device,
        "dtype": config.dtype,
        "estimated_cost_usd": "unknown — measure a small run first (no benchmark exists)",
    }
