"""Training configuration. Pure Pydantic; safe to import without torch installed."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class TrainingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Identity / mode
    run_name: str = "copley-process-modernbert-base"
    mode: str = Field(default="real", pattern="^(real|tiny)$")
    # `tiny` builds a small randomly initialized ModernBERT for offline smoke tests and
    # writes a `test_only` artifact. `real` loads the pretrained backbone (requires a
    # network download unless cached) and writes a `research_candidate` artifact.

    base_model: str = "answerdotai/ModernBERT-base"
    # Pin AFTER verifying; see docs/research.md. Current HF main revision recorded there.
    base_model_revision: str | None = "8949b909ec900327062f0ebf497f51aef5e6f0c8"
    trust_remote_code: bool = False

    num_labels: int = 2
    max_length: int = 512
    learning_rate: float = 2e-5
    epochs: int = 3
    batch_size: int = 8
    gradient_accumulation_steps: int = 4
    seed: int = 42
    weight_decay: float = 0.01

    # Guards
    max_steps: int | None = None
    max_wall_seconds: int | None = None

    # Hardware / precision
    device: str = "auto"  # auto | cpu | cuda | mps
    dtype: str = "float32"  # float32 | bfloat16 | float16
    attn_implementation: str = "sdpa"  # sdpa is CPU-safe; flash_attention_2 is optional only

    # Data
    data_path: Path | None = None  # JSONL of labeled windows; if null, use synthetic fixtures
    output_dir: Path = Path("artifacts/neural")

    # Tiny-mode architecture (ignored in real mode)
    tiny_hidden_size: int = 64
    tiny_layers: int = 2
    tiny_heads: int = 2
    tiny_vocab_size: int = 1024
    tiny_max_position: int = 256

    @classmethod
    def from_yaml(cls, path: Path) -> TrainingConfig:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)
