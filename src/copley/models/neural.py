"""Load a neural artifact and score evidence. Imports torch/transformers lazily."""

from __future__ import annotations

from pathlib import Path

from copley.models.artifact import (
    ArtifactError,
    ArtifactMetadata,
    load_calibration,
    verify_weights,
)
from copley.models.base import BasePredictor
from copley.training.tokenizer import CharHashTokenizer, HFTokenizerWrapper


class NeuralPredictor(BasePredictor):
    def __init__(self, metadata: ArtifactMetadata, model, tokenizer, max_length: int, **kw) -> None:
        super().__init__(metadata, **kw)
        self._model = model
        self._tok = tokenizer
        self._max_length = max_length
        self._pos_index = metadata.label_mapping[metadata.positive_label]

    @classmethod
    def load(cls, directory: Path) -> NeuralPredictor:
        import torch
        from safetensors.torch import load_model
        from transformers import ModernBertConfig, ModernBertForSequenceClassification

        directory = Path(directory)
        metadata = ArtifactMetadata.load(directory)
        if metadata.model_type != "modernbert":
            raise ArtifactError(f"not a neural artifact: {metadata.model_type}")
        weights = verify_weights(directory, metadata)

        config = ModernBertConfig.from_pretrained(str(directory))
        config._attn_implementation = metadata.extra.get("attn_implementation", "sdpa")
        model = ModernBertForSequenceClassification(config)
        load_model(model, str(weights))
        model.eval()

        tok_type = metadata.extra.get("tokenizer_type", "char_hash")
        tok = (
            CharHashTokenizer.load(directory)
            if tok_type == "char_hash"
            else HFTokenizerWrapper.load(directory)
        )
        max_length = int(metadata.extra.get("max_length", 512))
        _ = torch  # ensure torch import is used/available
        return cls(metadata, model, tok, max_length, calibration=load_calibration(directory))

    def _score_text(self, text: str) -> float:
        import torch

        ids, mask = self._tok.encode_batch([text], self._max_length)
        with torch.no_grad():
            out = self._model(
                input_ids=torch.tensor(ids, dtype=torch.long),
                attention_mask=torch.tensor(mask, dtype=torch.long),
            )
            probs = torch.softmax(out.logits, dim=-1)[0]
        return float(probs[self._pos_index].item())
