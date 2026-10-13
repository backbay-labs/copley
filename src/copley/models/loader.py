"""Dispatch artifact loading by model_type. Neural import stays lazy."""

from __future__ import annotations

from pathlib import Path

from copley.models.artifact import ArtifactError, ArtifactMetadata
from copley.models.base import BasePredictor


def load_predictor(directory: Path) -> BasePredictor:
    directory = Path(directory)
    metadata = ArtifactMetadata.load(directory)
    if metadata.model_type == "linear":
        from copley.models.linear import LinearPredictor

        return LinearPredictor.load(directory)
    if metadata.model_type == "modernbert":
        try:
            from copley.models.neural import NeuralPredictor
        except ImportError as exc:  # torch not installed
            raise ArtifactError(
                "neural artifact requires the `train` extra (torch/transformers): "
                "install with `uv sync --extra train`"
            ) from exc
        return NeuralPredictor.load(directory)
    raise ArtifactError(f"unknown model_type: {metadata.model_type}")
