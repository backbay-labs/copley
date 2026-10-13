"""Character TF-IDF + logistic regression baseline.

Independently implemented (not a reproduction of AMIDES). The vocabulary and all learned
preprocessing are fit on the training split only. Train and inference share the exact same
serializer and vectorizer, so there is no train/serve skew.

Persistence uses joblib. Loading is restricted to local artifact directories we produced
and is guarded by a weights digest recorded in metadata; there is no arbitrary upload path.
"""

from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from copley.data.serialize import SERIALIZER_VERSION, serialize
from copley.models.artifact import (
    ArtifactError,
    ArtifactMetadata,
    load_calibration,
    sha256_file,
    verify_weights,
)
from copley.models.base import BasePredictor
from copley.provenance import git_revision, lock_digest
from copley.schemas import (
    TASK_PROCESS_EXECUTION,
    ArtifactKind,
    Label,
    LabeledWindow,
)

WEIGHTS_FILE = "model.joblib"
PREPROCESSING_VERSION = "linear-tfidf-char-v1"
LABEL_MAPPING = {Label.benign.value: 0, Label.malicious.value: 1}


def build_pipeline(
    *,
    max_features: int = 20_000,
    ngram_range: tuple[int, int] = (2, 5),
    seed: int = 42,
) -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=ngram_range,
                    max_features=max_features,
                    lowercase=False,
                    min_df=1,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=seed,
                    C=1.0,
                ),
            ),
        ]
    )


def _texts_labels(records: list[LabeledWindow]) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    for rec in records:
        if rec.annotation.label is Label.unlabeled:
            continue
        ser = serialize(rec.evidence)
        if ser.text is None:
            continue
        texts.append(ser.text)
        labels.append(LABEL_MAPPING[rec.annotation.label.value])
    return texts, labels


def train_linear(
    train_records: list[LabeledWindow],
    output_dir: Path,
    *,
    model_id: str,
    artifact_kind: ArtifactKind = ArtifactKind.fixture_baseline,
    fixture_trained: bool = True,
    seed: int = 42,
    max_features: int = 20_000,
) -> ArtifactMetadata:
    texts, labels = _texts_labels(train_records)
    if len(set(labels)) < 2:
        raise ArtifactError(
            f"linear training needs both classes in train split; got labels {sorted(set(labels))}"
        )
    pipeline = build_pipeline(max_features=max_features, seed=seed)
    pipeline.fit(texts, labels)

    output_dir.mkdir(parents=True, exist_ok=True)
    weights_path = output_dir / WEIGHTS_FILE
    joblib.dump(pipeline, weights_path)

    rev, dirty = git_revision()
    counts = {
        "train_total": len(train_records),
        "train_scored": len(texts),
        "train_positive": sum(labels),
        "train_negative": len(labels) - sum(labels),
    }
    metadata = ArtifactMetadata(
        model_id=model_id,
        model_type="linear",
        artifact_kind=artifact_kind,
        fixture_trained=fixture_trained,
        task_id=TASK_PROCESS_EXECUTION,
        weights_file=WEIGHTS_FILE,
        weights_sha256=sha256_file(weights_path),
        preprocessing_version=PREPROCESSING_VERSION,
        serializer_version=SERIALIZER_VERSION,
        label_mapping=LABEL_MAPPING,
        git_revision=rev,
        git_dirty=dirty,
        lock_digest=lock_digest(),
        train_counts=counts,
        extra={"max_features": max_features, "seed": seed},
    )
    metadata.save(output_dir)
    return metadata


class LinearPredictor(BasePredictor):
    def __init__(
        self, directory: Path, metadata: ArtifactMetadata, pipeline: Pipeline, **kw
    ) -> None:
        super().__init__(metadata, **kw)
        self._pipeline = pipeline
        self._pos_index = list(pipeline.classes_).index(LABEL_MAPPING[metadata.positive_label])

    @classmethod
    def load(cls, directory: Path) -> LinearPredictor:
        directory = Path(directory)
        metadata = ArtifactMetadata.load(directory)
        if metadata.model_type != "linear":
            raise ArtifactError(f"not a linear artifact: {metadata.model_type}")
        weights = verify_weights(directory, metadata)
        pipeline = joblib.load(weights)
        return cls(directory, metadata, pipeline, calibration=load_calibration(directory))

    def _score_text(self, text: str) -> float:
        proba = self._pipeline.predict_proba([text])[0]
        return float(proba[self._pos_index])
