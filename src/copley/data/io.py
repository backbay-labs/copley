"""JSONL read/write for labeled windows and evidence, with explicit error reporting."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from copley.schemas import EvidenceWindow, LabeledWindow


@dataclass(frozen=True)
class RecordError:
    line_number: int
    error: str


@dataclass
class LoadResult:
    records: list[LabeledWindow]
    errors: list[RecordError]

    @property
    def ok(self) -> bool:
        return not self.errors


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict]]:
    with path.open("r", encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            yield i, json.loads(line)


def load_labeled(path: Path) -> LoadResult:
    records: list[LabeledWindow] = []
    errors: list[RecordError] = []
    try:
        pairs = list(iter_jsonl(path))
    except json.JSONDecodeError as exc:
        return LoadResult([], [RecordError(exc.lineno, f"invalid JSON: {exc.msg}")])
    for line_no, raw in pairs:
        try:
            records.append(LabeledWindow.model_validate(raw))
        except ValidationError as exc:
            errors.append(RecordError(line_no, _compact(exc)))
    return LoadResult(records, errors)


def load_evidence(path: Path) -> tuple[list[EvidenceWindow], list[RecordError]]:
    windows: list[EvidenceWindow] = []
    errors: list[RecordError] = []
    for line_no, raw in iter_jsonl(path):
        payload = raw.get("evidence", raw)
        try:
            windows.append(EvidenceWindow.model_validate(payload))
        except ValidationError as exc:
            errors.append(RecordError(line_no, _compact(exc)))
    return windows, errors


def write_labeled(path: Path, records: list[LabeledWindow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec.model_dump_json() + "\n")


def _compact(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
