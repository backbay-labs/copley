"""Dataset validation and per-split accounting."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field

from copley.data.io import RecordError
from copley.data.serialize import serialize
from copley.data.split import SplitResult
from copley.schemas import Label, LabeledWindow


@dataclass
class ValidationSummary:
    total: int
    valid: int
    errors: list[dict]
    label_counts: dict[str, int]
    source_counts: dict[str, int]
    category_counts: dict[str, int]
    serializable: int
    unserializable: list[dict]
    missing_parent: int

    def to_dict(self) -> dict:
        return asdict(self)


def validate_records(
    records: list[LabeledWindow], load_errors: list[RecordError]
) -> ValidationSummary:
    labels: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    serializable = 0
    unserializable: list[dict] = []
    missing_parent = 0
    for rec in records:
        labels[rec.annotation.label.value] += 1
        sources[rec.annotation.label_source.value] += 1
        categories[rec.annotation.provenance.category.value] += 1
        ser = serialize(rec.evidence)
        if ser.usable:
            serializable += 1
        else:
            unserializable.append(
                {
                    "window_id": rec.evidence.window_id,
                    "reason": ser.overflow_reason or ser.insufficient_reason,
                }
            )
        anchor = rec.evidence.anchor
        if not (anchor.parent_image or anchor.parent_command_line):
            missing_parent += 1
    return ValidationSummary(
        total=len(records) + len(load_errors),
        valid=len(records),
        errors=[{"line": e.line_number, "error": e.error} for e in load_errors],
        label_counts=dict(labels),
        source_counts=dict(sources),
        category_counts=dict(categories),
        serializable=serializable,
        unserializable=unserializable,
        missing_parent=missing_parent,
    )


@dataclass
class SplitAccounting:
    ok: bool
    reason: str | None
    counts: dict[str, int]
    per_split: dict[str, dict] = field(default_factory=dict)
    group_leakage: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def account_split(result: SplitResult) -> SplitAccounting:
    if not result.ok:
        return SplitAccounting(False, result.reason, {})
    from copley.data.split import group_key

    per_split: dict[str, dict] = {}
    group_to_part: dict[str, set[str]] = {}
    for part, recs in result.partitions.items():
        labels: Counter[str] = Counter()
        cats: Counter[str] = Counter()
        groups: set[str] = set()
        future = 0
        for rec in recs:
            labels[rec.annotation.label.value] += 1
            cats[rec.annotation.provenance.category.value] += 1
            gk = group_key(rec)
            groups.add(gk)
            group_to_part.setdefault(gk, set()).add(part)
            for ev in rec.evidence.events:
                if ev.timestamp and ev.timestamp > rec.evidence.as_of:
                    future += 1
        per_split[part] = {
            "n": len(recs),
            "labels": dict(labels),
            "categories": dict(cats),
            "groups": len(groups),
            "future_events": future,
        }
    leakage = [gk for gk, parts in group_to_part.items() if len(parts) > 1]
    return SplitAccounting(True, None, result.counts(), per_split, leakage)


def label_distribution(records: list[LabeledWindow]) -> dict[str, int]:
    c: Counter[str] = Counter(r.annotation.label.value for r in records)
    for lab in Label:
        c.setdefault(lab.value, 0)
    return dict(c)
