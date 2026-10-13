"""Group-aware, leakage-resistant splitting.

Policy (decided from input structure, never from test outcomes):

1. Assign each record a *group key* from its grouping identifiers, falling back to a
   content hash of the serialized evidence so near-duplicates cluster together.
2. Keep every record of a group in exactly one partition.
3. Produce four disjoint partitions: train, validation, calibration, test.
4. If there are too few independent groups per class to fill the needed partitions,
   return an `insufficient_data` result instead of a random row split.

This is deterministic given the seed. The fixture corpus uses this same code path; its
report is still labeled a synthetic smoke test.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from copley.data.serialize import serialize
from copley.schemas import Label, LabeledWindow

PARTITIONS = ("train", "validation", "calibration", "test")


@dataclass
class SplitResult:
    ok: bool
    reason: str | None
    partitions: dict[str, list[LabeledWindow]] = field(default_factory=dict)
    group_assignment: dict[str, str] = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.partitions.items()}


def group_key(record: LabeledWindow) -> str:
    keys = record.annotation.grouping.keys()
    if keys:
        return "|".join(sorted(keys))
    ser = serialize(record.evidence)
    basis = ser.text if ser.text is not None else record.evidence.anchor.command_line or ""
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"content:{digest}"


def _dedup_within_group(records: list[LabeledWindow]) -> list[LabeledWindow]:
    """Collapse exact serialized duplicates inside a group to one representative."""
    seen: dict[str, LabeledWindow] = {}
    for rec in records:
        ser = serialize(rec.evidence)
        sig = ser.text if ser.text is not None else rec.evidence.window_id
        seen.setdefault(sig, rec)
    return list(seen.values())


def split(
    records: list[LabeledWindow],
    *,
    seed: int = 42,
    ratios: tuple[float, float, float, float] = (0.5, 0.2, 0.15, 0.15),
) -> SplitResult:
    labeled = [r for r in records if r.annotation.label is not Label.unlabeled]
    if not labeled:
        return SplitResult(False, "no labeled records to split")

    groups: dict[str, list[LabeledWindow]] = defaultdict(list)
    for rec in labeled:
        groups[group_key(rec)].append(rec)

    # Group-level label: a group is positive if any member is malicious.
    group_label: dict[str, Label] = {}
    for gk, recs in groups.items():
        group_label[gk] = (
            Label.malicious
            if any(r.annotation.label is Label.malicious for r in recs)
            else Label.benign
        )

    by_class: dict[Label, list[str]] = defaultdict(list)
    for gk, lab in group_label.items():
        by_class[lab].append(gk)

    needed = sum(1 for r in ratios if r > 0)
    for lab in (Label.malicious, Label.benign):
        if len(by_class[lab]) < needed:
            return SplitResult(
                False,
                f"insufficient_data: class {lab.value} has {len(by_class[lab])} independent "
                f"groups; need at least {needed} for disjoint {PARTITIONS}",
            )

    assignment: dict[str, str] = {}
    # Deterministic, class-stratified round-robin by shuffled group order.
    import random

    # Non-cryptographic: only used to shuffle group order for a reproducible data split.
    rng = random.Random(seed)  # noqa: S311
    cum: list[float] = []
    acc = 0.0
    for r in ratios:
        acc += r
        cum.append(acc)

    for lab in (Label.malicious, Label.benign):
        gks = sorted(by_class[lab])
        rng.shuffle(gks)
        n = len(gks)
        # Guarantee at least one group per partition by filling partitions first.
        for i, part in enumerate(PARTITIONS):
            assignment[gks[i]] = part
        for j, gk in enumerate(gks[len(PARTITIONS) :], start=len(PARTITIONS)):
            frac = j / n
            part = next(PARTITIONS[k] for k, c in enumerate(cum) if frac < c)
            assignment[gk] = part

    partitions: dict[str, list[LabeledWindow]] = {p: [] for p in PARTITIONS}
    for gk, recs in groups.items():
        part = assignment[gk]
        partitions[part].extend(_dedup_within_group(recs))

    return SplitResult(True, None, partitions, assignment)
