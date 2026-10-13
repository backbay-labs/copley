"""Source/label correlation audit.

If benign examples come from one set of sources and malicious from a disjoint set, a learned
model can score the *source* rather than the behavior. This module measures that risk from
dataset structure alone and returns a machine-readable verdict. It never silently "fixes"
anything; it tells the caller whether strong release claims should be blocked.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field

from copley.schemas import Label, LabeledWindow


@dataclass
class SourceAudit:
    source_id: str
    datasets: list[str]
    categories: list[str]
    benign: int
    malicious: int
    unlabeled: int

    @property
    def single_class(self) -> bool:
        return (self.benign > 0) != (self.malicious > 0)  # XOR: exactly one class present


@dataclass
class SourceLabelAudit:
    per_source: list[dict]
    total_sources: int
    sources_with_both_classes: int
    class_disjoint_sources: bool
    exploratory_only: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def audit_source_label_correlation(records: list[LabeledWindow]) -> SourceLabelAudit:
    # Key by acquisition source only. Provenance category is label-correlated by design
    # (e.g. controlled_attack_execution -> malicious), so it must not be part of the key;
    # the concern here is whether the *source lab* predicts the label.
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"benign": 0, "malicious": 0, "unlabeled": 0}
    )
    datasets: dict[str, set[str]] = defaultdict(set)
    categories: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        prov = rec.annotation.provenance
        counts[prov.source_id][rec.annotation.label.value] += 1
        datasets[prov.source_id].add(prov.dataset_id)
        categories[prov.source_id].add(prov.category.value)

    audits = [
        SourceAudit(
            sid,
            sorted(datasets[sid]),
            sorted(categories[sid]),
            c["benign"],
            c["malicious"],
            c["unlabeled"],
        )
        for sid, c in sorted(counts.items())
    ]

    labeled_sources = [a for a in audits if (a.benign + a.malicious) > 0]
    both = [a for a in labeled_sources if a.benign > 0 and a.malicious > 0]
    # Class-disjoint: every labeled source is single-class (the dangerous case). Only
    # meaningful when there are at least two labeled sources.
    class_disjoint = len(labeled_sources) >= 2 and len(both) == 0

    reasons: list[str] = []
    if class_disjoint:
        reasons.append(
            "Every labeled source is single-class: a model may learn the source, not the "
            "behavior. Treat results as exploratory and block strong release claims until "
            "source-balanced labeled data exists."
        )
    if len(labeled_sources) < 2:
        reasons.append(
            "Fewer than two labeled sources: source-held-out evaluation is not possible; "
            "cross-source generalization is unassessed."
        )

    return SourceLabelAudit(
        per_source=[asdict(a) | {"single_class": a.single_class} for a in audits],
        total_sources=len(audits),
        sources_with_both_classes=len(both),
        class_disjoint_sources=class_disjoint,
        exploratory_only=class_disjoint or len(labeled_sources) < 2,
        reasons=reasons,
    )


def label_only_from_structure(records: list[LabeledWindow]) -> dict[str, int]:
    """Helper: class counts, used to confirm a split still has both classes."""
    out = {Label.benign.value: 0, Label.malicious.value: 0, Label.unlabeled.value: 0}
    for rec in records:
        out[rec.annotation.label.value] += 1
    return out
