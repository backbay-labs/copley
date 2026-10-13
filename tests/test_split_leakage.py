"""Group/duplicate separation and insufficient-data behavior."""

from __future__ import annotations

from copley.data.split import PARTITIONS, group_key, split
from copley.data.validate import account_split


def test_no_group_leakage(split_result):
    assert split_result.ok
    acc = account_split(split_result)
    assert acc.group_leakage == []


def test_every_group_in_one_partition(fixtures, split_result):
    seen: dict[str, str] = {}
    for part, recs in split_result.partitions.items():
        for rec in recs:
            gk = group_key(rec)
            assert seen.setdefault(gk, part) == part


def test_all_partitions_populated(split_result):
    for part in PARTITIONS:
        assert len(split_result.partitions[part]) >= 1


def test_template_variants_not_split(fixtures, split_result):
    # Every variant of a template shares a template_id group, so they must co-locate.
    template_part: dict[str, str] = {}
    for part, recs in split_result.partitions.items():
        for rec in recs:
            tid = rec.annotation.grouping.template_id
            assert template_part.setdefault(tid, part) == part


def test_insufficient_data_returns_visible_result(fixtures):
    # Keep only two malicious groups -> fewer than the 4 partitions need.
    subset = [
        r
        for r in fixtures
        if r.annotation.grouping.template_id in {"certutil_download", "git_status"}
    ]
    result = split(subset, seed=1)
    assert not result.ok
    assert result.reason is not None
    assert "insufficient_data" in result.reason


def test_dedup_collapses_identical(fixtures):
    # Duplicate one record within its group; split should dedup to the same count.
    dup = fixtures + [fixtures[0]]
    base = split(fixtures, seed=42)
    with_dup = split(dup, seed=42)
    assert sum(base.counts().values()) == sum(with_dup.counts().values())
