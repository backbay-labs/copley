from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from copley.schemas import (
    TASK_PROCESS_EXECUTION,
    EvidenceWindow,
    ProcessEvent,
)

_T = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _event(eid="e0", ts=_T, **kw):
    return ProcessEvent(event_id=eid, timestamp=ts, observed_at=ts, command_line="cmd", **kw)


def _window(**kw):
    ev = kw.pop("event", _event())
    return EvidenceWindow(
        window_id="w0",
        task_id=TASK_PROCESS_EXECUTION,
        as_of=_T + timedelta(minutes=1),
        anchor_event_id=ev.event_id,
        events=[ev],
        **kw,
    )


def test_unsupported_task_rejected():
    with pytest.raises(ValidationError, match="unsupported task_id"):
        EvidenceWindow(
            window_id="w",
            task_id="totally.unsupported.v9",
            as_of=_T,
            anchor_event_id="e0",
            events=[_event()],
        )


def test_future_event_rejected():
    future = _event(ts=_T + timedelta(hours=1))
    with pytest.raises(ValidationError, match="future evidence"):
        EvidenceWindow(
            window_id="w",
            task_id=TASK_PROCESS_EXECUTION,
            as_of=_T,
            anchor_event_id=future.event_id,
            events=[future],
        )


def test_observed_after_as_of_rejected():
    ev = ProcessEvent(
        event_id="e0", timestamp=_T, observed_at=_T + timedelta(hours=2), command_line="x"
    )
    with pytest.raises(ValidationError, match="not observed until after"):
        EvidenceWindow(
            window_id="w",
            task_id=TASK_PROCESS_EXECUTION,
            as_of=_T + timedelta(hours=1),
            anchor_event_id="e0",
            events=[ev],
        )


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError, match="timezone"):
        ProcessEvent(event_id="e0", timestamp=datetime(2026, 1, 1, 0, 0), command_line="x")


def test_anchor_must_exist():
    with pytest.raises(ValidationError, match="anchor_event_id"):
        EvidenceWindow(
            window_id="w",
            task_id=TASK_PROCESS_EXECUTION,
            as_of=_T,
            anchor_event_id="missing",
            events=[_event()],
        )


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        ProcessEvent(event_id="e0", command_line="x", secret_annotation="malicious")


def test_evidence_profile_labels():
    w = _window()
    assert w.evidence_profile == "command_line_only"
    ev = _event(image="C:\\a.exe", parent_image="C:\\p.exe")
    assert _window(event=ev).evidence_profile == "process_with_parent"
