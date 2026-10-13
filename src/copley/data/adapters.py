"""Adapters from external telemetry formats into Copley evidence.

`sysmon_xml` parses Windows Sysmon EventID 1 (process creation) records from the
Windows Event XML format used by Splunk Attack Data `windows-sysmon.log` files (one
`<Event>...</Event>` per line, or concatenated). It produces unlabeled evidence windows:
the adapter never assigns a malicious label. Labeling is a separate, reviewed step.

This adapter is UNVERIFIED against a live sample in this scaffold (no data was downloaded;
$0 authorized, network-free tests). It is unit-tested against a small inline Sysmon XML
fixture. To verify against real data, fetch one enabled source and run
`copley data adapt`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from copley.schemas import (
    TASK_PROCESS_EXECUTION,
    ContextInfo,
    EvidenceWindow,
    ProcessEvent,
)

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
_EVENTID_RE = re.compile(r"<EventID>\s*(\d+)\s*</EventID>")
_DATA_RE = re.compile(r"<Data Name=['\"]([^'\"]+)['\"]>(.*?)</Data>", re.DOTALL)
_SYSTIME_RE = re.compile(r"<TimeCreated SystemTime=['\"]([^'\"]+)['\"]")

# Sysmon field -> Copley ProcessEvent field.
_FIELD_MAP = {
    "Image": "image",
    "OriginalFileName": "original_file_name",
    "CommandLine": "command_line",
    "CurrentDirectory": "current_directory",
    "IntegrityLevel": "integrity_level",
    "User": "user",
    "ProcessId": "process_id",
    "ParentImage": "parent_image",
    "ParentCommandLine": "parent_command_line",
    "ParentProcessId": "parent_process_id",
}


@dataclass
class AdaptResult:
    windows: list[EvidenceWindow]
    skipped: int
    source_id: str


def _unescape(v: str) -> str:
    return (
        v.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&amp;", "&")
    )


def _parse_time(raw: str) -> datetime | None:
    raw = raw.strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_sysmon_xml(text: str, *, source_id: str, as_of: datetime | None = None) -> AdaptResult:
    windows: list[EvidenceWindow] = []
    skipped = 0
    for i, match in enumerate(_EVENT_RE.findall(text)):
        eid_m = _EVENTID_RE.search(match)
        if not eid_m or eid_m.group(1) != "1":
            skipped += 1
            continue
        fields = {name: _unescape(val.strip()) for name, val in _DATA_RE.findall(match)}
        ts_m = _SYSTIME_RE.search(match)
        ts = _parse_time(ts_m.group(1)) if ts_m else None
        kwargs = {dst: fields.get(src) for src, dst in _FIELD_MAP.items()}
        kwargs = {k: (v if v else None) for k, v in kwargs.items()}
        if not (kwargs.get("image") or kwargs.get("command_line")):
            skipped += 1
            continue
        event = ProcessEvent(event_id=f"{source_id}-{i}", timestamp=ts, observed_at=ts, **kwargs)
        window_as_of = as_of or (ts or datetime.now(UTC))
        if ts and ts > window_as_of:
            window_as_of = ts
        windows.append(
            EvidenceWindow(
                window_id=f"{source_id}-w{i}",
                task_id=TASK_PROCESS_EXECUTION,
                as_of=window_as_of,
                anchor_event_id=event.event_id,
                events=[event],
                context=ContextInfo(policy="anchor_only", related_events_available=False),
            )
        )
    return AdaptResult(windows=windows, skipped=skipped, source_id=source_id)
