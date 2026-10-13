"""Deterministic, versioned serializer from evidence to model-input text.

Only fields in `MODEL_INPUT_ALLOWLIST` are emitted. Identifiers, hostnames, user names,
absolute timestamps, and anything from annotations are excluded by construction: the
function signature accepts an `EvidenceWindow` and nothing else.

Values are emitted verbatim (quoting, backslashes, spacing preserved) and JSON-escaped
only for control characters so the representation is unambiguous and line-oriented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from copley.schemas import EvidenceWindow, ProcessEvent

SERIALIZER_VERSION = "copley-serializer/v1"

# Order matters: it is part of the serializer version.
MODEL_INPUT_ALLOWLIST: tuple[str, ...] = (
    "image",
    "original_file_name",
    "command_line",
    "current_directory",
    "integrity_level",
    "parent_image",
    "parent_command_line",
)

# Present in evidence but deliberately withheld from learned models because they are
# likely lab/source artifacts (hostnames, account names, raw IDs, absolute times).
WITHHELD_FROM_MODEL: tuple[str, ...] = (
    "event_id",
    "host",
    "user",
    "process_id",
    "parent_process_id",
    "timestamp",
    "observed_at",
)

DEFAULT_MAX_BYTES = 8192
DEFAULT_MAX_EVENTS = 16


@dataclass(frozen=True)
class SerializedInput:
    text: str | None
    input_event_ids: list[str]
    warnings: list[str]
    overflow_reason: str | None
    insufficient_reason: str | None

    @property
    def usable(self) -> bool:
        return self.text is not None


def _value(v: str) -> str:
    # json.dumps escapes control characters and quotes deterministically while keeping
    # backslashes and spacing recoverable; ensure_ascii=False keeps non-ASCII paths readable.
    return json.dumps(v, ensure_ascii=False)


def _event_block(role: str, ev: ProcessEvent, anchor: ProcessEvent) -> list[str]:
    lines = [f"[event role={role}]"]
    if role != "anchor" and ev.timestamp is not None and anchor.timestamp is not None:
        delta = int((ev.timestamp - anchor.timestamp).total_seconds())
        lines.append(f"relative_seconds={delta}")
    missing = []
    for name in MODEL_INPUT_ALLOWLIST:
        val = getattr(ev, name)
        if val in (None, ""):
            missing.append(name)
            continue
        lines.append(f"{name}={_value(val)}")
    if missing:
        lines.append("missing=" + ",".join(missing))
    truncated = [f for f in ev.source_truncated_fields if f in MODEL_INPUT_ALLOWLIST]
    if truncated:
        lines.append("source_truncated=" + ",".join(truncated))
    return lines


def serialize(
    window: EvidenceWindow,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_events: int = DEFAULT_MAX_EVENTS,
) -> SerializedInput:
    """Serialize a window, or explain why it cannot be scored.

    Overflow is not silently truncated: the caller receives `overflow_reason` and must
    abstain. Related events are ordered by timestamp (unknown last) then event_id.
    """
    if not isinstance(window, EvidenceWindow):
        raise TypeError(
            "serialize() accepts EvidenceWindow only; annotations must never reach the model"
        )
    anchor = window.anchor
    ids = [anchor.event_id] + [e.event_id for e in window.related]
    warnings: list[str] = []

    if not (anchor.command_line or anchor.image):
        return SerializedInput(
            None, ids, warnings, None, "anchor event has neither image nor command_line"
        )

    profile = window.evidence_profile
    if profile == "command_line_only":
        warnings.append("single_field_example:command_line_only")
    if not (anchor.parent_image or anchor.parent_command_line):
        warnings.append("missing_parent_process_fields")
    if anchor.source_truncated_fields:
        warnings.append("source_truncated_fields:" + ",".join(anchor.source_truncated_fields))
    if window.context.related_events_omitted:
        warnings.append(f"related_events_omitted:{window.context.related_events_omitted}")

    if len(window.events) > max_events:
        return SerializedInput(
            None,
            ids,
            warnings,
            f"window has {len(window.events)} events; serializer limit is {max_events}",
            None,
        )

    related = sorted(
        window.related,
        key=lambda e: (
            e.timestamp is None,
            e.timestamp.isoformat() if e.timestamp else "",
            e.event_id,
        ),
    )
    lines = [
        SERIALIZER_VERSION,
        f"task={window.task_id}",
        f"context_policy={window.context.policy}",
        f"related_events={len(related)}",
    ]
    lines += _event_block("anchor", anchor, anchor)
    for ev in related:
        lines += _event_block("related", ev, anchor)
    text = "\n".join(lines)

    size = len(text.encode("utf-8"))
    if size > max_bytes:
        return SerializedInput(
            None, ids, warnings, f"serialized input is {size} bytes; limit is {max_bytes}", None
        )
    return SerializedInput(
        text, [anchor.event_id] + [e.event_id for e in related], warnings, None, None
    )
