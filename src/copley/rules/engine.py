"""Compile a pinned Sigma subset through pySigma's SQLite backend and execute it.

Design choices:

* Logsource mapping is explicit: only `process_creation` / `windows` events are loaded
  into the query table, and only rules with that logsource are applied. We do not use a
  vendor pipeline (which would still pin pySigma<2); instead rule field names map
  directly to our normalized columns.
* Each rule compiles to `SELECT * FROM logs WHERE ...`. We rewrite it into
  `SELECT event_id FROM events WHERE ...` and run it against an in-memory SQLite table
  of the same evidence the models see.
* Conversion failures are recorded as `conversion_failed` and are NOT negative matches.
* Event matches are aggregated to the window level: a window matches if its anchor event
  matches (documented aggregation rule `anchor_match`).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

from copley.schemas import EvidenceWindow, ProcessEvent

# Normalized SQLite columns. NOCASE mirrors how Zircolite-style tables behave, so rule
# equality on OriginalFileName matches case-insensitively like Sigma expects.
COLUMNS: tuple[str, ...] = (
    "Image",
    "OriginalFileName",
    "CommandLine",
    "CurrentDirectory",
    "IntegrityLevel",
    "User",
    "ProcessId",
    "ParentImage",
    "ParentCommandLine",
    "ParentProcessId",
)

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

_SELECT_RE = re.compile(r"^SELECT \* FROM logs\b", re.IGNORECASE)


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    source_path: str
    sha256: str | None
    status: str  # "ok" | "conversion_failed" | "unsupported"
    sql: str | None
    detail: str | None = None


@dataclass
class RuleMatch:
    window_id: str
    rule_id: str
    rule_title: str


@dataclass
class SigmaRunResult:
    compiled: list[CompiledRule]
    matches: list[RuleMatch]
    window_matched: dict[str, list[str]] = field(default_factory=dict)

    @property
    def ok_rules(self) -> list[CompiledRule]:
        return [r for r in self.compiled if r.status == "ok"]

    @property
    def failed_rules(self) -> list[CompiledRule]:
        return [r for r in self.compiled if r.status != "ok"]

    def matched(self, window_id: str) -> bool:
        return bool(self.window_matched.get(window_id))


def _row(ev: ProcessEvent) -> tuple:
    return tuple(getattr(ev, _FIELD_MAP[c]) for c in COLUMNS)


def _build_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cols = ",\n  ".join(f"{c} TEXT COLLATE NOCASE" for c in COLUMNS)
    conn.execute(
        f"CREATE TABLE events (\n  event_id TEXT PRIMARY KEY,\n  window_id TEXT,\n  {cols}\n)"
    )
    return conn


def compile_rules(rule_files: list[Path]) -> list[CompiledRule]:
    from sigma.backends.sqlite import sqliteBackend

    backend = sqliteBackend(collate_nocase=True)
    compiled: list[CompiledRule] = []
    for path in rule_files:
        text = path.read_text(encoding="utf-8")
        try:
            raw = yaml.safe_load(text)
            rid = str(raw.get("id", path.stem))
            title = str(raw.get("title", path.stem))
            ls = raw.get("logsource", {}) or {}
            if ls.get("category") != "process_creation":
                compiled.append(
                    CompiledRule(
                        rid,
                        title,
                        str(path),
                        None,
                        "unsupported",
                        None,
                        f"logsource category {ls.get('category')!r} not supported",
                    )
                )
                continue
        except yaml.YAMLError as exc:
            compiled.append(
                CompiledRule(
                    path.stem,
                    path.stem,
                    str(path),
                    None,
                    "conversion_failed",
                    None,
                    f"yaml error: {exc}",
                )
            )
            continue
        try:
            collection = SigmaCollection.from_yaml(text)
            queries = backend.convert(collection)
            if not queries:
                raise ValueError("backend produced no query")
            sql = _SELECT_RE.sub("SELECT event_id FROM events", queries[0])
            compiled.append(CompiledRule(rid, title, str(path), None, "ok", sql))
        except Exception as exc:  # noqa: BLE001 - we must surface any conversion failure, not crash
            compiled.append(
                CompiledRule(rid, title, str(path), None, "conversion_failed", None, str(exc))
            )
    return compiled


def run_rules(
    windows: list[EvidenceWindow],
    compiled: list[CompiledRule],
    *,
    aggregation: str = "anchor_match",
) -> SigmaRunResult:
    conn = _build_db()
    placeholders = ",".join("?" * (2 + len(COLUMNS)))
    for w in windows:
        for ev in w.events:
            conn.execute(
                f"INSERT OR REPLACE INTO events VALUES ({placeholders})",  # noqa: S608
                (ev.event_id, w.window_id, *_row(ev)),
            )
    conn.commit()

    anchor_ids = {w.anchor_event_id for w in windows}
    event_to_window = {ev.event_id: w.window_id for w in windows for ev in w.events}

    matches: list[RuleMatch] = []
    window_matched: dict[str, list[str]] = {}
    for rule in compiled:
        if rule.status != "ok" or rule.sql is None:
            continue
        try:
            # rule.sql is generated by pySigma's SQLite backend from pinned, hash-verified
            # rules, not from user input. Values are embedded by the backend's own escaping.
            cur = conn.execute(rule.sql)  # noqa: S608
            hit_events = [r[0] for r in cur.fetchall()]
        except sqlite3.Error as exc:
            rule.status = "conversion_failed"
            rule.detail = f"sqlite error: {exc}"
            continue
        for eid in hit_events:
            if aggregation == "anchor_match" and eid not in anchor_ids:
                continue
            wid = event_to_window[eid]
            matches.append(RuleMatch(wid, rule.rule_id, rule.title))
            window_matched.setdefault(wid, [])
            if rule.rule_id not in window_matched[wid]:
                window_matched[wid].append(rule.rule_id)
    conn.close()
    return SigmaRunResult(compiled, matches, window_matched)
