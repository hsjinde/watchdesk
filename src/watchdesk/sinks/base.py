"""The sink contract, and the rule that stops it becoming noise.

An on-call channel that reposts an unchanged alert every five minutes gets
muted within a day — and a muted channel somebody still believes is watching
is worse than no channel at all.  So repetition is suppressed here rather than
in each sink: a brief whose findings are identical to the last one delivered
is not sent again until ``resend_after_minutes`` has passed.

The digest deliberately covers *which* findings fired and at what severity,
not their prose.  A rate that ticks from 170 to 174 is the same situation; a
new jail going blind is not.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from ..brief import Brief
from ..detect.rules import Severity
from ..detect.state import StateStore

__all__ = ["Sink", "SinkResult", "should_send", "suppression_digest", "record_sent"]

_SEVERITY_BY_NAME = {str(level): level for level in Severity}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
    id        INTEGER PRIMARY KEY,
    sink      TEXT NOT NULL,
    digest    TEXT NOT NULL,
    sent_at   TEXT NOT NULL,
    headline  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS notifications_sink_time ON notifications (sink, sent_at DESC);
"""


@dataclass(frozen=True)
class SinkResult:
    sent: bool
    reason: str
    detail: str = ""


@runtime_checkable
class Sink(Protocol):
    name: str

    def deliver(self, brief: Brief) -> SinkResult: ...


def suppression_digest(brief: Brief) -> str:
    """Identity of a *situation*, not of a message.

    Built from the rules that fired, their severity and their labels. Two
    rounds that found the same problems in the same places produce the same
    digest even though their numbers moved.
    """
    parts = sorted(
        f"{finding.rule}|{finding.severity}|"
        + ",".join(f"{k}={v}" for k, v in sorted(finding.labels.items()))
        for finding in brief.findings
    )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def _ensure_schema(store: StateStore) -> None:
    store.connection.executescript(_SCHEMA)
    store.connection.commit()


def should_send(
    brief: Brief,
    sink: str,
    store: StateStore | None,
    now: datetime,
    min_severity: str = "warning",
    resend_after_minutes: int = 720,
) -> SinkResult:
    """Decide whether this brief is worth somebody's attention right now."""
    floor = _SEVERITY_BY_NAME.get(min_severity.lower(), Severity.WARNING)
    if not brief.findings:
        return SinkResult(False, "nothing to report")
    if brief.severity < floor:
        return SinkResult(
            False, f"highest finding is {brief.severity}, below the {floor} floor for this sink"
        )
    if store is None:
        return SinkResult(True, "no history available, sending")

    _ensure_schema(store)
    digest = suppression_digest(brief)
    row = store.connection.execute(
        "SELECT sent_at FROM notifications WHERE sink = ? AND digest = ? "
        "ORDER BY sent_at DESC LIMIT 1",
        (sink, digest),
    ).fetchone()
    if row is None:
        return SinkResult(True, "new situation")

    last = datetime.fromisoformat(row["sent_at"])
    if last.tzinfo is None:
        last = last.replace(tzinfo=now.tzinfo)
    age = now - last
    if age < timedelta(minutes=resend_after_minutes):
        return SinkResult(
            False,
            f"identical findings were sent {int(age.total_seconds() // 60)} minutes ago; "
            f"suppressed until {resend_after_minutes} minutes have passed",
        )
    return SinkResult(True, f"unchanged for {age}, re-sending as a reminder")


def record_sent(brief: Brief, sink: str, store: StateStore | None, now: datetime) -> None:
    if store is None:
        return
    _ensure_schema(store)
    store.connection.execute(
        "INSERT INTO notifications (sink, digest, sent_at, headline) VALUES (?, ?, ?, ?)",
        (sink, suppression_digest(brief), now.isoformat(), brief.headline[:200]),
    )
    store.connection.commit()
