"""Snapshot history.

This is the difference between watchdesk and the audit script it grew out of.
``audit.sh`` prints what is true now; a value is only meaningful against what
it was last time.  "12,000 SASL failures all-time" was equally true during the
August incident and for the two quiet months before it.  "Six an hour became
thirty" is a fact about *this* window.

Only values are stored, not evidence.  Evidence is quoted from the current
round when a finding is written; keeping every log excerpt from every round
would grow without bound and would put unredacted log lines in a file that
outlives the round that needed them.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..collect import Round
from ..sources.base import Signal, SignalKind

__all__ = ["Observation", "StateStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rounds (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT 'live',
    signals     INTEGER NOT NULL DEFAULT 0,
    errors      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS observations (
    round_id    INTEGER NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    value_num   REAL,
    value_text  TEXT,
    unit        TEXT,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (round_id, key)
);

CREATE INDEX IF NOT EXISTS observations_key_time
    ON observations (key, observed_at DESC);

CREATE INDEX IF NOT EXISTS rounds_started_at ON rounds (started_at DESC);
"""


@dataclass(frozen=True)
class Observation:
    key: str
    name: str
    kind: str
    value: float | str | bool | None
    unit: str | None
    observed_at: datetime
    label: str

    def age(self, now: datetime) -> timedelta:
        return now - self.observed_at

    @property
    def number(self) -> float | None:
        """The value if it is genuinely numeric.

        bool is a subclass of int in Python, so an unguarded isinstance check
        hands True back as a number — and every change rule then happily
        differences a state flip against a counter. The storage layer already
        keeps booleans out of the numeric column; this is the same trap one
        layer up.
        """
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            return None
        return float(self.value)


def _as_utc(text: str) -> datetime:
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


class StateStore:
    """SQLite-backed history of every round's values."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(_SCHEMA)
        self.connection.commit()

    # -- writing -------------------------------------------------------

    def record(self, result: Round, label: str = "live") -> int:
        errors = sum(1 for signal in result.signals if signal.kind is SignalKind.ERROR)
        cursor = self.connection.execute(
            "INSERT INTO rounds (started_at, label, signals, errors) VALUES (?, ?, ?, ?)",
            (result.started_at.isoformat(), label, len(result.signals), errors),
        )
        round_id = int(cursor.lastrowid or 0)
        self.connection.executemany(
            """
            INSERT OR REPLACE INTO observations
                (round_id, key, name, kind, value_num, value_text, unit, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [self._row(round_id, signal) for signal in result.signals],
        )
        self.connection.commit()
        return round_id

    @staticmethod
    def _row(round_id: int, signal: Signal) -> tuple:
        number: float | None = None
        text: str | None = None
        # bool is a subclass of int; storing True as 1.0 would let a state flip
        # be read back as a metric and differenced, which is nonsense.
        if isinstance(signal.value, bool) or signal.value is None:
            text = str(signal.value)
        elif isinstance(signal.value, (int, float)):
            number = float(signal.value)
        else:
            text = str(signal.value)
        return (
            round_id,
            signal.key,
            signal.name,
            signal.kind.value,
            number,
            text,
            signal.unit,
            signal.observed_at.isoformat(),
        )

    # -- reading -------------------------------------------------------

    def previous(self, key: str, before: datetime) -> Observation | None:
        """The most recent observation of ``key`` strictly before ``before``."""
        row = self.connection.execute(
            """
            SELECT o.*, r.label FROM observations o
            JOIN rounds r ON r.id = o.round_id
            WHERE o.key = ? AND o.observed_at < ?
            ORDER BY o.observed_at DESC LIMIT 1
            """,
            (key, before.isoformat()),
        ).fetchone()
        return self._observation(row) if row else None

    def history(self, key: str, before: datetime, limit: int = 24) -> list[Observation]:
        rows = self.connection.execute(
            """
            SELECT o.*, r.label FROM observations o
            JOIN rounds r ON r.id = o.round_id
            WHERE o.key = ? AND o.observed_at < ?
            ORDER BY o.observed_at DESC LIMIT ?
            """,
            (key, before.isoformat(), limit),
        ).fetchall()
        return [self._observation(row) for row in rows]

    def keys_seen(self, before: datetime, within: timedelta) -> set[str]:
        """Keys observed in the recent past — the basis for silence detection.

        A signal that used to be reported and no longer is looks, to every
        threshold rule ever written, exactly like a healthy system. It is the
        failure this project exists to catch, so it needs its own question:
        what did we used to know that we no longer know?
        """
        rows = self.connection.execute(
            "SELECT DISTINCT key FROM observations WHERE observed_at < ? AND observed_at >= ?",
            (before.isoformat(), (before - within).isoformat()),
        ).fetchall()
        return {row["key"] for row in rows}

    def round_count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) AS n FROM rounds").fetchone()["n"])

    @staticmethod
    def _observation(row: sqlite3.Row) -> Observation:
        value: float | str | bool | None
        if row["value_num"] is not None:
            value = row["value_num"]
        elif row["value_text"] in ("True", "False"):
            value = row["value_text"] == "True"
        elif row["value_text"] == "None":
            value = None
        else:
            value = row["value_text"]
        return Observation(
            key=row["key"],
            name=row["name"],
            kind=row["kind"],
            value=value,
            unit=row["unit"],
            observed_at=_as_utc(row["observed_at"]),
            label=row["label"],
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def signals_by_key(signals: Iterable[Signal]) -> dict[str, Signal]:
    return {signal.key: signal for signal in signals}
