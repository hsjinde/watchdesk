"""The unit of observation.

A source does not decide whether anything is wrong.  It reports what it saw,
with enough structure that ``detect/rules.py`` can compare this round against
the last one, and enough provenance that ``brief.py`` can point at a specific
line when it makes a claim.

That split is the reason this project is not just ``audit.sh`` with nicer
output.  ``audit.sh`` prints text for a human to judge; a source emits values
that a machine can subtract from last round's values.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "Evidence",
    "Signal",
    "SignalKind",
    "SignalSource",
    "SourceContext",
    "utcnow",
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SignalKind(str, Enum):
    """What kind of thing a signal is, which decides how rules treat it.

    ``METRIC`` values get differenced against history; ``STATE`` values get
    compared for change; ``EVENT`` values are counted within a window;
    ``ERROR`` means the source could not answer, which is itself a finding —
    a source that silently returns nothing looks exactly like a healthy
    system, and that is the failure mode this whole project exists to catch.
    """

    METRIC = "metric"
    STATE = "state"
    EVENT = "event"
    ERROR = "error"


@dataclass(frozen=True)
class Evidence:
    """A pointer to the thing that justifies a signal.

    ``excerpt`` holds raw, unredacted text: evidence is only useful if it is
    literally what the log said.  Redaction happens at the exits, not here, so
    that local debugging keeps full fidelity — see ``redact.py``.
    """

    kind: str
    ref: str
    excerpt: str
    line_no: int | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "ref": self.ref, "excerpt": self.excerpt}
        if self.line_no is not None:
            out["line_no"] = self.line_no
        return out


@dataclass(frozen=True)
class Signal:
    """One observation, at one point in time, about one labelled thing."""

    name: str
    kind: SignalKind
    value: Any
    source: str
    labels: Mapping[str, str] = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()
    observed_at: datetime = field(default_factory=utcnow)
    unit: str | None = None
    note: str | None = None

    @property
    def key(self) -> str:
        """Stable identity across rounds, used as the SQLite history key.

        Labels are sorted so that dictionary ordering cannot silently split
        one series into two.
        """
        if not self.labels:
            return self.name
        labels = ",".join(f"{k}={v}" for k, v in sorted(self.labels.items()))
        return f"{self.name}{{{labels}}}"

    def redacted(self, redactor: Any) -> Signal:
        """A copy safe to send off this machine.

        Only *data* is redacted, never schema. Signal names, label keys, units
        and kinds are written in this repository, not read off the host — and
        they are dotted identifiers, so a text-level pass mistakes
        ``fail2ban.jail.running`` for a hostname and pseudonymises it into
        noise. Label values, on the other hand, routinely carry addresses, so
        they go through, and ``key`` is rebuilt from the redacted labels
        rather than redacted as a string.
        """
        return Signal(
            name=self.name,
            kind=self.kind,
            value=redactor.text(self.value) if isinstance(self.value, str) else self.value,
            source=self.source,
            labels={key: redactor.text(value) for key, value in self.labels.items()},
            evidence=tuple(
                Evidence(
                    kind=item.kind,
                    ref=redactor.text(item.ref),
                    excerpt=redactor.text(item.excerpt),
                    line_no=item.line_no,
                )
                for item in self.evidence
            ),
            observed_at=self.observed_at,
            unit=self.unit,
            note=redactor.text(self.note) if self.note else None,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "key": self.key,
            "name": self.name,
            "kind": self.kind.value,
            "value": self.value,
            "source": self.source,
            "labels": dict(self.labels),
            "observed_at": self.observed_at.isoformat(),
        }
        if self.unit:
            out["unit"] = self.unit
        if self.note:
            out["note"] = self.note
        if self.evidence:
            out["evidence"] = [item.to_dict() for item in self.evidence]
        return out


@dataclass
class SourceContext:
    """Everything a source is allowed to touch.

    Passing this in rather than letting sources reach for ``subprocess`` is
    what makes the allowlist enforceable and the fixture replay possible: the
    same source code runs against a live host and against a recorded incident,
    and cannot tell the difference.
    """

    runner: Any  # sources.shell.CommandRunner — typed loosely to avoid a cycle
    config: Any  # config.Config
    now: datetime = field(default_factory=utcnow)


@runtime_checkable
class SignalSource(Protocol):
    """A named collector.

    ``collect`` must not raise for an expected failure (a missing container, a
    denied command, an unreadable file).  It yields an ``ERROR`` signal
    instead, because an exception would take the rest of the round down with
    it and a partially blind round that says so is worth more than no round.
    """

    name: str

    def collect(self, ctx: SourceContext) -> Iterable[Signal]: ...
