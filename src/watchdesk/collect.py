"""Running a round: build a context, ask every source, keep going.

One source failing must not take the round down.  A round that says "postfix
is unreadable, here is everything else" is worth more than no round at all,
and the failure itself becomes a signal that ``detect/rules.py`` can act on —
a collector that goes quiet looks exactly like a system with nothing to
report, which is the confusion this whole project exists to remove.
"""

from __future__ import annotations

import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from .config import Config
from .sources.alertmanager import AlertmanagerSource
from .sources.base import Signal, SignalKind, SignalSource, SourceContext, utcnow
from .sources.disk import DiskSource
from .sources.docker_state import DockerStateSource
from .sources.dovecot import DovecotSource
from .sources.fail2ban import Fail2banSource
from .sources.postfix import PostfixSource
from .sources.shell import AllowlistRunner, CommandRunner
from .sources.tls_cert import TlsCertSource

__all__ = ["Round", "default_sources", "run_round"]


ALL_SOURCES: dict[str, type] = {
    "fail2ban": Fail2banSource,
    "postfix": PostfixSource,
    "dovecot": DovecotSource,
    "docker_state": DockerStateSource,
    "alertmanager": AlertmanagerSource,
    "disk": DiskSource,
    "tls_cert": TlsCertSource,
}


def default_sources(names: Sequence[str] | None = None) -> list[SignalSource]:
    """Instantiate the configured sources.

    An unknown name raises rather than being skipped: a typo in the config
    that silently disables a collector would produce a round that looks
    healthy because nobody looked.
    """
    if names is None:
        return [factory() for factory in ALL_SOURCES.values()]
    unknown = [name for name in names if name not in ALL_SOURCES]
    if unknown:
        raise KeyError(f"unknown source(s) in config: {unknown}; known: {sorted(ALL_SOURCES)}")
    return [ALL_SOURCES[name]() for name in names]


@dataclass
class Round:
    started_at: datetime
    signals: list[Signal] = field(default_factory=list)
    failed_sources: list[str] = field(default_factory=list)

    def by_name(self, name: str) -> list[Signal]:
        return [signal for signal in self.signals if signal.name == name]

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at.isoformat(),
            "signal_count": len(self.signals),
            "failed_sources": self.failed_sources,
            "signals": [signal.to_dict() for signal in self.signals],
        }


def run_round(
    config: Config,
    runner: CommandRunner | None = None,
    sources: Sequence[SignalSource] | None = None,
    now: datetime | None = None,
) -> Round:
    moment = now or utcnow()
    if runner is None:
        runner = AllowlistRunner(
            config.shell.to_allowlist(), timeout_s=config.shell.timeout_s
        )
    ctx = SourceContext(runner=runner, config=config, now=moment)
    result = Round(started_at=moment)

    for source in sources if sources is not None else default_sources(config.sources):
        try:
            result.signals.extend(source.collect(ctx))
        except Exception as exc:  # noqa: BLE001 - a source must never kill the round
            result.failed_sources.append(source.name)
            result.signals.append(
                Signal(
                    name="watchdesk.source_crashed",
                    kind=SignalKind.ERROR,
                    value=f"{type(exc).__name__}: {exc}",
                    source=source.name,
                    labels={"source": source.name},
                    observed_at=moment,
                    note=(
                        "This source produced no observations at all this round. Treat every "
                        "metric it would have supplied as unknown, not as zero.\n"
                        + traceback.format_exc(limit=3)
                    ),
                )
            )
    return result
