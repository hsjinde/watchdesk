"""Anomaly × recent change.

"The failure rate jumped" and "the failure rate jumped four minutes after the
filter file was edited" are different findings, and only the second one tells
anybody what to do next.  This module does not decide causation — it puts the
changes it can see next to the anomalies that happened in the same window, and
lets the reader draw the line.

The changes it can see are deliberately few, and all of them are things
watchdesk already measures for other reasons:

* a config file's digest differing from the previous round,
* fail2ban restarting inside the window,
* a container's start time or restart count moving.

There is no attempt to read shell history, package logs, or anything else that
would need write-adjacent access or a bigger allowlist.  A short list of
changes it is certain about beats a long list it has to guess at.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from .config import Config
from .detect.rules import Finding
from .detect.state import StateStore
from .sources.base import Signal

__all__ = ["Change", "collect_changes", "correlate"]


@dataclass(frozen=True)
class Change:
    kind: str
    description: str
    #: Labels this change is about, used to decide which findings it belongs
    #: to. An empty mapping means it applies to everything in the round.
    scope: dict[str, str]


def collect_changes(
    config: Config,
    signals: Sequence[Signal],
    store: StateStore | None,
    now: datetime,
) -> list[Change]:
    by_key = {signal.key: signal for signal in signals}
    changes: list[Change] = []

    def previous(key: str):
        return store.previous(key, now) if store else None

    # --- configuration edits ------------------------------------------
    for signal in signals:
        if signal.name != "fail2ban.config_digest":
            continue
        before = previous(signal.key)
        if before is None or before.value == signal.value:
            continue
        filename = signal.labels.get("file", "?")
        # jail.local affects every jail; a filter file affects the one jail
        # named after it. Anything else gets round-wide scope rather than a
        # guessed association.
        scope: dict[str, str] = {}
        if filename.startswith("filter.d/") and filename.endswith(".conf"):
            scope = {"jail": filename[len("filter.d/") : -len(".conf")]}
        changes.append(
            Change(
                kind="config_edit",
                description=(
                    f"{filename} changed between rounds "
                    f"({before.value} -> {signal.value}, previous round "
                    f"{before.observed_at.isoformat()})"
                ),
                scope=scope,
            )
        )

    # --- fail2ban restarts --------------------------------------------
    starts = by_key.get("fail2ban.server_starts")
    if starts and isinstance(starts.value, (int, float)) and starts.value > 0:
        changes.append(
            Change(
                kind="service_restart",
                description=(
                    f"fail2ban started {int(starts.value)} time(s) inside this window; "
                    "every jail's in-memory counters reset with it"
                ),
                scope={},
            )
        )

    # --- container churn ----------------------------------------------
    window_start = now - timedelta(minutes=config.window_minutes)
    for signal in signals:
        container = signal.labels.get("container", "?")
        if signal.name == "docker.container.started_at" and isinstance(signal.value, str):
            started = _parse(signal.value)
            before = previous(signal.key)
            moved = before is not None and before.value != signal.value
            inside = started is not None and window_start <= started <= now
            if not (moved or inside):
                continue
            if started is not None and started > now:
                # A fixture records container state as it is at bake time,
                # which can be later than the window it represents. A start
                # time in the future is an artefact of that, not an event.
                continue
            changes.append(
                Change(
                    kind="container_start",
                    description=f"container {container} started at {signal.value}",
                    scope={"container": container},
                )
            )
        elif signal.name == "docker.container.restart_count":
            before = previous(signal.key)
            if (
                before is None
                or before.number is None
                or not isinstance(signal.value, (int, float))
                or signal.value <= before.number
            ):
                continue
            changes.append(
                Change(
                    kind="container_restart",
                    description=(
                        f"container {container} restart count rose "
                        f"{before.number:g} -> {signal.value:g}"
                    ),
                    scope={"container": container},
                )
            )

    return changes


def correlate(
    config: Config,
    findings: Sequence[Finding],
    signals: Sequence[Signal],
    store: StateStore | None,
    now: datetime,
) -> list[Finding]:
    """Attach the changes that share a finding's scope.

    A change with empty scope (fail2ban restarting) attaches to everything; a
    scoped one attaches only where its labels match, so a filter edit for one
    jail does not turn up as an explanation for another jail's numbers.
    """
    changes = collect_changes(config, signals, store, now)
    if not changes:
        return list(findings)

    # A jail's traffic comes from a container; carrying that mapping lets a
    # container restart attach to a jail-scoped finding and vice versa.
    jail_container = {
        spec.name: spec.container for spec in config.fail2ban.jails if spec.container
    }

    out: list[Finding] = []
    for finding in findings:
        scopes = dict(finding.labels)
        if "jail" in scopes and scopes["jail"] in jail_container:
            scopes.setdefault("container", jail_container[scopes["jail"]])

        matched = [
            change
            for change in changes
            if not change.scope
            or all(scopes.get(key) == value for key, value in change.scope.items())
        ]
        if not matched:
            out.append(finding)
            continue

        out.append(
            Finding(
                rule=finding.rule,
                severity=finding.severity,
                confidence=finding.confidence,
                title=finding.title,
                detail=finding.detail,
                labels=finding.labels,
                evidence=finding.evidence,
                signal_keys=finding.signal_keys,
                baseline=finding.baseline,
                correlations=tuple(
                    f"[{change.kind}] {change.description}" for change in matched
                ),
            )
        )
    return out


def _parse(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
