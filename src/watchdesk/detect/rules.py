"""Rules: what makes a set of numbers worth waking someone for.

Three shapes of rule, and the ordering matters more than the list:

* **Thresholds** on things that are wrong at any value — a jail that cannot
  see the traffic it is supposed to be counting, a filter file the jail is not
  actually using.  These need no history.
* **Change** against the previous round — a rate that multiplied, a state
  that flipped, a cumulative counter that went *down* (which means the
  service restarted, not that things improved).
* **Silence** — a signal that used to be reported and no longer is.  This one
  exists because every other rule in the file reads an absent signal as a
  healthy one.

Every finding carries the signals it rests on and the evidence underneath
them.  A rule that cannot point at a line does not get to make a claim; that
constraint is what stage 3 leans on when it lets an LLM write prose.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from typing import Any

from ..config import Config
from ..sources.base import Evidence, Signal, SignalKind
from .state import Observation, StateStore

__all__ = ["Confidence", "Finding", "RuleContext", "Severity", "evaluate"]


class Severity(IntEnum):
    INFO = 0
    NOTICE = 1
    WARNING = 2
    CRITICAL = 3

    def __str__(self) -> str:
        return self.name.lower()


class Confidence(str, Enum):
    """How much of a finding is measurement and how much is inference.

    Rules only ever produce the first two. ``HYPOTHESIS`` exists so that
    stage 3 has somewhere to put an LLM's explanation without it being
    mistaken for something that was observed.
    """

    OBSERVED = "observed"
    DERIVED = "derived"
    HYPOTHESIS = "hypothesis"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    confidence: Confidence
    title: str
    detail: str
    labels: Mapping[str, str] = field(default_factory=dict)
    evidence: tuple[Evidence, ...] = ()
    signal_keys: tuple[str, ...] = ()
    baseline: str | None = None
    correlations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "severity": str(self.severity),
            "confidence": self.confidence.value,
            "title": self.title,
            "detail": self.detail,
            "labels": dict(self.labels),
            "signal_keys": list(self.signal_keys),
        }
        if self.baseline:
            out["baseline"] = self.baseline
        if self.correlations:
            out["correlations"] = list(self.correlations)
        if self.evidence:
            out["evidence"] = [item.to_dict() for item in self.evidence]
        return out

    def redacted(self, redactor: Any) -> Finding:
        """Data goes through the redactor; the rule name and severity do not."""
        return Finding(
            rule=self.rule,
            severity=self.severity,
            confidence=self.confidence,
            title=redactor.text(self.title),
            detail=redactor.text(self.detail),
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
            signal_keys=self.signal_keys,
            baseline=redactor.text(self.baseline) if self.baseline else None,
            correlations=tuple(redactor.text(item) for item in self.correlations),
        )


def _dedupe(evidence: Iterable[Evidence]) -> tuple[Evidence, ...]:
    """Drop repeats.

    The same log line is legitimately cited by a signal and by its per-service
    breakdown. Printing it twice makes a finding look like it rests on more
    than it does, which is the opposite of what evidence binding is for.
    """
    seen: set[tuple[str, str, int | None]] = set()
    out: list[Evidence] = []
    for item in evidence:
        marker = (item.ref, item.excerpt, item.line_no)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return tuple(out)


@dataclass
class RuleContext:
    config: Config
    signals: Sequence[Signal]
    store: StateStore | None
    now: datetime

    def __post_init__(self) -> None:
        self.by_key: dict[str, Signal] = {signal.key: signal for signal in self.signals}
        self.by_name: dict[str, list[Signal]] = {}
        for signal in self.signals:
            self.by_name.setdefault(signal.name, []).append(signal)

    def previous(self, key: str) -> Observation | None:
        return self.store.previous(key, self.now) if self.store else None

    def value(self, key: str) -> Any:
        signal = self.by_key.get(key)
        return signal.value if signal else None

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.config.window_minutes)


# --------------------------------------------------------------------------
# Threshold rules — wrong at any value, no history needed
# --------------------------------------------------------------------------


def rule_uncounted_failures(ctx: RuleContext) -> Iterable[Finding]:
    """The jail cannot see traffic that is in the log it is reading.

    This is the August 2026 incident, and it is the reason this project
    exists. Note what it does *not* rely on: no threshold on the number of
    failures, no baseline, no anomaly score. The finding is that two counts of
    the same log disagree, which is wrong at any volume.
    """
    for signal in ctx.by_name.get("fail2ban.jail.uncounted_failures", []):
        missed = signal.value
        if not isinstance(missed, (int, float)) or missed <= 0:
            continue
        jail = signal.labels.get("jail", "?")
        observed = ctx.value(f"fail2ban.jail.observed_failures{{jail={jail}}}")
        coverage = ctx.value(f"fail2ban.jail.coverage_ratio{{jail={jail}}}")

        per_service = [
            item
            for item in ctx.by_name.get("fail2ban.jail.uncounted_failures_by_service", [])
            if item.labels.get("jail") == jail
            and isinstance(item.value, (int, float))
            and item.value > 0
        ]
        breakdown = ", ".join(
            f"{item.labels.get('service', '?')}: {int(item.value)}" for item in per_service
        )
        blind_services = [item.labels.get("service", "?") for item in per_service]

        matched = ctx.value(f"fail2ban.jail.filter_matched_lines{{jail={jail}}}")
        tool = ctx.value(f"fail2ban.jail.regex_tool_matches{{jail={jail}}}")
        found = ctx.value(f"fail2ban.jail.found_events{{jail={jail}}}")

        detail = (
            f"{int(missed)} of {int(observed or 0)} authentication failures in this window are "
            f"present in the log the jail reads and are not matched by the filter it uses. "
            f"Coverage {coverage}. By listener — {breakdown or 'n/a'}. "
            f"The jail's own view is corroborated independently: watchdesk applying the on-disk "
            f"failregex sees {matched} matching lines, fail2ban-regex sees {tool}, and the "
            f"running fail2ban logged {found} Found events. Those agreeing is what rules out "
            f"an error in watchdesk's own matcher."
        )
        yield Finding(
            rule="fail2ban.uncounted_failures",
            severity=Severity.CRITICAL,
            confidence=Confidence.DERIVED,
            title=(
                f"{jail} is blind to {int(missed)} authentication failures"
                + (f" on {', '.join(blind_services)}" if blind_services else "")
            ),
            detail=detail,
            labels={"jail": jail},
            evidence=_dedupe(
                tuple(signal.evidence)
                + tuple(item for entry in per_service for item in entry.evidence)
            ),
            signal_keys=(signal.key,) + tuple(item.key for item in per_service),
        )


def rule_filter_wiring(ctx: RuleContext) -> Iterable[Finding]:
    """A correct filter file is not the same as a jail using it.

    The ``[dovecot-docker]`` stanza on this server pointed at fail2ban's stock
    ``dovecot`` filter for weeks while the correct file sat next to it, unused.
    Nothing about that looks broken from any status output.
    """
    for signal in ctx.by_name.get("fail2ban.jail.filter_as_expected", []):
        if signal.value is not False:
            continue
        jail = signal.labels.get("jail", "?")
        declared = ctx.value(f"fail2ban.jail.filter_declared{{jail={jail}}}")
        yield Finding(
            rule="fail2ban.filter_not_as_expected",
            severity=Severity.CRITICAL,
            confidence=Confidence.OBSERVED,
            title=f"{jail} is using filter '{declared}', not the one it is configured to expect",
            detail=(
                "The filter file being present is not the same as the jail using it. A jail "
                "pointing at a stock filter that does not understand this log format matches "
                "nothing and reports itself healthy indefinitely."
            ),
            labels={"jail": jail},
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )

    for signal in ctx.by_name.get("fail2ban.jail.filter_file_present", []):
        if signal.value is not False:
            continue
        jail = signal.labels.get("jail", "?")
        yield Finding(
            rule="fail2ban.filter_file_missing",
            severity=Severity.CRITICAL,
            confidence=Confidence.OBSERVED,
            title=f"{jail} points at a filter file that does not exist",
            detail=(
                "fail2ban falls back silently in this situation. The jail keeps running and "
                "keeps reporting itself enabled."
            ),
            labels={"jail": jail},
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )


def rule_dovecot_blind(ctx: RuleContext) -> Iterable[Finding]:
    for signal in ctx.by_name.get("dovecot.auth_logging_healthy", []):
        if signal.value is not False:
            continue
        container = signal.labels.get("container", "dovecot")
        yield Finding(
            rule="dovecot.auth_logging_blind",
            severity=Severity.CRITICAL,
            confidence=Confidence.OBSERVED,
            title="Dovecot is not logging authentication where the jail can read it",
            detail=(
                f"log_path is {ctx.value(f'dovecot.log_path{{container={container}}}')!r} and "
                f"auth_verbose is "
                f"{ctx.value(f'dovecot.auth_verbose{{container={container}}}')!r}. Dovecot's "
                "default is syslog, which a container relays nowhere — the jail reading that "
                "log has nothing to match and cannot distinguish that from an absence of "
                "attacks."
            ),
            labels={"container": container},
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )


def rule_filter_engine_drift(ctx: RuleContext) -> Iterable[Finding]:
    """The filter on disk is not the filter in memory.

    ``fail2ban-client reload <jail>`` has returned OK on this host without
    taking effect; a full restart was required. Config review cannot find
    that, because the config is correct.
    """
    threshold = ctx.config.rules.drift_threshold
    for signal in ctx.by_name.get("fail2ban.jail.filter_engine_drift", []):
        drift = signal.value
        if not isinstance(drift, (int, float)) or abs(drift) < threshold:
            continue
        jail = signal.labels.get("jail", "?")
        matched = ctx.value(f"fail2ban.jail.filter_matched_lines{{jail={jail}}}")
        found = ctx.value(f"fail2ban.jail.found_events{{jail={jail}}}")
        direction = (
            "more than the running process counted"
            if drift > 0
            else "fewer than the running process counted"
        )
        yield Finding(
            rule="fail2ban.filter_engine_drift",
            severity=Severity.WARNING,
            confidence=Confidence.DERIVED,
            title=f"{jail}: on-disk filter and running fail2ban disagree by {int(drift)}",
            detail=(
                f"The filter file on disk matches {matched} lines in this window, {direction} "
                f"({found} Found events). Three things produce this and they are worth "
                "separating before acting: a reload that returned OK without taking effect, a "
                "filter edited part-way through the window, or lines arriving at a window edge. "
                "Only the first is a fault, and it is the one a config review cannot see."
            ),
            labels={"jail": jail},
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )


#: Alertmanager's severity label, mapped onto watchdesk's. Anything unmapped
#: becomes a NOTICE rather than being guessed upward — a neighbouring system's
#: idea of "critical" is not automatically this one's.
_ALERT_SEVERITY = {
    "critical": Severity.CRITICAL,
    "error": Severity.CRITICAL,
    "page": Severity.CRITICAL,
    "warning": Severity.WARNING,
    "warn": Severity.WARNING,
}


def rule_external_alert(ctx: RuleContext) -> Iterable[Finding]:
    """An alert reported by Alertmanager is firing.

    Note the exact claim: watchdesk observed that *Alertmanager says* something
    is wrong. It did not observe the thing itself, and the finding says so —
    otherwise a brief ends up asserting a disk is full on the authority of a
    label somebody else wrote.
    """
    for signal in ctx.by_name.get("alertmanager.alert", []):
        if str(signal.value).lower() != "firing":
            continue
        name = signal.labels.get("alertname", "unnamed")
        severity = _ALERT_SEVERITY.get(signal.labels.get("severity", "").lower(), Severity.NOTICE)
        where = signal.labels.get("instance") or signal.labels.get("job") or ""
        yield Finding(
            rule="alertmanager.alert_firing",
            severity=severity,
            confidence=Confidence.OBSERVED,
            title=f"Alertmanager: {name} firing" + (f" on {where}" if where else ""),
            detail=(
                "Reported by Alertmanager, not measured by watchdesk. The text below is "
                "free-form and comes from whoever wrote the alerting rule; treat it as a "
                "pointer to look at that system, not as a measurement made here."
            ),
            labels=dict(signal.labels),
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )


def rule_collection_errors(ctx: RuleContext) -> Iterable[Finding]:
    """A collector that could not see is not a collector that saw nothing."""
    errors = [signal for signal in ctx.signals if signal.kind is SignalKind.ERROR]
    for signal in errors:
        yield Finding(
            rule="watchdesk.collection_error",
            severity=Severity.WARNING,
            confidence=Confidence.OBSERVED,
            title=f"{signal.source} could not complete its collection",
            detail=(
                f"{signal.value}\n\nEvery metric this source would have supplied is unknown for "
                "this round, not zero. Treat the corresponding rules as unevaluated."
            ),
            labels=dict(signal.labels),
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
        )


# --------------------------------------------------------------------------
# Change rules — need the previous round
# --------------------------------------------------------------------------


def _stale(ctx: RuleContext, previous: Observation) -> str | None:
    limit = ctx.window * ctx.config.rules.stale_baseline_factor
    age = previous.age(ctx.now)
    if age > limit:
        return f"baseline is {age} old, more than {ctx.config.rules.stale_baseline_factor} windows"
    return None


def rule_rate_spike(ctx: RuleContext) -> Iterable[Finding]:
    """A watched metric multiplied since the previous round.

    Both a factor and an absolute delta must be exceeded. The factor alone
    fires on 1 -> 5, which on a quiet server happens constantly; the delta
    alone fires on 400 -> 430, which is not news. Real escalations do both.
    """
    if ctx.store is None:
        return
    rules = ctx.config.rules
    for name in rules.spike_watch:
        for signal in ctx.by_name.get(name, []):
            current = signal.value
            if not isinstance(current, (int, float)) or isinstance(current, bool):
                continue
            previous = ctx.previous(signal.key)
            if previous is None or previous.number is None:
                continue
            before = previous.number
            delta = current - before
            if delta < rules.spike_min_delta:
                continue
            # A jump from zero has no ratio. It is still the most interesting
            # shape there is on a server that is usually quiet, so it is
            # reported on the absolute delta alone.
            from_zero = before == 0
            if not from_zero and current < before * rules.spike_factor:
                continue

            severity = (
                Severity.CRITICAL if signal.name in rules.critical_on_spike else Severity.WARNING
            )
            factor = "from zero" if from_zero else f"x{current / before:.1f}"
            yield Finding(
                rule="change.rate_spike",
                severity=severity,
                confidence=Confidence.DERIVED,
                title=(
                    f"{signal.name} {factor}: {before:g} -> {current:g} "
                    f"{signal.unit or ''}"
                ).strip(),
                detail=(
                    f"{signal.key} moved from {before:g} to {current:g} "
                    f"(+{delta:g}) between the previous round and this one."
                ),
                labels=dict(signal.labels),
                evidence=tuple(signal.evidence),
                signal_keys=(signal.key,),
                baseline=(
                    f"previous round at {previous.observed_at.isoformat()} ({previous.label})"
                    + (f" — {stale}" if (stale := _stale(ctx, previous)) else "")
                ),
            )


def rule_counter_reset(ctx: RuleContext) -> Iterable[Finding]:
    """A cumulative counter went down.

    fail2ban keeps Total failed in memory; a restart sets it to zero. Read
    without this rule, the next round shows a jail that suddenly looks calm.
    """
    if ctx.store is None:
        return
    cumulative = (
        "fail2ban.jail.total_failed",
        "fail2ban.jail.total_banned",
        "docker.container.restart_count",
    )
    for name in cumulative:
        for signal in ctx.by_name.get(name, []):
            current = signal.value
            if not isinstance(current, (int, float)):
                continue
            previous = ctx.previous(signal.key)
            if previous is None or previous.number is None or current >= previous.number:
                continue
            restarts = ctx.value("fail2ban.server_starts")
            yield Finding(
                rule="change.counter_reset",
                severity=Severity.NOTICE,
                confidence=Confidence.DERIVED,
                title=f"{signal.name} went backwards: {previous.number:g} -> {current:g}",
                detail=(
                    "A cumulative counter cannot decrease while the process that owns it keeps "
                    "running, so this is a restart. Bans survive it (they are in sqlite); the "
                    "counters do not. The consequence for the next few rounds is that low "
                    "numbers mean lost history, not calm."
                    + (
                        f" fail2ban recorded {restarts} start(s) in this window."
                        if isinstance(restarts, (int, float)) and restarts
                        else ""
                    )
                ),
                labels=dict(signal.labels),
                signal_keys=(signal.key,),
                baseline=(
                    f"previous value {previous.number:g} at "
                    f"{previous.observed_at.isoformat()}"
                ),
            )


def rule_state_changed(ctx: RuleContext) -> Iterable[Finding]:
    """A STATE signal is not what it was last round.

    Most of these are informational on their own; they earn their place by
    being the thing correlate.py pairs with a metric that moved.
    """
    if ctx.store is None:
        return
    interesting = {
        "fail2ban.jail.running",
        "fail2ban.jail.filter_declared",
        "fail2ban.config_digest",
        "dovecot.log_path",
        "dovecot.auth_verbose",
        "docker.container.running",
        "docker.container.started_at",
        "postfix.sasl_backend",
    }
    for signal in ctx.signals:
        if signal.kind is not SignalKind.STATE or signal.name not in interesting:
            continue
        previous = ctx.previous(signal.key)
        if previous is None or previous.value == signal.value:
            continue
        yield Finding(
            rule="change.state_changed",
            severity=Severity.NOTICE,
            confidence=Confidence.OBSERVED,
            title=f"{signal.key} changed: {previous.value} -> {signal.value}",
            detail=(
                "A state watchdesk tracks between rounds is different. On its own this is "
                "context rather than a problem; it matters when something else moved at the "
                "same time."
            ),
            labels=dict(signal.labels),
            evidence=tuple(signal.evidence),
            signal_keys=(signal.key,),
            baseline=f"previous value at {previous.observed_at.isoformat()}",
        )


def rule_silence(ctx: RuleContext) -> Iterable[Finding]:
    """Something we used to know, we no longer know.

    Every other rule in this file reads an absent signal as a healthy one.
    This is the rule that refuses to.
    """
    if ctx.store is None:
        return
    lookback = timedelta(hours=ctx.config.rules.silence_lookback_hours)
    known = ctx.store.keys_seen(ctx.now, lookback)
    if not known:
        return
    missing = sorted(known - set(ctx.by_key))
    # Per-source labels churn legitimately: the top-five attacker breakdown is
    # a different five every round. Silence is only meaningful for keys that
    # are supposed to be there every time.
    missing = [key for key in missing if "source=" not in key and "service=" not in key]
    if not missing:
        return
    yield Finding(
        rule="change.went_silent",
        severity=Severity.WARNING,
        confidence=Confidence.DERIVED,
        title=f"{len(missing)} signal(s) stopped being reported",
        detail=(
            "These were observed in the last "
            f"{ctx.config.rules.silence_lookback_hours}h and are absent this round:\n"
            + "\n".join(f"  {key}" for key in missing[:20])
            + "\n\nA collector that has gone quiet is indistinguishable from a quiet system "
            "unless something asks this question explicitly."
        ),
        signal_keys=tuple(missing[:20]),
    )


ALL_RULES = (
    rule_uncounted_failures,
    rule_filter_wiring,
    rule_dovecot_blind,
    rule_external_alert,
    rule_filter_engine_drift,
    rule_rate_spike,
    rule_counter_reset,
    rule_state_changed,
    rule_silence,
    rule_collection_errors,
)


def evaluate(
    config: Config,
    signals: Sequence[Signal],
    store: StateStore | None,
    now: datetime,
) -> list[Finding]:
    """Run every rule, most severe first."""
    ctx = RuleContext(config=config, signals=signals, store=store, now=now)
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(ctx))
    findings.sort(key=lambda finding: (-int(finding.severity), finding.rule, finding.title))
    return findings
