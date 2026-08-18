"""Rules, including the ones that must stay quiet.

Half of these assert that nothing fires. A rules engine is only useful if its
silence means something, and the way that degrades is one rule at a time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from watchdesk.collect import Round
from watchdesk.config import load_config
from watchdesk.detect.rules import Severity, evaluate
from watchdesk.detect.state import StateStore
from watchdesk.sources.base import Evidence, Signal, SignalKind

T0 = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(hours=1)


@pytest.fixture
def config():
    return load_config().model_copy(update={"window_minutes": 60})


@pytest.fixture
def store(tmp_path):
    with StateStore(tmp_path / "state.sqlite3") as opened:
        yield opened


def metric(name: str, value, at: datetime = T1, unit: str = "events", **labels) -> Signal:
    return Signal(
        name=name,
        kind=SignalKind.METRIC,
        value=value,
        source="test",
        labels=labels,
        observed_at=at,
        unit=unit,
    )


def state(name: str, value, at: datetime = T1, **labels) -> Signal:
    return Signal(
        name=name, kind=SignalKind.STATE, value=value, source="test", labels=labels, observed_at=at
    )


def rules_of(findings) -> set[str]:
    return {finding.rule for finding in findings}


# --------------------------------------------------------------------------
# Thresholds
# --------------------------------------------------------------------------


def test_uncounted_failures_is_critical_at_any_volume(config) -> None:
    """No threshold on the count. Two counts of one log disagreeing is wrong
    whether the number is 210 or 1."""
    signals = [
        metric("fail2ban.jail.uncounted_failures", 1, jail="postfix-docker"),
        metric("fail2ban.jail.observed_failures", 3, jail="postfix-docker"),
        metric(
            "fail2ban.jail.uncounted_failures_by_service",
            1,
            jail="postfix-docker",
            service="submission/smtpd",
        ),
    ]
    findings = evaluate(config, signals, None, T1)
    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert "submission/smtpd" in findings[0].title


def test_a_fully_covered_jail_produces_nothing(config) -> None:
    signals = [
        metric("fail2ban.jail.uncounted_failures", 0, jail="postfix-docker"),
        metric("fail2ban.jail.observed_failures", 23, jail="postfix-docker"),
        state("fail2ban.jail.filter_as_expected", True, jail="postfix-docker"),
        state("dovecot.auth_logging_healthy", True, container="dovecot"),
    ]
    assert evaluate(config, signals, None, T1) == []


def test_wrong_filter_is_critical_even_with_no_failures(config) -> None:
    signals = [
        state("fail2ban.jail.filter_as_expected", False, jail="dovecot-docker"),
        state("fail2ban.jail.filter_declared", "dovecot", jail="dovecot-docker"),
    ]
    findings = evaluate(config, signals, None, T1)
    assert rules_of(findings) == {"fail2ban.filter_not_as_expected"}
    assert "'dovecot'" in findings[0].title


def test_drift_below_the_threshold_is_not_reported(config) -> None:
    """A window edge routinely produces one or two. Reporting those trains the
    reader to ignore the rule."""
    signals = [metric("fail2ban.jail.filter_engine_drift", 1, jail="postfix-docker")]
    assert evaluate(config, signals, None, T1) == []


def test_collection_errors_are_never_read_as_zero(config) -> None:
    signals = [
        Signal(
            name="postfix.collection_problem",
            kind=SignalKind.ERROR,
            value="could not read the log",
            source="postfix",
            observed_at=T1,
        )
    ]
    findings = evaluate(config, signals, None, T1)
    assert rules_of(findings) == {"watchdesk.collection_error"}
    assert "not zero" in findings[0].detail


# --------------------------------------------------------------------------
# Change
# --------------------------------------------------------------------------


def test_rate_spike_needs_both_a_factor_and_a_delta(config, store: StateStore) -> None:
    store.record(
        Round(
            started_at=T0,
            signals=[
                metric("postfix.auth_failures", 1, T0),  # x5 but only +4
                metric("dovecot.auth_failures", 400, T0),  # +30 but only x1.075
                metric("fail2ban.jail.found_events", 6, T0, jail="postfix-docker"),
            ],
        )
    )
    signals = [
        metric("postfix.auth_failures", 5),
        metric("dovecot.auth_failures", 430),
        metric("fail2ban.jail.found_events", 170, jail="postfix-docker"),
    ]
    findings = [f for f in evaluate(config, signals, store, T1) if f.rule == "change.rate_spike"]
    assert len(findings) == 1
    assert "fail2ban.jail.found_events" in findings[0].title


def test_a_jump_from_zero_is_reported_on_the_delta_alone(config, store: StateStore) -> None:
    """There is no ratio out of zero, and on a quiet server it is the most
    interesting shape there is."""
    store.record(Round(started_at=T0, signals=[metric("postfix.auth_failures", 0, T0)]))
    findings = evaluate(config, [metric("postfix.auth_failures", 30)], store, T1)
    assert [f.rule for f in findings] == ["change.rate_spike"]
    assert "from zero" in findings[0].title


def test_outbound_mail_spike_is_critical_not_a_curiosity(config, store: StateStore) -> None:
    store.record(Round(started_at=T0, signals=[metric("postfix.messages_sent", 1, T0)]))
    findings = evaluate(config, [metric("postfix.messages_sent", 500)], store, T1)
    assert findings[0].severity is Severity.CRITICAL


def test_a_counter_going_backwards_is_a_restart_not_an_improvement(
    config, store: StateStore
) -> None:
    store.record(
        Round(
            started_at=T0,
            signals=[metric("fail2ban.jail.total_failed", 931, T0, jail="postfix-docker")],
        )
    )
    signals = [
        metric("fail2ban.jail.total_failed", 12, jail="postfix-docker"),
        metric("fail2ban.server_starts", 1, unit="restarts"),
    ]
    findings = [f for f in evaluate(config, signals, store, T1) if f.rule == "change.counter_reset"]
    assert len(findings) == 1
    assert "lost history, not calm" in findings[0].detail
    assert "1 start(s)" in findings[0].detail


def test_state_flip_is_reported_with_both_values(config, store: StateStore) -> None:
    store.record(
        Round(
            started_at=T0,
            signals=[state("fail2ban.config_digest", "aaa", T0, file="jail.local")],
        )
    )
    findings = evaluate(
        config, [state("fail2ban.config_digest", "bbb", file="jail.local")], store, T1
    )
    assert [f.rule for f in findings] == ["change.state_changed"]
    assert "aaa -> bbb" in findings[0].title


def test_no_history_means_no_change_findings(config) -> None:
    """First ever round. Reporting every value as new would bury the round
    that actually matters."""
    assert evaluate(config, [metric("postfix.auth_failures", 500)], None, T1) == []


# --------------------------------------------------------------------------
# Silence
# --------------------------------------------------------------------------


def test_a_signal_that_stops_being_reported_is_a_finding(config, store: StateStore) -> None:
    """Every other rule in the file reads an absent signal as a healthy one."""
    store.record(
        Round(
            started_at=T0,
            signals=[
                metric("postfix.auth_failures", 20, T0),
                metric("dovecot.auth_failures", 5, T0),
            ],
        )
    )
    findings = [
        f
        for f in evaluate(config, [metric("postfix.auth_failures", 21)], store, T1)
        if f.rule == "change.went_silent"
    ]
    assert len(findings) == 1
    assert "dovecot.auth_failures" in findings[0].detail


def test_per_source_churn_is_not_silence(config, store: StateStore) -> None:
    """The top-five attacker breakdown is a different five every round. Treating
    that as signals going quiet makes the rule fire constantly and mean nothing."""
    store.record(
        Round(
            started_at=T0,
            signals=[
                metric("postfix.auth_failures_by_source", 3, T0, source="ip:aaa"),
                metric("postfix.auth_failures", 20, T0),
            ],
        )
    )
    signals = [
        metric("postfix.auth_failures_by_source", 4, source="ip:bbb"),
        metric("postfix.auth_failures", 21),
    ]
    assert not [f for f in evaluate(config, signals, store, T1) if f.rule == "change.went_silent"]


# --------------------------------------------------------------------------
# Evidence binding
# --------------------------------------------------------------------------


def test_findings_carry_the_evidence_of_the_signals_they_rest_on(config) -> None:
    evidence = Evidence(kind="log_line", ref="postfix:json-log:103", excerpt="...SASL LOGIN...")
    signal = Signal(
        name="fail2ban.jail.uncounted_failures",
        kind=SignalKind.METRIC,
        value=210,
        source="fail2ban",
        labels={"jail": "postfix-docker"},
        evidence=(evidence,),
        observed_at=T1,
    )
    findings = evaluate(config, [signal], None, T1)
    assert findings[0].evidence == (evidence,)
    assert findings[0].signal_keys == ("fail2ban.jail.uncounted_failures{jail=postfix-docker}",)
