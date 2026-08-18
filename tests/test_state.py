"""History storage: the thing that makes change detectable at all."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from watchdesk.collect import Round
from watchdesk.detect.state import StateStore
from watchdesk.sources.base import Signal, SignalKind

T0 = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)


def metric(name: str, value, at: datetime, **labels) -> Signal:
    return Signal(
        name=name,
        kind=SignalKind.METRIC,
        value=value,
        source="test",
        labels=labels,
        observed_at=at,
        unit="events",
    )


def state(name: str, value, at: datetime, **labels) -> Signal:
    return Signal(
        name=name, kind=SignalKind.STATE, value=value, source="test", labels=labels, observed_at=at
    )


def a_round(at: datetime, *signals: Signal) -> Round:
    return Round(started_at=at, signals=list(signals))


@pytest.fixture
def store(tmp_path):
    with StateStore(tmp_path / "state.sqlite3") as opened:
        yield opened


def test_previous_returns_the_last_value_before_now(store: StateStore) -> None:
    store.record(a_round(T0, metric("x", 3, T0)))
    store.record(a_round(T0 + timedelta(hours=1), metric("x", 400, T0 + timedelta(hours=1))))

    latest = store.previous("x", T0 + timedelta(hours=2))
    assert latest and latest.value == 400
    earlier = store.previous("x", T0 + timedelta(minutes=30))
    assert earlier and earlier.value == 3


def test_previous_is_strictly_before(store: StateStore) -> None:
    """A round must never be handed itself as its own baseline."""
    store.record(a_round(T0, metric("x", 5, T0)))
    assert store.previous("x", T0) is None


def test_labels_separate_series(store: StateStore) -> None:
    store.record(
        a_round(
            T0,
            metric("f.found", 6, T0, jail="postfix-docker"),
            metric("f.found", 879, T0, jail="sshd"),
        )
    )
    assert store.previous("f.found{jail=postfix-docker}", T0 + timedelta(hours=1)).value == 6
    assert store.previous("f.found{jail=sshd}", T0 + timedelta(hours=1)).value == 879


def test_booleans_do_not_become_numbers(store: StateStore) -> None:
    """bool is a subclass of int in Python.

    Stored as 1.0, a state flip reads back as a metric and gets differenced,
    which turns "the jail stopped using the right filter" into "a counter went
    down by one".
    """
    store.record(a_round(T0, state("healthy", True, T0), state("blind", False, T0)))
    healthy = store.previous("healthy", T0 + timedelta(minutes=1))
    blind = store.previous("blind", T0 + timedelta(minutes=1))
    assert healthy.value is True
    assert blind.value is False
    assert healthy.number is None


def test_keys_seen_supports_silence_detection(store: StateStore) -> None:
    store.record(a_round(T0, metric("a", 1, T0), metric("b", 2, T0)))
    seen = store.keys_seen(T0 + timedelta(hours=1), timedelta(hours=24))
    assert seen == {"a", "b"}


def test_keys_seen_ignores_the_distant_past(store: StateStore) -> None:
    store.record(a_round(T0 - timedelta(days=30), metric("ancient", 1, T0 - timedelta(days=30))))
    assert store.keys_seen(T0, timedelta(hours=24)) == set()


def test_history_survives_reopening(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    with StateStore(path) as first:
        first.record(a_round(T0, metric("x", 1, T0)))
    with StateStore(path) as second:
        assert second.round_count() == 1
        assert second.previous("x", T0 + timedelta(hours=1)).value == 1


def test_round_labels_are_kept(store: StateStore) -> None:
    """So a finding can say which capture its baseline came from."""
    store.record(a_round(T0, metric("x", 1, T0)), label="2026-08-fail2ban-gap")
    assert store.previous("x", T0 + timedelta(hours=1)).label == "2026-08-fail2ban-gap"
