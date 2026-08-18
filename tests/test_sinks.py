"""Sinks, and the suppression that keeps a channel worth reading.

The delivery mechanics are two lines of HTTP. What is worth testing is when a
message is *not* sent, because an on-call channel that reposts an unchanged
alert every five minutes gets muted within a day — and a muted channel
somebody still believes is watching is worse than no channel at all.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from watchdesk.brief import Brief
from watchdesk.config import load_config
from watchdesk.detect.rules import Confidence, Finding, Severity
from watchdesk.detect.state import StateStore
from watchdesk.leakcheck import LeakError
from watchdesk.redact import RedactionPolicy, Redactor
from watchdesk.sinks import DiscordSink, suppression_digest
from watchdesk.sinks.base import record_sent, should_send
from watchdesk.sources.base import Evidence

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def finding(
    rule="fail2ban.uncounted_failures",
    severity=Severity.CRITICAL,
    title="blind",
    **labels,
):
    return Finding(
        rule=rule,
        severity=severity,
        confidence=Confidence.DERIVED,
        title=title,
        detail="detail",
        labels=labels,
    )


def brief(*findings, headline="headline", **kwargs) -> Brief:
    return Brief(
        generated_at=NOW,
        headline=headline,
        headline_source="rules",
        findings=tuple(findings),
        **kwargs,
    )


class FakeTransport:
    def __init__(self, status: int = 204):
        self.status = status
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, payload: dict) -> tuple[int, str]:
        self.calls.append((url, payload))
        return self.status, ""


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def store(tmp_path):
    with StateStore(tmp_path / "state.sqlite3") as opened:
        yield opened


@pytest.fixture
def redactor():
    return Redactor(RedactionPolicy(salt="sink-test"))


# --------------------------------------------------------------------------
# Suppression
# --------------------------------------------------------------------------


def test_the_same_situation_is_not_sent_twice(store: StateStore) -> None:
    first = brief(finding(jail="postfix-docker"))
    assert should_send(first, "discord", store, NOW).sent
    record_sent(first, "discord", store, NOW)

    again = brief(finding(jail="postfix-docker"), headline="different wording, same problem")
    decision = should_send(again, "discord", store, NOW + timedelta(minutes=5))
    assert not decision.sent
    assert "suppressed" in decision.reason


def test_moving_numbers_do_not_make_it_a_new_situation() -> None:
    """A rate ticking from 170 to 174 is the same problem. The digest covers
    which rules fired and where, not their prose."""
    a = brief(finding(title="found_events x28.3: 6 -> 170", jail="postfix-docker"))
    b = brief(finding(title="found_events x29.0: 6 -> 174", jail="postfix-docker"))
    assert suppression_digest(a) == suppression_digest(b)


def test_a_new_jail_going_blind_is_a_new_situation() -> None:
    a = brief(finding(jail="postfix-docker"))
    b = brief(finding(jail="postfix-docker"), finding(jail="dovecot-docker"))
    assert suppression_digest(a) != suppression_digest(b)


def test_an_unchanged_problem_is_repeated_eventually(store: StateStore) -> None:
    """Silence forever would let a real problem fade out of memory."""
    first = brief(finding(jail="postfix-docker"))
    record_sent(first, "discord", store, NOW)
    later = should_send(first, "discord", store, NOW + timedelta(hours=13))
    assert later.sent
    assert "re-sending" in later.reason


def test_findings_below_the_floor_are_stored_but_not_pushed(store: StateStore) -> None:
    notice = brief(finding(rule="change.state_changed", severity=Severity.NOTICE))
    decision = should_send(notice, "discord", store, NOW, min_severity="warning")
    assert not decision.sent
    assert "below" in decision.reason


def test_nothing_to_report_is_not_a_message(store: StateStore) -> None:
    assert not should_send(brief(), "discord", store, NOW).sent


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


def test_a_delivered_message_carries_the_findings_first(config, store, redactor) -> None:
    transport = FakeTransport()
    sink = DiscordSink("https://discord.example/webhook", redactor, config, store, NOW, transport)
    result = sink.deliver(brief(finding(title="postfix-docker is blind", jail="postfix-docker")))

    assert result.sent
    (_, payload) = transport.calls[0]
    description = payload["embeds"][0]["description"]
    assert description.startswith("**[CRITICAL]**")
    assert "postfix-docker is blind" in description


def test_delivery_is_recorded_so_the_next_round_suppresses(config, store, redactor) -> None:
    transport = FakeTransport()
    sink = DiscordSink("https://discord.example/webhook", redactor, config, store, NOW, transport)
    payload = brief(finding(jail="postfix-docker"))
    assert sink.deliver(payload).sent
    assert not sink.deliver(payload).sent
    assert len(transport.calls) == 1


def test_a_rate_limit_is_obeyed_not_retried(config, store, redactor) -> None:
    """Being rate-limited by a chat service is not an emergency, and the next
    round carries the same findings anyway."""
    transport = FakeTransport(status=429)
    sink = DiscordSink("https://discord.example/webhook", redactor, config, store, NOW, transport)
    result = sink.deliver(brief(finding()))
    assert not result.sent
    assert "429" in result.reason
    assert len(transport.calls) == 1


def test_a_failed_send_is_not_recorded_as_sent(config, store, redactor) -> None:
    transport = FakeTransport(status=500)
    sink = DiscordSink("https://discord.example/webhook", redactor, config, store, NOW, transport)
    payload = brief(finding())
    assert not sink.deliver(payload).sent
    # The next round must try again rather than suppressing a message nobody
    # ever received.
    assert should_send(payload, "discord", store, NOW + timedelta(minutes=5)).sent


def test_no_webhook_configured_is_a_reason_not_a_crash(config, store, redactor) -> None:
    sink = DiscordSink("", redactor, config, store, NOW, FakeTransport())
    assert not sink.deliver(brief(finding())).sent


# --------------------------------------------------------------------------
# The exit guard
# --------------------------------------------------------------------------


class NullRedactor:
    def text(self, value: str) -> str:
        return value


def test_an_unredacted_payload_never_reaches_discord(config, store) -> None:
    """The guard runs over the serialised body, not field by field: it is the
    bytes on the wire that matter."""
    transport = FakeTransport()
    sink = DiscordSink(
        "https://discord.example/webhook", NullRedactor(), config, store, NOW, transport
    )
    leaky = brief(
        finding(title="attacker 93.184.216.34 hit submission"),
        headline="93.184.216.34 is hammering the mail server",
    )
    with pytest.raises(LeakError):
        sink.deliver(leaky)
    assert transport.calls == []


def test_a_real_brief_serialises_clean(config, store, redactor) -> None:
    from watchdesk.leakcheck import assert_clean

    transport = FakeTransport()
    sink = DiscordSink("https://discord.example/webhook", redactor, config, store, NOW, transport)
    sink.deliver(
        brief(
            Finding(
                rule="fail2ban.uncounted_failures",
                severity=Severity.CRITICAL,
                confidence=Confidence.DERIVED,
                title="postfix-docker is blind to 210 failures",
                detail="from 93.184.216.34 and /home/operator/Maildir",
                labels={"jail": "postfix-docker"},
                evidence=(
                    Evidence(kind="log_line", ref="postfix:json-log:1", excerpt="rip=198.51.100.7"),
                ),
            )
        )
    )
    assert_clean(json.dumps(transport.calls[0][1], ensure_ascii=False))
