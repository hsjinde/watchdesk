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

from watchdesk.brief import Brief, Claim, RejectedClaim
from watchdesk.config import load_config
from watchdesk.detect.rules import Confidence, Finding, Severity
from watchdesk.detect.state import StateStore
from watchdesk.leakcheck import LeakError
from watchdesk.redact import RedactionPolicy, Redactor
from watchdesk.sinks import DiscordSink, suppression_digest
from watchdesk.sinks.base import record_sent, should_send
from watchdesk.sinks.discord import format_payload
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
    assert description.startswith("🔴 **CRITICAL** ·")
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


# --------------------------------------------------------------------------
# Formatting: what the message looks like to a tired reader
# --------------------------------------------------------------------------
#
# The delivery mechanics above decide *whether* a message is worth sending.
# These decide whether it is worth reading once it arrives, which is the same
# question one step later: a channel nobody can skim gets skimmed anyway, and
# then the finding that mattered was on screen and went unread.


def loaded_brief() -> Brief:
    """One of each thing the format has to keep apart."""
    return Brief(
        generated_at=NOW,
        headline="submission is taking failures fail2ban cannot see",
        headline_source="llm",
        findings=(
            Finding(
                rule="fail2ban.uncounted_failures",
                severity=Severity.CRITICAL,
                confidence=Confidence.DERIVED,
                title="postfix-docker is blind to 210 failures",
                detail="detail",
                baseline="7d median 12/h, now 210/h",
                correlations=("postfix.submission_failures rose in the same window",),
            ),
            Finding(
                rule="disk.growth",
                severity=Severity.WARNING,
                confidence=Confidence.DERIVED,
                title="/var is 87% full",
                detail="detail",
            ),
        ),
        claims=(
            Claim(
                text="Look at the submission listener first.",
                kind="observation",
                confidence=Confidence.DERIVED,
                refs=("fail2ban.uncounted_failures",),
            ),
            Claim(
                text="The jail's logpath no longer matches where postfix writes.",
                kind="explanation",
                confidence=Confidence.HYPOTHESIS,
                refs=("fail2ban.uncounted_failures",),
            ),
        ),
        rejected=(RejectedClaim(text="the attackers moved to port 587", reason="cites nothing"),),
        model="claude-opus-5",
    )


def test_each_finding_is_its_own_block() -> None:
    """Two findings run together are read as one, and the second one loses."""
    description = format_payload(loaded_brief(), 4096)["embeds"][0]["description"]
    head, _, rest = description.partition("postfix-docker is blind to 210 failures")
    assert "\n\n" in rest.split("/var is 87% full")[0]


def test_supporting_lines_are_quoted_rather_than_indented_with_whitespace() -> None:
    """Discord does not lay out leading whitespace, so an indent made of it is
    not structure — it is a space. A blockquote is structure."""
    description = format_payload(loaded_brief(), 4096)["embeds"][0]["description"]
    assert "\u3000" not in description
    assert "> baseline · 7d median 12/h, now 210/h" in description
    assert "> alongside · postfix.submission_failures rose in the same window" in description


def test_one_correlation_shared_by_three_findings_is_printed_once() -> None:
    """``correlate.py`` attaches the same surrounding event to every finding it
    plausibly explains. Printed under each of them, one config edit outweighs
    the three measurements it relates to, and quoted lines stop being read."""
    edit = "[config_edit] filter.d/postfix-docker.conf changed between rounds"
    shared = brief(
        *(
            Finding(
                rule=f"rule.{index}",
                severity=Severity.WARNING,
                confidence=Confidence.DERIVED,
                title=f"finding {index}",
                detail="detail",
                correlations=(edit,),
            )
            for index in range(3)
        )
    )
    description = format_payload(shared, 4096)["embeds"][0]["description"]
    assert description.count(edit) == 1
    assert description.count("finding ") == 3


def test_severity_is_visible_before_the_title_is_read() -> None:
    description = format_payload(loaded_brief(), 4096)["embeds"][0]["description"]
    assert description.startswith("🔴 **CRITICAL** · postfix-docker is blind")
    assert "🟠 **WARNING** · /var is 87% full" in description


def test_the_model_s_prose_is_labelled_as_the_model_s() -> None:
    """The findings are arithmetic and the claims are a language model's
    triage. They were formatted identically, which is the one thing this
    message must not do."""
    description = format_payload(loaded_brief(), 4096)["embeds"][0]["description"]
    assert "**Triage**" in description
    assert description.index("postfix-docker is blind") < description.index("**Triage**")


def test_a_hypothesis_says_so_in_words_rather_than_in_punctuation() -> None:
    description = format_payload(loaded_brief(), 4096)["embeds"][0]["description"]
    assert "*Hypothesis* · The jail's logpath" in description
    assert "・" not in description
    assert "\n? " not in description


def test_truncation_drops_the_prose_before_it_drops_a_measurement() -> None:
    """The findings are the product; the prose is a convenience. If the message
    will not fit, the convenience is what should be lost.

    The width here is chosen so that both findings fit and the triage does not
    — a width that only fits *one* block would pass this test for the wrong
    reason, by dropping everything after the first finding.
    """
    description = format_payload(loaded_brief(), 240)["embeds"][0]["description"]
    assert "postfix-docker is blind" in description
    assert "> baseline · 7d median 12/h, now 210/h" in description
    assert "/var is 87% full" in description
    assert "Triage" not in description
    assert description.endswith("_truncated_")


def test_a_truncated_message_does_not_end_mid_quote() -> None:
    """A half-cut blockquote reads worse than the indent it replaced: the
    reader cannot tell whether the number was small or the line was clipped."""
    for width in range(60, 420, 7):
        description = format_payload(loaded_brief(), width)["embeds"][0]["description"]
        last = description.rsplit("\n", 1)[-1]
        if last.startswith(">"):
            assert not last.endswith("..."), f"quoted line cut at width {width}: {last!r}"


def test_a_finding_too_long_to_fit_keeps_its_title_and_drops_its_support() -> None:
    description = format_payload(loaded_brief(), 60)["embeds"][0]["description"]
    assert description == "🔴 **CRITICAL** · postfix-docker is blind to 210 failures"


def test_a_title_too_long_to_fit_is_cut_rather_than_dropped() -> None:
    """Truncated evidence beats an empty message."""
    description = format_payload(loaded_brief(), 40)["embeds"][0]["description"]
    assert description.startswith("🔴 **CRITICAL** · postfix")
    assert description.endswith("...")


def test_the_footer_counts_one_finding_in_the_singular() -> None:
    payload = format_payload(brief(finding()), 4096)
    assert payload["embeds"][0]["footer"]["text"].startswith("watchdesk · 1 finding ·")
