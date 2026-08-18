"""The acceptance test: replay the incident and require the finding.

``tests/fixtures/2026-08-fail2ban-gap/`` is a genuine capture from the server,
redacted at capture time (see its ``meta.yaml`` for what is captured and what
is reconstructed).  On that day the ``postfix-docker`` jail was blind to the
submission listener while reporting itself perfectly healthy.

If watchdesk cannot say so from these files, it does not do the one thing it
claims to do, and this file is the place that says so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from watchdesk.collect import run_round
from watchdesk.config import load_config
from watchdesk.fixtures import open_fixture
from watchdesk.leakcheck import assert_clean
from watchdesk.redact import RedactionPolicy, Redactor
from watchdesk.sources.base import SignalKind

FIXTURE = Path(__file__).parent / "fixtures" / "2026-08-fail2ban-gap"
CONFIG = Path(__file__).parent.parent / "config" / "watchdesk.example.yaml"


@pytest.fixture(scope="module")
def replay():
    runner, now, config = open_fixture(FIXTURE, load_config(CONFIG))
    return run_round(config, runner=runner, now=now), config


def value(round_, key: str):
    matches = [signal for signal in round_.signals if signal.key == key]
    assert matches, f"no signal {key}; got {sorted({s.key for s in round_.signals})}"
    return matches[0].value


# --------------------------------------------------------------------------
# The finding
# --------------------------------------------------------------------------


def test_the_submission_listener_is_named_as_the_blind_spot(replay) -> None:
    """The headline. 210 authentication failures on port 587, none counted."""
    round_, _ = replay
    uncounted = value(
        round_,
        "fail2ban.jail.uncounted_failures_by_service"
        "{jail=postfix-docker,service=submission/smtpd}",
    )
    assert uncounted == 210


def test_port_25_is_not_blamed(replay) -> None:
    """The listener that was working must come back clean, or the finding is
    'something is wrong somewhere' — which is what a dashboard already says."""
    round_, _ = replay
    assert (
        value(
            round_,
            "fail2ban.jail.uncounted_failures_by_service{jail=postfix-docker,service=smtpd}",
        )
        == 0
    )


def test_the_gap_is_almost_the_whole_of_the_traffic(replay) -> None:
    round_, _ = replay
    assert value(round_, "fail2ban.jail.observed_failures{jail=postfix-docker}") == 212
    assert value(round_, "fail2ban.jail.filter_would_match{jail=postfix-docker}") == 2
    assert value(round_, "fail2ban.jail.uncounted_failures{jail=postfix-docker}") == 210
    assert value(round_, "fail2ban.jail.coverage_ratio{jail=postfix-docker}") < 0.02


def test_three_independent_counts_agree_on_what_the_jail_saw(replay) -> None:
    """The method, not the answer.

    watchdesk's application of the on-disk filter, fail2ban's own
    ``fail2ban-regex`` tool, and the running fail2ban's logged Found events
    all put the jail's view of that day at six lines. Agreement here is what
    makes the 212 credible: it rules out "watchdesk's regex is just wrong".
    """
    round_, _ = replay
    assert value(round_, "fail2ban.jail.filter_matched_lines{jail=postfix-docker}") == 6
    assert value(round_, "fail2ban.jail.regex_tool_matches{jail=postfix-docker}") == 6
    assert value(round_, "fail2ban.jail.found_events{jail=postfix-docker}") == 6


def test_the_jail_looked_healthy_the_whole_time(replay) -> None:
    """Why no dashboard would have caught this.

    Enabled, using the filter it was supposed to use, with a filter file that
    exists, counters in the hundreds, and a ban that same day.
    """
    round_, _ = replay
    assert value(round_, "fail2ban.jail.running{jail=postfix-docker}") is True
    assert value(round_, "fail2ban.jail.filter_as_expected{jail=postfix-docker}") is True
    assert value(round_, "fail2ban.jail.filter_file_present{jail=postfix-docker}") is True
    assert value(round_, "fail2ban.jail.total_failed{jail=postfix-docker}") > 0
    assert value(round_, "fail2ban.jail.ban_events{jail=postfix-docker}") >= 1


def test_dovecot_is_not_dragged_in(replay) -> None:
    """The other jail was fine that day. A detector that flags everything
    during an incident has told you nothing."""
    round_, _ = replay
    assert value(round_, "fail2ban.jail.uncounted_failures{jail=dovecot-docker}") == 0
    assert value(round_, "dovecot.auth_logging_healthy{container=dovecot}") is True


def test_the_round_completed_without_collection_errors(replay) -> None:
    round_, _ = replay
    errors = [signal for signal in round_.signals if signal.kind is SignalKind.ERROR]
    assert not errors, [signal.to_dict() for signal in errors]
    assert not round_.failed_sources


# --------------------------------------------------------------------------
# The pipeline gate, on real data
# --------------------------------------------------------------------------


def test_the_whole_round_survives_redaction_intact(replay) -> None:
    """The redaction gate, end to end, on a real incident rather than on
    hand-written sample lines."""
    round_, config = replay
    policy = RedactionPolicy(
        salt="replay-test-salt",
        own_domains=("example.com",),
        own_mailboxes=("owner",),
        own_hostnames=("mail.example.com",),
    )
    redactor = Redactor(policy)
    payload = json.dumps(
        [signal.redacted(redactor).to_dict() for signal in round_.signals],
        ensure_ascii=False,
    )
    assert_clean(payload)


def test_signal_names_survive_redaction(replay) -> None:
    """Redaction applies to data, not schema.

    A text-level pass over a rendered line mistakes ``fail2ban.jail.running``
    for a hostname and pseudonymises it into noise, which is how this was
    found.
    """
    round_, _ = replay
    redactor = Redactor(RedactionPolicy(salt="replay-test-salt"))
    redacted = [signal.redacted(redactor) for signal in round_.signals]
    assert any(signal.name == "fail2ban.jail.uncounted_failures" for signal in redacted)
    prefixes = ("fail2ban.", "postfix.", "dovecot.", "docker.", "watchdesk.")
    assert all(signal.name.startswith(prefixes) for signal in redacted)
