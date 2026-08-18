"""Change detection across two real, adjacent days.

The two fixtures are 2026-07-31 (the jail blind to the submission listener)
and 2026-08-01 (the day the filter was corrected). Replayed in order through
one history, watchdesk has to do three separate things, and getting two of
them right is not enough:

* report the gap on the first day,
* report what multiplied on the second, and point at the config edit that
  happened in the same window,
* stay quiet about the metric that did not meaningfully move.

The third is the one that decides whether any of this is usable. A detector
that flags everything during an incident has told nobody anything.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from watchdesk.collect import run_round
from watchdesk.config import load_config
from watchdesk.correlate import correlate
from watchdesk.detect.rules import Severity, evaluate
from watchdesk.detect.state import StateStore
from watchdesk.leakcheck import assert_clean
from watchdesk.redact import RedactionPolicy, Redactor
from watchdesk.sources.shell import RecordedRunner

FIXTURES = Path(__file__).parent / "fixtures"
GAP = FIXTURES / "2026-08-fail2ban-gap"
FIXED = FIXTURES / "2026-08-fail2ban-fixed"
CONFIG = Path(__file__).parent.parent / "config" / "watchdesk.example.yaml"


def _run(fixture: Path, config, store: StateStore):
    meta = yaml.safe_load((fixture / "meta.yaml").read_text(encoding="utf-8"))
    now = datetime.fromisoformat(str(meta["as_of"]).replace("Z", "+00:00")).astimezone(timezone.utc)
    round_config = config.model_copy(update={"window_minutes": meta["window_minutes"]})
    runner = RecordedRunner(fixture, allowlist=round_config.shell.to_allowlist())
    result = run_round(round_config, runner=runner, now=now)
    findings = evaluate(round_config, result.signals, store, now)
    findings = correlate(round_config, findings, result.signals, store, now)
    store.record(result, label=fixture.name)
    return result, findings


@pytest.fixture(scope="module")
def replay(tmp_path_factory):
    config = load_config(CONFIG)
    store = StateStore(tmp_path_factory.mktemp("state") / "state.sqlite3")
    first = _run(GAP, config, store)
    second = _run(FIXED, config, store)
    yield first, second
    store.close()


def by_rule(findings, rule: str):
    return [finding for finding in findings if finding.rule == rule]


# --------------------------------------------------------------------------


def test_the_first_day_reports_the_gap(replay) -> None:
    (_, first_findings), _ = replay
    gap = by_rule(first_findings, "fail2ban.uncounted_failures")
    assert len(gap) == 1
    assert gap[0].severity is Severity.CRITICAL
    assert "210" in gap[0].title
    assert "submission/smtpd" in gap[0].title


def test_the_first_day_has_no_change_findings(replay) -> None:
    """There is nothing before it. Inventing a baseline out of the first round
    would make every deployment start with a page."""
    (_, first_findings), _ = replay
    assert not [f for f in first_findings if f.rule.startswith("change.")]


def test_the_second_day_reports_what_multiplied(replay) -> None:
    _, (_, second_findings) = replay
    spikes = {
        finding.labels.get("jail", "") + ":" + finding.title.split()[0]
        for finding in by_rule(second_findings, "change.rate_spike")
    }
    assert "postfix-docker:fail2ban.jail.found_events" in spikes
    assert "postfix-docker:fail2ban.jail.ban_events" in spikes


def test_the_spike_is_paired_with_the_config_edit(replay) -> None:
    """The point of correlate.py. "Bans multiplied by 32" is a fact; "bans
    multiplied by 32 and the filter file changed in the same window" is an
    explanation somebody can act on."""
    _, (_, second_findings) = replay
    spikes = by_rule(second_findings, "change.rate_spike")
    assert spikes
    for finding in spikes:
        assert any(
            "config_edit" in item and "postfix-docker.conf" in item
            for item in finding.correlations
        ), finding.correlations


def test_the_flat_metric_stays_quiet(replay) -> None:
    """Real authentication failures went 212 -> 226 across these two days.

    That is the traffic itself, and it barely moved. What changed was how much
    of it fail2ban could see. A rule that cannot tell those apart would report
    an attack that did not happen.
    """
    (first_round, _), (second_round, second_findings) = replay
    before = next(
        s.value for s in first_round.signals if s.key == "postfix.auth_failures{container=postfix}"
    )
    after = next(
        s.value for s in second_round.signals if s.key == "postfix.auth_failures{container=postfix}"
    )
    assert (before, after) == (212, 226)
    assert not [
        finding
        for finding in by_rule(second_findings, "change.rate_spike")
        if "postfix.auth_failures" in finding.title
    ]


def test_the_mid_window_filter_change_shows_up_as_engine_drift(replay) -> None:
    """The filter was corrected part-way through 2026-08-01, so the file on
    disk at the end of the day matches more than the running process counted
    during it. That is a real disagreement and it is reported — with the edit
    attached, so it reads as an explanation rather than a fault."""
    _, (_, second_findings) = replay
    drift = by_rule(second_findings, "fail2ban.filter_engine_drift")
    assert len(drift) == 1
    assert "filter edited part-way through the window" in drift[0].detail
    assert any("config_edit" in item for item in drift[0].correlations)


def test_nothing_went_silent_between_two_healthy_rounds(replay) -> None:
    _, (_, second_findings) = replay
    assert not by_rule(second_findings, "change.went_silent")


def test_no_collection_errors_in_either_round(replay) -> None:
    (first_round, first_findings), (second_round, second_findings) = replay
    assert not first_round.failed_sources and not second_round.failed_sources
    assert not by_rule(first_findings, "watchdesk.collection_error")
    assert not by_rule(second_findings, "watchdesk.collection_error")


def test_findings_survive_redaction(replay) -> None:
    """Findings leave this machine, so they go through the same gate signals do."""
    _, (_, second_findings) = replay
    redactor = Redactor(
        RedactionPolicy(
            salt="replay-change-salt",
            own_domains=("example.com",),
            own_hostnames=("mail.example.com",),
        )
    )
    payload = json.dumps(
        [finding.redacted(redactor).to_dict() for finding in second_findings], ensure_ascii=False
    )
    assert_clean(payload)
    assert "change.rate_spike" in payload
