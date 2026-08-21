"""Evidence binding: what the model says only counts if it can point at it.

These run entirely against recorded completions, so the assertions are about
watchdesk's verification and not about any model's behaviour on the day.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from watchdesk.brief import Claim, build_brief, build_catalogue, rules_headline, verify_claim
from watchdesk.config import load_config
from watchdesk.detect.rules import Confidence, Finding, Severity
from watchdesk.llm import RecordedLLM
from watchdesk.sources.base import Evidence, Signal, SignalKind

NOW = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)

EVIDENCE = Evidence(
    kind="log_line",
    ref="postfix:json-log:103",
    excerpt='{"log":"postfix/submission/smtpd[9152]: SASL LOGIN authentication failed"}',
)

SIGNAL = Signal(
    name="fail2ban.jail.uncounted_failures",
    kind=SignalKind.METRIC,
    value=210,
    source="fail2ban",
    labels={"jail": "postfix-docker"},
    evidence=(EVIDENCE,),
    observed_at=NOW,
    unit="failures",
)

#: A realistic subset of one round, so the recorded completion's citations
#: resolve the way they would in production. A catalogue built from one signal
#: would make every claim look fabricated and the test would pass for the wrong
#: reason.
ROUND_SIGNALS = [
    SIGNAL,
    Signal(
        name="fail2ban.jail.observed_failures",
        kind=SignalKind.METRIC,
        value=212,
        source="fail2ban",
        labels={"jail": "postfix-docker"},
        observed_at=NOW,
        unit="failures",
    ),
    Signal(
        name="fail2ban.jail.filter_would_match",
        kind=SignalKind.METRIC,
        value=2,
        source="fail2ban",
        labels={"jail": "postfix-docker"},
        observed_at=NOW,
        unit="failures",
    ),
    Signal(
        name="fail2ban.jail.coverage_ratio",
        kind=SignalKind.METRIC,
        value=0.0094,
        source="fail2ban",
        labels={"jail": "postfix-docker"},
        observed_at=NOW,
        unit="ratio",
    ),
    Signal(
        name="fail2ban.jail.filter_as_expected",
        kind=SignalKind.STATE,
        value=True,
        source="fail2ban",
        labels={"jail": "postfix-docker"},
        observed_at=NOW,
    ),
    Signal(
        name="fail2ban.jail.uncounted_failures_by_service",
        kind=SignalKind.METRIC,
        value=210,
        source="fail2ban",
        labels={"jail": "postfix-docker", "service": "submission/smtpd"},
        observed_at=NOW,
        unit="failures",
    ),
]

FINDING = Finding(
    rule="fail2ban.uncounted_failures",
    severity=Severity.CRITICAL,
    confidence=Confidence.DERIVED,
    title="postfix-docker is blind to 210 authentication failures on submission/smtpd",
    detail="210 of 212 authentication failures are not matched by the filter. Coverage 0.0094.",
    labels={"jail": "postfix-docker"},
    evidence=(EVIDENCE,),
    signal_keys=("fail2ban.jail.uncounted_failures{jail=postfix-docker}",),
)


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def catalogue():
    return build_catalogue([FINDING], ROUND_SIGNALS)


def response(**body) -> RecordedLLM:
    import json

    return RecordedLLM([json.dumps(body)])


# --------------------------------------------------------------------------
# Claim verification
# --------------------------------------------------------------------------


def test_a_well_cited_claim_survives(catalogue) -> None:
    claim, reason = verify_claim(
        {
            "text": "210 failures on submission/smtpd went uncounted.",
            "kind": "observation",
            "refs": ["fail2ban.jail.uncounted_failures{jail=postfix-docker}"],
        },
        catalogue,
    )
    assert reason is None
    assert isinstance(claim, Claim)
    assert claim.confidence is Confidence.DERIVED


def test_a_claim_with_no_citation_is_dropped(catalogue) -> None:
    """Not softened. Dropped."""
    claim, reason = verify_claim(
        {"text": "The mail server is compromised.", "kind": "observation", "refs": []}, catalogue
    )
    assert claim is None
    assert reason == "cites no evidence"


def test_a_fabricated_citation_is_dropped(catalogue) -> None:
    """Worse than no citation: it survives a skim, because the reader sees a
    reference and stops checking."""
    claim, reason = verify_claim(
        {
            "text": "Outbound delivery tripled.",
            "kind": "observation",
            "refs": ["postfix.messages_sent_per_day{container=postfix}"],
        },
        catalogue,
    )
    assert claim is None
    assert "not in this round" in reason


def test_an_observation_asserting_an_unmeasured_number_is_dropped(catalogue) -> None:
    """The classic failure: correct-sounding prose around a number nobody
    measured."""
    claim, reason = verify_claim(
        {
            "text": "There were 4821 failed logins from one address.",
            "kind": "observation",
            "refs": ["fail2ban.jail.uncounted_failures{jail=postfix-docker}"],
        },
        catalogue,
    )
    assert claim is None
    assert "nothing in this round measured" in reason


def test_a_measured_number_cited_imprecisely_is_downgraded_not_dropped(catalogue) -> None:
    """Observed live: a model wrote "210 of 212" while citing only the signal
    worth 210. Both numbers are real. Treating that as a fabrication would bury
    actual fabrications in noise, so it is a lesser fault with its own wording.
    """
    claim, reason = verify_claim(
        {
            "text": "210 of 212 authentication failures were on submission/smtpd.",
            "kind": "observation",
            "refs": [
                "fail2ban.jail.uncounted_failures_by_service"
                "{jail=postfix-docker,service=submission/smtpd}"
            ],
        },
        catalogue,
    )
    assert reason is None
    assert claim.confidence is Confidence.HYPOTHESIS
    assert "cited imprecisely" in claim.note
    assert "212" in claim.note


def test_numbers_inside_a_ref_are_not_treated_as_measurements(catalogue) -> None:
    """postfix:json-log:103 contains "103"; citing it is not claiming 103 of
    anything."""
    claim, _ = verify_claim(
        {
            "text": "The log line at postfix:json-log:103 shows the submission listener.",
            "kind": "observation",
            "refs": ["postfix:json-log:103"],
        },
        catalogue,
    )
    assert claim.confidence is Confidence.DERIVED


def test_an_explanation_is_a_hypothesis_even_when_well_cited(catalogue) -> None:
    """Evidence can support "210 failures were on submission"; it cannot make
    "because the attackers migrated" into an observation."""
    claim, _ = verify_claim(
        {
            "text": "Scanners appear to have moved from port 25 to submission.",
            "kind": "explanation",
            "refs": ["fail2ban.uncounted_failures"],
        },
        catalogue,
    )
    assert claim.confidence is Confidence.HYPOTHESIS


# --------------------------------------------------------------------------
# The brief as a whole
# --------------------------------------------------------------------------


def test_the_model_is_not_called_when_nothing_fired(config) -> None:
    """Cost, and the fact that a summary produced every five minutes about
    nothing teaches the reader to skip it."""
    client = RecordedLLM(['{"headline": "should never be used"}'])
    brief = build_brief(config, [], ROUND_SIGNALS, NOW, client=client)
    assert client.requests == []
    assert brief.headline_source == "rules"
    assert "Nothing to report" in brief.headline


def test_the_model_is_not_called_below_the_severity_floor(config) -> None:
    notice = Finding(
        rule="change.state_changed",
        severity=Severity.NOTICE,
        confidence=Confidence.OBSERVED,
        title="a digest changed",
        detail="",
    )
    client = RecordedLLM(['{"headline": "unused"}'])
    build_brief(config, [notice], ROUND_SIGNALS, NOW, client=client)
    assert client.requests == []


def test_a_hallucinated_headline_is_replaced_by_the_rules(config) -> None:
    """The headline is the one line that always gets read."""
    client = response(
        headline="9 jails are down and 40000 accounts were breached",
        headline_refs=["fail2ban.uncounted_failures"],
        claims=[],
    )
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    assert brief.headline_source == "rules"
    assert "40000" not in brief.headline
    assert brief.headline == rules_headline([FINDING])


def test_a_supported_headline_is_kept(config) -> None:
    client = response(
        headline="postfix-docker is blind to 210 authentication failures",
        headline_refs=["fail2ban.uncounted_failures"],
        claims=[],
    )
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    assert brief.headline_source == "llm"
    assert "210" in brief.headline


def test_an_unreachable_model_still_produces_a_brief(config) -> None:
    """The rules are the product. The prose is a convenience."""
    client = RecordedLLM([])  # exhausted immediately
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    assert brief.llm_error
    assert brief.headline_source == "rules"
    assert brief.findings == (FINDING,)


def test_garbage_from_the_model_does_not_take_the_round_down(config) -> None:
    client = RecordedLLM(["I'm sorry, I can't help with that."])
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    assert brief.llm_error
    assert brief.findings == (FINDING,)


def test_the_recorded_incident_response_is_filtered_as_expected(config) -> None:
    """The acceptance case, against a recording written to contain every
    failure mode at once."""
    client = RecordedLLM(Path(__file__).parent / "fixtures" / "llm" / "gap-brief.json")
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)

    kept = {claim.text for claim in brief.claims}
    dropped = {claim.text: claim.reason for claim in brief.rejected}

    # Uncited and fabricated-citation claims are gone entirely.
    assert not any("almost certainly compromised" in text for text in kept)
    assert not any("Outbound delivery volume tripled" in text for text in kept)
    assert any(reason == "cites no evidence" for reason in dropped.values())
    assert any("not in this round" in reason for reason in dropped.values())
    assert len(brief.rejected) == 3

    # The invented number is gone entirely, with a reason a reader can check.
    assert not any("4821" in text for text in kept)
    assert any("nothing in this round measured" in reason for reason in dropped.values())

    # Real numbers cited one ref short are kept, marked, and explained.
    imprecise = [claim for claim in brief.claims if "210 of 212" in claim.text]
    assert len(imprecise) == 1
    assert imprecise[0].confidence is Confidence.HYPOTHESIS
    assert "cited imprecisely" in imprecise[0].note

    # The causal story is kept but marked.
    causal = [claim for claim in brief.claims if "moved from port 25" in claim.text]
    assert causal and causal[0].confidence is Confidence.HYPOTHESIS

    # The two well-supported observations survive as derived.
    supported = [claim for claim in brief.claims if claim.confidence is Confidence.DERIVED]
    assert len(supported) == 2


def test_every_surviving_claim_cites_something_that_exists(config) -> None:
    client = RecordedLLM(Path(__file__).parent / "fixtures" / "llm" / "gap-brief.json")
    brief = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    catalogue = build_catalogue([FINDING], ROUND_SIGNALS)
    for claim in brief.claims:
        assert claim.refs
        assert all(ref in catalogue.entries for ref in claim.refs)


def test_the_rendered_brief_marks_hypotheses_visibly(config) -> None:
    client = RecordedLLM(Path(__file__).parent / "fixtures" / "llm" / "gap-brief.json")
    rendered = build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client).render()
    assert "hypothesis" in rendered
    assert "dropped for lack of evidence" in rendered


# --------------------------------------------------------------------------
# Writing the prose in another language
# --------------------------------------------------------------------------


def test_the_language_clause_is_absent_unless_configured(config) -> None:
    client = RecordedLLM(Path(__file__).parent / "fixtures" / "llm" / "gap-brief.json")
    build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    system, _ = client.requests[0]
    assert "Write \"headline\"" not in system


def test_the_language_clause_names_the_language_and_pins_the_digits(config) -> None:
    """The digit rule is the load-bearing half of this clause.

    ``_NUMBER`` matches ASCII digits only, so a claim written with full-width
    or spelled-out numerals carries an assertion that the fabrication check
    cannot see — it would pass verification without ever being checked, which
    is worse than failing it.
    """
    config.llm.language = "Traditional Chinese (Taiwan)"
    client = RecordedLLM(Path(__file__).parent / "fixtures" / "llm" / "gap-brief.json")
    build_brief(config, [FINDING], ROUND_SIGNALS, NOW, client=client)
    system, _ = client.requests[0]

    assert "Traditional Chinese (Taiwan)" in system
    assert "ASCII numerals" in system
    assert "full-width" in system
    # The identifiers the reader greps for must survive translation.
    assert "Do not translate refs" in system
    # The original contract is still in force, not replaced by the clause.
    assert "Do not state any number that does not appear" in system


def test_verification_is_unchanged_by_a_claim_written_in_chinese(config) -> None:
    """The guard reads digits and refs, not English prose, so a translated
    brief is checked exactly as hard as an English one."""
    catalogue = build_catalogue([FINDING], ROUND_SIGNALS)
    ref = "fail2ban.jail.uncounted_failures{jail=postfix-docker}"

    supported, reason = verify_claim(
        {"text": "在這個窗口內有 210 次認證失敗未被計數。", "kind": "observation", "refs": [ref]},
        catalogue,
    )
    assert reason is None
    assert supported is not None and supported.confidence is Confidence.DERIVED

    fabricated, reason = verify_claim(
        {"text": "有 4821 次來自單一位址的登入失敗。", "kind": "observation", "refs": [ref]},
        catalogue,
    )
    assert fabricated is None
    assert "4821" in reason

    uncited, reason = verify_claim(
        {"text": "郵件伺服器幾乎確定已被入侵。", "kind": "observation", "refs": []},
        catalogue,
    )
    assert uncited is None
    assert reason == "cites no evidence"
