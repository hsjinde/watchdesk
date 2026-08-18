"""The adapter for everything watchdesk does not measure itself.

Two things get tested here beyond the mapping: that alert labels are treated
as ordinary untrusted data (they carry addresses, and they go out through the
same redaction as anything else), and that a malformed spool file is reported
rather than skipped — a gap that reports nothing looks exactly like an absence
of alerts.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from watchdesk.config import load_config
from watchdesk.detect.rules import Severity, evaluate
from watchdesk.leakcheck import assert_clean
from watchdesk.redact import RedactionPolicy, Redactor
from watchdesk.sources.alertmanager import (
    MAX_ANNOTATION_CHARS,
    AlertmanagerSource,
    alerts_to_signals,
    parse_payload,
)
from watchdesk.sources.base import SignalKind, SourceContext

NOW = datetime(2026, 8, 18, 16, 0, tzinfo=timezone.utc)

PAYLOAD = {
    "version": "4",
    "status": "firing",
    "receiver": "watchdesk",
    "externalURL": "https://alertmanager.example.com",
    "alerts": [
        {
            "status": "firing",
            "fingerprint": "7b1a2c3d",
            "labels": {
                "alertname": "HostDiskWillFill",
                "severity": "critical",
                "instance": "10.0.0.5:9100",
                "job": "node",
            },
            "annotations": {"summary": "Filesystem / will be full in 4 hours"},
            "startsAt": "2026-08-18T15:40:00Z",
            "generatorURL": "https://prometheus.internal.example/graph?g0.expr=x",
        },
        {
            "status": "resolved",
            "fingerprint": "9f8e7d6c",
            "labels": {"alertname": "BlackboxProbeFailed", "severity": "warning"},
            "annotations": {"summary": "IMAPS probe recovered"},
            "startsAt": "2026-08-18T14:00:00Z",
        },
    ],
}


@pytest.fixture
def config():
    return load_config()


def signals():
    return alerts_to_signals(parse_payload(PAYLOAD), NOW)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_a_webhook_becomes_one_signal_per_alert_plus_a_count() -> None:
    produced = signals()
    alerts = [s for s in produced if s.name == "alertmanager.alert"]
    assert len(alerts) == 2
    assert {s.value for s in alerts} == {"firing", "resolved"}
    firing = next(s for s in produced if s.name == "alertmanager.alerts_firing")
    assert firing.value == 1


def test_only_bounded_labels_become_signal_keys() -> None:
    """Alertmanager label sets are unbounded. Keying on all of them would
    fragment history into one series per unique combination, and every change
    rule compares a series against its own past."""
    alert = next(s for s in signals() if s.labels.get("alertname") == "HostDiskWillFill")
    assert set(alert.labels) <= {"alertname", "severity", "instance", "job"}


def test_annotations_are_length_capped() -> None:
    """Free text from a neighbouring system reaches the LLM prompt. A hostile
    annotation should not be able to fill the context window."""
    payload = json.loads(json.dumps(PAYLOAD))
    payload["alerts"][0]["annotations"]["summary"] = "A" * 5000
    alert = next(
        s
        for s in alerts_to_signals(parse_payload(payload), NOW)
        if s.labels.get("alertname") == "HostDiskWillFill"
    )
    assert len(alert.evidence[0].excerpt) <= MAX_ANNOTATION_CHARS


def test_truncated_alerts_are_counted_because_nothing_else_records_them() -> None:
    payload = json.loads(json.dumps(PAYLOAD))
    payload["truncatedAlerts"] = 7
    produced = alerts_to_signals(parse_payload(payload), NOW)
    assert any(s.name == "alertmanager.truncated_alerts" and s.value == 7 for s in produced)


def test_malformed_payloads_are_rejected_with_a_reason() -> None:
    with pytest.raises(ValueError, match="not JSON"):
        parse_payload("{not json")
    with pytest.raises(ValueError, match="not a JSON object"):
        parse_payload("[1, 2, 3]")


def test_an_unknown_shape_is_rejected_rather_than_half_read() -> None:
    with pytest.raises(ValueError):
        parse_payload({"alerts": "this should be a list"})


# --------------------------------------------------------------------------
# Redaction — an alert is untrusted data like any other
# --------------------------------------------------------------------------


def test_instance_labels_carry_addresses_and_are_redacted() -> None:
    """`instance` is almost always host:port. Nothing here is exempt because
    it arrived from a system the operator trusts."""
    redactor = Redactor(RedactionPolicy(salt="am-test"))
    payload = json.dumps([s.redacted(redactor).to_dict() for s in signals()])
    assert "10.0.0.5" not in payload
    assert_clean(payload)


def test_generator_urls_stay_legible_after_redaction() -> None:
    """The host goes; "it was an HTTPS link with a path" stays, because that
    is what makes the evidence worth showing at all."""
    redactor = Redactor(RedactionPolicy(salt="am-test"))
    alert = next(s for s in signals() if s.labels.get("alertname") == "HostDiskWillFill")
    generator = next(e for e in alert.redacted(redactor).evidence if e.kind == "alert_source")
    assert generator.excerpt.startswith("https://host:")
    assert "prometheus.internal.example" not in generator.excerpt


# --------------------------------------------------------------------------
# The spool
# --------------------------------------------------------------------------


def context(tmp_path, config, now=NOW):
    return SourceContext(
        runner=None,
        config=config.model_copy(
            update={"alertmanager": config.alertmanager.model_copy(
                update={"spool_dir": str(tmp_path)}
            )}
        ),
        now=now,
    )


def test_a_missing_spool_is_a_state_not_a_failure(config, tmp_path) -> None:
    ctx = context(tmp_path / "absent", config)
    produced = list(AlertmanagerSource().collect(ctx))
    assert [s.name for s in produced] == ["alertmanager.spool_present"]
    assert produced[0].value is False


def test_spooled_payloads_are_read(config, tmp_path) -> None:
    (tmp_path / "a.json").write_text(json.dumps(PAYLOAD), encoding="utf-8")
    produced = list(AlertmanagerSource().collect(context(tmp_path, config)))
    assert any(s.name == "alertmanager.alert" for s in produced)
    assert next(s for s in produced if s.name == "alertmanager.payloads_read").value == 1


def test_an_unreadable_spool_file_is_reported_not_skipped(config, tmp_path) -> None:
    """A gap that reports nothing looks exactly like an absence of alerts."""
    (tmp_path / "broken.json").write_text("{ not json", encoding="utf-8")
    produced = list(AlertmanagerSource().collect(context(tmp_path, config)))
    errors = [s for s in produced if s.kind is SignalKind.ERROR]
    assert len(errors) == 1
    assert "broken.json" in str(errors[0].value)


def test_an_oversized_payload_is_refused_unread(config, tmp_path) -> None:
    (tmp_path / "huge.json").write_text("x" * (config.alertmanager.max_payload_bytes + 1))
    produced = list(AlertmanagerSource().collect(context(tmp_path, config)))
    errors = [s for s in produced if s.kind is SignalKind.ERROR]
    assert errors and "over the configured cap" in str(errors[0].value)


def test_payloads_older_than_the_window_are_ignored(config, tmp_path) -> None:
    (tmp_path / "old.json").write_text(json.dumps(PAYLOAD), encoding="utf-8")
    ctx = context(tmp_path, config, now=NOW + timedelta(days=3))
    produced = list(AlertmanagerSource().collect(ctx))
    assert next(s for s in produced if s.name == "alertmanager.payloads_read").value == 0


# --------------------------------------------------------------------------
# The rule
# --------------------------------------------------------------------------


def test_a_firing_alert_becomes_a_finding_at_its_own_severity(config) -> None:
    findings = evaluate(config, signals(), None, NOW)
    firing = [f for f in findings if f.rule == "alertmanager.alert_firing"]
    assert len(firing) == 1
    assert firing[0].severity is Severity.CRITICAL
    assert "HostDiskWillFill" in firing[0].title


def test_a_resolved_alert_produces_no_finding(config) -> None:
    findings = evaluate(config, signals(), None, NOW)
    assert not any("BlackboxProbeFailed" in f.title for f in findings)


def test_an_unmapped_severity_is_not_guessed_upward(config) -> None:
    payload = json.loads(json.dumps(PAYLOAD))
    payload["alerts"][0]["labels"]["severity"] = "spicy"
    findings = evaluate(config, alerts_to_signals(parse_payload(payload), NOW), None, NOW)
    firing = next(f for f in findings if f.rule == "alertmanager.alert_firing")
    assert firing.severity is Severity.NOTICE


def test_the_finding_says_who_observed_it(config) -> None:
    """watchdesk observed that Alertmanager says something is wrong. It did not
    observe the thing itself, and a brief must not claim otherwise."""
    findings = evaluate(config, signals(), None, NOW)
    firing = next(f for f in findings if f.rule == "alertmanager.alert_firing")
    assert "not measured by watchdesk" in firing.detail
