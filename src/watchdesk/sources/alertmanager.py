"""Alertmanager webhooks, turned into Signals.

This is the seam for everything watchdesk does not measure itself.  Node
exporter, blackbox probes, certificate expiry, whatever else ends up in
Prometheus later — none of that needs a second collector here.  It needs one
adapter, and this is it.

**watchdesk does not listen on a port.**  A read-only monitoring tool on a mail
server has no business opening a socket, and a webhook receiver is an
unauthenticated HTTP endpoint by default.  Instead, payloads are written into a
spool directory by something that already terminates HTTP — nginx, a socket-
activated unit, `watchdesk ingest` behind either — and rounds read the spool.
The trade is a few seconds of latency for not adding a listening service to the
box being watched.

**A payload is untrusted input**, and it is untrusted in a way that is easy to
forget: alert annotations are free text written by whoever configured the
alerting rules, and they flow into the brief, which flows into an LLM prompt.
That is a prompt-injection path from a neighbouring system straight into the
thing that writes your on-call summary. Three defences here, none of them
clever: annotations are length-capped, they are carried as evidence rather than
as instructions, and every claim in a brief still has to cite a ref that
resolves — text arriving in an annotation cannot manufacture a measurement.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from ..config import Config
from .base import Evidence, Signal, SignalKind, SourceContext

__all__ = [
    "Alert",
    "AlertmanagerPayload",
    "AlertmanagerSource",
    "alerts_to_signals",
    "parse_payload",
]

#: Free text from another system. Long enough to be useful in a brief, short
#: enough that a hostile annotation cannot fill the LLM's context window.
MAX_ANNOTATION_CHARS = 400

#: Labels worth keying a signal on. Everything else is kept as evidence rather
#: than promoted to a label: Alertmanager label sets are unbounded, and a
#: signal key built from arbitrary labels would fragment history into one
#: series per unique combination and make every change rule useless.
KEY_LABELS = ("alertname", "severity", "instance", "job")


class Alert(BaseModel):
    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str = ""  # noqa: N815 - Alertmanager's field name
    endsAt: str = ""  # noqa: N815
    generatorURL: str = ""  # noqa: N815
    fingerprint: str = ""

    @property
    def name(self) -> str:
        return self.labels.get("alertname") or "unnamed"

    @property
    def severity(self) -> str:
        return (self.labels.get("severity") or "unknown").lower()

    @property
    def started(self) -> datetime | None:
        try:
            moment = datetime.fromisoformat(self.startsAt.replace("Z", "+00:00"))
        except ValueError:
            return None
        return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)

    def summary(self) -> str:
        for key in ("summary", "description", "message"):
            if self.annotations.get(key):
                return self.annotations[key][:MAX_ANNOTATION_CHARS]
        return ""


class AlertmanagerPayload(BaseModel):
    version: str = "4"
    status: str = "firing"
    receiver: str = ""
    groupKey: str = ""  # noqa: N815
    truncatedAlerts: int = 0  # noqa: N815
    externalURL: str = ""  # noqa: N815
    alerts: list[Alert] = Field(default_factory=list)


def parse_payload(raw: str | bytes | dict[str, Any]) -> AlertmanagerPayload:
    """Parse and validate one webhook body.

    Raises ``ValueError`` on anything malformed. The caller turns that into an
    ERROR signal rather than dropping it: a spool file nobody can read is a
    gap in coverage, and a gap that reports nothing looks exactly like an
    absence of alerts.
    """
    if isinstance(raw, (str, bytes)):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"not JSON: {exc}") from exc
    else:
        data = raw
    if not isinstance(data, dict):
        raise ValueError("payload is not a JSON object")
    try:
        return AlertmanagerPayload.model_validate(data)
    except ValidationError as exc:
        raise ValueError(
            f"not an Alertmanager webhook: {exc.error_count()} field error(s)"
        ) from exc


def alerts_to_signals(
    payload: AlertmanagerPayload,
    now: datetime,
    source_name: str = "alertmanager",
    received_at: datetime | None = None,
) -> list[Signal]:
    """One signal per alert, plus a count.

    Alert labels frequently carry addresses — `instance` is usually
    `10.0.0.5:9100` — so they are ordinary label values and go out through the
    same redaction as everything else. Nothing here is exempt because it came
    from a system the operator trusts.
    """
    signals: list[Signal] = []
    firing = 0

    for alert in payload.alerts:
        labels = {key: alert.labels[key] for key in KEY_LABELS if alert.labels.get(key)}
        labels.setdefault("alertname", alert.name)
        is_firing = alert.status.lower() == "firing"
        firing += int(is_firing)

        context = [f"{key}={value}" for key, value in sorted(alert.labels.items())]
        evidence = [
            Evidence(
                kind="alert",
                ref=f"alertmanager:{alert.fingerprint or alert.name}",
                excerpt=alert.summary() or " ".join(context)[:MAX_ANNOTATION_CHARS],
            )
        ]
        if alert.generatorURL:
            evidence.append(
                Evidence(
                    kind="alert_source",
                    ref=f"alertmanager:{alert.fingerprint or alert.name}:generator",
                    excerpt=alert.generatorURL[:MAX_ANNOTATION_CHARS],
                )
            )

        signals.append(
            Signal(
                name="alertmanager.alert",
                kind=SignalKind.STATE,
                value=alert.status.lower(),
                source=source_name,
                labels=labels,
                observed_at=received_at or now,
                evidence=tuple(evidence),
                note=(
                    "Reported by Alertmanager, not measured by watchdesk. The text is free-form "
                    "and comes from whoever wrote the alerting rule."
                ),
            )
        )

    signals.append(
        Signal(
            name="alertmanager.alerts_firing",
            kind=SignalKind.METRIC,
            value=firing,
            source=source_name,
            labels={"receiver": payload.receiver} if payload.receiver else {},
            observed_at=received_at or now,
            unit="alerts",
        )
    )
    if payload.truncatedAlerts:
        signals.append(
            Signal(
                name="alertmanager.truncated_alerts",
                kind=SignalKind.METRIC,
                value=payload.truncatedAlerts,
                source=source_name,
                observed_at=received_at or now,
                unit="alerts",
                note=(
                    "Alertmanager dropped these from the payload before sending. They are "
                    "invisible here, and a count is the only trace they leave."
                ),
            )
        )
    return signals


class AlertmanagerSource:
    """Reads spooled webhook payloads.

    Disabled unless ``alertmanager`` appears in the config's ``sources``, and
    it is not in the default list: a spool directory that does not exist is a
    normal state for most deployments, not a fault.
    """

    name = "alertmanager"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        spool = Path(config.alertmanager.spool_dir).expanduser()
        if not spool.is_dir():
            yield Signal(
                name="alertmanager.spool_present",
                kind=SignalKind.STATE,
                value=False,
                source=self.name,
                observed_at=ctx.now,
                note=f"No spool directory at {spool}; nothing is feeding watchdesk alerts.",
            )
            return

        cutoff = ctx.now - timedelta(minutes=config.window_minutes)
        seen = 0
        for path in sorted(spool.glob("*.json")):
            try:
                stat = path.stat()
            except OSError:
                continue
            received = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            if received < cutoff:
                continue
            if stat.st_size > config.alertmanager.max_payload_bytes:
                yield Signal(
                    name="alertmanager.spool_problem",
                    kind=SignalKind.ERROR,
                    value=f"{path.name} is {stat.st_size} bytes, over the configured cap",
                    source=self.name,
                    observed_at=ctx.now,
                    note="Refused unread. An oversized payload is a bug or an attempt.",
                )
                continue
            try:
                payload = parse_payload(path.read_text(encoding="utf-8", errors="replace"))
            except (ValueError, OSError) as exc:
                yield Signal(
                    name="alertmanager.spool_problem",
                    kind=SignalKind.ERROR,
                    value=f"{path.name}: {exc}",
                    source=self.name,
                    observed_at=ctx.now,
                    note="A spool file nobody can read is a gap, not an absence of alerts.",
                )
                continue
            seen += 1
            yield from alerts_to_signals(payload, ctx.now, self.name, received_at=received)

        yield Signal(
            name="alertmanager.payloads_read",
            kind=SignalKind.METRIC,
            value=seen,
            source=self.name,
            observed_at=ctx.now,
            unit="payloads",
        )
