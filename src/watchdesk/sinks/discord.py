"""Discord webhook sink.

The second of the two exits named in the redaction contract.  Everything that
goes out is redacted and then checked by ``leakcheck`` over the *serialised
payload*, not over the pieces — it is the bytes on the wire that matter, and a
field somebody forgot to redact is exactly the field that would be missed by
checking field by field.

Three behaviours here are about the channel staying useful rather than about
Discord:

* an unchanged situation is not re-sent (see ``sinks/base.py``),
* findings below the sink's floor are stored but not pushed,
* a 429 is obeyed rather than retried immediately. Being rate-limited by a
  chat service is not an emergency, and hammering it turns a quiet problem
  into a loud one.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from ..brief import Brief
from ..config import Config
from ..detect.rules import Confidence, Severity
from ..detect.state import StateStore
from ..leakcheck import guard
from ..redact import Redactor
from .base import SinkResult, record_sent, should_send

__all__ = ["DiscordSink", "format_payload"]

#: Discord's own limits, not ours.
_TITLE_LIMIT = 256
_DESCRIPTION_LIMIT = 4096

_COLOURS = {
    Severity.CRITICAL: 0xD64545,
    Severity.WARNING: 0xE0A030,
    Severity.NOTICE: 0x4A7DBF,
    Severity.INFO: 0x808080,
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def format_payload(brief: Brief, max_chars: int) -> dict[str, Any]:
    """Build the webhook body.

    Findings come before the model's prose on purpose. The findings are
    measurements; the prose is a convenience, and if the message gets truncated
    the convenience is what should be lost.
    """
    lines: list[str] = []
    for finding in brief.findings:
        lines.append(f"**[{str(finding.severity).upper()}]** {finding.title}")
        if finding.baseline:
            lines.append(f"　baseline: {finding.baseline}")
        for correlation in finding.correlations[:2]:
            lines.append(f"　correlation: {correlation}")

    if brief.claims:
        lines.append("")
        for claim in brief.claims:
            marker = "?" if claim.confidence is Confidence.HYPOTHESIS else "・"
            suffix = " *(hypothesis)*" if claim.confidence is Confidence.HYPOTHESIS else ""
            lines.append(f"{marker} {claim.text}{suffix}")

    if brief.rejected:
        lines.append("")
        lines.append(
            f"_{len(brief.rejected)} model claim(s) dropped for lack of evidence._"
        )
    if brief.llm_error:
        lines.append("")
        lines.append("_Summary written from the rules; the model was unavailable._")

    description = _truncate("\n".join(lines), min(max_chars, _DESCRIPTION_LIMIT))
    footer = f"watchdesk · {len(brief.findings)} finding(s)"
    if brief.model:
        footer += f" · {brief.model}"
    if brief.headline_source != "llm":
        footer += " · headline from rules"

    return {
        "username": "watchdesk",
        "embeds": [
            {
                "title": _truncate(brief.headline, _TITLE_LIMIT),
                "description": description,
                "color": _COLOURS.get(brief.severity, _COLOURS[Severity.INFO]),
                "footer": {"text": footer},
                "timestamp": brief.generated_at.isoformat(),
            }
        ],
    }


class DiscordSink:
    name = "discord"

    def __init__(
        self,
        webhook_url: str,
        redactor: Redactor,
        config: Config,
        store: StateStore | None = None,
        now: datetime | None = None,
        transport: Callable[[str, dict[str, Any]], tuple[int, str]] | None = None,
    ) -> None:
        self.webhook_url = webhook_url
        self.redactor = redactor
        self.config = config
        self.store = store
        self.now = now
        self._transport = transport or self._post

    @staticmethod
    def _post(url: str, payload: dict[str, Any]) -> tuple[int, str]:
        try:
            response = httpx.post(url, json=payload, timeout=20.0)
        except httpx.HTTPError as exc:
            return 0, str(exc)
        return response.status_code, response.text

    def deliver(self, brief: Brief) -> SinkResult:
        moment = self.now or brief.generated_at
        if not self.webhook_url:
            return SinkResult(False, "no DISCORD_WEBHOOK_URL configured")

        decision = should_send(
            brief,
            self.name,
            self.store,
            moment,
            min_severity=self.config.sink.min_severity,
            resend_after_minutes=self.config.sink.resend_after_minutes,
        )
        if not decision.sent:
            return decision

        redacted = brief.redacted(self.redactor) if hasattr(brief, "redacted") else brief
        payload = format_payload(redacted, self.config.sink.max_message_chars)

        # Guard the serialised body, not the fields. It is the bytes on the
        # wire that matter, and checking field by field is how the one field
        # nobody thought about gets through.
        guard(json.dumps(payload, ensure_ascii=False), "Discord")

        status, body = self._transport(self.webhook_url, payload)
        if status in (200, 204):
            record_sent(brief, self.name, self.store, moment)
            return SinkResult(True, f"delivered ({status})")
        if status == 429:
            # Obeyed, not retried. Being rate-limited by a chat service is not
            # an emergency, and the next round will carry the same findings.
            return SinkResult(False, "rate limited by Discord (429); will retry next round")
        if status == 0:
            return SinkResult(False, f"could not reach Discord: {body[:200]}")
        return SinkResult(False, f"Discord rejected the message ({status})", detail=body[:300])
