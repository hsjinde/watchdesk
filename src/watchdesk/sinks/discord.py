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

#: The same four levels again, for the reader who is skimming on a phone and
#: has not read a word yet. The embed's colour bar says this too, but only for
#: the message as a whole; per finding, this is all there is.
_MARKS = {
    Severity.CRITICAL: "🔴",
    Severity.WARNING: "🟠",
    Severity.NOTICE: "🔵",
    Severity.INFO: "⚪",
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


_TRUNCATED = "_truncated_"


def _fit(blocks: list[str], limit: int) -> str:
    """Drop whole blocks rather than cutting one in half.

    Blocks are emitted findings-first, so dropping from the end drops the
    model's prose before it drops a measurement — the same order the old
    character-wise cut had, but without leaving half a quoted line behind.
    A block too long on its own is thinned line by line instead, so what
    survives is the severity and the title rather than half a quoted number.
    """
    joined = "\n\n".join(blocks)
    if len(joined) <= limit:
        return joined

    kept: list[str] = []
    used = 0
    for block in blocks:
        cost = len(block) + (2 if kept else 0)
        if used + cost > limit:
            break
        kept.append(block)
        used += cost

    if not kept:
        return _fit_lines(blocks[0], limit)
    if used + 2 + len(_TRUNCATED) <= limit:
        kept.append(_TRUNCATED)
    return "\n\n".join(kept)


def _fit_lines(block: str, limit: int) -> str:
    """Thin one block to whole lines. Only its first line is ever cut mid-way,
    because a message with no title at all says nothing."""
    kept: list[str] = []
    used = 0
    for line in block.split("\n"):
        cost = len(line) + (1 if kept else 0)
        if used + cost > limit:
            break
        kept.append(line)
        used += cost
    if not kept:
        return _truncate(block, limit)
    return "\n".join(kept)


def format_payload(brief: Brief, max_chars: int) -> dict[str, Any]:
    """Build the webhook body.

    Two decisions about the layout, both about a reader who is skimming:

    *   **Findings come before the model's prose.** The findings are
        measurements; the prose is a convenience, and if the message gets
        truncated the convenience is what should be lost.
    *   **They do not look alike.** A finding is arithmetic over what was
        measured; a claim is a language model's triage of it. Formatting them
        identically invites the reader to trust them equally, which is the one
        thing this message must not ask for.

    Supporting lines are blockquoted rather than indented, because leading
    whitespace is not layout here: it renders as a space, not as a level.

    A correlation is printed once. ``correlate.py`` attaches the same
    surrounding event to every finding it plausibly explains, which is right
    for the data and wrong for the message: repeated verbatim under three
    findings, one config edit fills more of the screen than the three
    measurements it relates to, and the reader starts skipping quoted lines.
    """
    blocks: list[str] = []
    seen_correlations: set[str] = set()

    for finding in brief.findings:
        lines = [
            f"{_MARKS.get(finding.severity, _MARKS[Severity.INFO])} "
            f"**{str(finding.severity).upper()}** · {finding.title}"
        ]
        if finding.baseline:
            lines.append(f"> baseline · {finding.baseline}")
        fresh = [item for item in finding.correlations if item not in seen_correlations]
        for correlation in fresh[:2]:
            lines.append(f"> alongside · {correlation}")
            seen_correlations.add(correlation)
        blocks.append("\n".join(lines))

    if brief.claims:
        lines = ["**Triage** — the model's reading of the findings above"]
        for claim in brief.claims:
            if claim.confidence is Confidence.HYPOTHESIS:
                lines.append(f"• *Hypothesis* · {claim.text}")
            else:
                lines.append(f"• {claim.text}")
        blocks.append("\n".join(lines))

    trailer: list[str] = []
    if brief.rejected:
        count = len(brief.rejected)
        noun = "claim" if count == 1 else "claims"
        trailer.append(f"_{count} model {noun} dropped for lack of evidence._")
    if brief.llm_error:
        trailer.append("_Summary written from the rules; the model was unavailable._")
    if trailer:
        blocks.append("\n".join(trailer))

    description = _fit(blocks, min(max_chars, _DESCRIPTION_LIMIT))

    count = len(brief.findings)
    footer = f"watchdesk · {count} finding" + ("" if count == 1 else "s")
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
