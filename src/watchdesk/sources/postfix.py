"""Postfix: authentication failures, queue depth, delivery rate.

This module also owns watchdesk's *own* idea of what a Postfix authentication
failure looks like, which ``sources/fail2ban.py`` borrows to audit the jail.
That matters enough to state plainly: **the matchers here are deliberately
broader than any fail2ban filter, and must never be derived from one.**

Every gap this server has had was a filter that was narrower than reality —

* the mechanism list was uppercase-only, so ``SASL login`` never matched;
* the reject code was hard-coded ``554 5.7.1`` while every real line said
  ``454 4.7.1``;
* the service was ``postfix/\\w+``, which cannot match
  ``postfix/submission/smtpd``.

A detector that reuses the filter it is auditing inherits every one of those
blind spots and reports perfect agreement.  So these patterns match the
*shape* of a failure — any service path, any mechanism, any status code — and
let the comparison expose the difference.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from ..config import Config
from . import dockerlog
from .base import Evidence, Signal, SignalKind, SourceContext
from .shell import CommandDenied

__all__ = ["PostfixSource", "AuthFailure", "iter_auth_failures", "AUTH_FAILURE_RE"]

#: Any SASL authentication failure, on any listener, with any mechanism.
#: ``service`` captures the full path so that ``postfix/smtpd``,
#: ``postfix/submission/smtpd`` and ``postfix/smtps/smtpd`` are distinguished
#: rather than collapsed — the August incident was invisible precisely because
#: nobody was counting them separately.
AUTH_FAILURE_RE = re.compile(
    r"postfix/(?P<service>[\w.-]+(?:/[\w.-]+)*)\[\d+\]: "
    r"warning: [^[]*\[(?P<host>[^\]]+)\](?::\d+)?: "
    r"SASL (?P<mech>[A-Za-z0-9-]+) authentication failed",
    re.IGNORECASE,
)

#: Any status code, not just the one a filter happens to expect.
RELAY_DENIED_RE = re.compile(
    r"postfix/(?P<service>[\w.-]+(?:/[\w.-]+)*)\[\d+\]: "
    r"NOQUEUE: reject: RCPT from [^[]*\[(?P<host>[^\]]+)\](?::\d+)?: "
    r"(?P<code>\d{3} \d\.\d\.\d).*Relay access denied",
    re.IGNORECASE,
)

_SASL_USERNAME_RE = re.compile(r"sasl_username=(?P<user>[^,\s]+)")
_SENT_RE = re.compile(r"\bstatus=sent\b")
_QUEUE_SUMMARY_RE = re.compile(r"--\s*[\d.]+\s*\w?bytes in (?P<count>\d+) Request")


@dataclass(frozen=True)
class AuthFailure:
    service: str
    host: str
    mechanism: str
    username: str | None
    timestamp: str
    raw: str
    line_no: int


def iter_auth_failures(lines: Iterable[dockerlog.LogLine]) -> Iterable[AuthFailure]:
    """Yield every authentication failure, decoded.

    Matching runs against the *decoded* message rather than the raw JSON, so
    the ``\\u003c`` escaping of the json-file driver cannot cause an
    undercount here.  fail2ban has no such luxury — it matches the raw line —
    and that asymmetry is one of the things the cross-check measures.
    """
    for line in lines:
        match = AUTH_FAILURE_RE.search(line.message)
        if not match:
            continue
        user = _SASL_USERNAME_RE.search(line.message)
        yield AuthFailure(
            service=match.group("service"),
            host=match.group("host"),
            mechanism=match.group("mech"),
            username=user.group("user") if user else None,
            timestamp=line.timestamp,
            raw=line.raw,
            line_no=line.line_no,
        )


class PostfixSource:
    name = "postfix"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        container = config.containers.postfix
        window_hours = max(config.window_minutes, 1) / 60.0
        since = dockerlog.since_iso(ctx.now, config.window_minutes)

        read = dockerlog.load(ctx.runner, container, since=since)
        lines = read.lines
        for problem in read.problems:
            yield Signal(
                name="postfix.collection_problem",
                kind=SignalKind.ERROR,
                value=problem,
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
                note="Postfix log could not be read in full; counts below are incomplete.",
            )

        yield Signal(
            name="postfix.log_read_mode",
            kind=SignalKind.STATE,
            value="json-file" if read.wire_format else "docker logs (decoded only)",
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            note=(
                None
                if read.wire_format
                else "Reading through `docker logs` loses the exact bytes fail2ban matches, "
                "which disables the filter cross-check. Usually means the process cannot read "
                "/var/lib/docker/containers."
            ),
        )

        yield Signal(
            name="postfix.log_lines",
            kind=SignalKind.METRIC,
            value=len(lines),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="lines",
            note="Lines inside the window. Zero here means blindness, not calm.",
        )

        failures = list(iter_auth_failures(lines))
        by_service: Counter[str] = Counter()
        by_source: Counter[str] = Counter()
        samples: dict[str, AuthFailure] = {}
        for failure in failures:
            by_service[failure.service] += 1
            by_source[failure.host] += 1
            samples.setdefault(failure.service, failure)

        yield Signal(
            name="postfix.auth_failures",
            kind=SignalKind.METRIC,
            value=len(failures),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="failures",
            evidence=tuple(
                Evidence(
                    kind="log_line",
                    ref=f"{container}:json-log:{sample.line_no}",
                    excerpt=sample.raw.strip(),
                    line_no=sample.line_no,
                )
                for sample in list(samples.values())[:3]
            ),
        )

        yield Signal(
            name="postfix.auth_failures_per_hour",
            kind=SignalKind.METRIC,
            value=round(len(failures) / window_hours, 2),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="failures/hour",
        )

        # Per-listener breakdown. This is the shape of the August incident:
        # the totals looked normal because port 25 kept reporting, while the
        # submission listener carried the actual traffic.
        for service, count in sorted(by_service.items()):
            sample = samples[service]
            yield Signal(
                name="postfix.auth_failures_by_service",
                kind=SignalKind.METRIC,
                value=count,
                source=self.name,
                labels={"container": container, "service": service},
                observed_at=ctx.now,
                unit="failures",
                evidence=(
                    Evidence(
                        kind="log_line",
                        ref=f"{container}:json-log:{sample.line_no}",
                        excerpt=sample.raw.strip(),
                        line_no=sample.line_no,
                    ),
                ),
            )

        yield Signal(
            name="postfix.distinct_auth_sources",
            kind=SignalKind.METRIC,
            value=len(by_source),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="addresses",
            note="Distinct addresses behind the failures in this window.",
        )

        for host, count in by_source.most_common(5):
            yield Signal(
                name="postfix.auth_failures_by_source",
                kind=SignalKind.METRIC,
                value=count,
                source=self.name,
                labels={"container": container, "source": host},
                observed_at=ctx.now,
                unit="failures",
            )

        relay_denied = [
            match
            for match in (RELAY_DENIED_RE.search(line.message) for line in lines)
            if match is not None
        ]
        codes = Counter(match.group("code") for match in relay_denied)
        yield Signal(
            name="postfix.relay_denied",
            kind=SignalKind.METRIC,
            value=len(relay_denied),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="rejections",
            note=(
                "Status codes seen: "
                + (", ".join(f"{code}x{count}" for code, count in codes.most_common()) or "none")
            ),
        )

        sent = sum(1 for line in lines if _SENT_RE.search(line.message))
        yield Signal(
            name="postfix.messages_sent",
            kind=SignalKind.METRIC,
            value=sent,
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="messages",
        )
        yield Signal(
            name="postfix.messages_sent_per_hour",
            kind=SignalKind.METRIC,
            value=round(sent / window_hours, 2),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="messages/hour",
            note="A spike here on a personal server is the signature of a relay compromise.",
        )

        yield from self._queue_depth(ctx, container)
        yield from self._sasl_backend(ctx, container)

    def _queue_depth(self, ctx: SourceContext, container: str) -> Iterable[Signal]:
        try:
            result = ctx.runner.run(["mailq"], container=container)
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="postfix.collection_problem",
                kind=SignalKind.ERROR,
                value=f"mailq unavailable: {exc}",
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
            )
            return

        output = result.stdout.strip()
        depth = 0
        if output and "Mail queue is empty" not in output:
            summary = _QUEUE_SUMMARY_RE.search(output)
            depth = int(summary.group("count")) if summary else output.count("\n\n") + 1

        yield Signal(
            name="postfix.queue_depth",
            kind=SignalKind.METRIC,
            value=depth,
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="messages",
            evidence=(
                Evidence(
                    kind="command_output",
                    ref=f"docker exec {container} mailq",
                    excerpt=(output.splitlines() or ["Mail queue is empty"])[-1],
                ),
            ),
        )

    def _sasl_backend(self, ctx: SourceContext, container: str) -> Iterable[Signal]:
        """Report who actually checks SMTP AUTH passwords.

        With ``smtpd_sasl_type = dovecot`` a failed SMTP AUTH also produces a
        Dovecot ``auth-worker`` line for the same attempt.  Anyone reading the
        two logs side by side will eventually decide the dovecot jail is
        missing those lines and "fix" its filter — which would double-count
        attempts already handled from the Postfix side.  Recording the backend
        here is what lets the brief explain that instead of re-deriving it.
        """
        try:
            result = ctx.runner.run(["postconf", "smtpd_sasl_type"], container=container)
        except (CommandDenied, FileNotFoundError):
            return
        if not result.ok:
            return
        value = result.stdout.strip().partition("=")[2].strip() or "unknown"
        yield Signal(
            name="postfix.sasl_backend",
            kind=SignalKind.STATE,
            value=value,
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            evidence=(
                Evidence(
                    kind="command_output",
                    ref=f"docker exec {container} postconf smtpd_sasl_type",
                    excerpt=result.stdout.strip(),
                ),
            ),
        )
