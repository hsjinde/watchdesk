"""Dovecot: login activity, and whether Dovecot is logging at all.

The second half is not a formality.  Dovecot's default ``log_path`` is syslog,
and a container has nowhere to relay syslog to — so ``docker logs dovecot``
shows startup messages and nothing else, and any fail2ban jail reading that
file is permanently blind while looking completely healthy.  On this server
that was the state of affairs for weeks.

So ``log_path`` and ``auth_verbose`` are treated as health checks with their
own signals, not as configuration.  A jail cannot match lines that were never
written, and no amount of correct regex will tell you that.
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

__all__ = ["DovecotSource", "LoginEvent", "iter_auth_failures", "AUTH_FAILED_RE"]

#: Broader than the jail filter on purpose (see the note in postfix.py): any
#: login service, any disconnect wording, as long as the line reports failed
#: authentication attempts and carries a remote address.
AUTH_FAILED_RE = re.compile(
    r"(?P<service>pop3|imap|managesieve|submission)-login: "
    r".*?auth failed, (?P<attempts>\d+) attempts"
    r".*?\brip=(?P<host>[^,\s]+)",
    re.IGNORECASE,
)

LOGIN_OK_RE = re.compile(
    r"(?P<service>pop3|imap|managesieve|submission)-login: Info: Login: "
    r"user=<(?P<user>[^>]*)>.*?\brip=(?P<host>[^,\s]+)",
    re.IGNORECASE,
)

#: Values of log_path that mean "these lines are going nowhere a container can
#: read".  An empty value is Dovecot's default, which is syslog.
_BLIND_LOG_PATHS = {"", "syslog"}


@dataclass(frozen=True)
class LoginEvent:
    service: str
    host: str
    user: str | None
    attempts: int
    timestamp: str
    raw: str
    line_no: int


def iter_auth_failures(lines: Iterable[dockerlog.LogLine]) -> Iterable[LoginEvent]:
    for line in lines:
        match = AUTH_FAILED_RE.search(line.message)
        if not match:
            continue
        user = re.search(r"user=<(?P<user>[^>]*)>", line.message)
        yield LoginEvent(
            service=match.group("service").lower(),
            host=match.group("host"),
            user=(user.group("user") or None) if user else None,
            attempts=int(match.group("attempts")),
            timestamp=line.timestamp,
            raw=line.raw,
            line_no=line.line_no,
        )


class DovecotSource:
    name = "dovecot"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        container = config.containers.dovecot
        window_hours = max(config.window_minutes, 1) / 60.0
        since = dockerlog.since_iso(ctx.now, config.window_minutes)

        read = dockerlog.load(ctx.runner, container, since=since)
        lines = read.lines
        for problem in read.problems:
            yield Signal(
                name="dovecot.collection_problem",
                kind=SignalKind.ERROR,
                value=problem,
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
            )

        yield Signal(
            name="dovecot.log_read_mode",
            kind=SignalKind.STATE,
            value="json-file" if read.wire_format else "docker logs (decoded only)",
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            note=(
                None
                if read.wire_format
                else (
                    f"{read.fallback_reason}. Reading through `docker logs` gives the decoded "
                    "message rather than the bytes fail2ban matches, which disables the filter "
                    "cross-check. Grant read access to the json-file log to restore it."
                )
            ),
        )

        yield Signal(
            name="dovecot.log_lines",
            kind=SignalKind.METRIC,
            value=len(lines),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="lines",
        )

        failures = list(iter_auth_failures(lines))
        by_service: Counter[str] = Counter()
        by_source: Counter[str] = Counter()
        samples: dict[str, LoginEvent] = {}
        for event in failures:
            by_service[event.service] += 1
            by_source[event.host] += 1
            samples.setdefault(event.service, event)

        yield Signal(
            name="dovecot.auth_failures",
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
            name="dovecot.auth_failures_per_hour",
            kind=SignalKind.METRIC,
            value=round(len(failures) / window_hours, 2),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="failures/hour",
        )

        for service, count in sorted(by_service.items()):
            yield Signal(
                name="dovecot.auth_failures_by_service",
                kind=SignalKind.METRIC,
                value=count,
                source=self.name,
                labels={"container": container, "service": service},
                observed_at=ctx.now,
                unit="failures",
            )

        for host, count in by_source.most_common(5):
            yield Signal(
                name="dovecot.auth_failures_by_source",
                kind=SignalKind.METRIC,
                value=count,
                source=self.name,
                labels={"container": container, "source": host},
                observed_at=ctx.now,
                unit="failures",
            )

        logins = [match for match in (LOGIN_OK_RE.search(line.message) for line in lines) if match]
        yield Signal(
            name="dovecot.successful_logins",
            kind=SignalKind.METRIC,
            value=len(logins),
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            unit="logins",
        )
        for host, count in Counter(match.group("host") for match in logins).most_common(5):
            yield Signal(
                name="dovecot.successful_logins_by_source",
                kind=SignalKind.METRIC,
                value=count,
                source=self.name,
                labels={"container": container, "source": host},
                observed_at=ctx.now,
                unit="logins",
                note=(
                    "A successful login from an address that has never logged in before is "
                    "the signal that matters here; the count on its own is not."
                ),
            )

        yield from self._logging_health(ctx, container, auth_lines=len(failures) + len(logins))

    def _logging_health(
        self, ctx: SourceContext, container: str, auth_lines: int
    ) -> Iterable[Signal]:
        try:
            result = ctx.runner.run(["doveconf", "log_path", "auth_verbose"], container=container)
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="dovecot.collection_problem",
                kind=SignalKind.ERROR,
                value=f"doveconf unavailable: {exc}",
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
                note="Cannot confirm Dovecot is logging authentication at all.",
            )
            return

        settings = {}
        for line in result.stdout.splitlines():
            key, _, value = line.partition("=")
            settings[key.strip()] = value.strip()

        log_path = settings.get("log_path", "")
        auth_verbose = settings.get("auth_verbose", "no")
        evidence = (
            Evidence(
                kind="command_output",
                ref=f"docker exec {container} doveconf log_path auth_verbose",
                excerpt=result.stdout.strip(),
            ),
        )

        yield Signal(
            name="dovecot.log_path",
            kind=SignalKind.STATE,
            value=log_path or "(default: syslog)",
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            evidence=evidence,
        )
        yield Signal(
            name="dovecot.auth_verbose",
            kind=SignalKind.STATE,
            value=auth_verbose,
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            evidence=evidence,
        )

        blind = log_path.lower() in _BLIND_LOG_PATHS or auth_verbose.lower() != "yes"
        yield Signal(
            name="dovecot.auth_logging_healthy",
            kind=SignalKind.STATE,
            value=not blind,
            source=self.name,
            labels={"container": container},
            observed_at=ctx.now,
            evidence=evidence,
            note=(
                "log_path must be a file the container actually writes (/dev/stderr here) and "
                "auth_verbose must be yes. Otherwise the dovecot jail has nothing to match and "
                "will look healthy forever."
            ),
        )

        # The config can be right and the log still be empty — a container that
        # was reconfigured but never reloaded looks identical to a quiet one.
        if not blind and auth_lines == 0:
            yield Signal(
                name="dovecot.auth_lines_absent",
                kind=SignalKind.STATE,
                value=True,
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
                evidence=evidence,
                note=(
                    "Authentication logging is configured correctly but produced no lines in "
                    "this window. Quiet server, or a reconfiguration that was never reloaded — "
                    "these look identical from outside."
                ),
            )
