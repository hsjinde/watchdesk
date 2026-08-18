"""fail2ban: the jail is not asked whether it is working.

Every gap this server has had shared one property: the jail reported itself
healthy.  Enabled, running, counters incrementing, bans landing.  Asking
fail2ban how fail2ban is doing has never once surfaced a problem here.

So this module derives three *independent* counts of the same thing over the
same window, and treats their disagreement as the finding:

    A  observed      what watchdesk itself counts in the log, using a matcher
                     deliberately broader than any filter (see postfix.py)
    B  would_match   what the jail's own failregex, read from disk and applied
                     to the raw log lines, would count
    C  found_events  what the running fail2ban actually counted, from its own
                     "[jail] Found <ip>" entries in /var/log/fail2ban.log

The pairs mean different things, and that is the point:

* **A > B** — the filter is narrower than reality.  This is the August 2026
  incident: the failregex matched the service as ``postfix/\\w+``, so 210 of
  212 authentication failures on the submission listener were invisible while
  every dashboard stayed green.  The per-service breakdown names the listener.
* **B > C** — the filter on disk is not the filter in memory.  ``fail2ban-client
  reload <jail>`` has returned OK on this host without taking effect; a full
  ``systemctl restart fail2ban`` was needed.  Config review cannot see this,
  because the config is correct.
* **C > 0 while A == 0** — watchdesk's own matcher has drifted from the log
  format.  The detector is not exempt from being wrong, and this is how it
  says so.

``fail2ban-regex`` is run as a fourth opinion where it is affordable, because
it is fail2ban's own tooling and therefore the number a sceptical reader will
ask for.
"""

from __future__ import annotations

import configparser
import hashlib
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from ..config import Config, JailSpec
from . import dockerlog, dovecot, postfix
from .base import Evidence, Signal, SignalKind, SourceContext
from .shell import CommandDenied

__all__ = ["Fail2banSource", "JailStatus", "compile_failregex", "parse_jail_status"]

#: fail2ban's <HOST> expands to an address or a hostname.  Replaced with a
#: non-capturing equivalent: watchdesk never needs the jail's opinion of *who*
#: the attacker was — it has its own matcher for that — only whether the line
#: would have matched at all.  Non-capturing also sidesteps duplicate group
#: names when a failregex mentions <HOST> more than once.
_HOST_REPLACEMENT = r"(?:::f{4,6}:)?[0-9a-zA-Z:.\-]+"
_FAIL2BAN_TOKENS = {
    "<HOST>": _HOST_REPLACEMENT,
    "<ADDR>": _HOST_REPLACEMENT,
    "<IP>": _HOST_REPLACEMENT,
    "<CIDR>": _HOST_REPLACEMENT,
    "<DNS>": r"[0-9a-zA-Z.\-]+",
    "<SUBNET>": _HOST_REPLACEMENT,
}

_STATUS_FIELDS = {
    "currently_failed": re.compile(r"Currently failed:\s*(\d+)"),
    "total_failed": re.compile(r"Total failed:\s*(\d+)"),
    "currently_banned": re.compile(r"Currently banned:\s*(\d+)"),
    "total_banned": re.compile(r"Total banned:\s*(\d+)"),
}
_FILE_LIST_RE = re.compile(r"File list:\s*(.*)")
_BANNED_LIST_RE = re.compile(r"Banned IP list:\s*(.*)")

#: 2026-07-31 06:00:56,616 fail2ban.filter [1234]: INFO
#:     [postfix-docker] Found 1.2.3.4 - 2026-07-31 06:00:56
#:
#: The logger name is part of the match on purpose. "Found" is emitted by two
#: different loggers: fail2ban.filter, once per line the failregex matched,
#: and fail2ban.observer, which narrates its own ban-time scoring
#: ("Found 1.2.3.4, bad - <date>, 3 # -> 5.0, Ban"). Counting both inflates
#: the filter's tally — measured here at 50 against 40 real matches in one
#: day — and turns a healthy jail into a permanent phantom disagreement.
_F2B_EVENT_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+"
    r"(?P<logger>fail2ban\.\w+)\s+\[\d+\]:\s+\w+\s+"
    r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Restore Ban|Found|Ban|Unban)\b"
    r"(?P<rest>.*)$"
)

#: Which logger is authoritative for each action.
_EVENT_LOGGER = {
    "Found": "fail2ban.filter",
    "Ban": "fail2ban.actions",
    "Unban": "fail2ban.actions",
    "Restore Ban": "fail2ban.actions",
}

#: The trailing "- 2026-07-31 06:00:56" is when the *log line* happened, as
#: opposed to when fail2ban got round to reading it. Windowing on the event
#: time is what makes this number comparable to a count taken from the
#: container log; polling lag otherwise shows up as drift.
_F2B_EVENT_TIME_RE = re.compile(r"-\s+(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

_REGEX_TOOL_MATCHED_RE = re.compile(r"Lines:.*?(\d+) matched", re.IGNORECASE)

#: Fragments fail2ban assembles from elsewhere and Python cannot resolve:
#: uppercase <TOKEN> substitutions and %(name)s interpolations.
#:
#: This has to be narrow. A first version rejected any expression containing
#: "<" or ">", which threw out the dovecot filter for its perfectly ordinary
#: `(?:<|\\u003c)` and `[^>]*` — and a skipped cross-check reports no
#: disagreement, i.e. a clean bill of health for an unaudited jail. A detector
#: that fails silently is the thing this project exists to catch.
_UNRESOLVED_TOKEN = re.compile(r"(?<!\(\?P)<[A-Z][A-Z0-9_]*>|%\([^)]+\)s")


@dataclass
class JailStatus:
    name: str
    currently_failed: int | None = None
    total_failed: int | None = None
    currently_banned: int | None = None
    total_banned: int | None = None
    log_paths: tuple[str, ...] = ()
    banned_ips: tuple[str, ...] = ()
    raw: str = ""


@dataclass
class JailDefinition:
    """What ``jail.local`` says, as opposed to what the running jail does."""

    name: str
    enabled: bool | None = None
    filter_name: str | None = None
    log_path: str | None = None
    maxretry: int | None = None
    findtime: int | None = None
    present: bool = True
    raw: dict[str, str] = field(default_factory=dict)


def parse_jail_status(name: str, text: str) -> JailStatus:
    status = JailStatus(name=name, raw=text)
    for attribute, pattern in _STATUS_FIELDS.items():
        match = pattern.search(text)
        if match:
            setattr(status, attribute, int(match.group(1)))
    files = _FILE_LIST_RE.search(text)
    if files:
        status.log_paths = tuple(part for part in files.group(1).split() if part)
    banned = _BANNED_LIST_RE.search(text)
    if banned:
        status.banned_ips = tuple(part for part in banned.group(1).split() if part)
    return status


def compile_failregex(filter_text: str) -> tuple[list[re.Pattern[str]], list[str]]:
    """Turn a filter file's ``failregex`` into Python patterns.

    Returns ``(patterns, problems)`` — never raises.  A filter that cannot be
    compiled is a finding to report, not a reason to abandon the round; the
    stock ``sshd`` filter, for instance, is built from interpolated fragments
    that only fail2ban itself assembles.
    """
    parser = configparser.RawConfigParser(strict=False)
    problems: list[str] = []
    try:
        parser.read_string(filter_text)
    except configparser.Error as exc:
        return [], [f"filter file is not parseable: {exc}"]

    raw_value = ""
    for section in ("Definition", "definition"):
        if parser.has_section(section) and parser.has_option(section, "failregex"):
            raw_value = parser.get(section, "failregex")
            break
    if not raw_value.strip():
        return [], ["filter file declares no failregex"]

    patterns: list[re.Pattern[str]] = []
    for line in raw_value.splitlines():
        expression = line.strip()
        if not expression:
            continue
        # RawConfigParser leaves fail2ban's escaped %% alone; fail2ban itself
        # collapses it to a single % before compiling.
        expression = expression.replace("%%", "%")
        for token, replacement in _FAIL2BAN_TOKENS.items():
            expression = expression.replace(token, replacement)
        unresolved = _UNRESOLVED_TOKEN.search(expression)
        if unresolved:
            # fail2ban assembles these from other files; guessing at them would
            # produce a confident wrong answer.
            problems.append(
                f"failregex uses the fail2ban-internal token {unresolved.group(0)}, not analysed"
            )
            continue
        try:
            patterns.append(re.compile(expression))
        except re.error as exc:
            problems.append(f"failregex does not compile as a Python pattern: {exc}")
    return patterns, problems


def _parse_jail_local(text: str, name: str) -> JailDefinition:
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return JailDefinition(name=name, present=False)
    if not parser.has_section(name):
        return JailDefinition(name=name, present=False)

    section = dict(parser.items(name))
    defaults = dict(parser.defaults())

    def lookup(key: str) -> str | None:
        return section.get(key, defaults.get(key))

    def as_int(key: str) -> int | None:
        value = lookup(key)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None

    enabled_raw = lookup("enabled")
    return JailDefinition(
        name=name,
        enabled=None if enabled_raw is None else enabled_raw.strip().lower() == "true",
        filter_name=(lookup("filter") or "").strip() or None,
        log_path=(lookup("logpath") or "").strip() or None,
        maxretry=as_int("maxretry"),
        findtime=as_int("findtime"),
        raw=section,
    )


class Fail2banSource:
    name = "fail2ban"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        try:
            overview = ctx.runner.run(["fail2ban-client", "status"])
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="fail2ban.collection_problem",
                kind=SignalKind.ERROR,
                value=f"fail2ban-client unavailable: {exc}",
                source=self.name,
                observed_at=ctx.now,
                note="No jail can be audited this round.",
            )
            return

        running_jails = _jail_list(overview.stdout)
        yield Signal(
            name="fail2ban.jails_running",
            kind=SignalKind.METRIC,
            value=len(running_jails),
            source=self.name,
            observed_at=ctx.now,
            unit="jails",
            evidence=(
                Evidence(
                    kind="command_output",
                    ref="fail2ban-client status",
                    excerpt=overview.stdout.strip(),
                ),
            ),
        )

        jail_local = self._read_jail_local(ctx)
        events = self._found_events(ctx)
        yield from self._config_digests(ctx, jail_local)
        yield from self._server_starts(ctx)

        configured = {spec.name for spec in config.fail2ban.jails}
        for name in sorted(configured | set(running_jails)):
            spec = config.jail(name) or JailSpec(name=name)
            yield from self._audit_jail(ctx, spec, running_jails, jail_local, events)

    # -- per jail ------------------------------------------------------

    def _audit_jail(
        self,
        ctx: SourceContext,
        spec: JailSpec,
        running_jails: list[str],
        jail_local: str | None,
        events: dict[str, Counter[str]] | None,
    ) -> Iterable[Signal]:
        config: Config = ctx.config
        labels = {"jail": spec.name}

        yield Signal(
            name="fail2ban.jail.running",
            kind=SignalKind.STATE,
            value=spec.name in running_jails,
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            note=(
                "A configured jail missing from the running list is silently disabled."
                if spec.name not in running_jails
                else None
            ),
        )
        if spec.name not in running_jails:
            return

        status = self._jail_status(ctx, spec.name)
        if status is not None:
            counters = (
                "currently_failed",
                "total_failed",
                "currently_banned",
                "total_banned",
            )
            for attribute in counters:
                value = getattr(status, attribute)
                if value is None:
                    continue
                yield Signal(
                    name=f"fail2ban.jail.{attribute}",
                    kind=SignalKind.METRIC,
                    value=value,
                    source=self.name,
                    labels=labels,
                    observed_at=ctx.now,
                    unit="events",
                    note=(
                        "Cumulative since the last fail2ban restart, not since the last round — "
                        "a restart resets it to zero and a low number is not automatically good."
                        if attribute.startswith("total")
                        else None
                    ),
                    evidence=(
                        Evidence(
                            kind="command_output",
                            ref=f"fail2ban-client status {spec.name}",
                            excerpt=status.raw.strip(),
                        ),
                    ),
                )

        definition = _parse_jail_local(jail_local, spec.name) if jail_local else None
        yield from self._filter_wiring(ctx, spec, definition, labels)

        if spec.container and spec.dialect in {"postfix", "dovecot"}:
            yield from self._cross_check(ctx, spec, definition, status, events, labels)

        if events is not None:
            found = events.get(spec.name, Counter()).get("Found", 0)
            yield Signal(
                name="fail2ban.jail.found_events",
                kind=SignalKind.METRIC,
                value=found,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                unit="events",
                note=(
                    f"What the running fail2ban actually counted in the last "
                    f"{config.window_minutes} minutes, from its own log."
                ),
            )
            yield Signal(
                name="fail2ban.jail.ban_events",
                kind=SignalKind.METRIC,
                value=events.get(spec.name, Counter()).get("Ban", 0),
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                unit="events",
            )

    def _filter_wiring(
        self,
        ctx: SourceContext,
        spec: JailSpec,
        definition: JailDefinition | None,
        labels: dict[str, str],
    ) -> Iterable[Signal]:
        """Check that the jail uses the filter somebody thinks it uses.

        The failure this catches really happened: ``[dovecot-docker]`` pointed
        at ``filter = dovecot`` — fail2ban's stock filter, which does not
        understand Docker's JSON-wrapped lines — while a correct
        ``dovecot-docker.conf`` sat next to it, unused. Everything about that
        setup looks configured. The file existing is not the same as the jail
        using it.
        """
        config: Config = ctx.config
        if definition is None or not definition.present:
            yield Signal(
                name="fail2ban.jail.stanza_present",
                kind=SignalKind.STATE,
                value=False,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                note=f"No [{spec.name}] stanza found in {config.fail2ban.jail_local}.",
            )
            return

        declared = definition.filter_name or spec.name
        yield Signal(
            name="fail2ban.jail.filter_declared",
            kind=SignalKind.STATE,
            value=declared,
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            evidence=(
                Evidence(
                    kind="config_line",
                    ref=f"{config.fail2ban.jail_local} [{spec.name}]",
                    excerpt=f"filter = {declared}",
                ),
            ),
        )

        if spec.expect_filter:
            matches = declared == spec.expect_filter
            yield Signal(
                name="fail2ban.jail.filter_as_expected",
                kind=SignalKind.STATE,
                value=matches,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                evidence=(
                    Evidence(
                        kind="config_line",
                        ref=f"{config.fail2ban.jail_local} [{spec.name}]",
                        excerpt=f"filter = {declared} (expected {spec.expect_filter})",
                    ),
                ),
                note=(
                    None
                    if matches
                    else (
                        f"The jail is using filter '{declared}', not '{spec.expect_filter}'. "
                        "A correct filter file can exist and be entirely unused."
                    )
                ),
            )

        filter_path = str(Path(config.fail2ban.filter_dir) / f"{declared}.conf")
        try:
            ctx.runner.read_text(filter_path)
            present = True
        except (CommandDenied, FileNotFoundError, OSError):
            present = False
        yield Signal(
            name="fail2ban.jail.filter_file_present",
            kind=SignalKind.STATE,
            value=present,
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            evidence=(Evidence(kind="path", ref=filter_path, excerpt=filter_path),),
            note=(
                None
                if present
                else "Jail points at a filter file that does not exist; fail2ban falls back "
                "silently to a stock filter that may match nothing here."
            ),
        )

    def _cross_check(
        self,
        ctx: SourceContext,
        spec: JailSpec,
        definition: JailDefinition | None,
        status: JailStatus | None,
        events: dict[str, Counter[str]] | None,
        labels: dict[str, str],
    ) -> Iterable[Signal]:
        """The heart of the project: three counts of one window."""
        config: Config = ctx.config
        assert spec.container is not None

        since = dockerlog.since_iso(ctx.now, config.window_minutes)
        log_path = None
        if status and status.log_paths:
            # Audit the file the jail itself reads, not a second view of the
            # same events. If those two ever differ, the difference is the bug.
            log_path = status.log_paths[0]
        read = dockerlog.load(ctx.runner, spec.container, since=since, path=log_path)
        lines = read.lines
        for problem in read.problems:
            yield Signal(
                name="fail2ban.collection_problem",
                kind=SignalKind.ERROR,
                value=problem,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
            )
        if not lines:
            return

        if not read.wire_format:
            # The log came back through `docker logs`, which hands over the
            # decoded message rather than the bytes on disk. Every filter here
            # anchors on ^\{"log":" — applying it to decoded text matches
            # nothing, and the cross-check would report the entire window as
            # uncounted. A confident false alarm from the one rule this project
            # exists for is worse than admitting the check could not run.
            yield Signal(
                name="fail2ban.jail.cross_check_unavailable",
                kind=SignalKind.ERROR,
                value=True,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                note=(
                    "The container log could not be read from disk, so watchdesk only has the "
                    "decoded messages, not the bytes fail2ban matches. The filter cross-check — "
                    "the most important check here — is skipped rather than run against the "
                    "wrong representation. Grant read access to the json-file log to restore it."
                ),
            )
            return

        # (A) watchdesk's own count, from the decoded messages.
        if spec.dialect == "postfix":
            observed = [
                (item.service, item.raw, item.line_no) for item in postfix.iter_auth_failures(lines)
            ]
        else:
            observed = [
                (item.service, item.raw, item.line_no) for item in dovecot.iter_auth_failures(lines)
            ]

        # (B) what the jail's own failregex would match, applied to the raw
        # lines exactly as fail2ban sees them.
        declared = (definition.filter_name if definition else None) or spec.name
        filter_path = str(Path(config.fail2ban.filter_dir) / f"{declared}.conf")
        patterns: list[re.Pattern[str]] = []
        try:
            patterns, compile_problems = compile_failregex(ctx.runner.read_text(filter_path))
        except (CommandDenied, FileNotFoundError, OSError) as exc:
            compile_problems = [f"could not read {filter_path}: {exc}"]
        for problem in compile_problems:
            yield Signal(
                name="fail2ban.jail.filter_not_analysable",
                kind=SignalKind.ERROR,
                value=problem,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                note="Cross-check skipped for this pattern; the jail is unaudited to that extent.",
            )
        if not patterns:
            return

        # Every line the jail's filter matches, across all of its failregex
        # rules — not just the authentication failures watchdesk counts. The
        # postfix filter also bans on "Relay access denied", and fail2ban logs
        # a Found event for those too. Comparing fail2ban's Found count against
        # the auth-failure subset reports a permanent phantom drift (measured:
        # -27 over 24h on this host) for a jail that is working perfectly.
        matched_lines = {
            line.line_no for line in lines if any(pattern.search(line.raw) for pattern in patterns)
        }

        observed_by_service: Counter[str] = Counter()
        uncounted_by_service: Counter[str] = Counter()
        samples: dict[str, tuple[str, int]] = {}
        for service, raw, line_no in observed:
            observed_by_service[service] += 1
            if line_no not in matched_lines:
                uncounted_by_service[service] += 1
                samples.setdefault(service, (raw, line_no))

        total_observed = len(observed)
        total_matched = sum(1 for _, _, line_no in observed if line_no in matched_lines)
        uncounted = total_observed - total_matched

        common = dict(
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            unit="failures",
        )
        yield Signal(
            name="fail2ban.jail.observed_failures",
            kind=SignalKind.METRIC,
            value=total_observed,
            note="Counted by watchdesk from the log, independently of any fail2ban filter.",
            **common,
        )
        yield Signal(
            name="fail2ban.jail.filter_would_match",
            kind=SignalKind.METRIC,
            value=total_matched,
            note=f"How many of those the jail's own filter ('{declared}') matches.",
            **common,
        )
        yield Signal(
            name="fail2ban.jail.uncounted_failures",
            kind=SignalKind.METRIC,
            value=uncounted,
            note=(
                "Authentication failures present in the log that this jail's filter does not "
                "match. Anything above zero means the jail is blind to real traffic while "
                "reporting itself healthy."
            ),
            evidence=tuple(
                Evidence(
                    kind="log_line",
                    ref=f"{spec.container}:json-log:{line_no}",
                    excerpt=raw.strip(),
                    line_no=line_no,
                )
                for raw, line_no in list(samples.values())[:3]
            ),
            **common,
        )
        if total_observed:
            yield Signal(
                name="fail2ban.jail.coverage_ratio",
                kind=SignalKind.METRIC,
                value=round(total_matched / total_observed, 4),
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                unit="ratio",
                note="1.0 means the filter sees everything watchdesk sees.",
            )

        # The breakdown that names the blind spot. In August 2026 this is the
        # signal that would have said "submission listener, 210 failures, zero
        # counted" while every jail reported itself healthy.
        for service, count in sorted(observed_by_service.items()):
            missed = uncounted_by_service.get(service, 0)
            evidence = ()
            if missed and service in samples:
                raw, line_no = samples[service]
                evidence = (
                    Evidence(
                        kind="log_line",
                        ref=f"{spec.container}:json-log:{line_no}",
                        excerpt=raw.strip(),
                        line_no=line_no,
                    ),
                )
            yield Signal(
                name="fail2ban.jail.uncounted_failures_by_service",
                kind=SignalKind.METRIC,
                value=missed,
                source=self.name,
                labels={**labels, "service": service},
                observed_at=ctx.now,
                unit="failures",
                evidence=evidence,
                note=f"{missed} of {count} failures on {service} are invisible to this jail.",
            )

        yield Signal(
            name="fail2ban.jail.filter_matched_lines",
            kind=SignalKind.METRIC,
            value=len(matched_lines),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            unit="lines",
            note=(
                "Every line in the window matched by any of the jail's failregex rules, "
                "including rules watchdesk does not model (relay rejections, for instance)."
            ),
        )

        # (B) versus (C): the filter on disk against the filter in memory.
        if events is not None and status is not None:
            found = events.get(spec.name, Counter()).get("Found", 0)
            drift = len(matched_lines) - found
            yield Signal(
                name="fail2ban.jail.filter_engine_drift",
                kind=SignalKind.METRIC,
                value=drift,
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                unit="events",
                note=(
                    "Lines the on-disk filter matches, minus what the running fail2ban recorded "
                    "as Found in the same window. Sustained positive drift means the process is "
                    "not using the filter on disk — 'fail2ban-client reload' has returned OK "
                    "without taking effect on this host, and a full restart was required. "
                    "Negative drift is normal at a window edge (fail2ban re-reads lines it "
                    "already counted) and for jails whose ignoreip drops matches after the fact."
                ),
            )

        yield from self._regex_tool(ctx, spec, log_path, filter_path, labels)

    def _regex_tool(
        self,
        ctx: SourceContext,
        spec: JailSpec,
        log_path: str | None,
        filter_path: str,
        labels: dict[str, str],
    ) -> Iterable[Signal]:
        """fail2ban's own tool, as a fourth opinion.

        Slow on a large log, and it reads the *whole* file rather than the
        window, so its number is not comparable to the others — it is here
        because it is the number a sceptic will ask for, and because it is the
        one count that does not depend on watchdesk being right.
        """
        config: Config = ctx.config
        if not config.fail2ban.run_fail2ban_regex or not log_path:
            return
        try:
            result = ctx.runner.run(["fail2ban-regex", log_path, filter_path])
        except (CommandDenied, FileNotFoundError):
            return
        if not result.ok:
            return
        match = _REGEX_TOOL_MATCHED_RE.search(result.stdout)
        if not match:
            return
        yield Signal(
            name="fail2ban.jail.regex_tool_matches",
            kind=SignalKind.METRIC,
            value=int(match.group(1)),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            unit="lines",
            note="Whole-file count from fail2ban-regex; not windowed, so compare trends only.",
            evidence=(
                Evidence(
                    kind="command_output",
                    ref=f"fail2ban-regex {log_path} {filter_path}",
                    excerpt=match.group(0),
                ),
            ),
        )

    # -- helpers -------------------------------------------------------

    def _jail_status(self, ctx: SourceContext, name: str) -> JailStatus | None:
        try:
            result = ctx.runner.run(["fail2ban-client", "status", name])
        except (CommandDenied, FileNotFoundError):
            return None
        if not result.ok:
            return None
        return parse_jail_status(name, result.stdout)

    def _config_digests(self, ctx: SourceContext, jail_local: str | None) -> Iterable[Signal]:
        """Fingerprint the files that decide what gets counted.

        Not a security control — anyone who can edit these can edit this — but
        a change here between two rounds is the single most useful thing to
        put next to "the numbers moved". It is what lets correlate.py say
        "coverage recovered, and the filter file changed in the same window"
        instead of leaving a human to guess.

        A digest rather than the content: it travels to the LLM and to Discord
        without carrying a config file with it.
        """
        config: Config = ctx.config
        sources: list[tuple[str, str | None]] = [("jail.local", jail_local)]
        for spec in config.fail2ban.jails:
            name = spec.expect_filter or spec.name
            path = str(Path(config.fail2ban.filter_dir) / f"{name}.conf")
            try:
                sources.append((f"filter.d/{name}.conf", ctx.runner.read_text(path)))
            except (CommandDenied, FileNotFoundError, OSError):
                continue

        for label, text in sources:
            if text is None:
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
            yield Signal(
                name="fail2ban.config_digest",
                kind=SignalKind.STATE,
                value=digest,
                source=self.name,
                labels={"file": label},
                observed_at=ctx.now,
                note=(
                    "A change between rounds marks a config edit; correlate.py pairs it "
                    "with anomalies in the same window."
                ),
            )

    def _server_starts(self, ctx: SourceContext) -> Iterable[Signal]:
        """How many times fail2ban started inside the window.

        A restart resets every jail's in-memory counters to zero, so a low
        Total failed after one means "we lost the history", not "it is quiet".
        Reporting the restart is what stops the next reader drawing the
        comfortable conclusion.
        """
        try:
            text = ctx.runner.read_text("/var/log/fail2ban.log")
        except (CommandDenied, FileNotFoundError, OSError):
            return
        cutoff = ctx.now.replace(tzinfo=None) - timedelta(minutes=ctx.config.window_minutes)
        starts = 0
        for line in text.splitlines():
            if "Starting Fail2ban" not in line:
                continue
            try:
                stamp = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if stamp >= cutoff:
                starts += 1
        yield Signal(
            name="fail2ban.server_starts",
            kind=SignalKind.METRIC,
            value=starts,
            source=self.name,
            observed_at=ctx.now,
            unit="restarts",
            note=(
                "fail2ban restarts reset every jail's Total failed to zero. Bans survive in "
                "sqlite; counters do not."
            ),
        )

    def _read_jail_local(self, ctx: SourceContext) -> str | None:
        try:
            return ctx.runner.read_text(ctx.config.fail2ban.jail_local)
        except (CommandDenied, FileNotFoundError, OSError):
            return None

    def _found_events(self, ctx: SourceContext) -> dict[str, Counter[str]] | None:
        """Count Found/Ban entries per jail inside the window.

        fail2ban writes local time with no zone, so the comparison uses naive
        local time on purpose — matching the host clock the log was written
        with, rather than pretending to a precision the format does not carry.
        """
        try:
            text = ctx.runner.read_text("/var/log/fail2ban.log")
        except (CommandDenied, FileNotFoundError, OSError):
            return None

        cutoff = ctx.now.replace(tzinfo=None) - timedelta(minutes=ctx.config.window_minutes)
        counts: dict[str, Counter[str]] = {}
        for line in text.splitlines():
            match = _F2B_EVENT_RE.match(line)
            if not match:
                continue
            action = match.group("action")
            if match.group("logger") != _EVENT_LOGGER.get(action):
                continue
            event_time = _F2B_EVENT_TIME_RE.search(match.group("rest"))
            stamp_text = event_time.group("stamp") if event_time else match.group("stamp")
            try:
                stamp = datetime.strptime(stamp_text, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if stamp < cutoff:
                continue
            counts.setdefault(match.group("jail"), Counter())[action] += 1
        return counts


def _jail_list(text: str) -> list[str]:
    for line in text.splitlines():
        if "Jail list" in line:
            _, _, names = line.partition(":")
            return [name.strip() for name in names.split(",") if name.strip()]
    return []
