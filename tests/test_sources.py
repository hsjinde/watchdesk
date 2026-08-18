"""Parsers, and the blind spots they were written against.

Each test below corresponds to a filter gap that actually happened on this
server. They are here so the *detector* cannot regress into the same shape as
the bug it detects.
"""

from __future__ import annotations

import textwrap

from watchdesk.sources import dockerlog, dovecot, postfix
from watchdesk.sources.fail2ban import compile_failregex, parse_jail_status


def json_line(message: str, when: str = "2026-07-31T12:00:00.000000000Z") -> str:
    escaped = message.replace("<", "\\u003c").replace(">", "\\u003e")
    return f'{{"log":"{escaped}\\n","stream":"stdout","time":"{when}"}}'


def as_lines(*messages: str) -> list[dockerlog.LogLine]:
    parsed = [dockerlog.parse_json_line(json_line(m), i) for i, m in enumerate(messages, 1)]
    return [line for line in parsed if line is not None]


# --------------------------------------------------------------------------
# Postfix
# --------------------------------------------------------------------------


def test_all_three_listeners_are_counted_separately() -> None:
    """The August 2026 incident in one assertion.

    A filter matching the service as `postfix/\\w+` sees only the first of
    these. watchdesk's own matcher must see all three, and must not merge them
    — a merged total was exactly what made the gap invisible.
    """
    lines = as_lines(
        "Jul 31 01:00:00 mail postfix/smtpd[1]: warning: unknown[192.0.2.1]: "
        "SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=info",
        "Jul 31 01:00:01 mail postfix/submission/smtpd[2]: warning: unknown[192.0.2.2]: "
        "SASL LOGIN authentication failed: UGFzc3dvcmQ6, sasl_username=fax",
        "Jul 31 01:00:02 mail postfix/smtps/smtpd[3]: warning: unknown[192.0.2.3]: "
        "SASL PLAIN authentication failed: UGFzc3dvcmQ6",
    )
    services = sorted(item.service for item in postfix.iter_auth_failures(lines))
    assert services == ["smtpd", "smtps/smtpd", "submission/smtpd"]


def test_mechanism_case_does_not_matter() -> None:
    """Postfix echoes the mechanism in whatever case the client sent.

    A fixed uppercase list missed 76 lowercase `SASL login` lines here, plus
    NTLM and GSSAPI, and that is why one prober was never counted.
    """
    lines = as_lines(
        "Jul 31 01:00:00 mail postfix/smtpd[1]: warning: unknown[192.0.2.1]: "
        "SASL login authentication failed: x",
        "Jul 31 01:00:01 mail postfix/smtpd[2]: warning: unknown[192.0.2.2]: "
        "SASL NTLM authentication failed: x",
        "Jul 31 01:00:02 mail postfix/smtpd[3]: warning: unknown[192.0.2.3]: "
        "SASL GSSAPI authentication failed: x",
    )
    assert len(list(postfix.iter_auth_failures(lines))) == 3


def test_relay_rejection_matches_any_status_code() -> None:
    """The filter expected 554 5.7.1; every real line on this host said
    454 4.7.1, so the rule was dead for months."""
    lines = as_lines(
        "Jul 31 01:00:00 mail postfix/smtpd[1]: NOQUEUE: reject: RCPT from "
        "unknown[192.0.2.1]: 454 4.7.1 <a@example.org>: Relay access denied; "
        "from=<b@example.net> to=<a@example.org> proto=ESMTP helo=<x>",
        "Jul 31 01:00:01 mail postfix/smtpd[2]: NOQUEUE: reject: RCPT from "
        "unknown[192.0.2.2]: 554 5.7.1 <a@example.org>: Relay access denied; "
        "from=<b@example.net> to=<a@example.org> proto=ESMTP helo=<x>",
    )
    codes = sorted(
        match.group("code")
        for match in (postfix.RELAY_DENIED_RE.search(line.message) for line in lines)
        if match
    )
    assert codes == ["454 4.7.1", "554 5.7.1"]


def test_matching_happens_on_the_decoded_message() -> None:
    """The raw line has \\u003c escapes; the decoded one does not.

    watchdesk reads the decoded form so the escaping cannot cause an
    undercount. fail2ban has no such luxury — it matches the raw bytes — and
    that asymmetry is precisely what the cross-check measures.
    """
    (line,) = as_lines(
        "Jul 31 01:00:00 mail postfix/smtpd[1]: NOQUEUE: reject: RCPT from "
        "unknown[192.0.2.1]: 454 4.7.1 <victim@example.org>: Relay access denied"
    )
    assert "\\u003c" in line.raw
    assert "<victim@example.org>" in line.message


# --------------------------------------------------------------------------
# Dovecot
# --------------------------------------------------------------------------


def test_dovecot_failure_formats() -> None:
    lines = as_lines(
        "Jul 31 01:00:00 pop3-login: Info: Disconnected (auth failed, 3 attempts in 12 secs): "
        "user=<operator>, method=PLAIN, rip=192.0.2.1, lip=172.19.0.3, session=<abc>",
        "Jul 31 01:00:01 imap-login: Info: Disconnected: Connection closed "
        "(auth failed, 1 attempts in 4 secs): user=<test>, method=PLAIN, rip=192.0.2.2, "
        "lip=172.19.0.3, TLS, session=<def>",
    )
    events = list(dovecot.iter_auth_failures(lines))
    assert sorted(event.service for event in events) == ["imap", "pop3"]
    assert sorted(event.attempts for event in events) == [1, 3]


def test_dovecot_ignores_connections_with_no_auth_attempt() -> None:
    """A TLS handshake failure is noise, not a brute-force attempt."""
    lines = as_lines(
        "Jul 31 00:00:13 imap-login: Info: Disconnected: Connection closed: "
        "SSL_accept() failed (no auth attempts in 2 secs): user=<>, rip=192.0.2.1, "
        "lip=172.19.0.3"
    )
    assert list(dovecot.iter_auth_failures(lines)) == []


# --------------------------------------------------------------------------
# fail2ban
# --------------------------------------------------------------------------


def test_jail_status_parsing() -> None:
    status = parse_jail_status(
        "postfix-docker",
        textwrap.dedent(
            """\
            Status for the jail: postfix-docker
            |- Filter
            |  |- Currently failed:\t13
            |  |- Total failed:\t1078
            |  `- File list:\t/var/log/postfix-docker.log
            `- Actions
               |- Currently banned:\t13
               |- Total banned:\t174
               `- Banned IP list:\t192.0.2.1 192.0.2.2
            """
        ),
    )
    assert status.total_failed == 1078
    assert status.currently_banned == 13
    assert status.log_paths == ("/var/log/postfix-docker.log",)
    assert status.banned_ips == ("192.0.2.1", "192.0.2.2")


def test_failregex_with_literal_angle_brackets_still_compiles() -> None:
    """Regression: a first version rejected any expression containing < or >,
    which threw out the dovecot filter for its ordinary `(?:<|\\\\u003c)` — and
    a skipped cross-check reports no disagreement, i.e. a clean bill of health
    for a jail nobody audited."""
    patterns, problems = compile_failregex(
        textwrap.dedent(
            r"""
            [Definition]
            failregex = ^\{"log":".*?pop3-login: .*user=(?:<|\\u003c)[^>]*(?:>|\\u003e), rip=<HOST>
            """
        )
    )
    assert problems == []
    assert len(patterns) == 1


def test_fail2ban_internal_tokens_are_reported_not_guessed() -> None:
    patterns, problems = compile_failregex(
        "[Definition]\nfailregex = ^%(__prefix_line)sFailed password for <HOST>\n"
    )
    assert patterns == []
    assert problems and "fail2ban-internal token" in problems[0]


def test_broken_and_fixed_postfix_filters_disagree_by_the_listener() -> None:
    """The two filter versions, side by side, on the same line.

    This is the mechanism of the incident reduced to its smallest form: the
    extra path segment in postfix/submission/smtpd is not \\w.
    """
    line = json_line(
        "Jul 31 01:00:01 mail postfix/submission/smtpd[2]: warning: unknown[192.0.2.2]: "
        "SASL LOGIN authentication failed: x"
    )
    broken, _ = compile_failregex(
        r'[Definition]' "\n"
        r'failregex = ^\{"log":".*?\bpostfix/\w+\[\d+\]: warning: [^[]*\[<HOST>\]'
        r'(?::\d+)?: SASL [A-Za-z0-9-]+ authentication failed' "\n"
    )
    fixed, _ = compile_failregex(
        r'[Definition]' "\n"
        r'failregex = ^\{"log":".*?\bpostfix/(?:\w+/)?\w+\[\d+\]: warning: [^[]*\[<HOST>\]'
        r'(?::\d+)?: SASL [A-Za-z0-9-]+ authentication failed' "\n"
    )
    assert not any(pattern.search(line) for pattern in broken)
    assert any(pattern.search(line) for pattern in fixed)


# --------------------------------------------------------------------------
# Reading the log when the json-file is unreadable
# --------------------------------------------------------------------------


class FakeRunner:
    """Denies the file read, answers docker logs. What a non-root process sees."""

    def __init__(self, stdout: str, timestamps: bool = True):
        self.stdout = stdout
        self.timestamps = timestamps
        self.argvs: list[list[str]] = []

    def run(self, argv, container=None):
        from watchdesk.sources.shell import CommandResult

        self.argvs.append(list(argv))
        if argv[:2] == ["docker", "inspect"]:
            return CommandResult(tuple(argv), 0, "/var/lib/docker/containers/x/x-json.log\n", "")
        if argv[:2] == ["docker", "logs"]:
            return CommandResult(tuple(argv), 0, self.stdout, "")
        return CommandResult(tuple(argv), 1, "", "no")

    def read_text(self, path):
        raise PermissionError(path)

    def read_lines(self, path):
        raise PermissionError(path)


TIMESTAMPED = (
    "2026-08-18T14:00:00.000000000Z Jul 31 01:00:00 mail postfix/submission/smtpd[2]: "
    "warning: unknown[192.0.2.2]: SASL LOGIN authentication failed: x\n"
)


def test_docker_logs_fallback_is_asked_for_timestamps() -> None:
    """Without --timestamps there is no time on those lines at all, and the
    window filter would silently keep or drop everything."""
    runner = FakeRunner(TIMESTAMPED)
    read = dockerlog.load(runner, "postfix")
    assert ["docker", "logs", "--timestamps", "postfix"] in runner.argvs
    assert len(read.lines) == 1


def test_docker_logs_fallback_still_counts_failures() -> None:
    """The bug CI caught: the fallback returned plain text, parse_json_line
    rejected every line, and a busy container reported zero failures with no
    error anywhere."""
    read = dockerlog.load(FakeRunner(TIMESTAMPED), "postfix")
    assert len(list(postfix.iter_auth_failures(read.lines))) == 1


def test_the_fallback_declares_itself_not_wire_format() -> None:
    """`docker logs` hands over the decoded message, not the bytes on disk.
    Anything that depends on those bytes has to know that."""
    read = dockerlog.load(FakeRunner(TIMESTAMPED), "postfix")
    assert read.wire_format is False
    assert all(line.wire_format is False for line in read.lines)


def test_reading_the_json_file_is_wire_format() -> None:
    lines = as_lines("Jul 31 01:00:00 mail postfix/smtpd[1]: warning: x")
    assert all(line.wire_format for line in lines)
