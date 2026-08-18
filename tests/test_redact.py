"""The redaction gate.

This file is a hard CI gate, not a unit test suite that happens to cover
redact.py.  watchdesk is a public repository watching a private mail server;
if these tests are red, nothing else about the project matters.

The gate has two halves, and both are needed:

  * the redacted output contains no identifiers, and
  * the *un*redacted input does — otherwise a broken leak-checker would let a
    broken redactor pass, and the whole gate would be decorative.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from watchdesk.leakcheck import assert_clean, find_leaks
from watchdesk.redact import (
    RedactionError,
    RedactionPolicy,
    Redactor,
    Style,
    load_salt,
)

FIXTURE = Path(__file__).parent / "fixtures" / "redaction" / "sample_lines.txt"

SALT = "gate-test-salt-not-the-production-one"


@pytest.fixture
def policy() -> RedactionPolicy:
    return RedactionPolicy(
        salt=SALT,
        own_domains=("example-mail.xyz",),
        own_mailboxes=("operator", "postmaster"),
        own_hostnames=("mail-01",),
    )


@pytest.fixture
def redactor(policy: RedactionPolicy) -> Redactor:
    return Redactor(policy)


@pytest.fixture
def sample_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The gate itself
# --------------------------------------------------------------------------


def test_the_gate_is_not_vacuous(sample_text: str) -> None:
    """The raw fixture must trip the leak-checker.

    Without this, a leak-checker that matched nothing would make every other
    assertion in this file pass trivially.
    """
    leaks = find_leaks(sample_text)
    kinds = {
        "ipv4": any(leak.count(".") == 3 and leak[0].isdigit() for leak in leaks),
        "ipv6": any(":" in leak for leak in leaks),
        "email": any("@" in leak for leak in leaks),
        "path": any(leak.startswith("/") for leak in leaks),
    }
    assert all(kinds.values()), f"fixture does not exercise every leak class: {kinds}"


def test_redacted_fixture_has_no_identifiers(redactor: Redactor, sample_text: str) -> None:
    assert_clean(redactor.text(sample_text))


def test_redacted_fixture_line_by_line(redactor: Redactor, sample_text: str) -> None:
    """Line-scoped too: a whole-file pass could hide a rule that only works
    because of surrounding context."""
    for line in sample_text.splitlines():
        assert_clean(redactor.text(line))


def test_structured_payload_is_redacted_including_dict_keys(redactor: Redactor) -> None:
    payload = {
        "jail": "postfix-docker",
        "top_sources": {"93.184.216.34": 440, "198.51.100.23": 222},
        "evidence": [
            "warning: unknown[93.184.216.34]: SASL LOGIN authentication failed",
            {"path": "/home/operator/Maildir", "mailbox": "operator@example-mail.xyz"},
        ],
        "counts": (1, 2, 3),
    }
    assert_clean(json.dumps(redactor.value(payload)))


# --------------------------------------------------------------------------
# Pseudonym behaviour: correlation must survive, identity must not
# --------------------------------------------------------------------------


def test_same_address_yields_same_pseudonym(redactor: Redactor) -> None:
    """The reason for pseudonyms over a flat mask: a report has to still show
    that two log lines came from one source."""
    out = redactor.text("first 93.184.216.34 ... later 93.184.216.34 ... other 93.184.216.35")
    tokens = [word for word in out.split() if word.startswith("ip:")]
    assert tokens[0] == tokens[1]
    assert tokens[2] != tokens[0]


def test_pseudonym_depends_on_the_salt(policy: RedactionPolicy) -> None:
    other = RedactionPolicy(
        salt="a-different-salt",
        own_domains=policy.own_domains,
        own_mailboxes=policy.own_mailboxes,
        own_hostnames=policy.own_hostnames,
    )
    line = "unknown[93.184.216.34]"
    assert Redactor(policy).text(line) != Redactor(other).text(line)


def test_pseudonym_shape(redactor: Redactor) -> None:
    out = redactor.text("unknown[93.184.216.34]")
    token = out[len("unknown[") : -len("]")]
    assert token.startswith("ip:")
    assert len(token) == len("ip:") + 6
    assert all(char in "0123456789abcdef" for char in token[3:])


def test_loopback_and_private_are_labelled_not_just_hashed(redactor: Redactor) -> None:
    """Losing "this was the Docker gateway, not the internet" would cost more
    diagnostic value than the addresses are worth hiding."""
    out = redactor.text("rip=127.0.0.1 lip=172.19.0.1 remote=93.184.216.34")
    assert "ip:loopback" in out
    assert "ip:private-" in out
    assert_clean(out)


# --------------------------------------------------------------------------
# Individual rules that have bitten before
# --------------------------------------------------------------------------


def test_reverse_dns_name_loses_its_octets(redactor: Redactor) -> None:
    """A PTR name carries the same four octets as the address it resolves."""
    out = redactor.text("Invalid user admin from 93-184-216-34.static.example-isp.net port 51422")
    assert "93-184-216-34" not in out
    assert "example-isp" not in out
    assert_clean(out)


def test_ipv4_mapped_ipv6_is_matched_whole(redactor: Redactor) -> None:
    """Matching only the ::ffff:203 prefix would leave three octets behind."""
    out = redactor.text("client ::ffff:93.184.216.34 connected")
    assert "93.184" not in out
    assert_clean(out)


def test_own_mailbox_is_masked_and_others_are_pseudonymised(redactor: Redactor) -> None:
    out = redactor.text("from=<operator@example-mail.xyz> to=<attacker@example-isp.net>")
    assert "mbox:own" in out
    assert "mbox:own" != out.split("to=<")[1].rstrip(">")
    assert_clean(out)


def test_generic_system_paths_survive_but_home_does_not(redactor: Redactor) -> None:
    """/etc/fail2ban/jail.local is the evidence for the most important rule in
    this project; /home/<user>/Maildir is somebody's name."""
    out = redactor.text(
        "check /etc/fail2ban/jail.local and /var/log/fail2ban.log not /home/operator/Maildir"
    )
    assert "/etc/fail2ban/jail.local" in out
    assert "/var/log/fail2ban.log" in out
    assert "/home/operator" not in out
    assert_clean(out)


def test_filenames_are_not_mistaken_for_domains(redactor: Redactor) -> None:
    text = "filter = dovecot-docker in jail.local, see 10-logging.conf and fail2ban.log"
    assert redactor.text(text) == text


def test_short_hostname_is_replaced(redactor: Redactor) -> None:
    """syslog prints the short form, which has no dots for the FQDN rule to
    catch."""
    out = redactor.text("Aug 01 23:09:11 mail-01 postfix/smtpd[1]:")
    assert "mail-01" not in out
    # The positive half matters as much: an assertion that only checks for the
    # absence of a string passes just as happily when the input never
    # contained it, which is how a test quietly stops testing anything.
    assert "host:self" in out


def test_html_escaped_angle_brackets_are_left_intact(redactor: Redactor) -> None:
    """Docker's json-file driver writes < and > as \\u003c / \\u003e.

    The escape sits flush against the value being redacted, and its trailing
    "c" is a word character — a naive email rule starts one character early
    and eats it, leaving a line that no longer parses as JSON.
    """
    line = (
        r"from=\u003cattacker@example.net\u003e rip=93.184.216.34"
        r" to=\u003coperator@example-mail.xyz\u003e"
    )
    out = redactor.text(line)

    assert out.count(r"\u003c") == 2
    assert out.count(r"\u003e") == 2
    assert "attacker@" not in out
    assert "mbox:own" in out
    assert_clean(out)


def test_json_wrapped_line_survives_as_json(redactor: Redactor) -> None:
    """A redacted container log line must still load as JSON, or replaying a
    baked fixture through the real parsers stops being a real test."""
    raw = (
        '{"log":"Aug 01 23:10:02 mail-01 postfix/smtpd[15801]: NOQUEUE: reject: '
        'RCPT from unknown[93.184.216.34]: 454 4.7.1 \\u003cvictim@example.org\\u003e: '
        'Relay access denied\\n","stream":"stdout","time":"2026-08-01T23:10:02.114000000Z"}'
    )
    out = redactor.text(raw)
    parsed = json.loads(out)

    assert parsed["stream"] == "stdout"
    assert "<victim@example.org>" not in parsed["log"]
    assert parsed["log"].endswith("\n")
    assert_clean(out)


# --------------------------------------------------------------------------
# Fixture baking (PLACEHOLDER style)
# --------------------------------------------------------------------------


def test_placeholder_style_keeps_the_line_parseable(
    policy: RedactionPolicy, sample_text: str
) -> None:
    """A baked fixture has to still look like a log file, or it stops
    exercising the parsers it exists to test."""
    baked = Redactor(policy, Style.PLACEHOLDER).text(sample_text)
    assert "postfix/submission/smtpd[15734]" in baked
    assert "SASL LOGIN authentication failed" in baked
    assert "93.184.216.34" not in baked
    assert "mail-01" not in baked
    assert "example.com" in baked or "example.net" in baked


def test_placeholder_addresses_are_unique(policy: RedactionPolicy) -> None:
    """Sequential allocation, not a truncated hash: a fixture in which two
    attackers collapse into one address would silently break rate rules."""
    redactor = Redactor(policy, Style.PLACEHOLDER)
    originals = [f"93.184.216.{n}" for n in range(1, 60)]
    baked = redactor.text(" ".join(originals))
    produced = [word for word in baked.split()]
    assert len(set(produced)) == len(originals)


def test_baked_fixture_still_passes_the_runtime_gate(
    policy: RedactionPolicy, sample_text: str
) -> None:
    """Committed fixtures are baked; at runtime they go out through the
    pseudonym exit anyway.  Both passes must end clean."""
    baked = Redactor(policy, Style.PLACEHOLDER).text(sample_text)
    assert_clean(Redactor(policy).text(baked))


def test_placeholder_output_is_not_redacted_twice(policy: RedactionPolicy) -> None:
    redactor = Redactor(policy, Style.PLACEHOLDER)
    assert redactor.text("host mail-01 up") == "host mail.example.com up"


# --------------------------------------------------------------------------
# Salt handling
# --------------------------------------------------------------------------


def test_policy_refuses_to_exist_without_a_salt() -> None:
    with pytest.raises(RedactionError):
        RedactionPolicy(salt="   ")


def test_env_salt_wins(tmp_path: Path) -> None:
    env = {"WATCHDESK_REDACT_SALT": "from-env", "WATCHDESK_SALT_FILE": str(tmp_path / "s.salt")}
    assert load_salt(env) == "from-env"
    assert not (tmp_path / "s.salt").exists()


def test_generated_salt_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "redact.salt"
    salt = load_salt({"WATCHDESK_SALT_FILE": str(path)})
    assert len(salt) >= 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_salt({"WATCHDESK_SALT_FILE": str(path)}) == salt
