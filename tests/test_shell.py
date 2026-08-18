"""The allowlist is a security control, so it gets tested like one.

Every test here is a denial that must hold, or a permission that must be
narrow. The interesting cases are not "does an allowed command run" but
"does an almost-allowed command stay denied".
"""

from __future__ import annotations

import pytest

from watchdesk.sources.shell import (
    Allowlist,
    AllowlistRunner,
    CommandDenied,
    RecordedRunner,
    recording_slug,
)


@pytest.fixture
def allowlist() -> Allowlist:
    return Allowlist(
        host=(
            ("fail2ban-client", "status"),
            ("fail2ban-client", "status", "*"),
            ("docker", "logs", "*"),
        ),
        containers={
            "postfix": (("mailq",),),
            "dovecot": (("doveconf", "log_path", "auth_verbose"),),
        },
        read_paths=("/etc/fail2ban", "/var/log/fail2ban.log"),
    )


def test_unlisted_command_is_denied(allowlist: Allowlist) -> None:
    assert not allowlist.permits(["rm", "-rf", "/"])
    assert not allowlist.permits(["fail2ban-client", "unban", "1.2.3.4"])


def test_permission_is_per_container_not_per_command(allowlist: Allowlist) -> None:
    """The whole reason the allowlist is keyed on (container, argv).

    'mailq is read-only' is not a useful statement. 'the postfix container may
    run exactly mailq' is.
    """
    assert allowlist.permits(["mailq"], container="postfix")
    assert not allowlist.permits(["mailq"], container="dovecot")
    assert not allowlist.permits(["mailq"])


def test_extra_arguments_are_not_permitted(allowlist: Allowlist) -> None:
    assert allowlist.permits(["fail2ban-client", "status"])
    assert not allowlist.permits(["fail2ban-client", "status", "postfix-docker", "--extra"])


def test_wildcard_matches_one_argument_only(allowlist: Allowlist) -> None:
    assert allowlist.permits(["fail2ban-client", "status", "postfix-docker"])
    assert not allowlist.permits(["fail2ban-client", "status", "a", "b"])


def test_wildcard_refuses_to_absorb_a_flag(allowlist: Allowlist) -> None:
    """Otherwise `fail2ban-client status *` quietly becomes
    `fail2ban-client status --anything`."""
    assert not allowlist.permits(["fail2ban-client", "status", "--all"])
    assert not allowlist.permits(["docker", "logs", "--since=1h"])


def test_wildcard_refuses_shell_metacharacters(allowlist: Allowlist) -> None:
    """Nothing runs through a shell, so this cannot be exploited — but an
    argument shaped like an injection means something upstream is already
    wrong, and passing it along is not the right response."""
    assert not allowlist.permits(["docker", "logs", "postfix; rm -rf /"])
    assert not allowlist.permits(["docker", "logs", "$(whoami)"])
    assert not allowlist.permits(["docker", "logs", "a b"])


def test_reads_are_allowlisted_too(allowlist: Allowlist) -> None:
    assert allowlist.permits_read("/etc/fail2ban/jail.local")
    assert allowlist.permits_read("/var/log/fail2ban.log")
    assert not allowlist.permits_read("/etc/shadow")
    assert not allowlist.permits_read("/root/.ssh/id_rsa")


def test_prefix_lookalike_paths_are_denied(allowlist: Allowlist) -> None:
    assert not allowlist.permits_read("/etc/fail2ban-evil/secrets")


def test_runner_raises_rather_than_running(allowlist: Allowlist) -> None:
    runner = AllowlistRunner(allowlist)
    with pytest.raises(CommandDenied):
        runner.run(["cat", "/etc/shadow"])
    with pytest.raises(CommandDenied):
        runner.read_text("/etc/shadow")


def test_denials_are_recorded(allowlist: Allowlist) -> None:
    """A denial is an event worth seeing, not a silent no-op."""
    runner = AllowlistRunner(allowlist)
    with pytest.raises(CommandDenied):
        runner.run(["whoami"])
    assert runner.log == [("host: whoami", False)]


def test_recorded_runner_refuses_to_invent_output(tmp_path) -> None:
    """A missing recording must fail loudly.

    Returning empty output for an unrecorded command would build the exact
    failure mode this project exists to detect — a collector that reports
    nothing and looks like a healthy system — into the test harness.
    """
    (tmp_path / "commands").mkdir()
    runner = RecordedRunner(tmp_path)
    with pytest.raises(FileNotFoundError):
        runner.run(["fail2ban-client", "status"])


def test_recorded_runner_replays_exit_codes(tmp_path) -> None:
    (tmp_path / "commands").mkdir()
    slug = recording_slug(["mailq"], "postfix")
    (tmp_path / "commands" / slug).write_text("#exit 1\nmail: not found\n")
    result = RecordedRunner(tmp_path).run(["mailq"], container="postfix")
    assert result.returncode == 1
    assert result.stdout == "mail: not found\n"
    assert not result.ok
