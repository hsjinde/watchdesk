#!/usr/bin/env python3
"""Turn a real incident on this host into a committable fixture.

Run as root on the machine that owns the logs.  It reads the live artefacts,
passes everything through ``redact.py`` in PLACEHOLDER style — which swaps
real addresses for documentation-range ones while leaving the line parseable —
and writes a fixture directory plus a ``meta.yaml`` recording exactly what is
genuine and what was reconstructed.

The original-to-placeholder mapping is written *outside* the repository.  It
is the reverse lookup table for everything the fixture contains, so it is
treated like the salt: useful locally, never published.

Provenance rules this script follows, because a fixture that overstates its
own authenticity is worse than a synthetic one:

* Log files are genuine captures, redacted.  Nothing is added or reordered.
* Command outputs that no longer exist for a past moment (a jail's counters
  as they stood that night) are *reconstructed* from those same logs, by
  replaying the events fail2ban itself recorded, and are labelled as such.
* Config files that have since been fixed are reconstructed by reverting the
  one documented change, and are labelled as such.
"""

from __future__ import annotations

import argparse
import configparser
import gzip
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from watchdesk.redact import RedactionPolicy, Redactor, Style  # noqa: E402
from watchdesk.sources.shell import recording_slug  # noqa: E402

F2B_EVENT = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+"
    r"(?P<logger>fail2ban\.\w+)\s+\[\d+\]:\s+\w+\s+"
    r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Restore Ban|Found|Ban|Unban)\b(?P<rest>.*)$"
)
EVENT_LOGGER = {
    "Found": "fail2ban.filter",
    "Ban": "fail2ban.actions",
    "Unban": "fail2ban.actions",
    "Restore Ban": "fail2ban.actions",
}


def read_any(path: Path) -> str:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="replace").read()
    return path.read_text(errors="replace")


def container_log(container: str) -> Path:
    cid = subprocess.run(
        ["docker", "inspect", "--format", "{{.LogPath}}", container],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return Path(cid)


def slice_json_log(path: Path, day: str) -> list[str]:
    return [line for line in read_any(path).splitlines() if f'"time":"{day}' in line]


def slice_plain_log(paths: list[Path], day: str) -> list[str]:
    out: list[str] = []
    for path in paths:
        out += [line for line in read_any(path).splitlines() if line.startswith(day)]
    return out


def replay_counters(paths: list[Path], until: datetime, since: datetime) -> dict[str, dict]:
    """Reconstruct each jail's counters as they stood at ``until``.

    fail2ban keeps Total failed / Total banned in memory only, so the numbers
    from a past evening are not recoverable from any file — but they are
    *derivable*, because every increment was logged as it happened. ``since``
    must be the last fail2ban restart: the counters reset there.
    """
    stats: dict[str, dict] = {}
    for path in paths:
        for line in read_any(path).splitlines():
            match = F2B_EVENT.match(line)
            if not match:
                continue
            action = match.group("action")
            if match.group("logger") != EVENT_LOGGER[action]:
                continue
            stamp = datetime.strptime(match.group("stamp"), "%Y-%m-%d %H:%M:%S")
            if not (since <= stamp < until):
                continue
            jail = stats.setdefault(
                match.group("jail"),
                {"found": 0, "banned": 0, "current": set(), "recent": Counter()},
            )
            tail = match.group("rest").split()
            address = tail[0].rstrip(",") if tail else ""
            if action == "Found":
                jail["found"] += 1
                if stamp >= until - timedelta(days=1):
                    jail["recent"][address] += 1
            elif action == "Ban":
                jail["banned"] += 1
                jail["current"].add(address)
            elif action == "Unban":
                jail["current"].discard(address)
    return stats


def status_block(jail: str, stats: dict, log_path: str) -> str:
    """Render the reconstruction in fail2ban-client's exact output format."""
    currently_failed = sum(
        count for address, count in stats["recent"].items() if address not in stats["current"]
    )
    banned = " ".join(sorted(stats["current"]))
    return (
        f"Status for the jail: {jail}\n"
        f"|- Filter\n"
        f"|  |- Currently failed:\t{currently_failed}\n"
        f"|  |- Total failed:\t{stats['found']}\n"
        f"|  `- File list:\t{log_path}\n"
        f"`- Actions\n"
        f"   |- Currently banned:\t{len(stats['current'])}\n"
        f"   |- Total banned:\t{stats['banned']}\n"
        f"   `- Banned IP list:\t{banned}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", required=True, help="UTC day to capture, e.g. 2026-07-31")
    parser.add_argument("--out", required=True, help="fixture directory to write")
    parser.add_argument(
        "--mapping",
        required=True,
        help="where to write the original->placeholder table (outside the repo)",
    )
    parser.add_argument(
        "--counters-since",
        required=True,
        help="last fail2ban restart before the capture; counters reset there",
    )
    parser.add_argument("--salt", default="fixture-bake", help="salt for the placeholder mapping")
    parser.add_argument(
        "--mapping-in",
        help=(
            "reuse an earlier bake's mapping, so adjacent fixtures agree on which "
            "placeholder stands for which real value"
        ),
    )
    parser.add_argument("--own-domains", default="")
    parser.add_argument("--own-mailboxes", default="")
    parser.add_argument("--own-hostnames", default="")
    parser.add_argument("--revert-postfix-filter", action="store_true")
    args = parser.parse_args()

    out = Path(args.out)
    (out / "files/var/log").mkdir(parents=True, exist_ok=True)
    (out / "files/etc/fail2ban/filter.d").mkdir(parents=True, exist_ok=True)
    (out / "commands").mkdir(parents=True, exist_ok=True)

    def csv(raw: str) -> tuple[str, ...]:
        return tuple(item.strip().lower() for item in raw.split(",") if item.strip())

    policy = RedactionPolicy(
        salt=args.salt,
        own_domains=csv(args.own_domains),
        own_mailboxes=csv(args.own_mailboxes),
        own_hostnames=csv(args.own_hostnames),
    )
    # One redactor for the whole bake, so a given address maps to the same
    # placeholder in the container log, the fail2ban log and the command
    # recordings. Correlation across files is most of what a replay tests.
    preset = {}
    if args.mapping_in:
        preset = json.loads(Path(args.mapping_in).read_text(encoding="utf-8"))
    redactor = Redactor(policy, Style.PLACEHOLDER, preset=preset)

    day = args.day
    until = datetime.strptime(day, "%Y-%m-%d") + timedelta(days=1)
    since = datetime.strptime(args.counters_since, "%Y-%m-%d %H:%M:%S")

    f2b_logs = sorted(Path("/var/log").glob("fail2ban.log*"))
    written: list[str] = []

    for container, name in (("postfix", "postfix-docker"), ("dovecot", "dovecot-docker")):
        lines = slice_json_log(container_log(container), day)
        target = out / "files/var/log" / f"{name}.log"
        target.write_text(redactor.text("\n".join(lines)) + "\n", encoding="utf-8")
        written.append(f"{target.relative_to(out)} ({len(lines)} lines, genuine capture)")
        slug = recording_slug(["docker", "inspect", "--format", "{{.LogPath}}", container])
        (out / "commands" / slug).write_text(f"/var/log/{name}.log\n", encoding="utf-8")

    f2b_lines = slice_plain_log(f2b_logs, day)
    (out / "files/var/log/fail2ban.log").write_text(
        redactor.text("\n".join(f2b_lines)) + "\n", encoding="utf-8"
    )
    written.append(f"files/var/log/fail2ban.log ({len(f2b_lines)} lines, genuine capture)")

    # Every filter file jail.local actually references, resolved from the file
    # rather than listed by hand. Omitting one makes watchdesk report a
    # missing-filter CRITICAL that is an artefact of the fixture, and a fixture
    # that manufactures findings is worse than no fixture.
    jail_local_text = Path("/etc/fail2ban/jail.local").read_text()
    parser_ = configparser.RawConfigParser(strict=False)
    parser_.read_string(jail_local_text)
    referenced = sorted(
        # A stanza with no explicit "filter =" uses a filter named after the
        # jail — that is how [sshd] resolves, and a regex over the file misses
        # it entirely.
        {
            parser_.get(section, "filter", fallback=section)
            for section in parser_.sections()
        }
    )
    sources = [Path("/etc/fail2ban/jail.local")] + [
        Path(f"/etc/fail2ban/filter.d/{name}.conf") for name in referenced
    ]
    for source in sources:
        if not source.exists():
            continue
        text = source.read_text()
        if args.revert_postfix_filter and source.name == "postfix-docker.conf":
            # Revert exactly the 2026-08-01 fix, and nothing else: the service
            # was matched as postfix/\w+, which cannot match the extra path
            # segment in postfix/submission/smtpd. This is what the file
            # contained on the day being captured.
            text = text.replace(r"postfix/(?:\w+/)?\w+\[", r"postfix/\w+\[")
            text = re.sub(r"#\n# FIXED 2026-08-01:.*?listeners\n", "", text, flags=re.S)
        target = out / "files" / str(source).lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(redactor.text(text), encoding="utf-8")
        written.append(f"{target.relative_to(out)} (config as of the capture)")

    stats = replay_counters(f2b_logs, until=until, since=since)
    jail_names = sorted(stats)
    (out / "commands" / recording_slug(["fail2ban-client", "status"])).write_text(
        "Status\n|- Number of jail:\t"
        f"{len(jail_names)}\n`- Jail list:\t{', '.join(jail_names)}\n",
        encoding="utf-8",
    )
    for jail in jail_names:
        log_path = f"/var/log/{jail}.log" if jail.endswith("-docker") else "/var/log/auth.log"
        block = status_block(jail, stats[jail], log_path)
        slug = recording_slug(["fail2ban-client", "status", jail])
        (out / "commands" / slug).write_text(redactor.text(block), encoding="utf-8")
        written.append(f"commands/{slug} (RECONSTRUCTED from fail2ban.log events)")

    # Commands whose answer is a stable fact about the deployment rather than
    # about the incident. They cannot be recovered for a past evening, so they
    # are captured now and labelled in meta.yaml as exactly that. No finding in
    # this fixture depends on them.
    live_captures = [
        (["postconf", "smtpd_sasl_type"], "postfix"),
        (["mailq"], "postfix"),
        (["doveconf", "log_path", "auth_verbose"], "dovecot"),
    ]
    # Container state. Recorded now, but checked against the window below:
    # these containers last started well before the day being captured and
    # have never restarted, so the values are the historical ones. The check
    # is in the code rather than in a comment because the day this stops being
    # true, the fixture would quietly start asserting a fiction.
    containers = ["postfix", "dovecot", "opendkim", "django", "certbot"]
    anachronistic: list[str] = []
    for container in containers:
        for template in ("{{json .State}}", "{{.RestartCount}}"):
            argv = ["docker", "inspect", "--format", template, container]
            completed = subprocess.run(argv, capture_output=True, text=True, check=False)
            slug = recording_slug(argv)
            (out / "commands" / slug).write_text(
                redactor.text(completed.stdout), encoding="utf-8"
            )
        started = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", container],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if started and started[:10] > day:
            anachronistic.append(f"{container} (started {started})")
    written.append(
        f"commands/host_docker_inspect_* ({len(containers)} containers, state at bake time"
        + (f"; NEWER THAN THE WINDOW: {', '.join(anachronistic)}" if anachronistic else
           "; all started before the captured day, so these are the historical values")
        + ")"
    )
    for argv, container in live_captures:
        completed = subprocess.run(
            ["docker", "exec", container, *argv], capture_output=True, text=True, check=False
        )
        slug = recording_slug(argv, container)
        (out / "commands" / slug).write_text(redactor.text(completed.stdout), encoding="utf-8")
        written.append(f"commands/{slug} (captured at bake time, not from the incident)")

    # fail2ban-regex is run against the fixture's *own* files, so this
    # recording is genuine rather than reconstructed: it is fail2ban's real
    # tooling answering a real question about the bytes that ship in the repo.
    for jail, container_log_name in (
        ("postfix-docker", "postfix-docker"),
        ("dovecot-docker", "dovecot-docker"),
    ):
        log = out / "files/var/log" / f"{container_log_name}.log"
        filter_file = out / "files/etc/fail2ban/filter.d" / f"{jail}.conf"
        completed = subprocess.run(
            ["fail2ban-regex", str(log), str(filter_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        argv = [
            "fail2ban-regex",
            f"/var/log/{container_log_name}.log",
            f"/etc/fail2ban/filter.d/{jail}.conf",
        ]
        slug = recording_slug(argv)
        (out / "commands" / slug).write_text(redactor.text(completed.stdout), encoding="utf-8")
        written.append(f"commands/{slug} (genuine: fail2ban-regex run against the fixture itself)")

    mapping = Path(args.mapping)
    mapping.parent.mkdir(parents=True, exist_ok=True)
    mapping.write_text(json.dumps(redactor.mapping, indent=2, sort_keys=True), encoding="utf-8")

    meta = {
        "name": out.name,
        "as_of": f"{day}T23:59:59Z",
        "window_minutes": 1440,
        "sources": ["fail2ban", "postfix", "dovecot", "docker_state"],
        "captured_from": "a single self-hosted mail server, redacted at capture time",
        "provenance": {
            "genuine_redacted": [
                "files/var/log/postfix-docker.log",
                "files/var/log/dovecot-docker.log",
                "files/var/log/fail2ban.log",
                "commands/host_fail2ban_regex_*",
            ],
            "reconstructed": {
                "commands/host_fail2ban_client_status_*": (
                    "fail2ban keeps Total failed / Total banned in memory only, so the "
                    "numbers from that evening are not in any file. They are replayed "
                    "from the Found/Ban events fail2ban logged as they happened, counted "
                    f"from the last restart at {args.counters_since}. Currently failed is "
                    "derived as trailing-24h Found events from addresses not currently "
                    "banned."
                ),
                "files/etc/fail2ban/filter.d/postfix-docker.conf": (
                    "the live file with the 2026-08-01 fix reverted, and only that: the "
                    "service was matched as postfix/\\w+, which cannot match the extra "
                    "path segment in postfix/submission/smtpd. This is what the file "
                    "contained on the day captured."
                ),
            },
            "captured_at_bake_time": [
                "commands/exec_postfix_mailq.txt",
                "commands/exec_postfix_postconf_smtpd_sasl_type.txt",
                "commands/exec_dovecot_doveconf_log_path_auth_verbose.txt",
                "commands/host_docker_inspect_* (container state; every container"
                " last started before the captured day and has never restarted,"
                " so these values are the historical ones)"
                if not anachronistic
                else "commands/host_docker_inspect_* (WARNING: container state is"
                f" newer than the captured window: {', '.join(anachronistic)})",
            ],
        },
        "redaction": {
            "style": "placeholder",
            "note": (
                "Addresses are substituted for documentation-range addresses (RFC 5737 / "
                "3849) so the lines still parse; private and loopback addresses are left "
                "as they were, since they identify nobody and the detection rules key on "
                "them. The original-to-placeholder mapping is not in this repository."
            ),
        },
    }
    (out / "meta.yaml").write_text(
        "# Written by scripts/bake_fixture.py. Provenance is part of the fixture:\n"
        "# a capture that overstates its own authenticity is worse than a synthetic one.\n"
        + yaml.safe_dump(meta, sort_keys=False, allow_unicode=True, width=88),
        encoding="utf-8",
    )

    print(f"wrote {out} ({len(redactor.mapping)} values substituted)")
    for item in written:
        print(f"  {item}")
    print(f"\nmapping (keep out of the repo): {mapping}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
