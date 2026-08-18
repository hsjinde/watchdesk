"""The only place watchdesk is allowed to execute anything.

Every command is checked against a plaintext allowlist before it runs, and the
allowlist is keyed on the *(container, argv)* pair rather than on a command
name.  That distinction is the point:

    docker exec postfix mailq

is read-only because ``mailq`` happens to read.  ``docker exec`` itself is
not read-only, and "allow the postfix container to run mailq" is a claim you
can check, while "allow mailq" is not — it says nothing about which container,
and nothing about which arguments.  So an allowlist entry names both, the
runner assembles the ``docker exec`` line itself, and a config file can never
smuggle in ``-v /:/host`` or ``-u root``.

This is a guardrail against watchdesk misbehaving.  It is not a sandbox: the
process still holds the Docker group, and whoever can edit the config can run
anything in those containers.  The README says so in as many words.

Two implementations satisfy :class:`CommandRunner`:

* :class:`AllowlistRunner` shells out for real.
* :class:`RecordedRunner` replays a fixture directory.

Sources cannot tell them apart, which is what makes
``watchdesk replay tests/fixtures/2026-08-fail2ban-gap/`` a test of the real
collection code rather than of a parallel mock.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = [
    "Allowlist",
    "AllowlistRunner",
    "CommandDenied",
    "CommandResult",
    "CommandRunner",
    "RecordedRunner",
    "recording_slug",
]

#: A single ``*`` in an allowlist entry stands for exactly one argument — a
#: jail name, a container name, a log path.  It is not a glob: it never spans
#: arguments, and the argument it matches still has to survive _SAFE_ARG.
WILDCARD = "*"

#: Arguments are restricted to characters that cannot change the meaning of an
#: argv list.  No spaces, quotes, backticks, semicolons, redirections or shell
#: expansions — none of which would be interpreted anyway, since nothing here
#: runs through a shell, but a jail name containing ``$(...)`` is a sign that
#: something upstream is already wrong and is worth refusing rather than
#: passing along.
_SAFE_ARG = re.compile(r"^[A-Za-z0-9._:/@=,+-]{1,256}$")


class CommandDenied(RuntimeError):
    """Raised when a command is not on the allowlist. Never caught silently."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float = 0.0
    container: str | None = None
    recorded: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def display(self) -> str:
        """How this command is named in evidence: exactly what ran."""
        if self.container:
            return f"docker exec {self.container} " + " ".join(self.argv)
        return " ".join(self.argv)


def _entry_matches(entry: Sequence[str], argv: Sequence[str]) -> bool:
    if len(entry) != len(argv):
        return False
    for expected, actual in zip(entry, argv, strict=True):
        if expected == WILDCARD:
            if not _SAFE_ARG.match(actual):
                return False
            if actual.startswith("-"):
                # A wildcard is there to stand for a jail or a path. Letting it
                # absorb a flag would turn "fail2ban-client status *" into
                # "fail2ban-client status --anything".
                return False
            continue
        if expected != actual:
            return False
    return True


@dataclass(frozen=True)
class Allowlist:
    """Deny by default.  Both halves are plain data, printable in one screen."""

    host: tuple[tuple[str, ...], ...] = ()
    containers: Mapping[str, tuple[tuple[str, ...], ...]] = field(default_factory=dict)
    read_paths: tuple[str, ...] = ()

    def permits(self, argv: Sequence[str], container: str | None = None) -> bool:
        entries = self.host if container is None else self.containers.get(container, ())
        return any(_entry_matches(entry, argv) for entry in entries)

    def permits_read(self, path: str | Path) -> bool:
        resolved = str(path)
        return any(
            resolved == allowed or resolved.startswith(allowed.rstrip("/") + "/")
            for allowed in self.read_paths
        )

    def describe(self) -> list[str]:
        """The allowlist as a human reads it — used by ``watchdesk doctor``."""
        lines = [f"host: {' '.join(entry)}" for entry in self.host]
        for container, entries in sorted(self.containers.items()):
            lines += [f"exec {container}: {' '.join(entry)}" for entry in entries]
        lines += [f"read: {path}" for path in self.read_paths]
        return lines


@runtime_checkable
class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], container: str | None = None) -> CommandResult: ...

    def read_text(self, path: str) -> str: ...

    def read_lines(self, path: str) -> list[str]: ...


class AllowlistRunner:
    """Runs allowlisted commands on this host.  Never uses a shell."""

    def __init__(self, allowlist: Allowlist, timeout_s: float = 60.0) -> None:
        self.allowlist = allowlist
        self.timeout_s = timeout_s
        self.log: list[tuple[str, bool]] = []

    def run(self, argv: Sequence[str], container: str | None = None) -> CommandResult:
        argv = tuple(argv)
        if not self.allowlist.permits(argv, container):
            self.log.append((f"{container or 'host'}: {' '.join(argv)}", False))
            raise CommandDenied(
                f"not on the allowlist: container={container or 'host'} argv={list(argv)}"
            )
        self.log.append((f"{container or 'host'}: {' '.join(argv)}", True))

        # The docker exec line is assembled here, from the container name and
        # the allowlisted argv only. Nothing from the config lands between
        # "exec" and the container name, so no config edit can add a mount, a
        # user switch or a privilege flag.
        command = list(argv) if container is None else ["docker", "exec", container, *argv]

        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(argv, 127, "", str(exc), time.monotonic() - started, container)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(argv, 124, "", str(exc), time.monotonic() - started, container)
        return CommandResult(
            argv,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            time.monotonic() - started,
            container,
        )

    def read_text(self, path: str) -> str:
        if not self.allowlist.permits_read(path):
            raise CommandDenied(f"not on the read allowlist: {path}")
        return Path(path).read_text(encoding="utf-8", errors="replace")

    def read_lines(self, path: str) -> list[str]:
        return self.read_text(path).splitlines()


def recording_slug(argv: Sequence[str], container: str | None = None) -> str:
    """Filename a command's recorded output lives under in a fixture.

    Derived from the command itself so that a recording is obviously matched
    to what it claims to record, and a missing one fails loudly instead of
    quietly returning empty output.
    """
    prefix = "host" if container is None else f"exec_{container}"
    body = "_".join(argv)
    return re.sub(r"[^A-Za-z0-9]+", "_", f"{prefix}__{body}").strip("_") + ".txt"


class RecordedRunner:
    """Replays a fixture directory captured from a real host.

    Layout::

        <fixture>/commands/<slug>.txt   stdout of one allowlisted command
        <fixture>/files/<flattened>     contents of one allowlisted file read
        <fixture>/logs/...              log files, referenced by the above

    A command with no recording raises rather than returning empty output: a
    silent empty result is exactly the failure this project exists to detect,
    and it would be perverse to build it into the test harness.
    """

    def __init__(self, root: str | Path, allowlist: Allowlist | None = None) -> None:
        self.root = Path(root)
        self.allowlist = allowlist
        self.requested: list[str] = []

    def run(self, argv: Sequence[str], container: str | None = None) -> CommandResult:
        argv = tuple(argv)
        if self.allowlist is not None and not self.allowlist.permits(argv, container):
            raise CommandDenied(
                f"not on the allowlist: container={container or 'host'} argv={list(argv)}"
            )
        slug = recording_slug(argv, container)
        self.requested.append(slug)
        path = self.root / "commands" / slug
        if not path.exists():
            raise FileNotFoundError(
                f"fixture {self.root.name} has no recording for "
                f"{'docker exec ' + container + ' ' if container else ''}{' '.join(argv)} "
                f"(expected {path.relative_to(self.root)})"
            )
        payload = path.read_text(encoding="utf-8")
        returncode = 0
        # An optional first line of "#exit <n>" records a non-zero exit, so a
        # fixture can reproduce a failing command as faithfully as a working
        # one.
        if payload.startswith("#exit "):
            first, _, rest = payload.partition("\n")
            returncode = int(first.split(maxsplit=1)[1])
            payload = rest
        return CommandResult(argv, returncode, payload, "", 0.0, container, recorded=True)

    def _file_path(self, path: str) -> Path:
        direct = self.root / "files" / path.lstrip("/")
        if direct.exists():
            return direct
        return self.root / "files" / re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")

    def read_text(self, path: str) -> str:
        if self.allowlist is not None and not self.allowlist.permits_read(path):
            raise CommandDenied(f"not on the read allowlist: {path}")
        self.requested.append(path)
        resolved = self._file_path(path)
        if not resolved.exists():
            raise FileNotFoundError(f"fixture {self.root.name} has no capture of {path}")
        return resolved.read_text(encoding="utf-8", errors="replace")

    def read_lines(self, path: str) -> list[str]:
        return self.read_text(path).splitlines()


def docker_logs(runner: CommandRunner, container: str) -> list[str]:
    """Full container log, deliberately without ``--since``.

    ``docker logs --since`` has returned silently truncated output on this
    host — ``--since 7d`` yielding a single line from a container with
    thousands.  A monitoring tool that trusts it reports "nothing happened"
    when it means "I could not see", which is the exact failure mode watchdesk
    was built to catch, so it is not used here at any cost in runtime.

    Filter by timestamp in Python instead (see :func:`within_window`).  If you
    are reading this because the full pull looks wasteful: it is, and it stays.
    """
    result = runner.run(["docker", "logs", container])
    if not result.ok:
        return []
    return result.stdout.splitlines()


def within_window(lines: Iterable[str], since_iso: str | None) -> list[str]:
    """Keep json-file lines whose ``time`` field is at or after ``since_iso``.

    String comparison is valid here because Docker writes RFC3339 in UTC with
    a fixed prefix layout, so lexical order is chronological order.
    """
    if since_iso is None:
        return list(lines)
    kept = []
    for line in lines:
        stamp = _json_time(line)
        if stamp is None or stamp >= since_iso:
            kept.append(line)
    return kept


_TIME_FIELD = re.compile(r'"time":"([^"]+)"')


def _json_time(line: str) -> str | None:
    match = _TIME_FIELD.search(line)
    return match.group(1) if match else None
