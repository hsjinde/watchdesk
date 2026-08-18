"""Reading container logs the way fail2ban reads them.

watchdesk reads the ``json-file`` log **file**, not ``docker logs``, whenever
it can resolve the path.  Two reasons, and the second is the important one:

1. ``docker logs --since`` has returned silently truncated output on this
   host, so the convenient API is untrustworthy (see :func:`load`).
2. The jail being audited reads that exact file.  Auditing a counter by
   consulting a *different* view of the same events would leave the most
   likely failure — the two views disagreeing — permanently invisible.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .shell import CommandDenied, CommandRunner

__all__ = ["LogLine", "load", "container_log_path", "parse_json_line", "since_iso"]

_TIME_FIELD = re.compile(r'"time":"([^"]+)"')


@dataclass(frozen=True)
class LogLine:
    """One entry, kept in both forms.

    ``raw`` is the JSON as written to disk — the bytes fail2ban's failregex is
    applied to, complete with ``\\u003c`` escapes.  ``message`` is the decoded
    payload, which is what a human (and watchdesk's own matchers) should read.

    Keeping both is not redundancy.  The August incident was a disagreement
    between what the log said and what the filter matched, and you cannot
    measure that disagreement from one representation.
    """

    raw: str
    message: str
    timestamp: str
    line_no: int

    @property
    def moment(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None


def parse_json_line(line: str, line_no: int = 0) -> LogLine | None:
    """Decode one json-file line, tolerating a truncated tail.

    A container writing at the moment of the read leaves a partial final line;
    dropping it is correct, but dropping it *silently* is how a collector
    starts under-reporting, so callers get ``None`` and can count it.
    """
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    message = payload.get("log")
    if not isinstance(message, str):
        return None
    return LogLine(
        raw=line,
        message=message.rstrip("\n"),
        timestamp=str(payload.get("time", "")),
        line_no=line_no,
    )


def container_log_path(runner: CommandRunner, container: str) -> str | None:
    """Ask Docker where the container's json log lives."""
    try:
        result = runner.run(["docker", "inspect", "--format", "{{.LogPath}}", container])
    except (CommandDenied, FileNotFoundError):
        return None
    path = result.stdout.strip()
    return path if result.ok and path else None


def since_iso(now: datetime, window_minutes: int) -> str:
    """RFC3339 cut-off matching the format Docker writes.

    Compared as a string: Docker always writes UTC with a fixed layout, so
    lexical order is chronological order and no per-line parse is needed for
    the common case of "is this line inside the window".
    """
    cutoff = now.astimezone(timezone.utc) - timedelta(minutes=window_minutes)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")


def load(
    runner: CommandRunner,
    container: str,
    *,
    since: str | None = None,
    path: str | None = None,
) -> tuple[list[LogLine], list[str]]:
    """Return ``(lines, problems)`` for one container's log.

    ``docker logs --since`` is never used, at any cost in runtime.  On this
    host it has returned a single line for a window containing thousands —
    silently, with exit status 0.  A monitoring tool that trusts it reports
    "nothing happened" when it means "I could not see", which is precisely the
    class of failure watchdesk exists to catch; shipping that bug inside the
    detector would be self-defeating.

    So the full log is pulled and filtered here, in Python, by timestamp.  If
    this looks wasteful in a profile: it is, and it stays. Do not "optimise"
    it back to --since.
    """
    problems: list[str] = []
    resolved = path or container_log_path(runner, container)

    text: str | None = None
    if resolved:
        try:
            text = runner.read_text(resolved)
        except (CommandDenied, FileNotFoundError, OSError) as exc:
            problems.append(f"could not read {resolved}: {exc}")

    if text is None:
        try:
            # Fallback only. Note the absence of --since.
            result = runner.run(["docker", "logs", container])
        except (CommandDenied, FileNotFoundError) as exc:
            problems.append(f"could not read the log of container {container}: {exc}")
            return [], problems
        if not result.ok:
            problems.append(f"docker logs {container} exited {result.returncode}")
            return [], problems
        text = result.stdout

    lines: list[LogLine] = []
    undecodable = 0
    for index, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        if since is not None:
            stamp = _TIME_FIELD.search(raw)
            if stamp and stamp.group(1) < since:
                continue
        parsed = parse_json_line(raw, index)
        if parsed is None:
            undecodable += 1
            continue
        lines.append(parsed)
    if undecodable:
        problems.append(f"{undecodable} log line(s) could not be decoded as json-file entries")
    return lines, problems
