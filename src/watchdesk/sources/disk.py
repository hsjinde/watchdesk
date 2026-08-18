"""Disk and inode headroom.

The interesting number is not how full the disk is — it is how fast it is
filling.  95% that has been 95% for six months is a fact about the machine;
95% that was 91% an hour ago is four hours from an outage, and only the second
one is worth being woken for.  That distinction needs history, which is why
this source reports free *bytes* alongside the percentage: a percentage cannot
be differentiated into a rate that means anything.

Inodes get their own signals because they run out independently and produce a
disk-full error on a disk with free space, which is a genuinely confusing
half-hour if nobody thought to look.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..config import Config
from .base import Evidence, Signal, SignalKind, SourceContext
from .shell import CommandDenied

__all__ = ["DiskSource", "parse_df"]


def parse_df(output: str) -> list[dict[str, str]]:
    """Parse POSIX ``df -P`` output.

    ``-P`` is not decoration: without it a long device name wraps onto its own
    line and every field shifts, which is the sort of thing that works on the
    machine you wrote it on and silently mis-parses somewhere else.
    """
    rows: list[dict[str, str]] = []
    lines = output.strip().splitlines()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        rows.append(
            {
                "filesystem": fields[0],
                "total": fields[1],
                "used": fields[2],
                "available": fields[3],
                "capacity": fields[4].rstrip("%"),
                "mount": " ".join(fields[5:]),
            }
        )
    return rows


class DiskSource:
    name = "disk"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        yield from self._report(ctx, ["df", "-P", "-k"], "space", config)
        yield from self._report(ctx, ["df", "-P", "-i"], "inodes", config)

    def _report(
        self, ctx: SourceContext, argv: list[str], kind: str, config: Config
    ) -> Iterable[Signal]:
        try:
            result = ctx.runner.run(argv)
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="disk.collection_problem",
                kind=SignalKind.ERROR,
                value=f"{' '.join(argv)}: {exc}",
                source=self.name,
                observed_at=ctx.now,
            )
            return
        if not result.ok:
            yield Signal(
                name="disk.collection_problem",
                kind=SignalKind.ERROR,
                value=f"{' '.join(argv)} exited {result.returncode}",
                source=self.name,
                observed_at=ctx.now,
            )
            return

        for row in parse_df(result.stdout):
            if row["filesystem"] in config.disk.ignore_filesystems:
                continue
            labels = {"mount": row["mount"]}
            evidence = (
                Evidence(
                    kind="command_output",
                    ref=" ".join(argv),
                    excerpt=f"{row['filesystem']} {row['used']}/{row['total']} "
                    f"({row['capacity']}%) on {row['mount']}",
                ),
            )
            try:
                capacity = int(row["capacity"])
                available = int(row["available"])
            except ValueError:
                continue

            if kind == "space":
                yield Signal(
                    name="disk.used_percent",
                    kind=SignalKind.METRIC,
                    value=capacity,
                    source=self.name,
                    labels=labels,
                    observed_at=ctx.now,
                    unit="percent",
                    evidence=evidence,
                )
                yield Signal(
                    name="disk.available_kb",
                    kind=SignalKind.METRIC,
                    value=available,
                    source=self.name,
                    labels=labels,
                    observed_at=ctx.now,
                    unit="KiB",
                    note=(
                        "Reported alongside the percentage because a percentage cannot be "
                        "differentiated into a fill rate that means anything."
                    ),
                )
            else:
                yield Signal(
                    name="disk.inodes_used_percent",
                    kind=SignalKind.METRIC,
                    value=capacity,
                    source=self.name,
                    labels=labels,
                    observed_at=ctx.now,
                    unit="percent",
                    evidence=evidence,
                    note=(
                        "Inodes run out independently of space, and produce a disk-full error "
                        "on a filesystem with room left."
                    ),
                )
