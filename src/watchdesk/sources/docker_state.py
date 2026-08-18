"""Container state: is it up, has it restarted, was it killed.

Small on purpose.  This exists mainly so ``correlate.py`` has a timeline of
recent changes to test an anomaly against — "the failure rate changed" is a
different finding from "the failure rate changed forty seconds after this
container restarted".

Only narrow ``--format`` templates are used rather than a full
``docker inspect``: the full output is ten kilobytes of JSON per container,
most of it environment variables and mounts that nobody reads and that would
be a redaction liability in every stored round.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from ..config import Config
from .base import Evidence, Signal, SignalKind, SourceContext
from .shell import CommandDenied

__all__ = ["DockerStateSource"]


class DockerStateSource:
    name = "docker_state"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        containers = [
            config.containers.postfix,
            config.containers.dovecot,
            config.containers.opendkim,
            config.containers.django,
            config.containers.certbot,
        ]
        for container in containers:
            yield from self._one(ctx, container)

    def _one(self, ctx: SourceContext, container: str) -> Iterable[Signal]:
        try:
            state_result = ctx.runner.run(
                ["docker", "inspect", "--format", "{{json .State}}", container]
            )
            restarts_result = ctx.runner.run(
                ["docker", "inspect", "--format", "{{.RestartCount}}", container]
            )
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="docker.collection_problem",
                kind=SignalKind.ERROR,
                value=f"cannot inspect {container}: {exc}",
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
            )
            return

        if not state_result.ok:
            yield Signal(
                name="docker.container.present",
                kind=SignalKind.STATE,
                value=False,
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
                note="Container named in the config does not exist on this host.",
            )
            return

        try:
            state = json.loads(state_result.stdout)
        except json.JSONDecodeError as exc:
            yield Signal(
                name="docker.collection_problem",
                kind=SignalKind.ERROR,
                value=f"unparseable state for {container}: {exc}",
                source=self.name,
                labels={"container": container},
                observed_at=ctx.now,
            )
            return

        labels = {"container": container}
        evidence = (
            Evidence(
                kind="command_output",
                ref=f"docker inspect --format {{{{json .State}}}} {container}",
                excerpt=state_result.stdout.strip(),
            ),
        )

        yield Signal(
            name="docker.container.running",
            kind=SignalKind.STATE,
            value=bool(state.get("Running")),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            evidence=evidence,
        )
        yield Signal(
            name="docker.container.started_at",
            kind=SignalKind.STATE,
            value=str(state.get("StartedAt", "")),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            evidence=evidence,
            note="Used by correlate.py as a change to test anomalies against.",
        )
        yield Signal(
            name="docker.container.oom_killed",
            kind=SignalKind.STATE,
            value=bool(state.get("OOMKilled")),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            evidence=evidence,
        )
        if state.get("Health"):
            yield Signal(
                name="docker.container.health",
                kind=SignalKind.STATE,
                value=str(state["Health"].get("Status", "unknown")),
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                evidence=evidence,
            )

        restarts = restarts_result.stdout.strip()
        if restarts_result.ok and restarts.isdigit():
            yield Signal(
                name="docker.container.restart_count",
                kind=SignalKind.METRIC,
                value=int(restarts),
                source=self.name,
                labels=labels,
                observed_at=ctx.now,
                unit="restarts",
                note=(
                    "Cumulative for the container's life. A rule watches this for an "
                    "increase since the previous round, not for its absolute value."
                ),
            )
