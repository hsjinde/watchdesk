"""Loading a recorded capture.

A fixture declares which sources it can answer for.  Without that, adding a
source to the default list breaks every replay — not because the capture is
wrong, but because a collector with no recording starts reporting errors about
data that was never in scope for it.  Worse, if it reported *zeros* instead,
the replay would look healthier than the incident it contains.

Shared by the CLI and the tests so there is one definition of "run this
capture", rather than a copy in each that can drift.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import Config
from .sources.shell import RecordedRunner

__all__ = ["FixtureRun", "load_meta", "open_fixture"]


class FixtureRun:
    def __init__(self, runner: RecordedRunner, now: datetime, config: Config, meta: dict[str, Any]):
        self.runner = runner
        self.now = now
        self.config = config
        self.meta = meta

    def __iter__(self):
        return iter((self.runner, self.now, self.config))


def load_meta(fixture: str | Path) -> dict[str, Any]:
    path = Path(fixture) / "meta.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def open_fixture(fixture: str | Path, config: Config) -> FixtureRun:
    """Pin the clock to when the capture happened and scope it to its sources.

    Pinning matters more than it looks: measured from *now*, the window would
    exclude every recorded line and the replay would come back empty — which
    reads as a clean bill of health for an incident.
    """
    fixture = Path(fixture)
    meta = load_meta(fixture)

    as_of = meta.get("as_of")
    now = (
        datetime.fromisoformat(str(as_of).replace("Z", "+00:00")).astimezone(timezone.utc)
        if as_of
        else datetime.now(timezone.utc)
    )

    updates: dict[str, Any] = {}
    if meta.get("window_minutes"):
        updates["window_minutes"] = int(meta["window_minutes"])
    if meta.get("sources"):
        updates["sources"] = list(meta["sources"])
    if updates:
        config = config.model_copy(update=updates)

    return FixtureRun(
        RecordedRunner(fixture, allowlist=config.shell.to_allowlist()), now, config, meta
    )
