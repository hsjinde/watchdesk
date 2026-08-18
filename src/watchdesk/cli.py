"""Command line: once, replay, doctor. (serve arrives with stage 4.)"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .collect import run_round
from .config import Config, load_config
from .redact import Redactor
from .sources.base import Signal, SignalKind
from .sources.shell import AllowlistRunner, RecordedRunner

__all__ = ["main"]


def _fixture_context(fixture: Path, config: Config) -> tuple[RecordedRunner, datetime, Config]:
    """Load a recorded incident and pin the clock to when it happened.

    Without this the window would be measured from *now* and every recorded
    line would fall outside it — the replay would come back empty and look
    like a clean bill of health.
    """
    meta_path = fixture / "meta.yaml"
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    as_of = meta.get("as_of")
    now = (
        datetime.fromisoformat(str(as_of).replace("Z", "+00:00"))
        if as_of
        else datetime.now(timezone.utc)
    )
    if meta.get("window_minutes"):
        config = config.model_copy(update={"window_minutes": int(meta["window_minutes"])})
    runner = RecordedRunner(fixture, allowlist=config.shell.to_allowlist())
    return runner, now, config


#: How much of an evidence excerpt the terminal shows. The full text stays on
#: the Signal for the brief to quote; this is only about readability.
_EXCERPT_LINES = 4
_EXCERPT_WIDTH = 200


def _emit(signals: list[Signal], redactor: Redactor | None, as_json: bool) -> None:
    if redactor is not None:
        signals = [signal.redacted(redactor) for signal in signals]

    if as_json:
        print(json.dumps([signal.to_dict() for signal in signals], indent=2, ensure_ascii=False))
        return

    for signal in signals:
        line = f"{signal.kind.value:6}  {signal.key} = {signal.value}"
        if signal.unit:
            line += f" {signal.unit}"
        print(line)
        if signal.note:
            for wrapped in signal.note.splitlines():
                print(f"        {wrapped}")
        for item in signal.evidence:
            print(f"        evidence[{item.kind}] {item.ref}")
            excerpt = item.excerpt.splitlines() or [""]
            for text in excerpt[:_EXCERPT_LINES]:
                print(f"          {text[:_EXCERPT_WIDTH]}")
            if len(excerpt) > _EXCERPT_LINES:
                print(f"          ... {len(excerpt) - _EXCERPT_LINES} more line(s)")


def _cmd_once(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.window:
        config = config.model_copy(update={"window_minutes": args.window})

    if args.fixture:
        runner, now, config = _fixture_context(Path(args.fixture), config)
    else:
        runner = AllowlistRunner(config.shell.to_allowlist(), timeout_s=config.shell.timeout_s)
        now = datetime.now(timezone.utc)

    result = run_round(config, runner=runner, now=now)

    # --raw is for local debugging on the host that owns the data. Every path
    # that leaves this machine redacts; this one does not leave.
    redactor = None if args.raw else Redactor(config.redaction_policy())
    _emit(result.signals, redactor, args.json)

    errors = [s for s in result.signals if s.kind is SignalKind.ERROR]
    summary = f"\n{len(result.signals)} signals, {len(errors)} collection errors"
    if result.failed_sources:
        summary += ", sources crashed: " + ", ".join(result.failed_sources)
    print(summary, file=sys.stderr)
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    args.fixture = args.fixture_dir
    return _cmd_once(args)


def _cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    allowlist = config.shell.to_allowlist()
    print("Command allowlist — everything watchdesk may run, in full:\n")
    for entry in allowlist.describe():
        print(f"  {entry}")
    print(
        "\nNote: 'exec <container>' entries run through `docker exec`. That is a"
        "\nread-only *choice*, not a read-only capability — see the README."
    )
    if args.live:
        print("\n--live checks are added in stage 3 (LLM endpoint smoke test).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchdesk", description=__doc__)
    parser.add_argument("--config", help="path to watchdesk.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    once = sub.add_parser("once", help="collect one round of signals")
    once.add_argument("--fixture", help="replay a recorded fixture directory instead of this host")
    once.add_argument("--window", type=int, help="window in minutes (default from config)")
    once.add_argument("--json", action="store_true", help="emit structured JSON")
    once.add_argument(
        "--raw",
        action="store_true",
        help="skip redaction (local debugging only; output must not leave this host)",
    )
    once.add_argument("--dry-run", action="store_true", help="collect only; never notify")
    once.add_argument("--sink", default="stdout", choices=["stdout"], help="where to send output")
    once.set_defaults(func=_cmd_once)

    replay = sub.add_parser("replay", help="run a recorded incident fixture")
    replay.add_argument("fixture_dir", help="fixture directory")
    replay.add_argument("--window", type=int)
    replay.add_argument("--json", action="store_true")
    replay.add_argument("--raw", action="store_true")
    replay.add_argument("--dry-run", action="store_true", default=True)
    replay.add_argument("--sink", default="stdout", choices=["stdout"])
    replay.set_defaults(func=_cmd_replay)

    doctor = sub.add_parser("doctor", help="show what watchdesk is allowed to do")
    doctor.add_argument("--live", action="store_true", help="also probe live endpoints")
    doctor.set_defaults(func=_cmd_doctor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
