"""Command line: once, replay, doctor. (serve arrives with stage 4.)"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .collect import Round, run_round
from .config import Config, load_config
from .correlate import correlate
from .detect.rules import Finding, evaluate
from .detect.state import StateStore
from .redact import Redactor
from .sources.base import Signal, SignalKind
from .sources.shell import AllowlistRunner, RecordedRunner

__all__ = ["main"]

#: How much of an evidence excerpt the terminal shows. The full text stays on
#: the Signal for the brief to quote; this is only about readability.
_EXCERPT_LINES = 3
_EXCERPT_WIDTH = 200


def _fixture_meta(fixture: Path) -> dict:
    meta_path = fixture / "meta.yaml"
    return yaml.safe_load(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}


def _fixture_context(fixture: Path, config: Config) -> tuple[RecordedRunner, datetime, Config]:
    """Load a recorded incident and pin the clock to when it happened.

    Without this the window would be measured from *now* and every recorded
    line would fall outside it — the replay would come back empty and look
    like a clean bill of health.
    """
    meta = _fixture_meta(fixture)
    as_of = meta.get("as_of")
    now = (
        datetime.fromisoformat(str(as_of).replace("Z", "+00:00")).astimezone(timezone.utc)
        if as_of
        else datetime.now(timezone.utc)
    )
    if meta.get("window_minutes"):
        config = config.model_copy(update={"window_minutes": int(meta["window_minutes"])})
    runner = RecordedRunner(fixture, allowlist=config.shell.to_allowlist())
    return runner, now, config


def _print_signals(signals: list[Signal]) -> None:
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


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("no findings: every rule evaluated and none fired")
        return
    for finding in findings:
        print(f"\n[{str(finding.severity).upper()}] {finding.title}")
        print(f"  rule: {finding.rule}  confidence: {finding.confidence.value}")
        for line in finding.detail.splitlines():
            print(f"  {line}")
        if finding.baseline:
            print(f"  baseline: {finding.baseline}")
        for item in finding.correlations:
            print(f"  correlation: {item}")
        for item in finding.evidence[:2]:
            print(f"  evidence[{item.kind}] {item.ref}")
            for text in (item.excerpt.splitlines() or [""])[:_EXCERPT_LINES]:
                print(f"    {text[:_EXCERPT_WIDTH]}")


def _analyse(
    config: Config,
    result: Round,
    store: StateStore | None,
    now: datetime,
    label: str,
) -> list[Finding]:
    findings = evaluate(config, result.signals, store, now)
    findings = correlate(config, findings, result.signals, store, now)
    if store is not None:
        # Recorded *after* evaluation, so that a rule comparing against "the
        # previous round" is not handed this round as its own baseline.
        store.record(result, label=label)
    return findings


def _open_store(config: Config, args: argparse.Namespace) -> StateStore | None:
    if getattr(args, "no_state", False):
        return None
    path = getattr(args, "state_db", None) or config.state_db
    return StateStore(path)


def _report(
    config: Config,
    result: Round,
    findings: list[Finding],
    args: argparse.Namespace,
) -> None:
    # --raw is for local debugging on the host that owns the data. Every path
    # that leaves this machine redacts; this one does not leave.
    redactor = None if args.raw else Redactor(config.redaction_policy())
    signals = result.signals
    if redactor is not None:
        signals = [signal.redacted(redactor) for signal in signals]
        findings = [finding.redacted(redactor) for finding in findings]

    if args.json:
        print(
            json.dumps(
                {
                    "findings": [finding.to_dict() for finding in findings],
                    "signals": [signal.to_dict() for signal in signals],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    _print_findings(findings)
    if args.signals:
        print()
        _print_signals(signals)

    errors = [signal for signal in result.signals if signal.kind is SignalKind.ERROR]
    # stdout is block-buffered when piped while stderr is not, so without this
    # the summary overtakes the report it summarises.
    sys.stdout.flush()
    summary = (
        f"\n{len(result.signals)} signals, {len(findings)} findings, "
        f"{len(errors)} collection errors"
    )
    if result.failed_sources:
        summary += ", sources crashed: " + ", ".join(result.failed_sources)
    print(summary, file=sys.stderr)


def _cmd_once(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.window:
        config = config.model_copy(update={"window_minutes": args.window})

    if args.fixture:
        runner, now, config = _fixture_context(Path(args.fixture), config)
        label = Path(args.fixture).name
    else:
        runner = AllowlistRunner(config.shell.to_allowlist(), timeout_s=config.shell.timeout_s)
        now = datetime.now(timezone.utc)
        label = "live"

    store = _open_store(config, args)
    try:
        result = run_round(config, runner=runner, now=now)
        findings = _analyse(config, result, store, now, label)
        _report(config, result, findings, args)
    finally:
        if store is not None:
            store.close()
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    """Replay one or more fixtures in chronological order through one history.

    More than one fixture is the interesting case: change detection has
    nothing to say about a single snapshot, which is the whole argument for
    keeping history in the first place.
    """
    config = load_config(args.config)
    fixtures = sorted(
        (Path(path) for path in args.fixture_dir),
        key=lambda path: str(_fixture_meta(path).get("as_of", path.name)),
    )
    # Replays default to an in-memory history so that running the acceptance
    # test never writes to, or reads from, the operator's real state file.
    store = StateStore(args.state_db or ":memory:") if not args.no_state else None
    try:
        for index, fixture in enumerate(fixtures):
            runner, now, round_config = _fixture_context(fixture, config)
            result = run_round(round_config, runner=runner, now=now)
            findings = _analyse(round_config, result, store, now, fixture.name)
            if len(fixtures) > 1:
                print(f"\n{'=' * 72}\n== {fixture.name}  (as of {now.isoformat()})\n{'=' * 72}")
            if index < len(fixtures) - 1 and not args.all_rounds:
                # Earlier rounds exist to build the baseline; printing every
                # one buries the round the reader actually asked about.
                print(f"   {len(result.signals)} signals recorded as baseline")
                continue
            _report(round_config, result, findings, args)
    finally:
        if store is not None:
            store.close()
    return 0


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
    store_path = config.state_db_path()
    print(f"\nstate history: {store_path}")
    if store_path.exists():
        with StateStore(store_path) as store:
            print(f"  {store.round_count()} round(s) recorded")
    else:
        print("  not created yet — the first round will create it")
    if args.live:
        print("\n--live checks are added in stage 3 (LLM endpoint smoke test).")
    return 0


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--window", type=int, help="window in minutes (default from config)")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    parser.add_argument("--signals", action="store_true", help="also print every signal")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="skip redaction (local debugging only; output must not leave this host)",
    )
    parser.add_argument("--state-db", help="path to the history database")
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="do not read or write history; threshold rules only",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchdesk", description=__doc__)
    parser.add_argument("--config", help="path to watchdesk.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    once = sub.add_parser("once", help="collect one round and evaluate the rules")
    once.add_argument("--fixture", help="replay a recorded fixture directory instead of this host")
    once.add_argument("--dry-run", action="store_true", help="collect only; never notify")
    once.add_argument("--sink", default="stdout", choices=["stdout"], help="where to send output")
    _add_common(once)
    once.set_defaults(func=_cmd_once)

    replay = sub.add_parser("replay", help="run recorded fixtures in chronological order")
    replay.add_argument("fixture_dir", nargs="+", help="fixture directories")
    replay.add_argument(
        "--all-rounds",
        action="store_true",
        help="report every round, not only the last",
    )
    replay.add_argument("--dry-run", action="store_true", default=True)
    replay.add_argument("--sink", default="stdout", choices=["stdout"])
    _add_common(replay)
    replay.set_defaults(func=_cmd_replay)

    doctor = sub.add_parser("doctor", help="show what watchdesk is allowed to do")
    doctor.add_argument("--live", action="store_true", help="also probe live endpoints")
    doctor.set_defaults(func=_cmd_doctor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
