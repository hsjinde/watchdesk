"""Command line: once, replay, doctor. (serve arrives with stage 4.)"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .brief import Brief, build_brief
from .collect import Round, run_round
from .config import Config, load_config
from .correlate import correlate
from .detect.rules import Finding, evaluate
from .detect.state import StateStore
from .llm import LLMError, RecordedLLM, build_client
from .redact import Redactor
from .sinks import DiscordSink
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


def _build_brief(
    config: Config,
    result: Round,
    findings: list[Finding],
    args: argparse.Namespace,
    now: datetime,
    redactor: Redactor | None,
) -> Brief | None:
    """Produce the brief, redacting before the model sees anything.

    Findings and signals are redacted *here*, not inside the client, so that
    what the model is asked about is exactly what a reader would see. The
    client redacts again and runs the leak check as a backstop; doing it twice
    is free because the replacements are not shaped like their inputs.
    """
    if args.no_brief:
        return None

    if args.llm_recording:
        client = RecordedLLM(args.llm_recording)
    elif args.no_llm:
        client = None
    else:
        client = build_client(config, redactor or Redactor(config.redaction_policy()))

    safe_findings = findings
    safe_signals = result.signals
    if redactor is not None:
        safe_findings = [finding.redacted(redactor) for finding in findings]
        safe_signals = [signal.redacted(redactor) for signal in result.signals]

    return build_brief(config, safe_findings, safe_signals, now, client=client)


def _report(
    config: Config,
    result: Round,
    findings: list[Finding],
    args: argparse.Namespace,
    brief: Brief | None = None,
) -> None:
    # --raw is for local debugging on the host that owns the data. Every path
    # that leaves this machine redacts; this one does not leave.
    redactor = None if args.raw else Redactor(config.redaction_policy())
    signals = result.signals
    if redactor is not None:
        signals = [signal.redacted(redactor) for signal in signals]
        findings = [finding.redacted(redactor) for finding in findings]

    if args.json:
        payload: dict = {
            "findings": [finding.to_dict() for finding in findings],
            "signals": [signal.to_dict() for signal in signals],
        }
        if brief is not None:
            payload["brief"] = brief.to_dict()
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if brief is not None:
        print(brief.render())
        print()
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
        redactor = None if args.raw else Redactor(config.redaction_policy())
        brief = _build_brief(config, result, findings, args, now, redactor)
        _report(config, result, findings, args, brief)
        _deliver(config, brief, args, store, now, redactor)
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
            redactor = None if args.raw else Redactor(round_config.redaction_policy())
            brief = _build_brief(round_config, result, findings, args, now, redactor)
            _report(round_config, result, findings, args, brief)
    finally:
        if store is not None:
            store.close()
    return 0


def _deliver(
    config: Config,
    brief: Brief | None,
    args: argparse.Namespace,
    store: StateStore | None,
    now: datetime,
    redactor: Redactor | None,
) -> None:
    """Push the brief to the configured sink, unless asked not to.

    --dry-run is honoured here and nowhere else: collection and analysis have
    no side effects to suppress, and the only thing worth being able to switch
    off is the part that talks to somebody.
    """
    if brief is None or args.sink == "stdout" or args.dry_run:
        return
    if args.sink != "discord":
        return
    sink = DiscordSink(
        webhook_url=config.env.discord_webhook_url,
        redactor=redactor or Redactor(config.redaction_policy()),
        config=config,
        store=store,
        now=now,
    )
    result = sink.deliver(brief)
    print(f"discord: {'sent' if result.sent else 'not sent'} — {result.reason}", file=sys.stderr)
    if result.detail:
        print(f"         {result.detail}", file=sys.stderr)


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run rounds on an interval in the foreground.

    The systemd timer in deploy/ is the recommended way to run this — it
    survives a crash, logs to the journal, and does not hold a process open
    between rounds. This exists for running it by hand and watching it work.
    """
    config = load_config(args.config)
    interval = (args.interval or config.interval_minutes) * 60
    print(f"watchdesk serve: every {interval // 60} minute(s), Ctrl-C to stop", file=sys.stderr)
    while True:
        started = time.monotonic()
        try:
            _cmd_once(args)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:  # noqa: BLE001 - a bad round must not end the service
            print(f"round failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        try:
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
        except KeyboardInterrupt:
            return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    """Write one Alertmanager webhook body into the spool.

    This is the whole of watchdesk's inbound path, and it deliberately does not
    speak HTTP. Point Alertmanager at whatever already terminates TLS on this
    host and have it pipe the body here; watchdesk stays a thing that reads,
    not a thing that listens.
    """
    from .sources.alertmanager import parse_payload

    config = load_config(args.config)
    if args.payload == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(args.payload).read_text(encoding="utf-8")

    cap = config.alertmanager.max_payload_bytes
    if len(raw.encode("utf-8")) > cap:
        print(f"refused: payload is over the {cap}-byte cap", file=sys.stderr)
        return 1
    try:
        payload = parse_payload(raw)
    except ValueError as exc:
        # Rejected at the door rather than spooled and puzzled over later.
        print(f"refused: {exc}", file=sys.stderr)
        return 1

    spool = Path(args.spool or config.alertmanager.spool_dir).expanduser()
    spool.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    target = spool / f"{stamp}-{payload.receiver or 'alerts'}.json"
    target.write_text(raw, encoding="utf-8")
    print(f"spooled {len(payload.alerts)} alert(s) to {target}", file=sys.stderr)
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
    if not args.live:
        print("\nRun with --live to smoke-test the LLM endpoint.")
        return 0

    print("\nLLM endpoint smoke test")
    env = config.env
    print(f"  url:   {env.llm_base_url or '(unset)'}")
    print(f"  model: {env.llm_model or '(unset)'}")
    print(f"  key:   {'set' if env.llm_api_key else 'NOT SET'}")
    client = build_client(config, Redactor(config.redaction_policy()))
    if client is None:
        print("  result: not configured — set LLM_BASE_URL and LLM_MODEL")
        return 1
    try:
        # Fixed text with nothing from this host in it: a reachability check
        # should not be the thing that ships a log line somewhere.
        response = client.complete(
            "Reply with a JSON object and nothing else.",
            '{"task": "reply with exactly {\"ok\": true}"}',
        )
    except LLMError as exc:
        print(f"  result: FAILED — {exc}")
        return 1
    print(f"  result: ok in {response.latency_s:.2f}s, model reported as {response.model}")
    print(f"  usage:  {response.usage or '(not reported)'}")
    print(f"  body:   {response.text.strip()[:200]}")
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
    parser.add_argument("--no-brief", action="store_true", help="findings only, no brief")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="build the brief from the rules alone, without calling a model",
    )
    parser.add_argument(
        "--llm-recording",
        help="replay recorded completions from a JSON file instead of calling a model",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchdesk", description=__doc__)
    parser.add_argument("--config", help="path to watchdesk.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    once = sub.add_parser("once", help="collect one round and evaluate the rules")
    once.add_argument("--fixture", help="replay a recorded fixture directory instead of this host")
    once.add_argument("--dry-run", action="store_true", help="collect only; never notify")
    once.add_argument(
        "--sink", default="stdout", choices=["stdout", "discord"], help="where to send the brief"
    )
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
    replay.add_argument("--sink", default="stdout", choices=["stdout", "discord"])
    _add_common(replay)
    replay.set_defaults(func=_cmd_replay)

    serve = sub.add_parser("serve", help="run rounds on an interval in the foreground")
    serve.add_argument("--interval", type=int, help="minutes between rounds")
    serve.add_argument("--fixture")
    serve.add_argument("--dry-run", action="store_true")
    serve.add_argument(
        "--sink", default="stdout", choices=["stdout", "discord"], help="where to send the brief"
    )
    _add_common(serve)
    serve.set_defaults(func=_cmd_serve)

    ingest = sub.add_parser("ingest", help="spool an Alertmanager webhook body")
    ingest.add_argument("payload", help="path to a JSON body, or - for stdin")
    ingest.add_argument("--spool", help="spool directory (default from config)")
    ingest.set_defaults(func=_cmd_ingest)

    doctor = sub.add_parser("doctor", help="show what watchdesk is allowed to do")
    doctor.add_argument("--live", action="store_true", help="also probe live endpoints")
    doctor.set_defaults(func=_cmd_doctor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
