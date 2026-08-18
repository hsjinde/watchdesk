"""Disk and certificate sources, and the thresholds behind them.

Both of these are easy to write as a percentage compared against a round
number, and both are much more useful when the threshold is tied to how the
underlying thing actually behaves. That reasoning is what these tests pin
down.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from watchdesk.collect import Round
from watchdesk.config import load_config
from watchdesk.detect.rules import Severity, evaluate
from watchdesk.detect.state import StateStore
from watchdesk.sources.base import Signal, SignalKind, SourceContext
from watchdesk.sources.disk import DiskSource, parse_df
from watchdesk.sources.shell import CommandResult
from watchdesk.sources.tls_cert import TlsCertSource, parse_openssl

NOW = datetime(2026, 8, 18, 16, 0, tzinfo=timezone.utc)

DF_K = """\
Filesystem     1024-blocks     Used Available Capacity Mounted on
tmpfs                98032     1852     96180       2% /run
/dev/vda2         16428244 15052776    621024      97% /
"""

DF_I = """\
Filesystem      Inodes  IUsed  IFree IUse% Mounted on
/dev/vda2      1048576 362276 686300   35% /
"""

CERT = "notAfter=Sep 22 04:23:59 2026 GMT\nsubject=CN = mail.example.com\n"


class Runner:
    def __init__(self, **outputs):
        self.outputs = outputs

    def run(self, argv, container=None):
        if argv[:2] == ["df", "-P"]:
            key = "inodes" if "-i" in argv else "space"
            return CommandResult(tuple(argv), 0, self.outputs.get(key, ""), "")
        if argv[0] == "openssl":
            return CommandResult(
                tuple(argv), self.outputs.get("rc", 0), self.outputs.get("cert", ""), ""
            )
        return CommandResult(tuple(argv), 1, "", "")

    def read_text(self, path):
        raise FileNotFoundError(path)

    def read_lines(self, path):
        raise FileNotFoundError(path)


@pytest.fixture
def config():
    return load_config()


def ctx(config, runner, now=NOW):
    return SourceContext(runner=runner, config=config, now=now)


# --------------------------------------------------------------------------
# Disk
# --------------------------------------------------------------------------


def test_df_parsing_keeps_mount_points_with_spaces() -> None:
    rows = parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                    "/dev/sda1 100 50 50 50% /mnt/my backup\n")
    assert rows[0]["mount"] == "/mnt/my backup"


def test_pseudo_filesystems_are_skipped(config) -> None:
    produced = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
    assert {s.labels.get("mount") for s in produced} == {"/"}


def test_free_bytes_are_reported_next_to_the_percentage(config) -> None:
    """A percentage cannot be differentiated into a fill rate that means
    anything, which is the whole basis of the projection rule."""
    produced = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
    assert any(s.name == "disk.available_kb" and s.value == 621024 for s in produced)
    assert any(s.name == "disk.used_percent" and s.value == 97 for s in produced)
    assert any(s.name == "disk.inodes_used_percent" and s.value == 35 for s in produced)


def test_a_full_disk_is_critical(config) -> None:
    signals = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
    findings = [f for f in evaluate(config, signals, None, NOW) if f.rule == "disk.space_low"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_inode_exhaustion_is_reported_separately(config) -> None:
    """Inodes run out independently and produce a disk-full error on a
    filesystem with space left."""
    inodes = DF_I.replace("362276 686300   35%", "1040000   8576   99%")
    signals = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=inodes))))
    findings = [f for f in evaluate(config, signals, None, NOW) if f.rule == "disk.inodes_low"]
    assert len(findings) == 1


def test_a_disk_that_is_merely_full_produces_no_projection(config, tmp_path) -> None:
    """95% that has been 95% for six months is a fact about the machine."""
    with StateStore(tmp_path / "s.sqlite3") as store:
        earlier = Signal(
            name="disk.available_kb",
            kind=SignalKind.METRIC,
            value=621024,
            source="disk",
            labels={"mount": "/"},
            observed_at=NOW - timedelta(hours=6),
            unit="KiB",
        )
        store.record(Round(started_at=NOW - timedelta(hours=6), signals=[earlier]))
        signals = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
        assert not [f for f in evaluate(config, signals, store, NOW) if f.rule == "disk.filling"]


def test_a_disk_that_is_filling_is_projected(config, tmp_path) -> None:
    with StateStore(tmp_path / "s.sqlite3") as store:
        earlier = Signal(
            name="disk.available_kb",
            kind=SignalKind.METRIC,
            value=1_221_024,  # 600 MB more free, six hours ago
            source="disk",
            labels={"mount": "/"},
            observed_at=NOW - timedelta(hours=6),
            unit="KiB",
        )
        store.record(Round(started_at=NOW - timedelta(hours=6), signals=[earlier]))
        signals = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
        findings = [f for f in evaluate(config, signals, store, NOW) if f.rule == "disk.filling"]
        assert len(findings) == 1
        assert "h of space left" in findings[0].title
        assert "order of magnitude, not a deadline" in findings[0].detail


def test_two_samples_minutes_apart_do_not_extrapolate(config, tmp_path) -> None:
    """A log rotation inside a short gap can imply the disk fills before lunch."""
    with StateStore(tmp_path / "s.sqlite3") as store:
        earlier = Signal(
            name="disk.available_kb",
            kind=SignalKind.METRIC,
            value=1_221_024,
            source="disk",
            labels={"mount": "/"},
            observed_at=NOW - timedelta(minutes=2),
            unit="KiB",
        )
        store.record(Round(started_at=NOW - timedelta(minutes=2), signals=[earlier]))
        signals = list(DiskSource().collect(ctx(config, Runner(space=DF_K, inodes=DF_I))))
        assert not [f for f in evaluate(config, signals, store, NOW) if f.rule == "disk.filling"]


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------


def test_openssl_output_is_parsed() -> None:
    not_after, subject = parse_openssl(CERT)
    assert not_after == datetime(2026, 9, 22, 4, 23, 59, tzinfo=timezone.utc)
    assert subject == "CN = mail.example.com"


def tls_config(config, days_paths=("/tmp/cert.pem",)):
    return config.model_copy(
        update={"tls": config.tls.model_copy(update={"cert_paths": list(days_paths)})}
    )


def test_thirty_days_left_is_not_news(config) -> None:
    """It is the renewal window opening. Alerting on it teaches the reader that
    this signal is noise, and then the one at five days is ignored too."""
    conf = tls_config(config)
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)  # 30 days before notAfter
    signals = list(TlsCertSource().collect(ctx(conf, Runner(cert=CERT), now)))
    assert not [f for f in evaluate(conf, signals, None, now) if f.rule == "tls.expiring"]


def test_below_three_weeks_means_a_renewal_already_failed(config) -> None:
    conf = tls_config(config)
    now = datetime(2026, 9, 5, tzinfo=timezone.utc)  # ~17 days left
    signals = list(TlsCertSource().collect(ctx(conf, Runner(cert=CERT), now)))
    findings = [f for f in evaluate(conf, signals, None, now) if f.rule == "tls.expiring"]
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARNING
    assert "renewal timer" in findings[0].detail


def test_a_week_left_is_critical(config) -> None:
    conf = tls_config(config)
    now = datetime(2026, 9, 18, tzinfo=timezone.utc)
    signals = list(TlsCertSource().collect(ctx(conf, Runner(cert=CERT), now)))
    findings = [f for f in evaluate(conf, signals, None, now) if f.rule == "tls.expiring"]
    assert findings[0].severity is Severity.CRITICAL


def test_an_unreadable_certificate_is_an_error_not_a_pass(config) -> None:
    """Renewal writes a new file. A missing one afterwards is exactly the
    failure this source exists to notice."""
    conf = tls_config(config)
    signals = list(TlsCertSource().collect(ctx(conf, Runner(cert="", rc=1))))
    assert [s.kind for s in signals] == [SignalKind.ERROR]


def test_no_configured_certificates_means_no_signals(config) -> None:
    """Guessing paths produces either false alarms or a source that silently
    checks nothing."""
    assert list(TlsCertSource().collect(ctx(config, Runner()))) == []


def test_the_expiry_date_is_tracked_so_renewal_is_visible(config) -> None:
    """A change in not_after between rounds is the only positive confirmation
    certbot gives from outside."""
    conf = tls_config(config)
    signals = list(TlsCertSource().collect(ctx(conf, Runner(cert=CERT))))
    assert any(s.name == "tls.not_after" for s in signals)
    assert textwrap.dedent("2026-09-22") in next(
        s.value for s in signals if s.name == "tls.not_after"
    )
