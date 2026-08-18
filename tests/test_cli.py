"""The command line, at the edges where it decides not to do something.

The happy paths are covered by the replay tests. What is worth pinning here is
the behaviour when things go wrong: a round that raises must not end a running
service, and the inbound path must refuse input before it reaches the spool.
"""

from __future__ import annotations

import json

import pytest

from watchdesk import cli


def test_a_failing_round_does_not_end_the_service(monkeypatch, capsys) -> None:
    """`serve` runs unattended. A source that throws on one round is a bad
    round, not a reason for the machine to stop being watched — and a service
    that exits quietly is indistinguishable from one with nothing to report.
    """
    calls = {"n": 0}

    def flaky(args):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("collection exploded")
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_cmd_once", flaky)
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)

    assert cli.main(["serve", "--interval", "1", "--no-state", "--no-brief"]) == 0
    assert calls["n"] == 2
    assert "collection exploded" in capsys.readouterr().err


def test_serve_stops_cleanly_on_interrupt(monkeypatch) -> None:
    def interrupted(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_cmd_once", interrupted)
    assert cli.main(["serve", "--no-state"]) == 0


# --------------------------------------------------------------------------
# ingest
# --------------------------------------------------------------------------


def test_a_malformed_body_is_refused_at_the_door(tmp_path, capsys) -> None:
    """Rejected before it is spooled, rather than spooled and puzzled over on
    some later round."""
    body = tmp_path / "bad.json"
    body.write_text("{ not json", encoding="utf-8")
    spool = tmp_path / "spool"

    assert cli.main(["ingest", str(body), "--spool", str(spool)]) == 1
    assert "refused" in capsys.readouterr().err
    assert not spool.exists()


def test_a_valid_body_is_spooled(tmp_path) -> None:
    body = tmp_path / "ok.json"
    body.write_text(
        json.dumps({"version": "4", "receiver": "watchdesk", "alerts": []}), encoding="utf-8"
    )
    spool = tmp_path / "spool"

    assert cli.main(["ingest", str(body), "--spool", str(spool)]) == 0
    assert len(list(spool.glob("*.json"))) == 1


def test_an_oversized_body_is_refused_unread(tmp_path, capsys, monkeypatch) -> None:
    body = tmp_path / "huge.json"
    body.write_text("x" * 400_000, encoding="utf-8")
    spool = tmp_path / "spool"

    assert cli.main(["ingest", str(body), "--spool", str(spool)]) == 1
    assert "over the" in capsys.readouterr().err
    assert not spool.exists()


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


def test_doctor_prints_the_whole_allowlist(capsys) -> None:
    """An allowlist nobody can read is not a control. `doctor` is how it gets
    read without opening the config."""
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "fail2ban-client status" in out
    assert "exec postfix: mailq" in out
    # And the honesty note that the README makes at length.
    assert "read-only *choice*, not a read-only capability" in out


def test_doctor_reports_the_history_database(capsys) -> None:
    assert cli.main(["doctor"]) == 0
    assert "state history:" in capsys.readouterr().out


def test_an_unknown_source_in_config_is_refused(tmp_path) -> None:
    """A typo that silently disables a collector would produce a round that
    looks healthy because nobody looked."""
    config = tmp_path / "c.yaml"
    config.write_text("sources: [fail2ban, typo]\n", encoding="utf-8")
    with pytest.raises(KeyError, match="typo"):
        cli.main(["--config", str(config), "once", "--no-state", "--no-brief", "--no-llm"])
