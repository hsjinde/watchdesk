# fake-stack

Two busybox containers replaying recorded Postfix and Dovecot log lines, so
that a round can be run against a real Docker daemon on a laptop.

```bash
docker compose -f tests/fake-stack/compose.yml up -d
watchdesk --config tests/fake-stack/watchdesk.yaml once --sink stdout
docker compose -f tests/fake-stack/compose.yml down
```

## Why containers rather than log files on disk

Reading the recorded logs straight off disk would be simpler and would test
almost nothing that has actually broken. Every seam between watchdesk and
Docker has produced a bug at some point:

- `docker logs --since` silently truncating on the host this was built for,
- the `json-file` driver writing `<` and `>` as the six-character escapes
  `<` / `>`, which is what fail2ban's regexes actually see,
- the difference between the decoded message and the raw bytes a filter
  matches, which is the whole basis of the cross-check in `sources/fail2ban.py`.

These containers are fake in exactly one way: the lines are recorded rather
than produced by a real Postfix. Everything else — the daemon, the log driver,
the CLI, the `docker exec` path — is real.

## What a round against it produces

The recorded lines are the redacted 2026-07-31 capture, so the incident's shape
comes through the real pipeline:

```
postfix.auth_failures{container=watchdesk-fake-postfix}                              212
postfix.auth_failures_by_service{container=watchdesk-fake-postfix,service=submission/smtpd}  210
postfix.auth_failures_by_service{container=watchdesk-fake-postfix,service=smtpd}       2
postfix.queue_depth{container=watchdesk-fake-postfix}                                  0
dovecot.auth_logging_healthy{container=watchdesk-fake-dovecot}                      True
```

32 signals, no collection errors.

`fail2ban` is deliberately **not** in this config's `sources` list. There are no
jails here, and leaving the source enabled would have it report zeros — a
collector that cannot see anything must not be left looking healthy, which is
the failure this whole project argues against.

## Things that will confuse you if nobody says them

- The containers **re-emit the whole log every 120 seconds**, so a round run at
  any moment finds lines inside its window. Two rounds a minute apart will
  therefore see different totals, and the change rules may report a spike that
  is an artefact of the replay loop rather than of anything in the data. Use
  `--no-state` when you only want to look at one round's signals.
- The timestamps *inside* the messages say July. The ones that matter are the
  ones Docker records on receipt, which are now.
- `mailq`, `postconf` and `doveconf` are three-line shell stubs mounted onto
  the containers' `PATH`. They exist so the `docker exec` path is exercised for
  real; only what they print is invented.
