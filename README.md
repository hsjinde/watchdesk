# watchdesk

A read-only on-call assistant for one self-hosted mail server. It runs as a
systemd timer on the host it watches, compares each round against the last
one, and only escalates to an LLM when a rule has already decided something
changed.

It is not a dashboard. Dashboards were the problem.

> **Status: staged build, stage 0 of 5 complete.**
> Stage 0 is the redaction gate and repository skeleton. The collector,
> detection, briefing and sink layers land in stages 1–5; the map below marks
> what exists today. Nothing in this README describes behaviour that is not
> in the tree.

## Why it exists

In August 2026 the `postfix-docker` fail2ban jail on my mail server stopped
counting most of the authentication failures reaching it. The failregex
matched the service field as `postfix/\w+\[`, which fits the port-25 process
name `postfix/smtpd` and nothing else. Postfix names its other listeners
`postfix/submission/smtpd` (587) and `postfix/smtps/smtpd` (465) — the extra
`/` is not `\w`, so every SMTP AUTH failure on those two ports was silently
unmatched.

The attackers had already migrated to 587. Over one week the split was 763
failures on submission and 49 on smtps against 35 on port 25. Two ranges were
averaging seven attempts per IP per day — above `maxretry=5` inside
`findtime=86400` — and were never counted, so never banned.

Every signal a human would normally check said the system was fine:

- `fail2ban-client status` showed three jails, all enabled, all running.
- The ban counters were still incrementing, because port 25 traffic still
  matched.
- The same IPs *had* been banned weeks earlier, when they were still probing
  port 25, so ban history looked healthy.

The gap was only visible by running `fail2ban-regex` against the raw container
log and comparing the match count to what the jail itself reported: 13,135
counted versus 13,972 actually matching. Nothing on any dashboard would ever
have shown that. **A service running is not the same as a service being
watched**, and the difference is only detectable by cross-checking two
independent sources that should agree.

watchdesk automates that cross-check, and the others like it.

## Design principles

1. **Detect change, not state.** Every round is snapshotted to SQLite and
   compared against history. "SASL failures went from 3/hour to 400/hour" is
   actionable; "12,000 failures all-time" is wallpaper — it was true during
   the incident and it was true before it.
2. **Read-only, via a plaintext allowlist keyed on `(container, argv)`** —
   not on command name. See the honesty note below.
3. **The LLM is called only after a rule has already fired.** It costs money
   and it writes prose; neither is useful every five minutes when nothing is
   happening.
4. **Every conclusion carries evidence.** The output schema requires a
   confidence level and evidence pointing at a specific log line or metric
   value. An inference that cannot name its evidence is downgraded to a
   hypothesis or dropped.
5. **Redaction happens before data leaves the machine** — once before the LLM
   call, once before the Discord push.
6. **Every entry in my `known-issues.md` becomes a detector**, not a paragraph
   somebody is supposed to remember.

## Two honesty notes

### "Read-only" is a claim about intent, not about capability

watchdesk never bans an IP, restarts a container, or edits a config, and its
shell layer refuses any `(container, argv)` pair that is not on the allowlist
in the config file. That is a real constraint and you can read the whole list
in one screen.

But `docker exec postfix mailq` is only read-only because `mailq` happens to
read. The `docker exec` capability itself is not restricted, and anyone who
can change the allowlist can run anything in those containers. The allowlist
is a guardrail against watchdesk misbehaving; it is not a sandbox, and it is
not a defence against whoever controls the config file. Treat watchdesk as
software with `docker exec` rights that has chosen not to use them.

### The pseudonyms are reversible if you hold the salt

Attacker addresses become salted pseudonyms — `ip:7f3a2c` — rather than a flat
`<ip>` mask, so a single report still shows which lines share a source. That
correlation is most of the diagnostic value.

This is pseudonymisation, not anonymisation. IPv4 is a 32-bit space; anyone
holding the salt can enumerate it in seconds and invert every `ip:` token in
every report ever published. The salt is the only thing standing there, it is
never committed, and rotating it deliberately breaks correlation with
everything published before. Do not describe the output as irreversible.

## Why it is not containerised

This is a deliberate decision, not a shortcut.

Everything fail2ban-related lives on the host: `fail2ban-client status`, the
jail stanzas in `/etc/fail2ban/jail.local`, and `fail2ban-regex` runs against
`/var/lib/docker/containers/*/*-json.log`. Reproducing that from inside a
container means mounting `/etc/fail2ban`, `/var/lib/docker`, the host PID
namespace and the systemd socket. The Docker side is worse: reaching the
Docker CLI from inside a container means mounting `/var/run/docker.sock`,
which is equivalent to handing out host root.

A tool whose entire pitch is "read-only, never acts" cannot coherently ask for
`docker.sock`. So watchdesk runs as a systemd service on the host, in a venv,
calling `fail2ban-client` and `docker` natively, and mounts no socket at all.
The cost is that it is not portable to a Kubernetes cluster. It was never
meant to be — it watches one machine.

## Architecture

```
src/watchdesk/
  cli.py              once / serve / replay / doctor            [stage 1]
  config.py           pydantic-settings: .env + YAML            [stage 1]
  sources/
    base.py           Signal dataclass + SignalSource protocol  [stage 1]
    shell.py          allowlisted read-only command runner      [stage 1]
    docker_state.py   health, restart counts, OOM kills         [stage 1]
    fail2ban.py       the core; see below                       [stage 1]
    postfix.py        SASL failure rate, queue depth, sent rate [stage 1]
    dovecot.py        login activity + log_path/auth_verbose    [stage 1]
    tls_cert.py       days to certificate expiry                [stage 1]
    disk.py           disk and inode headroom                   [stage 1]
    alertmanager.py   webhook payload -> Signal adapter         [stage 5]
  detect/
    state.py          SQLite snapshot history                   [stage 2]
    rules.py          thresholds, rate-of-change, silence       [stage 2]
  correlate.py        anomaly x recent change                   [stage 2]
  redact.py           IP / hostname / mailbox / path            [stage 0] DONE
  llm.py              OpenAI-compatible client                  [stage 3]
  brief.py            triage summary with evidence binding      [stage 3]
  sinks/              discord, stdout                           [stage 4]
```

The collection logic is lifted from `audit.sh`, a read-only scan script I
already ran by hand on this server; each of its sections becomes one source.
The difference is that a source emits structured `Signal` objects instead of
text for a human to skim.

### What `fail2ban.py` actually checks

These are transcribed from the incident notes, and the fourth is the reason
the project exists.

- **`docker logs --since` is not trusted.** On this host's Docker version it
  has returned silently truncated output (`--since 7d` returning one line from
  a container with thousands). Logs are pulled in full and filtered by
  timestamp in Python. The reason is a comment in the source, so that a future
  reader does not "optimise" it back.
- **Docker's `json-file` driver escapes `<` and `>`.** Go's `encoding/json`
  writes them as the six-character sequences `\u003c` / `\u003e`, so that is
  what fail2ban's filters and watchdesk's parsers actually see in
  `*-json.log`. Both forms are matched.
- **A filter file existing is not the same as a jail using it.** The
  `[dovecot-docker]` stanza once pointed at `filter = dovecot` while a correct
  `dovecot-docker.conf` sat next to it, unused, for weeks. The check compares
  the jail's live `filter =` target against the file it is supposed to use.
- **Cross-check the jail's own counter against `fail2ban-regex`.** Run
  `fail2ban-regex` over the real log with the jail's real filter and compare
  the match count to what the jail reports. Disagreement is the signature of
  the August incident, and this is the single most important rule in the
  project.
- **`fail2ban-client reload <jail>` can return OK without taking effect.**
  Detect the specific combination: jail claims to be running, reports zero
  matches, and the log demonstrably contains matching lines.
- **Dovecot logs to syslog by default**, which inside a container means the
  jail reading it is blind. `dovecot.py` treats `log_path` and `auth_verbose`
  as health checks, not configuration.

## Redaction contract

`redact.py` is enforced at two exits — before the LLM call and before the
Discord push — and covers:

| Input | Becomes |
| --- | --- |
| Third-party address | `ip:7f3a2c` (salted, stable within and across reports) |
| Loopback / RFC1918 | `ip:loopback`, `ip:private-a1b2c3` |
| Reverse-DNS name carrying octets (`93-184-216-34.isp.example`) | replaced whole, before the octets can survive as a hostname |
| Operator mailbox or domain | `mbox:own`, `domain:own` |
| Third-party mailbox | `mbox:7f3a2c` |
| Hostname | `host:self`, `host:7f3a2c` |
| Absolute path | `path:7f3a2c`, except an allowlist of generic system paths |

The path allowlist keeps `/etc/fail2ban/jail.local` and `/var/log/fail2ban.log`
readable, because those *are* the evidence for the most important rules here,
and they name software rather than a person. `/home/someone/Maildir` is not on
it. Anything unlisted is replaced, so forgetting to extend the list
over-redacts rather than leaks.

`tests/test_redact.py` is a hard CI gate. It runs real-format log lines through
the pipeline and asserts the output contains no IPv4, IPv6, dashed-quad,
email, or non-allowlisted absolute path. It also asserts that the *unredacted*
input trips the same checker — a leak-detector that matches nothing would make
the gate decorative.

## Fixtures

`tests/fixtures/redaction/sample_lines.txt` is synthetic: real log formats with
documentation-range values, written to exercise the redactor.

`tests/fixtures/2026-08-fail2ban-gap/` *(stage 1)* will be a real capture from
the incident — the container log and `fail2ban.log` from both sides of the gap
— passed through `redact.py` in its fixture-baking mode before being
committed. That mode substitutes documentation-range addresses instead of
`ip:` tokens, so the file still parses as a log while containing no real
address. The original-to-placeholder mapping is not in this repository.

## Verification

```bash
pytest
```

The redaction gate must be green before anything else is worth running.

Stage 2 onward adds the acceptance test that matters:

```bash
watchdesk replay tests/fixtures/2026-08-fail2ban-gap/
```

Fed the logs from the incident, watchdesk has to report that the jails looked
healthy while authentication failures on the submission port were going
uncounted. If it cannot produce that finding, the project has not done the one
thing it claims to do.

## Not in scope

- **No automated remediation.** No banning, no restarting, no config edits.
  This is a design position, not a phase-one limitation.
- **No `/var/run/docker.sock`**, mounted or otherwise.
- **No Prometheus or Grafana.** Alertmanager webhooks can be adapted into
  `Signal`s later (stage 5); watchdesk is not becoming a metrics stack.

## Licence

MIT. See [LICENSE](LICENSE).
