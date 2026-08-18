# watchdesk

A read-only on-call assistant for one self-hosted mail server. It runs as a
systemd timer on the host it watches, compares each round against the last
one, and only escalates to an LLM when a rule has already decided something
changed.

It is not a dashboard. Dashboards were the problem.

> **Status: all five stages complete.**
> Collection, change detection, the evidence-bound brief, the Discord sink, the
> systemd units and the Alertmanager adapter all exist and have been run.
> `watchdesk replay` reproduces the August incident and its resolution from two
> real captures; a round against a real Docker daemon runs in CI via
> `tests/fake-stack/`. Nothing in this README describes behaviour that is not
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
    dockerlog.py      json-file reader; never uses --since      [stage 1] DONE
    fail2ban.py       the core; see below                       [stage 1] DONE
    postfix.py        SASL failure rate, queue depth, sent rate [stage 1] DONE
    dovecot.py        login activity + log_path/auth_verbose    [stage 1] DONE
    docker_state.py   health, restart counts, OOM kills         [stage 2] DONE
    tls_cert.py       days to certificate expiry                via alertmanager
    disk.py           disk and inode headroom                   via alertmanager
    alertmanager.py   webhook payload -> Signal adapter         [stage 5] DONE
  detect/
    state.py          SQLite snapshot history                   [stage 2] DONE
    rules.py          thresholds, rate-of-change, silence       [stage 2] DONE
  correlate.py        anomaly x recent change                   [stage 2] DONE
  redact.py           IP / hostname / mailbox / path            [stage 0] DONE
  leakcheck.py        independent exit check; runtime + CI      [stage 3] DONE
  llm.py              OpenAI-compatible client                  [stage 3] DONE
  brief.py            triage summary with evidence binding      [stage 3] DONE
  sinks/              discord, stdout, repeat suppression       [stage 4] DONE
```

The collection logic is lifted from `audit.sh`, a read-only scan script I
already ran by hand on this server; each of its sections becomes one source.
The difference is that a source emits structured `Signal` objects instead of
text for a human to skim.

### What `fail2ban.py` actually checks

The jail is never asked how the jail is doing. Every gap this server has had
was a jail reporting itself healthy, so the module derives three *independent*
counts over the same window and treats their disagreement as the finding:

| | | |
| --- | --- | --- |
| **A** | `observed_failures` | what watchdesk counts in the log, with a matcher deliberately broader than any filter |
| **B** | `filter_matched_lines` | what the jail's own failregex, read from disk and applied to the raw lines, would match |
| **C** | `found_events` | what the running fail2ban actually counted, from its own `Found` entries in `fail2ban.log` |

**A > B** means the filter is narrower than reality. On the captured day that
is 212 versus 2. **B > C** means the filter on disk is not the filter in
memory — `fail2ban-client reload` has returned OK on this host without taking
effect, and config review cannot see that, because the config is correct.
**C > 0 while A = 0** means watchdesk's own matcher has drifted from the log
format; the detector is not exempt from being wrong, and this is how it says
so. `fail2ban-regex` is run as a fourth opinion, because it is fail2ban's own
tooling and therefore the number a sceptic asks for.

Getting C right took two corrections that are worth knowing about, because
both produced a confident wrong answer first:

- `Found` is emitted by two loggers. `fail2ban.filter` logs one per matched
  line; `fail2ban.observer` narrates its own ban-time scoring in the same
  wording. Counting both inflated a healthy jail's tally by 25% and
  manufactured a permanent disagreement.
- fail2ban's own timestamp is when it *read* the line, not when the line
  happened. The trailing `- <date>` on a `Found` entry is the latter, and it
  is the only one comparable to a count taken from the container log.

The specific checks, transcribed from the incident notes:

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

## What the rules actually do

Three shapes, and the ordering is the argument:

**Thresholds** for things that are wrong at any value — a jail that cannot see
the traffic in the log it is reading, a jail using a filter it was not
configured to use. These need no history. `fail2ban.uncounted_failures` has no
threshold on the number of failures at all: two counts of one log disagreeing
is wrong whether the number is 210 or 1.

**Change** against the previous round. A watched metric must both multiply by
a factor *and* move by an absolute amount before it is reported — the factor
alone fires on 1 → 5, which on a quiet server happens constantly, and the delta
alone fires on 400 → 430, which is not news. A jump *from zero* has no ratio
and is reported on the delta alone, because on a server that is usually quiet
it is the most interesting shape there is. A cumulative counter going
*backwards* is its own rule: fail2ban keeps `Total failed` in memory, so a
restart zeroes it, and the next round otherwise shows a jail that suddenly
looks calm.

**Silence.** A signal that used to be reported and no longer is. This rule
exists because every other rule in the file reads an absent signal as a healthy
one — which is the exact confusion the whole project is about.

Findings carry the signals they rest on, the evidence under those signals, and
a confidence marker that is `observed` or `derived`. Rules never produce
`hypothesis`; that value exists so stage 3 has somewhere to put an LLM's
explanation without it being mistaken for a measurement.

### Correlation

`correlate.py` puts the changes it can see next to the anomalies in the same
window: a config file's digest differing from the previous round, fail2ban
restarting, a container's start time or restart count moving. It does not
decide causation. "Bans multiplied by 32" is a fact; "bans multiplied by 32 and
the postfix-docker filter changed in the same window" is something a person can
act on.

The list of changes it knows about is deliberately short, and every one of them
is something watchdesk already measures for another reason. Nothing here reads
shell history or package logs — a short list of changes it is certain about
beats a long list it has to guess at.

## The brief, and what it is allowed to say

The findings are arithmetic over measurements; they are true by construction. A
language model adds triage prose — which of five findings to read first, what
they plausibly mean together, what to check next. That is genuinely useful, and
it is also exactly the kind of text that invents a number nobody measured.

So every statement the model returns is checked mechanically before it reaches
the output:

| The model says | What happens |
| --- | --- |
| a claim with no citation | **dropped** |
| a claim citing a ref that does not exist in this round | **dropped** — a fabricated citation survives a skim, because the reader sees a reference and stops checking |
| an observation asserting a number nothing measured | **dropped** |
| a number that *was* measured but is not in the refs it cited | kept, downgraded to **hypothesis**, with the reason attached |
| anything causal, however well cited | kept, marked **hypothesis** — evidence can support "210 failures were on submission"; it cannot make "because the attackers migrated" into an observation |
| a headline containing an unsupported number | replaced by one derived from the rules |

The split between the third and fourth rows is deliberate and came from
watching a real model on this data: it wrote "210 of 212" while citing only the
signal worth 210. Both numbers were real; the citation was one ref short.
Treating that as a fabrication would bury actual fabrications in noise, so it
is a lesser fault with its own wording.

If the endpoint is unreachable, returns something unparseable, or has every
claim rejected, the brief is still produced from the findings alone and says
so. The rules are the product; the prose is a convenience.

The model is only called once a rule has fired at or above `llm.min_severity`.
On a quiet server it is never called at all.

### Redaction at that exit

`llm.py` redacts its own arguments and then runs `leakcheck.py` over the result
before opening a socket. A caller that forgets to redact still cannot leak, and
a bug in `redact.py` raises instead of publishing.

`leakcheck.py` deliberately reimplements the patterns rather than importing
them from `redact.py`. Sharing them would be tidier and useless: a mistake in a
shared pattern would hide itself, since the same blind spot that failed to
redact a value would fail to detect it afterwards.

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

One deliberate trade-off in the hostname rule: an FQDN is only pseudonymised
if its last label is a known TLD. Dotted identifiers are everywhere in this
data and are not hosts — logger names like `fail2ban.filter`, module paths like
`watchdesk.sources.postfix` — and redacting them corrupts the evidence badly
enough that a baked fixture stops parsing as a fail2ban log. The cost is that a
hostname under a TLD missing from the list is not redacted. What that can
expose is a third party's reverse-DNS name; the operator's own identity does
not depend on the list, because `own_domains` and `own_hostnames` are matched
explicitly whatever their TLD, and no address reaches that rule unredacted.

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

`tests/fixtures/2026-08-fail2ban-gap/` is **a real capture from the incident**,
redacted at capture time by `scripts/bake_fixture.py`. Provenance is recorded
in its `meta.yaml` and split three ways, because a fixture that overstates its
own authenticity is worse than a synthetic one:

- **Genuine, redacted.** The Postfix and Dovecot container logs and
  `fail2ban.log` for 2026-07-31 UTC — 1657, 500 and 919 lines, nothing added
  or reordered. Also the `fail2ban-regex` output, which is genuine because it
  was produced by running the real tool against the fixture's own files.
- **Reconstructed, and labelled as such.** fail2ban keeps `Total failed` and
  `Total banned` in memory only, so that evening's counters exist in no file —
  they are replayed from the `Found`/`Ban` events fail2ban logged as they
  happened, counted from the last restart. The `postfix-docker.conf` in the
  fixture is the live file with the 2026-08-01 fix reverted and nothing else.
- **Captured at bake time.** `mailq`, `postconf smtpd_sasl_type` and
  `doveconf` answers are stable facts about the deployment that cannot be
  recovered for a past evening. No finding depends on them.

`tests/fixtures/2026-08-fail2ban-fixed/` is the following day, captured the
same way, with the filter file as it stood after the fix. Both were baked in
one chain so they share an address mapping — two fixtures from the same server
have to agree on which placeholder stands for which real address, or every
cross-fixture comparison silently compares unrelated attackers.

Redaction uses the fixture-baking style, which substitutes documentation-range
addresses (RFC 5737 / 3849) rather than `ip:` tokens, so every file still
parses as a log and still exercises the real parsers. Private and loopback
addresses are left intact — they identify nobody, and the detection rules key
on the Docker gateway being exactly what it is. The original-to-placeholder
mapping is not in this repository.

## Verification

```bash
pytest
```

The redaction gate must be green before anything else is worth running.

The acceptance test is the one that matters:

```bash
watchdesk --config config/watchdesk.example.yaml replay tests/fixtures/2026-08-fail2ban-gap/
```

Fed the real logs from the incident, watchdesk reports:

```
fail2ban.jail.observed_failures{jail=postfix-docker}                       212
fail2ban.jail.filter_would_match{jail=postfix-docker}                        2
fail2ban.jail.uncounted_failures{jail=postfix-docker}                      210
fail2ban.jail.coverage_ratio{jail=postfix-docker}                       0.0094
fail2ban.jail.uncounted_failures_by_service{...,service=submission/smtpd}  210
fail2ban.jail.uncounted_failures_by_service{...,service=smtpd}               0

fail2ban.jail.filter_matched_lines{jail=postfix-docker}                      6
fail2ban.jail.regex_tool_matches{jail=postfix-docker}                        6
fail2ban.jail.found_events{jail=postfix-docker}                              6
```

That is the incident: 210 of 212 authentication failures were on the
submission listener and invisible to the jail, while the jail itself was
enabled, using the filter it was supposed to use, and had banned an address
that same day. The three independent counts agreeing at six is what makes the
212 credible — it rules out "watchdesk's own regex is simply wrong".
`tests/test_replay_gap.py` asserts every number above.

### Change detection, across two real days

```bash
watchdesk --config config/watchdesk.example.yaml replay \
  tests/fixtures/2026-08-fail2ban-gap/ tests/fixtures/2026-08-fail2ban-fixed/
```

Two captures from adjacent days — the day the jail was blind, and the day the
filter was corrected — replayed in order through one history:

```
[CRITICAL] postfix-docker is blind to 210 authentication failures on submission/smtpd
           (first round; 212 observed, 2 matched, coverage 0.0094)

[WARNING]  fail2ban.jail.ban_events x32.0: 1 -> 32 events
           correlation: [config_edit] filter.d/postfix-docker.conf changed between rounds
[WARNING]  fail2ban.jail.found_events x28.3: 6 -> 170 events
           correlation: [config_edit] filter.d/postfix-docker.conf changed between rounds
[WARNING]  postfix-docker: on-disk filter and running fail2ban disagree by 61
           correlation: [config_edit] filter.d/postfix-docker.conf changed between rounds
```

The third finding is the filter being corrected part-way through the second
day: the file on disk at the end of it matches more than the running process
counted during it. That is a genuine disagreement, and it is reported with the
edit attached so it reads as an explanation rather than a fault.

What is *absent* matters as much. Real authentication failures went 212 → 226
across those two days — the traffic barely moved; what changed was how much of
it fail2ban could see — and no rule reports an attack that did not happen.
`tests/test_replay_change.py` asserts that silence explicitly.

### The brief, offline

```bash
watchdesk --config config/watchdesk.example.yaml replay \
  tests/fixtures/2026-08-fail2ban-gap/ --llm-recording tests/fixtures/llm/gap-brief.json
```

The recorded completion is hand-written to contain every failure mode at once.
What comes out:

```
[CRITICAL] postfix-docker matched 2 of 212 authentication failures this window
  - 210 authentication failures on submission/smtpd are present in the log ...
      [observation/derived] cites: fail2ban.jail.uncounted_failures{jail=postfix-docker}, ...
  ? 210 of 212 authentication failures in the window were on submission/smtpd.
      [observation/hypothesis] cites: fail2ban.jail.uncounted_failures_by_service{...}
      note: cited imprecisely: 212 was measured this round but is not in the evidence this claim cites
  ? The pattern is consistent with scanners having moved from port 25 ...
      [explanation/hypothesis] cites: fail2ban.jail.uncounted_failures_by_service{...}
  3 claim(s) dropped for lack of evidence:
      x The mail server is almost certainly compromised and mail is being relayed.
        cites no evidence
      x Outbound delivery volume tripled over the same window.
        cites 'postfix.messages_sent_per_day{container=postfix}', which is not in this round
      x There were 4821 failed logins from a single address.
        states 4821, which nothing in this round measured
```

`tests/test_brief.py` asserts each of those outcomes. Every test in this
project's LLM layer runs against recorded completions, so the assertions are
about watchdesk's verification rather than about any model's behaviour on the
day.

### Against a real Docker daemon

```bash
docker compose -f tests/fake-stack/compose.yml up -d
watchdesk --config tests/fake-stack/watchdesk.yaml once --sink stdout
docker compose -f tests/fake-stack/compose.yml down
```

Two busybox containers replay the redacted 2026-07-31 capture through the real
log driver, so a round reads it back through the real CLI:

```
postfix.auth_failures{container=watchdesk-fake-postfix}                              212
postfix.auth_failures_by_service{...,service=submission/smtpd}                       210
postfix.auth_failures_by_service{...,service=smtpd}                                    2
```

Reading those lines off disk instead would test almost nothing that has ever
broken — every bug found in this project's collection layer was in the seam
between watchdesk and Docker. CI runs this job on every push, and it earned
its place immediately: the runner is not root, so it took the `docker logs`
fallback, which returned plain text where the parser expected json-file lines
and reported **zero** failures from a busy container. That path had never run
on the host this was developed on, because there the file is readable.

The fallback now asks for `--timestamps` and marks its output as *not*
wire-format, and `sources/fail2ban.py` refuses to run the filter cross-check
against it — `docker logs` hands over the decoded message, not the bytes on
disk, and every filter here anchors on `^\{"log":"`. Applying them to decoded
text matches nothing and would report the entire window as uncounted. A
confident false alarm from the one rule this project exists for is worse than
saying the check could not run, so `postfix.log_read_mode` reports how the log
was reached and `fail2ban.jail.cross_check_unavailable` says plainly when the
important check is unavailable.

See `tests/fake-stack/README.md`.

### Against a real endpoint

```bash
watchdesk doctor --live
```

Sends fixed text with nothing from this host in it — a reachability check
should not be the thing that ships a log line somewhere — and reports latency,
the model the endpoint claims to have used, and token usage.

### Against the live host

Same command with no fixture:

```bash
watchdesk --config config/watchdesk.example.yaml once --window 1440
```

Output is redacted by default. `--raw` skips redaction for local debugging on
the machine that owns the data, `--signals` prints every signal rather than
only the findings, and `--no-state` skips history so only threshold rules run.

On this server, two consecutive rounds against a currently-healthy host produce
92 signals, 0 collection errors and **0 findings** — which is the result that
matters most for a tool whose silence is supposed to mean something.

`watchdesk doctor` prints the full command allowlist and the state of the
history database.

## Deploying it

```bash
sudo install -d -m 0755 /opt/watchdesk /etc/watchdesk
sudo install -d -m 0700 /var/lib/watchdesk
sudo git clone https://github.com/hsjinde/watchdesk /opt/watchdesk/src
sudo python3 -m venv /opt/watchdesk/.venv
sudo /opt/watchdesk/.venv/bin/pip install /opt/watchdesk/src

sudo cp /opt/watchdesk/src/config/watchdesk.example.yaml /etc/watchdesk/watchdesk.yaml
sudo cp /opt/watchdesk/src/.env.example /etc/watchdesk/watchdesk.env
sudo chmod 0600 /etc/watchdesk/watchdesk.env   # salt, LLM key, webhook

sudo cp /opt/watchdesk/src/deploy/watchdesk.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now watchdesk.timer

watchdesk --config /etc/watchdesk/watchdesk.yaml doctor        # what it may run
sudo systemctl start watchdesk.service                          # one round now
journalctl -u watchdesk.service -n 50
```

A timer rather than a daemon: a oneshot that crashes is retried on the next
tick and leaves a journal entry, while a daemon that wedges goes quiet and
looks exactly like a healthy system with nothing to report — which is the
failure mode this whole project is about.

### It runs as root, and here is why

The unit runs as root. That is not laziness, and the non-root version that
looks safer mostly is not.

| What it needs | Permissions on a default Ubuntu host |
| --- | --- |
| `fail2ban-client` | `/var/run/fail2ban/fail2ban.sock` is `srwx------ root root`. There is no group to join. |
| the jails' logs | `/var/lib/docker/containers/` is `drwx--x--- root root`, and the `/var/log/*-docker.log` symlinks point straight into it. |
| the `docker` CLI | `/var/run/docker.sock` is `srw-rw---- root docker`, and membership of `docker` is equivalent to root — a member can start a container with `/` mounted. |

So the "unprivileged" deployment needs ACLs on two root-only paths plus a group
that is already root-equivalent. `deploy/watchdesk-nonroot.service.example`
ships it, with the exact commands, because reducing the chance of an *accident*
is worth something. It does not reduce what the process could do, and claiming
otherwise would be the same species of "it looks fine" that this project exists
to argue against.

What the hardening does buy is real and it is smaller: it caps the blast radius
of a bug. `ProtectSystem=strict` with a single `ReadWritePaths`, and
`CapabilityBoundingSet=CAP_DAC_READ_SEARCH` — the one capability actually
needed, to read the container logs. Everything else root would normally carry
is dropped, including `CAP_NET_ADMIN`. Verified on the host it was written for:

```
$ systemd-run --property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH ... iptables -L DOCKER-USER
iptables v1.8.7: Could not fetch rule set generation id: Permission denied (you must be root)

$ iptables -L DOCKER-USER          # same command, no sandbox
Chain DOCKER-USER (1 references)
```

A tool sitting next to fail2ban should be the last thing on the box able to
touch the firewall, and under this unit it cannot — even though it is root.

The same sandbox running a real round: 92 signals, 0 collection errors.

### The Discord sink

```bash
watchdesk --config /etc/watchdesk/watchdesk.yaml once --sink discord
```

An on-call channel that reposts an unchanged alert every five minutes gets
muted within a day, and a muted channel somebody still believes is watching is
worse than no channel at all. So a brief whose *situation* is unchanged is not
sent again until `sink.resend_after_minutes` has passed.

"Situation" means which rules fired, at what severity, with which labels — not
the prose. A rate ticking from 170 to 174 is the same problem and stays quiet;
a second jail going blind is a new one and goes out immediately. An unchanged
problem is repeated eventually, because silence forever lets a real problem
fade out of memory.

Findings below `sink.min_severity` are collected and stored but never pushed. A
`429` from Discord is obeyed rather than retried — being rate-limited by a chat
service is not an emergency, and the next round carries the same findings. A
failed send is not recorded as sent, so the next round tries again.

`replay` can never notify. It accepts `--sink stdout` only, so no rehearsal of
a past incident can page anybody.

## Everything else, through Alertmanager

Certificate expiry, disk headroom, blackbox probes — none of that needs another
collector here. It needs one adapter, and `sources/alertmanager.py` is it.

```bash
# whatever already terminates HTTP on this host pipes the body in
watchdesk ingest - < webhook.json
# then rounds read the spool
watchdesk --config /etc/watchdesk/watchdesk.yaml once
```

```
[CRITICAL] Alertmanager: HostDiskWillFill firing on ip:private-96d000:9100
  rule: alertmanager.alert_firing  confidence: observed
  Reported by Alertmanager, not measured by watchdesk. The text below is
  free-form and comes from whoever wrote the alerting rule; treat it as a
  pointer to look at that system, not as a measurement made here.
  evidence[alert] alertmanager:7b1a2c3d
    Filesystem / will be full in 4 hours
```

Three decisions worth naming:

**watchdesk does not listen on a port.** A webhook receiver is an
unauthenticated HTTP endpoint by default, and a read-only monitoring tool on a
mail server has no business opening a socket. Payloads are spooled as files by
something that already terminates HTTP; rounds read the spool. The cost is a
few seconds of latency.

**An alert is untrusted input, in a way that is easy to miss.** Annotations are
free text written by whoever configured the alerting rules, and they flow into
the brief, which flows into an LLM prompt — a prompt-injection path from a
neighbouring system into the thing that writes your on-call summary. The
defences are unglamorous: annotations are length-capped, they are carried as
evidence rather than as instructions, and every claim in a brief still has to
cite a ref that resolves, so text arriving in an annotation cannot manufacture
a measurement. Alert labels also routinely carry addresses (`instance` is
almost always `host:port`), and they go out through the same redaction as
everything else — nothing is exempt for having come from a system the operator
trusts.

**The finding says who observed what.** watchdesk observed that *Alertmanager
says* a disk will fill. It did not observe the disk. An unmapped severity
becomes a `notice` rather than being guessed upward: a neighbouring system's
idea of "critical" is not automatically this one's.

## Not in scope

- **No automated remediation.** No banning, no restarting, no config edits.
  This is a design position, not a phase-one limitation.
- **No `/var/run/docker.sock`**, mounted or otherwise.
- **No Prometheus or Grafana.** Alertmanager webhooks are adapted into
  `Signal`s (above); watchdesk is not becoming a metrics stack.
- **No listening socket**, for the reasons above.

## Licence

MIT. See [LICENSE](LICENSE).
