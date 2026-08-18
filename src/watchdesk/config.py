"""Configuration: a YAML file for what to watch, the environment for secrets.

The split is deliberate.  The YAML is meant to be readable and committable —
it is where the command allowlist lives, and an allowlist nobody can read is
not a control.  Secrets (the redaction salt, the LLM key, the Discord webhook)
come from the environment, so the file that describes what watchdesk may do
can be shown to anyone.

Defaults come from the mail stack's ``docker-compose.yml`` (django, postfix,
dovecot, opendkim, certbot).  Every one of them is overridable, because a
container name is a fact about one deployment, not about this program.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .redact import RedactionPolicy, load_salt
from .sources.shell import Allowlist

__all__ = ["Config", "EnvSettings", "JailSpec", "load_config"]


class Containers(BaseModel):
    """Container names, defaulting to the compose file's service names."""

    postfix: str = "postfix"
    dovecot: str = "dovecot"
    opendkim: str = "opendkim"
    django: str = "django"
    certbot: str = "certbot"


class JailSpec(BaseModel):
    """One fail2ban jail and what it is supposed to be watching.

    ``expect_filter`` exists because of a real regression: the
    ``[dovecot-docker]`` stanza pointed at ``filter = dovecot`` — fail2ban's
    stock filter — while a correct ``dovecot-docker.conf`` sat unused next to
    it.  Everything looked configured.  Stating the expected filter here turns
    that from something a human has to notice into something that fails.
    """

    name: str
    container: str | None = None
    expect_filter: str | None = None
    #: Which log-line dialect this jail's log speaks, so watchdesk can form its
    #: own opinion of what a failure looks like independently of the jail's
    #: own filter (see sources/fail2ban.py).
    dialect: str = "postfix"


class Fail2banConfig(BaseModel):
    jail_local: str = "/etc/fail2ban/jail.local"
    filter_dir: str = "/etc/fail2ban/filter.d"
    jails: list[JailSpec] = Field(
        default_factory=lambda: [
            JailSpec(name="postfix-docker", container="postfix", expect_filter="postfix-docker"),
            JailSpec(
                name="dovecot-docker",
                container="dovecot",
                expect_filter="dovecot-docker",
                dialect="dovecot",
            ),
            JailSpec(name="sshd", dialect="sshd"),
        ]
    )
    #: fail2ban-regex over a large log is slow (tens of seconds on a 19 MB
    #: file). It is the only *independent* confirmation available from
    #: fail2ban's own tooling, so it stays on by default and is switched off
    #: only when a round has to be cheap.
    run_fail2ban_regex: bool = True


class ShellConfig(BaseModel):
    """The allowlist, as plain data.

    Entries are argv lists.  A bare ``*`` stands for exactly one argument.
    Container entries are the *(container, argv)* pairs described in
    ``sources/shell.py``; the ``docker exec`` prefix is never written here
    because watchdesk assembles it, which is what stops a config edit from
    adding a mount or a user switch.
    """

    host: list[list[str]] = Field(
        default_factory=lambda: [
            ["fail2ban-client", "status"],
            ["fail2ban-client", "status", "*"],
            ["fail2ban-client", "get", "*", "logpath"],
            ["fail2ban-client", "get", "*", "maxretry"],
            ["fail2ban-client", "get", "*", "findtime"],
            ["fail2ban-client", "get", "*", "ignoreip"],
            ["fail2ban-regex", "*", "*"],
            ["docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}"],
            ["docker", "logs", "*"],
            ["docker", "inspect", "*"],
            ["docker", "inspect", "--format", "{{.LogPath}}", "*"],
            ["docker", "inspect", "--format", "{{json .State}}", "*"],
            ["docker", "inspect", "--format", "{{.RestartCount}}", "*"],
            ["df", "-P", "-k"],
            ["df", "-P", "-i"],
        ]
    )
    containers: dict[str, list[list[str]]] = Field(
        default_factory=lambda: {
            "postfix": [["mailq"], ["postconf", "-n"], ["postconf", "smtpd_sasl_type"]],
            "dovecot": [["doveconf", "log_path", "auth_verbose"]],
        }
    )
    read_paths: list[str] = Field(
        default_factory=lambda: [
            "/etc/fail2ban",
            "/var/log/fail2ban.log",
            "/var/log/postfix-docker.log",
            "/var/log/dovecot-docker.log",
            "/var/lib/docker/containers",
        ]
    )
    timeout_s: float = 120.0

    def to_allowlist(self) -> Allowlist:
        return Allowlist(
            host=tuple(tuple(entry) for entry in self.host),
            containers={
                name: tuple(tuple(entry) for entry in entries)
                for name, entries in self.containers.items()
            },
            read_paths=tuple(self.read_paths),
        )


class RulesConfig(BaseModel):
    """Thresholds for change detection.

    Deliberately few, and all in one place. A rules engine with a knob per
    rule becomes a thing nobody can predict the behaviour of, which is the
    same failure as a dashboard nobody reads.
    """

    #: A metric must both multiply by this much and move by this much in
    #: absolute terms. The factor alone fires on 1 -> 5; the delta alone fires
    #: on 400 -> 430. Attacks do both.
    spike_factor: float = 4.0
    spike_min_delta: float = 10.0

    #: How far |filter_matched_lines - found_events| may drift before it is
    #: worth reporting. Small non-zero values are normal at a window edge.
    drift_threshold: int = 5

    #: A baseline older than this many windows is reported as stale rather
    #: than silently differenced against.
    stale_baseline_factor: float = 3.0

    #: How far back to look for keys that have stopped being reported.
    silence_lookback_hours: int = 24

    #: Metrics compared against their previous value. An explicit list rather
    #: than "every metric": watching everything means a spike report on every
    #: quiet server's log-line count, and an alert nobody reads is worse than
    #: no alert.
    spike_watch: list[str] = Field(
        default_factory=lambda: [
            "fail2ban.jail.found_events",
            "fail2ban.jail.ban_events",
            "fail2ban.jail.observed_failures",
            "fail2ban.jail.uncounted_failures",
            "postfix.auth_failures",
            "postfix.messages_sent",
            "postfix.queue_depth",
            "postfix.relay_denied",
            "dovecot.auth_failures",
            "dovecot.successful_logins",
        ]
    )

    #: Metrics whose spike is an emergency rather than a curiosity. Outbound
    #: mail from a personal server is the signature of a relay compromise.
    critical_on_spike: list[str] = Field(
        default_factory=lambda: ["postfix.messages_sent", "postfix.queue_depth"]
    )


class RedactionConfig(BaseModel):
    """Which identities are the operator's own, and therefore masked rather
    than pseudonymised."""

    own_domains: list[str] = Field(default_factory=list)
    own_mailboxes: list[str] = Field(default_factory=list)
    own_hostnames: list[str] = Field(default_factory=list)


class EnvSettings(BaseSettings):
    """Secrets and endpoints.  Never in the YAML, never in the repository."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    llm_base_url: str = "https://llm.example.com/v1/chat/completions"
    llm_model: str = ""
    llm_api_key: str = ""

    discord_webhook_url: str = ""

    watchdesk_own_domains: str = ""
    watchdesk_own_mailboxes: str = ""
    watchdesk_own_hostnames: str = ""

    @staticmethod
    def _csv(raw: str) -> list[str]:
        return [item.strip().lower() for item in raw.split(",") if item.strip()]


class Config(BaseModel):
    containers: Containers = Field(default_factory=Containers)
    fail2ban: Fail2banConfig = Field(default_factory=Fail2banConfig)
    shell: ShellConfig = Field(default_factory=ShellConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)

    #: How far back a round looks. Rates are computed over this window, and
    #: rules compare one window against the previous one, so it is the
    #: resolution at which "3 an hour became 400 an hour" becomes visible.
    window_minutes: int = 60

    #: Where snapshot history lives (stage 2).  Outside the repository, and
    #: outside /tmp, so that a reboot does not erase the baseline that every
    #: change-detection rule depends on.
    state_db: str = "~/.local/share/watchdesk/state.sqlite3"

    env: EnvSettings = Field(default_factory=EnvSettings)

    def redaction_policy(self) -> RedactionPolicy:
        """Merge YAML identity lists with anything the environment adds."""
        env = self.env
        return RedactionPolicy(
            salt=load_salt(),
            own_domains=tuple(
                dict.fromkeys(
                    [d.lower() for d in self.redaction.own_domains]
                    + EnvSettings._csv(env.watchdesk_own_domains)
                )
            ),
            own_mailboxes=tuple(
                dict.fromkeys(
                    [m.lower() for m in self.redaction.own_mailboxes]
                    + EnvSettings._csv(env.watchdesk_own_mailboxes)
                )
            ),
            own_hostnames=tuple(
                dict.fromkeys(
                    [h.lower() for h in self.redaction.own_hostnames]
                    + EnvSettings._csv(env.watchdesk_own_hostnames)
                )
            ),
        )

    def state_db_path(self) -> Path:
        return Path(self.state_db).expanduser()

    def jail(self, name: str) -> JailSpec | None:
        for spec in self.fail2ban.jails:
            if spec.name == name:
                return spec
        return None


def load_config(path: str | Path | None = None) -> Config:
    """Load YAML if given, otherwise use defaults; environment always applies."""
    data: dict[str, Any] = {}
    if path is not None:
        loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if loaded:
            data = loaded
    data.setdefault("env", EnvSettings())
    return Config.model_validate(data)
