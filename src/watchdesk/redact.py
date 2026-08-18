"""Redaction — the last thing that runs before data leaves this machine.

watchdesk is meant to be published as a public repository while it watches a
real, personal mail server. That only works if there is exactly one place
where host-identifying data can be turned into something safe to publish, and
if that place is enforced at every exit rather than remembered by hand.

Two exits are in scope, and both call this module:

  1. before a payload is handed to the LLM   (``llm.py``)
  2. before a message is pushed to Discord   (``sinks/discord.py``)

A third, offline use is fixture baking: turning a real log slice into a file
that can be committed to ``tests/fixtures/`` while still parsing exactly like
the original.  That is the same substitution machinery with a different
output shape, so it lives here too (see :class:`Style`).

What gets replaced
------------------
* IPv4 / IPv6 addresses, including the dashed-quad form that shows up inside
  reverse-DNS names (``198-51-100-23.dynamic-ip.example.net`` leaks the same
  four octets as the address does).
* Email addresses — the operator's own mailboxes and everyone else's.
* Hostnames and fully-qualified domain names.
* Absolute filesystem paths, except an explicit allowlist of generic system
  paths that carry no identity (``/etc/fail2ban/jail.local`` is evidence;
  ``/home/someone/Maildir`` is not).

On reversibility
----------------
Attacker addresses become salted pseudonyms (``ip:7f3a2c``) rather than a flat
``<ip>`` mask, so that a single report still shows *which* lines share a
source — that correlation is most of the diagnostic value.  The salt is not in
this repository.

This is pseudonymisation, not anonymisation.  The IPv4 space is 2^32; anyone
holding the salt can enumerate it in seconds and invert every ``ip:`` token in
every report ever published.  The salt is the only thing standing there.
Treat it as a secret, and do not describe watchdesk's output as irreversible.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "Style",
    "RedactionPolicy",
    "Redactor",
    "RedactionError",
    "load_salt",
    "DEFAULT_PATH_ALLOWLIST",
]


class RedactionError(RuntimeError):
    """Raised when redaction cannot be performed safely (e.g. no salt)."""


class Style(str, Enum):
    """How a redacted value is rendered.

    ``PSEUDONYM`` is the runtime style used at the LLM and Discord exits: the
    replacement is deliberately *not* shaped like the thing it replaced, so a
    grep for an address pattern over published output finds nothing.

    ``PLACEHOLDER`` is the fixture-baking style: the replacement keeps the
    original's shape (an address is replaced by an address from a
    documentation range) so a baked fixture still exercises the real parsers.
    """

    PSEUDONYM = "pseudonym"
    PLACEHOLDER = "placeholder"


#: Absolute paths under these prefixes are kept verbatim.  Everything on this
#: list is a stock location on any Ubuntu box running fail2ban + Docker: it
#: identifies software, not a person or a host.  Anything not matching is
#: replaced, so the failure mode of forgetting to extend this list is
#: over-redaction, never a leak.
DEFAULT_PATH_ALLOWLIST: tuple[str, ...] = (
    "/etc/fail2ban",
    "/etc/dovecot",
    "/etc/postfix",
    "/etc/docker",
    "/etc/systemd",
    "/var/lib/fail2ban",
    "/var/lib/docker/containers",
    "/var/log",
    "/dev",
    "/usr",
    "/proc",
)

#: Trailing labels that look like a TLD but are file extensions.  Without this
#: the FQDN rule would eat ``jail.local``, ``fail2ban.log``, ``10-logging.conf``
#: — all of which are evidence we want to keep readable.
_KNOWN_TLDS = frozenset(
    """
    com net org edu gov mil int info biz name pro mobi asia coop aero jobs tel travel cat post
    xyz top icu vip club online site shop live cloud app dev ai tech space store one fun link
    host email press blog wiki world life today zone group company services center media agency
    digital network systems solutions work win bond cyou sbs rest quest monster lol autos beauty
    hair skin makeup mom boats homes buzz cc tv ws su me io co
    tw jp cn hk kr sg my th vn ph id in pk bd lk np
    us ca mx br ar cl pe ve uy py bo ec
    uk de fr nl be ch at es it pt se no dk fi is ie pl cz sk hu ro bg gr hr si lt lv ee
    ru ua by kz md ge am az
    au nz za ng ke eg ma tn dz gh tz ug zm zw
    il tr ir sa ae qa kw om jo lb sy iq ye
    """.split()
)

#: Labels that look like a TLD but are not.  This list is the *second* guard;
#: the first is _KNOWN_TLDS above.
_NOT_A_TLD = frozenset(
    """
    local conf log logs py pyc sh bash yaml yml json toml ini cfg md txt rst
    service timer socket sock pid db sqlite3 gz bz2 xz zip tar example sample
    key pem crt cert csr lock tmp bak old new orig dist template html css js
    """.split()
)

#: RFC 2606 documentation domains — the output alphabet of PLACEHOLDER style.
_DOC_DOMAINS = ("example.com", "example.net", "example.org", "example.edu")

#: RFC 5737 / RFC 3849 ranges, which stand in for third-party addresses in
#: baked fixtures.
_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_IPV4 = re.compile(r"(?<![\w.\-])\d{1,3}(?:\.\d{1,3}){3}(?![\w.\-])")
# Dashed quad as it appears inside reverse-DNS names.
_IPV4_DASHED = re.compile(r"(?<![\w.\-])\d{1,3}(?:-\d{1,3}){3}(?![\w\-])")
# Deliberately loose: anything colon-separated and hex-ish is a *candidate*,
# and ipaddress.ip_address() is the actual arbiter.  Cheaper to reason about
# than a fully correct IPv6 grammar, and it cannot produce a false negative
# that a stricter regex would have caught.
# The charset includes "." so that an IPv4-mapped address (::ffff:203.0.113.9)
# is matched whole; matching only its "::ffff:203" prefix would leave three
# real octets in the output.
_IPV6_CANDIDATE = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{3,45}(?![\w:.])")
_EMAIL = re.compile(r"(?<![\w.\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}(?![\w.\-])")
_FQDN = re.compile(
    r"(?<![\w.\-@])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w\-])"
)
#: Matched before the path rule, which otherwise swallows "//host/path" whole
#: and turns a Prometheus graph link into unreadable noise — losing the one
#: thing that made it useful as evidence (that it is a link, and to what kind
#: of system) while still not treating the hostname as a hostname.
_URL = re.compile(
    r"\b(?P<scheme>https?|ftp)://(?P<host>[^\s/:?#\"']+)(?P<port>:\d+)?(?P<rest>[^\s\"'<>]*)"
)

#: The leading "/" in the lookbehind matters: without it, "//host/x" from a URL
#: is read as the filesystem path "/host", and the URL rule's own output gets
#: eaten by this one. A doubled slash is never a path worth redacting.
#: This module's own URL output, recognised so a second pass leaves it alone.
#: llm.py redacts text that a caller may already have redacted, so every rule
#: here has to be a no-op on its own output — otherwise the guard at the exit
#: sees different bytes each time it runs.
_REDACTED_URL = re.compile(r"^(?:https?|ftp)://host:[0-9a-f]{6}")

#: Same reasoning for the PLACEHOLDER-style path replacement, which unlike the
#: pseudonym form starts with a slash and would otherwise be re-matched as a
#: path on every subsequent pass.
_REDACTED_PATH = re.compile(r"^/redacted/path[0-9a-f]{6}$")

#: This module's own PLACEHOLDER-style email output. Deliberately narrow: an
#: earlier version skipped every address under a documentation domain, which
#: also skipped attacker@example.net in a fixture. The *domain* identifies
#: nobody, but the local part is data — in a real log it is the account
#: somebody was trying to break into.
_REDACTED_EMAIL = re.compile(r"^(?:owner@example\.com|user[0-9a-f]{6}@example\.net)$", re.I)

_ABS_PATH = re.compile(r"(?<![\w.\-@/])(?:/[A-Za-z0-9._@+\-]+)+/?")
_HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")

# Docker's json-file driver writes < and > as the six-character escapes
# \u003c / \u003e (Go's encoding/json default).  Those escapes sit flush
# against the values we redact:
#
#     from=\u003cnoauth@mail.example.com\u003e
#
# and the "c" of \u003c is a word character, so an email rule with a word-
# boundary lookbehind starts its match one character early and eats the
# escape.  The result still hides the address but corrupts the line: it no
# longer parses as JSON, and the whole reason watchdesk matches both bracket
# forms (see fail2ban.py) is lost.
#
# So the escapes are swapped for private-use sentinels for the duration of a
# pass, purely so that every boundary assertion sees a non-word character
# there, and restored byte-for-byte afterwards.
_JSON_ANGLE = re.compile(r"\\u003([ce])", re.IGNORECASE)
_SENTINELS = {"c": "\ue000", "e": "\ue001"}
_UNSENTINEL = {v: f"\\u003{k}" for k, v in _SENTINELS.items()}
_SENTINEL_RE = re.compile("|".join(_UNSENTINEL))


def load_salt(env: dict[str, str] | None = None) -> str:
    """Return the pseudonymisation salt, creating one on first use.

    Resolution order:

    1. ``WATCHDESK_REDACT_SALT`` in the environment (how the systemd unit
       supplies it, via ``EnvironmentFile``).
    2. The file named by ``WATCHDESK_SALT_FILE``, else
       ``~/.config/watchdesk/redact.salt``.  Created with mode 0600 if absent.

    The salt never appears in the repository — ``.gitignore`` excludes
    ``*.salt`` and ``.env`` — and rotating it deliberately breaks correlation
    with every previously published report.
    """
    env = os.environ if env is None else env

    inline = (env.get("WATCHDESK_REDACT_SALT") or "").strip()
    if inline:
        return inline

    path = Path(env.get("WATCHDESK_SALT_FILE") or Path.home() / ".config/watchdesk/redact.salt")
    if path.exists():
        salt = path.read_text(encoding="utf-8").strip()
        if salt:
            return salt
        raise RedactionError(f"salt file {path} is empty; delete it to have one generated")

    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(32)
    # Write through a 0600 handle rather than chmod-after-write: the latter
    # leaves a window where the salt is world-readable on disk.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(salt + "\n")
    return salt


@dataclass(frozen=True)
class RedactionPolicy:
    """What counts as "ours" — everything else is treated as a third party."""

    salt: str
    own_domains: tuple[str, ...] = ()
    own_mailboxes: tuple[str, ...] = ()
    own_hostnames: tuple[str, ...] = ()
    path_allowlist: tuple[str, ...] = DEFAULT_PATH_ALLOWLIST

    def __post_init__(self) -> None:
        if not self.salt or not self.salt.strip():
            raise RedactionError("RedactionPolicy requires a non-empty salt")

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> RedactionPolicy:
        env = os.environ if env is None else env

        def csv(name: str) -> tuple[str, ...]:
            raw = env.get(name, "")
            return tuple(part.strip().lower() for part in raw.split(",") if part.strip())

        return cls(
            salt=load_salt(env),
            own_domains=csv("WATCHDESK_OWN_DOMAINS"),
            own_mailboxes=csv("WATCHDESK_OWN_MAILBOXES"),
            own_hostnames=csv("WATCHDESK_OWN_HOSTNAMES"),
        )


class Redactor:
    """Applies a :class:`RedactionPolicy` to text or to nested data."""

    def __init__(
        self,
        policy: RedactionPolicy,
        style: Style = Style.PSEUDONYM,
        preset: Mapping[str, str] | None = None,
    ) -> None:
        self.policy = policy
        self.style = style
        # original -> replacement, for the fixture-baking workflow.  Written to
        # a file that .gitignore keeps out of the repo; it is a reverse lookup
        # table for every substitution made.
        #
        # ``preset`` carries that table forward into a later bake. Two fixtures
        # captured from the same server on adjacent days have to agree on which
        # placeholder stands for which real address, or every cross-fixture
        # comparison — the whole point of having two — silently compares
        # unrelated attackers.
        self.mapping: dict[str, str] = dict(preset or {})
        self._used: set[str] = set(self.mapping.values())

    # -- token helpers -------------------------------------------------

    def _token(self, kind: str, value: str) -> str:
        """Stable 6-hex pseudonym for ``value`` within namespace ``kind``.

        HMAC rather than ``hash(salt + value)``: the length-extension property
        of a plain salted digest is not exploitable here, but HMAC is the
        primitive that is actually specified for keyed hashing and costs
        nothing extra.
        """
        digest = hmac.new(
            self.policy.salt.encode("utf-8"),
            f"{kind}\x00{value.lower()}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return digest[:6]

    def _record(self, original: str, replacement: str) -> str:
        self.mapping[original] = replacement
        self._used.add(replacement)
        return replacement

    def _seen(self, original: str) -> str | None:
        """Whatever this exact value was replaced with before.

        Consulted first by every rule, so a value keeps one identity for the
        life of the redactor and across bakes that share a mapping.
        """
        return self.mapping.get(original)

    # -- public API ----------------------------------------------------

    def text(self, value: str) -> str:
        """Redact a single string.

        Rule order matters and is not arbitrary:

        * IPv6 before IPv4, because ``::ffff:203.0.113.9`` embeds an IPv4.
        * addresses before FQDNs, so a reverse-DNS name has its octets removed
          before the name itself is pseudonymised.
        * paths last, because a path can contain any of the above.
        """
        if not value:
            return value
        out = _JSON_ANGLE.sub(lambda m: _SENTINELS[m.group(1).lower()], value)
        out = _HEX64.sub(self._sub_container_id, out)
        out = _EMAIL.sub(self._sub_email, out)
        out = _IPV6_CANDIDATE.sub(self._sub_ipv6, out)
        out = _IPV4.sub(self._sub_ipv4, out)
        out = _URL.sub(self._sub_url, out)
        out = self._sub_own_hostnames(out)
        # FQDNs before the dashed-quad rule, so that a reverse-DNS name such as
        # 198-51-100-23.dynamic-ip.example.net is replaced as a single unit.
        # The other order pseudonymises the octets first and then re-matches the
        # remainder, producing a nested "ip:host:abc123" mess.
        out = _FQDN.sub(self._sub_fqdn, out)
        out = _IPV4_DASHED.sub(self._sub_ipv4_dashed, out)
        out = _ABS_PATH.sub(self._sub_path, out)
        return _SENTINEL_RE.sub(lambda m: _UNSENTINEL[m.group(0)], out)

    def value(self, obj: Any) -> Any:
        """Redact recursively through dicts, lists, tuples and sets.

        Dictionary *keys* are redacted too: per-source counters are routinely
        keyed by address, and a key is just as public as a value.
        """
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.value(k): self.value(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.value(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.value(v) for v in obj)
        if isinstance(obj, set):
            return {self.value(v) for v in obj}
        return obj

    # -- individual rules ----------------------------------------------

    def _sub_container_id(self, match: re.Match[str]) -> str:
        cid = match.group(0)
        if (seen := self._seen(cid)) is not None:
            return seen
        if self.style is Style.PLACEHOLDER:
            # Container IDs are not identifying, but a 64-char hex string in a
            # fixture is noise; collapse it to something readable and stable.
            return self._record(cid, f"{self._token('cid', cid)}{'0' * 58}")
        return self._record(cid, f"cid:{self._token('cid', cid)}")

    def _sub_email(self, match: re.Match[str]) -> str:
        address = match.group(0)
        if (seen := self._seen(address)) is not None:
            return seen
        if self.style is Style.PLACEHOLDER and _REDACTED_EMAIL.match(address):
            # Only in baking. In PSEUDONYM style these placeholders must still
            # be replaced: a baked fixture goes out through the runtime exit at
            # replay time, and the leak check there does not know an address is
            # a placeholder — nor should it, since by then it is too late to
            # tell.
            return address
        local, _, domain = address.partition("@")
        ours = (
            domain.lower() in self.policy.own_domains
            or local.lower() in self.policy.own_mailboxes
        )
        if self.style is Style.PLACEHOLDER:
            if ours:
                return self._record(address, "owner@example.com")
            return self._record(address, f"user{self._token('mbox', address)}@example.net")
        if ours:
            return self._record(address, "mbox:own")
        return self._record(address, f"mbox:{self._token('mbox', address)}")

    def _sub_ipv6(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return raw  # a timestamp, a MAC, a hex blob — not an address
        return self._replace_address(raw, addr)

    def _sub_ipv4(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return raw
        return self._replace_address(raw, addr)

    def _sub_ipv4_dashed(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            addr = ipaddress.ip_address(raw.replace("-", "."))
        except ValueError:
            return raw
        replacement = self._replace_address(raw.replace("-", "."), addr)
        if self.style is Style.PLACEHOLDER:
            replacement = replacement.replace(".", "-")
        return self._record(raw, replacement)

    @staticmethod
    def _is_documentation(addr: ipaddress._BaseAddress) -> bool:
        """Whether an address is from a documentation range.

        Python reports these as non-global, so without this check a baked
        fixture's stand-in for an attacker comes back through the runtime
        redactor labelled ``ip:private-...`` — telling a reader the traffic
        came from inside the network when it represents the opposite.
        """
        return any(addr in network for network in _DOC_NETWORKS)

    def _replace_address(self, raw: str, addr: ipaddress._BaseAddress) -> str:
        if (seen := self._seen(raw)) is not None:
            return seen
        if self.style is Style.PLACEHOLDER:
            if not addr.is_global:
                # RFC1918 / loopback / link-local identify no one, and keeping
                # them intact preserves the meaning of a fixture (the Docker
                # gateway really is 172.19.0.1 on that host, and rules key off
                # exactly that).
                return raw
            return self._record(raw, self._placeholder_address(raw, addr))
        if addr.is_loopback:
            return self._record(raw, "ip:loopback")
        if not addr.is_global and not self._is_documentation(addr):
            return self._record(raw, f"ip:private-{self._token('ip', raw)}")
        return self._record(raw, f"ip:{self._token('ip', raw)}")

    def _placeholder_address(self, raw: str, addr: ipaddress._BaseAddress) -> str:
        """Allocate an unused address from a documentation range (RFC 5737 / 3849).

        Sequential-with-skip rather than a truncated hash: a fixture in which
        two attackers collapse onto one address would silently break every
        per-source rate rule, and a 6-hex hash cannot promise they will not.
        Skipping values already in ``_used`` is what lets a second bake share
        the first one's mapping without colliding with it.
        """
        blocks = ("192.0.2", "198.51.100", "203.0.113")
        index = 0
        while True:
            if addr.version == 6:
                candidate = f"2001:db8::{index + 1:x}"
            else:
                candidate = f"{blocks[(index // 254) % len(blocks)]}.{index % 254 + 1}"
            if candidate not in self._used:
                return candidate
            index += 1

    def _sub_url(self, match: re.Match[str]) -> str:
        """Keep the shape of a URL, lose its identity.

        The scheme and the fact that there was a path survive, because "an
        HTTPS link with a path" is what makes a piece of evidence legible. The
        host and everything after it do not. The replacement is deliberately
        shaped so no later rule matches it again: the host token has no dots
        for the FQDN rule, and ``/<path>`` has no path-legal character after
        the slash.
        """
        url = match.group(0)
        if (seen := self._seen(url)) is not None:
            return seen
        if _REDACTED_URL.match(url):
            return url
        scheme = match.group("scheme")
        host = match.group("host")
        port = match.group("port") or ""
        rest = match.group("rest") or ""

        if host.lower().endswith(_DOC_DOMAINS):
            # Already a placeholder; leave the whole thing alone so example
            # URLs in documentation stay readable.
            return url

        if self.style is Style.PLACEHOLDER:
            replacement = f"{scheme}://host{self._token('host', host)}.example.net{port}"
        else:
            replacement = f"{scheme}://host:{self._token('host', host)}{port}"
        if rest and rest != "/":
            replacement += "/<path>"
        return self._record(url, replacement)

    def _sub_own_hostnames(self, value: str) -> str:
        """Replace configured hostnames, including their bare first label.

        The FQDN rule below cannot catch ``mail-01`` on its own —
        syslog prints the short hostname with no dots at all.

        Two things make this one pass over a single alternation rather than a
        loop of substitutions, and both are bugs that were observed rather
        than imagined:

        * A loop re-reads its own output. With ``mail`` configured, the first
          substitution produced ``mail.example.com`` and the next pass matched
          the ``mail`` inside it, yielding ``mail.example.com.example.com``.
        * A bare short name is also the first label of longer names. Without
          the lookahead below, ``mail`` inside ``mail.example.org`` is
          replaced on its own, corrupting a domain the FQDN rule was about to
          handle properly.
        """
        forms = []
        for hostname in self.policy.own_hostnames:
            for form in (hostname, hostname.split(".")[0]):
                if form and form not in forms:
                    forms.append(form)
        if not forms:
            return value

        # Longest first, so a configured FQDN wins over its own short form.
        pattern = re.compile(
            r"(?<![\w.\-])(?:"
            + "|".join(re.escape(form) for form in sorted(forms, key=len, reverse=True))
            + r")(?![\w\-]|\.[A-Za-z0-9])",
            re.IGNORECASE,
        )
        replacement = "mail.example.com" if self.style is Style.PLACEHOLDER else "host:self"

        def substitute(match: re.Match[str]) -> str:
            return self._record(match.group(0), replacement)

        return pattern.sub(substitute, value)

    def _sub_fqdn(self, match: re.Match[str]) -> str:
        name = match.group(0)
        if (seen := self._seen(name)) is not None:
            return seen
        tld = name.rstrip(".").rsplit(".", 1)[-1].lower()
        if tld in _NOT_A_TLD:
            return name  # a filename, not a host
        if tld not in _KNOWN_TLDS:
            # Dotted identifiers are everywhere in this data and are not hosts:
            # logger names (fail2ban.filter, fail2ban.actions), module paths
            # (watchdesk.sources.postfix), setting names. Redacting them
            # corrupts the evidence — a baked fixture whose logger names became
            # host9a3f.example.net stops parsing as a fail2ban log at all,
            # which is how this rule was found.
            #
            # The trade-off is deliberate and worth stating: a hostname under a
            # TLD missing from this list is NOT redacted. What that can expose
            # is a third party's reverse-DNS name. The operator's own identity
            # does not depend on this list — own_domains and own_hostnames are
            # matched explicitly, whatever their TLD — and neither does any
            # address, which is handled before this rule runs. Extend the list
            # if these logs start carrying hosts under a newer TLD.
            return name
        if name.lower().rstrip(".").endswith(_DOC_DOMAINS):
            # Already a placeholder: either something this redactor emitted
            # earlier in the pass, or a documentation domain that identifies
            # nobody.  Re-redacting it would double-substitute our own output.
            return name
        if name.lower().rstrip(".") in self.policy.own_domains:
            return self._record(
                name, "example.com" if self.style is Style.PLACEHOLDER else "domain:own"
            )
        if self.style is Style.PLACEHOLDER:
            return self._record(name, f"host{self._token('host', name)}.example.net")
        return self._record(name, f"host:{self._token('host', name)}")

    def _sub_path(self, match: re.Match[str]) -> str:
        path = match.group(0)
        if (seen := self._seen(path)) is not None:
            return seen
        if self.style is Style.PLACEHOLDER and _REDACTED_PATH.match(path):
            return path
        if any(path == p or path.startswith(p + "/") for p in self.policy.path_allowlist):
            return path
        if self.style is Style.PLACEHOLDER:
            return self._record(path, f"/redacted/path{self._token('path', path)}")
        return self._record(path, f"path:{self._token('path', path)}")
