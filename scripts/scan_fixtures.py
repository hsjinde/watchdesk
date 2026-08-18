#!/usr/bin/env python3
"""Fail if any committed fixture contains a globally-routable address.

The runtime redaction gate protects what watchdesk *sends*. This protects
what the repository *stores*, which no later check can undo once pushed.

Documentation ranges (RFC 5737 / 3849), RFC 1918 space and loopback are
allowed: fixtures are baked into those on purpose, and a fixture that could
not contain 172.19.0.1 could not represent the Docker gateway that half the
detection rules key on.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

#: The only globally-routable addresses permitted anywhere under tests/.
#: Every documentation range is, by definition, non-global — so a fixture that
#: needs to exercise the "third-party attacker" branch of the redactor has no
#: reserved address to reach for. These two are example.com's own published
#: addresses: they identify IANA's reference host, which is about as far from
#: this server's identity as an address can be. Anything else fails the scan.
ALLOWED = frozenset(
    {
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    }
)

_CANDIDATE = re.compile(r"(?<![\w.\-])\d{1,3}(?:[.\-]\d{1,3}){3}(?![\w.\-])")
_IPV6 = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{3,45}(?![\w:.])")


def offending(text: str) -> list[str]:
    found: list[str] = []
    for match in list(_CANDIDATE.finditer(text)) + list(_IPV6.finditer(text)):
        raw = match.group(0)
        try:
            address = ipaddress.ip_address(raw.replace("-", "."))
        except ValueError:
            continue
        if address.is_global and raw not in ALLOWED:
            found.append(raw)
    return found


def main() -> int:
    failures = 0
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        leaked = offending(text)
        if leaked:
            failures += 1
            rel = path.relative_to(ROOT)
            print(f"{rel}: {len(leaked)} routable address(es): {sorted(set(leaked))[:5]}")
    if failures:
        print("\nBake fixtures through redact.py in PLACEHOLDER style before committing.")
        return 1
    print(f"scanned {FIXTURES.relative_to(ROOT)}: no globally-routable addresses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
