"""The assertion behind the redaction gate.

Kept out of ``test_redact.py`` on purpose: later stages run the *whole*
pipeline (sources -> rules -> brief -> sink payload) through the same check,
and there must be one definition of "leaked" for all of them.

The check is deliberately blunt.  It does not know which addresses are the
operator's and which are an attacker's; anything that still parses as an
address, an email, or a non-allowlisted absolute path after redaction is a
failure, because by then it is too late to tell.
"""

from __future__ import annotations

import ipaddress
import re

from watchdesk.redact import DEFAULT_PATH_ALLOWLIST

_IPV4 = re.compile(r"(?<![\w.\-])\d{1,3}(?:\.\d{1,3}){3}(?![\w.\-])")
_IPV4_DASHED = re.compile(r"(?<![\w.\-])\d{1,3}(?:-\d{1,3}){3}(?![\w\-])")
_IPV6_CANDIDATE = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{3,45}(?![\w:.])")
_EMAIL = re.compile(r"(?<![\w.\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}(?![\w.\-])")
_ABS_PATH = re.compile(r"(?<![\w.\-@])(?:/[A-Za-z0-9._@+\-]+)+/?")


def _is_address(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def find_leaks(text: str, path_allowlist: tuple[str, ...] = DEFAULT_PATH_ALLOWLIST) -> list[str]:
    """Return every host-identifying token still present in ``text``."""
    leaks: list[str] = []

    leaks += [m.group(0) for m in _IPV4.finditer(text) if _is_address(m.group(0))]
    leaks += [
        m.group(0)
        for m in _IPV4_DASHED.finditer(text)
        if _is_address(m.group(0).replace("-", "."))
    ]
    leaks += [m.group(0) for m in _IPV6_CANDIDATE.finditer(text) if _is_address(m.group(0))]
    leaks += [m.group(0) for m in _EMAIL.finditer(text)]
    leaks += [
        m.group(0)
        for m in _ABS_PATH.finditer(text)
        if not any(m.group(0) == p or m.group(0).startswith(p + "/") for p in path_allowlist)
    ]
    return leaks


def assert_clean(text: str, path_allowlist: tuple[str, ...] = DEFAULT_PATH_ALLOWLIST) -> None:
    leaks = find_leaks(text, path_allowlist)
    assert not leaks, f"redaction leaked {len(leaks)} identifier(s): {sorted(set(leaks))}"
