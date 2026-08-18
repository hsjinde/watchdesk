"""The last check before anything leaves this machine.

This is the runtime half of the redaction gate.  ``redact.py`` decides what to
replace; this module decides whether the result is safe to send, and it is
called at every exit — before an LLM request, before a sink push — as well as
by the tests.

**The duplicated patterns here are the point.**  It would be tidier to import
the regexes from ``redact.py`` and reuse them.  It would also be useless: a
mistake in a shared pattern would hide itself, since the same blind spot that
failed to redact a value would fail to detect it afterwards.  Two independent
implementations of "what an address looks like" is the only version of this
check worth having.  When you change one, do not change the other to match —
work out which is right.

The check is deliberately blunt.  It does not know which addresses are the
operator's and which are an attacker's; anything that still parses as an
address, an email, or a non-allowlisted absolute path is a failure, because by
then it is too late to tell.
"""

from __future__ import annotations

import ipaddress
import re

from .redact import DEFAULT_PATH_ALLOWLIST

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


class LeakError(RuntimeError):
    """Raised at an exit when redacted output still contains an identifier."""


def assert_clean(text: str, path_allowlist: tuple[str, ...] = DEFAULT_PATH_ALLOWLIST) -> None:
    """Assertion form, for tests."""
    leaks = find_leaks(text, path_allowlist)
    assert not leaks, f"redaction leaked {len(leaks)} identifier(s): {sorted(set(leaks))}"


def guard(
    text: str,
    where: str,
    path_allowlist: tuple[str, ...] = DEFAULT_PATH_ALLOWLIST,
) -> str:
    """Runtime form: refuse to hand over text that still carries identifiers.

    Raising here fails the round.  That is the right trade: a round that did
    not report is a problem the operator notices and fixes, while a round that
    published an address is not undoable.
    """
    leaks = find_leaks(text, path_allowlist)
    if leaks:
        raise LeakError(
            f"refusing to send to {where}: {len(leaks)} identifier(s) survived redaction "
            f"({sorted(set(leaks))[:5]}). This is a bug in redact.py, not a reason to "
            f"bypass this check."
        )
    return text
