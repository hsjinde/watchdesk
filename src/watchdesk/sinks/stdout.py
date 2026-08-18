"""The default sink: print it.

Deliberately does no suppression. A person who typed the command is asking to
see the result now, whatever was sent to Discord an hour ago.
"""

from __future__ import annotations

from ..brief import Brief
from .base import SinkResult

__all__ = ["StdoutSink"]


class StdoutSink:
    name = "stdout"

    def deliver(self, brief: Brief) -> SinkResult:
        print(brief.render())
        return SinkResult(True, "printed")
