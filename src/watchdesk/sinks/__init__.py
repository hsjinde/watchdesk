"""Where a brief goes once it exists."""

from .base import Sink, SinkResult, suppression_digest
from .discord import DiscordSink
from .stdout import StdoutSink

__all__ = ["DiscordSink", "Sink", "SinkResult", "StdoutSink", "suppression_digest"]
