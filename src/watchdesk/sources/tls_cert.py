"""Certificate expiry.

Thresholds here are tied to how renewal actually works rather than to round
numbers.  Let's Encrypt certificates last 90 days and certbot renews at 30
days remaining, so:

* below 21 days, renewal has already failed at least once and nobody noticed;
* below 7 days, it has failed repeatedly and the clock is real.

"30 days left" is not news — it is the renewal window opening. Alerting on it
teaches the reader that this signal is noise, which is how the one at 5 days
gets ignored too.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from ..config import Config
from .base import Evidence, Signal, SignalKind, SourceContext
from .shell import CommandDenied

__all__ = ["TlsCertSource", "parse_openssl"]


def parse_openssl(output: str) -> tuple[datetime | None, str | None]:
    """Pull notAfter and subject out of ``openssl x509 -noout -enddate -subject``."""
    not_after: datetime | None = None
    subject: str | None = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("notAfter="):
            stamp = line.partition("=")[2].strip()
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                try:
                    not_after = datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
        elif line.startswith("subject="):
            subject = line.partition("=")[2].strip()
    return not_after, subject


class TlsCertSource:
    name = "tls_cert"

    def collect(self, ctx: SourceContext) -> Iterable[Signal]:
        config: Config = ctx.config
        if not config.tls.cert_paths:
            return
        for path in config.tls.cert_paths:
            yield from self._one(ctx, path)

    def _one(self, ctx: SourceContext, path: str) -> Iterable[Signal]:
        try:
            result = ctx.runner.run(
                ["openssl", "x509", "-in", path, "-noout", "-enddate", "-subject"]
            )
        except (CommandDenied, FileNotFoundError) as exc:
            yield Signal(
                name="tls.collection_problem",
                kind=SignalKind.ERROR,
                value=f"{path}: {exc}",
                source=self.name,
                labels={"cert": path},
                observed_at=ctx.now,
            )
            return
        if not result.ok:
            # A certificate that cannot be read is not a certificate that is
            # fine. Renewal writes a new file; a missing one after renewal is
            # exactly the failure this source exists to notice.
            yield Signal(
                name="tls.collection_problem",
                kind=SignalKind.ERROR,
                value=f"could not read a certificate at {path}",
                source=self.name,
                labels={"cert": path},
                observed_at=ctx.now,
            )
            return

        not_after, subject = parse_openssl(result.stdout)
        if not_after is None:
            yield Signal(
                name="tls.collection_problem",
                kind=SignalKind.ERROR,
                value=f"{path}: no parseable notAfter",
                source=self.name,
                labels={"cert": path},
                observed_at=ctx.now,
            )
            return

        labels = {"cert": subject or path}
        evidence = (
            Evidence(
                kind="command_output",
                ref=f"openssl x509 -in {path} -noout -enddate",
                excerpt=result.stdout.strip(),
            ),
        )
        days = (not_after - ctx.now).total_seconds() / 86400
        yield Signal(
            name="tls.days_to_expiry",
            kind=SignalKind.METRIC,
            value=round(days, 2),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            unit="days",
            evidence=evidence,
        )
        yield Signal(
            name="tls.not_after",
            kind=SignalKind.STATE,
            value=not_after.isoformat(),
            source=self.name,
            labels=labels,
            observed_at=ctx.now,
            note=(
                "A change here between rounds is a successful renewal, which is the only "
                "positive confirmation certbot gives from outside."
            ),
        )
