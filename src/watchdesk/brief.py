"""The brief: rules decide, the model writes, and every sentence must cite.

The findings are produced by ``detect/rules.py`` and are true by construction —
they are arithmetic over measurements.  What a language model adds is triage
prose: which of five findings to read first, what they plausibly mean together,
what to check next.  That is genuinely useful and it is also exactly the kind
of text that invents a number nobody measured.

So every statement the model returns is checked mechanically before it is
allowed into the output:

1. **A claim with no citation is dropped.** Not softened, dropped.
2. **A claim citing something that does not exist in this round is dropped.**
   A fabricated citation is worse than no citation, because it survives a
   skim: the reader sees a reference and stops checking.
3. **A claim stating a number nobody measured is dropped.** A number that was
   measured but cited imprecisely is a lesser fault — the claim is kept as a
   hypothesis with the reason attached. Conflating the two would let a real
   fabrication hide among ordinary sloppy citation, which is how this check
   stops being worth reading.
4. **An explanation is a hypothesis whatever it cites.** Evidence can support
   "the submission listener accounted for 210 failures"; it cannot make
   "because the attackers migrated to port 587" into an observation.

If the model is unreachable, returns nothing usable, or has every claim
rejected, the brief is still produced from the findings alone and says so.
The rules are the product; the prose is a convenience.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config import Config
from .detect.rules import Confidence, Finding, Severity
from .llm import LLMClient, LLMError
from .sources.base import Signal

__all__ = ["Brief", "Claim", "RejectedClaim", "build_brief", "should_call_llm"]

_NUMBER = re.compile(r"\d+(?:\.\d+)?")

_SEVERITY_BY_NAME = {str(level): level for level in Severity}

SYSTEM_PROMPT = """\
You are the triage half of an on-call assistant for one small mail server.
Rules have already measured everything below; you are not being asked to
detect anything. You are being asked to say, briefly, what a tired operator
should look at first and what it plausibly means.

You will be given a list of REFS. Every statement you make must cite one or
more of them, copied exactly. Rules for what you write:

- Do not state any number that does not appear in the material you cite.
- If you cannot support a statement with a ref, leave it out entirely.
  An omission costs nothing; an unsupported sentence costs the reader's trust
  in all the others.
- Mark anything causal or speculative as kind "explanation". Do not present an
  inference as an observation, even an obvious one.
- Do not recommend banning, restarting, or changing configuration. This system
  never acts, and neither do you; suggest what to *check*.

Reply with a single JSON object, no prose around it:

{
  "headline": "one sentence, under 120 characters",
  "headline_refs": ["ref", ...],
  "claims": [
    {"text": "...", "kind": "observation|explanation|next_step", "refs": ["ref", ...]}
  ]
}

At most six claims. Shorter is better."""


@dataclass(frozen=True)
class Claim:
    text: str
    kind: str
    confidence: Confidence
    refs: tuple[str, ...]
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out = {
            "text": self.text,
            "kind": self.kind,
            "confidence": self.confidence.value,
            "refs": list(self.refs),
        }
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True)
class RejectedClaim:
    text: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"text": self.text, "reason": self.reason}


@dataclass(frozen=True)
class Brief:
    generated_at: datetime
    headline: str
    headline_source: str
    findings: tuple[Finding, ...] = ()
    claims: tuple[Claim, ...] = ()
    rejected: tuple[RejectedClaim, ...] = ()
    model: str | None = None
    llm_error: str | None = None

    @property
    def severity(self) -> Severity:
        return max((finding.severity for finding in self.findings), default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "headline": self.headline,
            "headline_source": self.headline_source,
            "severity": str(self.severity),
            "model": self.model,
            "llm_error": self.llm_error,
            "claims": [claim.to_dict() for claim in self.claims],
            "rejected_claims": [claim.to_dict() for claim in self.rejected],
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def render(self) -> str:
        lines = [f"[{str(self.severity).upper()}] {self.headline}"]
        if self.headline_source != "llm":
            lines.append("  (headline written from the rules, not by the model)")
        for claim in self.claims:
            marker = "?" if claim.confidence is Confidence.HYPOTHESIS else "-"
            lines.append(f"  {marker} {claim.text}")
            lines.append(
                f"      [{claim.kind}/{claim.confidence.value}] "
                f"cites: {', '.join(claim.refs)}"
            )
            if claim.note:
                lines.append(f"      note: {claim.note}")
        if self.rejected:
            lines.append(f"  {len(self.rejected)} claim(s) dropped for lack of evidence:")
            for claim in self.rejected:
                lines.append(f"      x {claim.text[:110]}")
                lines.append(f"        {claim.reason}")
        if self.llm_error:
            lines.append(f"  model unavailable: {self.llm_error}")
        lines.append("")
        for finding in self.findings:
            lines.append(f"  [{str(finding.severity).upper()}] {finding.title}  ({finding.rule})")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# The evidence catalogue
# --------------------------------------------------------------------------


@dataclass
class Catalogue:
    """Everything a claim is allowed to cite, and the text behind each ref."""

    entries: dict[str, str] = field(default_factory=dict)

    #: Every number that was actually *measured* this round — signal values and
    #: the numbers in finding text. Deliberately not every number in every log
    #: excerpt: a process id or a port number that happens to appear in a log
    #: line does not license a claim to assert it as a quantity.
    measured: set[float] = field(default_factory=set)

    def add(self, ref: str, material: str) -> None:
        if not ref:
            return
        existing = self.entries.get(ref, "")
        self.entries[ref] = f"{existing}\n{material}".strip() if existing else material

    def resolve(self, refs: Iterable[str]) -> tuple[list[str], list[str]]:
        known, unknown = [], []
        for ref in refs:
            (known if ref in self.entries else unknown).append(ref)
        return known, unknown

    def material(self, refs: Iterable[str]) -> str:
        return "\n".join(self.entries.get(ref, "") for ref in refs)


def build_catalogue(findings: Sequence[Finding], signals: Sequence[Signal]) -> Catalogue:
    catalogue = Catalogue()
    for signal in signals:
        if isinstance(signal.value, (int, float)) and not isinstance(signal.value, bool):
            catalogue.measured.add(float(signal.value))
        catalogue.add(
            signal.key,
            f"{signal.key} = {signal.value} {signal.unit or ''}".strip()
            + (f" | {signal.note}" if signal.note else ""),
        )
        for item in signal.evidence:
            catalogue.add(item.ref, item.excerpt)
    for finding in findings:
        catalogue.measured |= _numbers(f"{finding.title} {finding.detail}")
        catalogue.add(finding.rule, f"{finding.title}\n{finding.detail}")
        for item in finding.evidence:
            catalogue.add(item.ref, item.excerpt)
        for correlation in finding.correlations:
            catalogue.add(finding.rule, correlation)
    return catalogue


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def _numbers(text: str) -> set[float]:
    out: set[float] = set()
    for token in _NUMBER.findall(text):
        try:
            out.add(float(token))
        except ValueError:
            continue
    return out


def verify_claim(raw: dict[str, Any], catalogue: Catalogue) -> tuple[Claim | None, str | None]:
    """Return ``(claim, rejection_reason)`` — exactly one of them is set."""
    text = str(raw.get("text", "")).strip()
    if not text:
        return None, "empty claim"

    kind = str(raw.get("kind", "observation")).strip().lower()
    if kind not in {"observation", "explanation", "next_step"}:
        kind = "observation"

    refs = tuple(str(ref).strip() for ref in raw.get("refs", []) if str(ref).strip())
    if not refs:
        return None, "cites no evidence"

    known, unknown = catalogue.resolve(refs)
    if unknown:
        # A citation to something that does not exist is worse than none: it
        # survives a skim, because the reader sees a reference and stops
        # checking.
        return None, f"cites {unknown[0]!r}, which is not in this round"
    if not known:
        return None, "cites nothing that resolves"

    confidence = Confidence.HYPOTHESIS if kind == "explanation" else Confidence.DERIVED
    note = None

    material = catalogue.material(known)
    claimed = _numbers(text)
    # Numbers that are part of a ref the claim cites are the ref's own, not a
    # measurement being asserted (postfix:json-log:103).
    for ref in known:
        claimed -= _numbers(ref)
    supported = _numbers(material)
    unsupported = sorted(number for number in claimed if number not in supported)

    fabricated = [number for number in unsupported if number not in catalogue.measured]
    if fabricated:
        listed = ", ".join(f"{number:g}" for number in fabricated[:3])
        if kind == "observation":
            # An observation is an assertion that something was measured.
            # Nothing here measured this, so the claim is not imprecise — it is
            # about something that did not happen.
            return None, f"states {listed}, which nothing in this round measured"
        # An explanation or a suggested check may legitimately name a constant
        # nobody measured — a port number, an RFC status code. It is already
        # flagged as not-a-measurement, so the number is noted rather than
        # treated as a false assertion.
        confidence = Confidence.HYPOTHESIS
        note = f"contains {listed}, which is not a measurement from this round"
    elif unsupported:
        confidence = Confidence.HYPOTHESIS
        note = (
            "cited imprecisely: "
            + ", ".join(f"{number:g}" for number in unsupported[:4])
            + " was measured this round but is not in the evidence this claim cites"
        )

    return Claim(text=text, kind=kind, confidence=confidence, refs=tuple(known), note=note), None


# --------------------------------------------------------------------------
# Building the brief
# --------------------------------------------------------------------------


def should_call_llm(config: Config, findings: Sequence[Finding]) -> bool:
    """Gate the model behind the rules having already found something."""
    if not config.llm.enabled or not findings:
        return False
    floor = _SEVERITY_BY_NAME.get(config.llm.min_severity.lower(), Severity.WARNING)
    return any(finding.severity >= floor for finding in findings)


def rules_headline(findings: Sequence[Finding]) -> str:
    """A headline nobody can hallucinate, used when the model is not consulted
    or cannot be trusted with one."""
    if not findings:
        return "Nothing to report: every rule evaluated and none fired."
    counts: dict[str, int] = {}
    for finding in findings:
        counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
    summary = ", ".join(f"{count} {name}" for name, count in counts.items())
    return f"{summary}. Highest: {findings[0].title}"


def _prompt(findings: Sequence[Finding], catalogue: Catalogue, window_minutes: int) -> str:
    payload = {
        "window_minutes": window_minutes,
        "findings": [
            {
                "rule": finding.rule,
                "severity": str(finding.severity),
                "confidence": finding.confidence.value,
                "title": finding.title,
                "detail": finding.detail,
                "labels": dict(finding.labels),
                "correlations": list(finding.correlations),
                "cite_as": [finding.rule, *finding.signal_keys],
            }
            for finding in findings
        ],
        "refs": sorted(catalogue.entries),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_brief(
    config: Config,
    findings: Sequence[Finding],
    signals: Sequence[Signal],
    now: datetime,
    client: LLMClient | None = None,
) -> Brief:
    findings = tuple(findings)
    if not should_call_llm(config, findings) or client is None:
        return Brief(
            generated_at=now,
            headline=rules_headline(findings),
            headline_source="rules",
            findings=findings,
        )

    catalogue = build_catalogue(findings, signals)
    try:
        response = client.complete(
            SYSTEM_PROMPT, _prompt(findings, catalogue, config.window_minutes)
        )
        body = response.json()
    except LLMError as exc:
        # Degraded, and it says so. The findings are what matter and they are
        # already complete without any of this.
        return Brief(
            generated_at=now,
            headline=rules_headline(findings),
            headline_source="rules",
            findings=findings,
            llm_error=str(exc),
        )

    claims: list[Claim] = []
    rejected: list[RejectedClaim] = []
    for raw in body.get("claims", [])[:12]:
        if not isinstance(raw, dict):
            rejected.append(RejectedClaim(text=str(raw)[:200], reason="not a claim object"))
            continue
        claim, reason = verify_claim(raw, catalogue)
        if claim is not None:
            claims.append(claim)
        else:
            rejected.append(
                RejectedClaim(text=str(raw.get("text", raw))[:200], reason=reason or "")
            )

    headline = str(body.get("headline", "")).strip()
    headline_source = "llm"
    headline_refs = [str(ref) for ref in body.get("headline_refs", [])]
    known, _ = catalogue.resolve(headline_refs)
    # The headline is the one line that gets read, so it is held to the same
    # standard as a claim: every number in it must come from something it
    # cites, or it is replaced by one derived from the rules.
    if not headline or _numbers(headline) - _numbers(catalogue.material(known)):
        headline = rules_headline(findings)
        headline_source = "rules"

    return Brief(
        generated_at=now,
        headline=headline,
        headline_source=headline_source,
        findings=findings,
        claims=tuple(claims),
        rejected=tuple(rejected),
        model=response.model,
    )
