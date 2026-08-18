"""OpenAI-compatible chat client, with redaction welded to the exit.

Two things matter more than the HTTP:

**Nothing can be sent un-redacted.** ``complete()`` redacts its arguments and
then runs the independent leak check over the result before opening a socket.
A caller that forgets to redact still cannot leak; a bug in ``redact.py``
raises instead of publishing. That is a deliberate trade — a round that fails
to report is a problem the operator sees and fixes, and a round that published
an address is not undoable.

**The LLM is an enhancement, never a dependency.** Every caller here is
expected to carry on without it. The rules produced the findings; the model
only writes about them.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import httpx

from .leakcheck import guard
from .redact import Redactor

__all__ = [
    "LLMClient",
    "LLMError",
    "LLMResponse",
    "OpenAICompatibleClient",
    "RecordedLLM",
    "build_client",
]


class LLMError(RuntimeError):
    """Any failure to obtain a usable completion. Never fatal to a round."""


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    usage: dict[str, Any] = field(default_factory=dict)
    latency_s: float = 0.0
    recorded: bool = False

    def json(self) -> Any:
        """Parse the response as JSON, tolerating the usual wrappers.

        Models fenced the JSON in ```json blocks for years and some still do,
        even when asked for a bare object. Refusing to cope with that would
        make the pipeline fail for a formatting habit rather than for anything
        that matters.
        """
        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
            if text.rstrip().endswith("```"):
                text = text.rstrip()[: -len("```")]
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise LLMError(f"response contained no JSON object: {self.text[:200]!r}")
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise LLMError(f"response was not valid JSON: {exc}") from exc


@runtime_checkable
class LLMClient(Protocol):
    model: str

    def complete(self, system: str, user: str, *, json_object: bool = True) -> LLMResponse: ...


class OpenAICompatibleClient:
    """Talks to any /v1/chat/completions endpoint.

    Pointed by default at the operator's own CLIProxyAPI, which is why the
    base URL is configured as the full endpoint rather than assembled from a
    host: proxies vary in where they mount it, and guessing the path is how
    you get a 404 that looks like an auth failure.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        redactor: Redactor,
        timeout_s: float = 60.0,
        max_output_tokens: int = 900,
        temperature: float = 0.1,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self._api_key = api_key
        self.redactor = redactor
        self.timeout_s = timeout_s
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature

    def complete(self, system: str, user: str, *, json_object: bool = True) -> LLMResponse:
        # Redact, then verify. Redaction is idempotent here because the
        # replacements are not shaped like their inputs — ip:7f3a2c contains no
        # dots for the hostname rule to catch, mbox:own has no @ — so applying
        # it to already-redacted text is a no-op rather than a corruption.
        system = guard(self.redactor.text(system), "the LLM endpoint")
        user = guard(self.redactor.text(user), "the LLM endpoint")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        if json_object:
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        started = time.monotonic()
        try:
            response = httpx.post(
                self.base_url, json=payload, headers=headers, timeout=self.timeout_s
            )
        except httpx.HTTPError as exc:
            raise LLMError(f"request to the LLM endpoint failed: {exc}") from exc
        latency = time.monotonic() - started

        if response.status_code >= 400:
            # The body can echo the request, so it is not quoted verbatim: a
            # 400 page containing the prompt would put log lines somewhere
            # nobody redacted.
            raise LLMError(
                f"LLM endpoint returned {response.status_code} "
                f"({len(response.content)} bytes of body, not quoted here)"
            )
        try:
            body = response.json()
            choice = body["choices"][0]["message"]["content"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected response shape from the LLM endpoint: {exc}") from exc

        return LLMResponse(
            text=choice or "",
            model=str(body.get("model", self.model)),
            usage=body.get("usage") or {},
            latency_s=latency,
        )


class RecordedLLM:
    """Replays recorded completions, for tests and offline development.

    Responses are consumed in order. Running out raises rather than returning
    something plausible — a test that silently gets an empty completion would
    pass for the wrong reason, and "looks fine but saw nothing" is the failure
    mode this whole project is about.
    """

    def __init__(self, responses: list[str] | str | Path, model: str = "recorded") -> None:
        if isinstance(responses, (str, Path)):
            loaded = json.loads(Path(responses).read_text(encoding="utf-8"))
            responses = loaded["responses"] if isinstance(loaded, dict) else loaded
        self._responses = [
            item if isinstance(item, str) else json.dumps(item) for item in responses
        ]
        self._index = 0
        self.model = model
        #: Every prompt this client was asked to send, so a test can assert on
        #: what would have gone out — including that it was redacted.
        self.requests: list[tuple[str, str]] = []

    def complete(self, system: str, user: str, *, json_object: bool = True) -> LLMResponse:
        self.requests.append((system, user))
        if self._index >= len(self._responses):
            raise LLMError(
                f"recorded LLM has no response {self._index + 1} "
                f"(only {len(self._responses)} recorded)"
            )
        text = self._responses[self._index]
        self._index += 1
        return LLMResponse(text=text, model=self.model, recorded=True)


def build_client(config: Any, redactor: Redactor) -> LLMClient | None:
    """Construct a client from configuration, or ``None`` if it is not set up.

    Returning None rather than raising: an operator who has not configured an
    endpoint should still get rule findings, which are the part that does not
    depend on anyone's API being up.
    """
    env = config.env
    if not env.llm_base_url or not env.llm_model:
        return None
    return OpenAICompatibleClient(
        base_url=env.llm_base_url,
        model=env.llm_model,
        api_key=env.llm_api_key,
        redactor=redactor,
        timeout_s=config.llm.timeout_s,
        max_output_tokens=config.llm.max_output_tokens,
        temperature=config.llm.temperature,
    )
