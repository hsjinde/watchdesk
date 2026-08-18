"""The client, and the guard welded to it."""

from __future__ import annotations

import json

import pytest

from watchdesk.leakcheck import LeakError
from watchdesk.llm import LLMError, LLMResponse, OpenAICompatibleClient, RecordedLLM, build_client
from watchdesk.redact import RedactionPolicy, Redactor


class NullRedactor:
    """A redactor that does nothing, standing in for a broken one.

    The guard exists precisely for the case where redact.py has a bug, so
    testing it against a working redactor would prove nothing.
    """

    def text(self, value: str) -> str:
        return value

    def value(self, obj):
        return obj


def test_unredacted_content_never_reaches_the_network() -> None:
    client = OpenAICompatibleClient(
        base_url="http://127.0.0.1:1/never-called",
        model="m",
        api_key="",
        redactor=NullRedactor(),
    )
    with pytest.raises(LeakError) as caught:
        client.complete("system", "attacker at 93.184.216.34 hit the submission port")
    assert "survived redaction" in str(caught.value)
    assert "bypass" in str(caught.value)


def test_the_guard_runs_before_any_socket_is_opened() -> None:
    """The base URL below is unroutable. If the guard did not fire first, this
    would fail with a connection error instead."""
    client = OpenAICompatibleClient(
        base_url="http://127.0.0.1:1/never-called",
        model="m",
        api_key="",
        redactor=NullRedactor(),
    )
    with pytest.raises(LeakError):
        client.complete("system", "mailbox operator@example-mail.xyz")


def test_redacted_content_passes_the_guard_and_then_fails_on_the_network() -> None:
    policy = RedactionPolicy(salt="t", own_domains=("example-mail.xyz",))
    client = OpenAICompatibleClient(
        base_url="http://127.0.0.1:1/never-called",
        model="m",
        api_key="",
        redactor=Redactor(policy),
        timeout_s=1.0,
    )
    with pytest.raises(LLMError) as caught:
        client.complete("system", "attacker at 93.184.216.34")
    assert "request to the LLM endpoint failed" in str(caught.value)


def test_recorded_client_replays_in_order() -> None:
    client = RecordedLLM(['{"a": 1}', '{"a": 2}'])
    assert client.complete("s", "u").json() == {"a": 1}
    assert client.complete("s", "u").json() == {"a": 2}


def test_running_out_of_recordings_raises_rather_than_returning_nothing() -> None:
    """An empty completion that looks like a valid one would make a test pass
    for the wrong reason — the exact failure shape this project is about."""
    client = RecordedLLM(['{"a": 1}'])
    client.complete("s", "u")
    with pytest.raises(LLMError):
        client.complete("s", "u")


def test_recorded_client_keeps_the_prompts_for_inspection() -> None:
    client = RecordedLLM(['{"ok": true}'])
    client.complete("system text", "user text")
    assert client.requests == [("system text", "user text")]


def test_fenced_json_is_parsed() -> None:
    response = LLMResponse(text='```json\n{"headline": "x"}\n```', model="m")
    assert response.json() == {"headline": "x"}


def test_prose_around_the_object_is_tolerated() -> None:
    response = LLMResponse(text='Sure! {"headline": "x"} Hope that helps.', model="m")
    assert response.json() == {"headline": "x"}


def test_a_response_with_no_object_is_an_error_not_an_empty_brief() -> None:
    with pytest.raises(LLMError):
        LLMResponse(text="I cannot help with that.", model="m").json()


def test_invalid_json_is_an_error() -> None:
    with pytest.raises(LLMError):
        LLMResponse(text='{"headline": }', model="m").json()


def test_recording_file_can_be_a_json_document(tmp_path) -> None:
    path = tmp_path / "rec.json"
    path.write_text(json.dumps({"responses": [{"headline": "from file"}]}), encoding="utf-8")
    assert RecordedLLM(path).complete("s", "u").json()["headline"] == "from file"


def test_unconfigured_endpoint_yields_no_client_rather_than_an_error() -> None:
    """An operator with no LLM configured still gets rule findings, which are
    the half that does not depend on anyone's API being up."""

    class Env:
        llm_base_url = ""
        llm_model = ""
        llm_api_key = ""

    class Config:
        env = Env()

    assert build_client(Config(), Redactor(RedactionPolicy(salt="t"))) is None
