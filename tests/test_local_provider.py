"""Tests for the Milestone-5 strictly-local, zero-cost Ollama provider.

Covers loopback-only enforcement (remote-host and redirect rejection), strict
structured-output validation, request timeouts, oversized-response caps, a hard
call-count limit, fail-closed error handling, hard-deny invariance and
deterministic policy precedence through the local adapter, the no-network
default path, and experiment-manifest recording of the local model config.

No test opens a real socket: every HTTP interaction is served by an injected
``httpx.MockTransport``. No model is downloaded and no cloud endpoint exists.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from textwrap import dedent

import httpx
import pytest

from agent44.eval_runner import build_manifest
from agent44.local_provider import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    LocalProviderError,
    LocalProviderResponseError,
    OllamaProvider,
    assert_loopback_host,
    local_model_adapter,
)
from agent44.model_adapter import ModelDecisionAdapter
from agent44.policy import Action, AdapterParseError, PolicyEngine
from agent44.proxy import RulesOnlyAdapter, parse_downstream_args

# A valid streamed Ollama body: newline-delimited JSON fragments.
STREAMED_OK = (
    b'{"response":"{\\"action\\": \\"DENY\\",'
    b' \\"reason\\": \\"local deny\\"}", "done": false}\n'
    b'{"done": true}\n'
)

POLICY = dedent(
    """
    version: "1"
    default_deny: true
    allow_tools: [add]
    hard_deny_tools: [shell_exec]
    adapter_tools: [review_tool]
    rules:
      - id: grant-ok
        tool: review_tool
        action: ALLOW
        reason: "review approved"
        when: {field: ok, equals: true}
    """
).lstrip()


def run(coro):
    return asyncio.run(coro)


def engine_for(tmp_path: Path) -> PolicyEngine:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return PolicyEngine.from_path(path)


def provider_with(handler, *, model: str = "llava:7b", **kwargs) -> OllamaProvider:
    """Build a provider whose HTTP is served by ``handler`` (no real socket)."""
    kwargs.setdefault("check_host", False)
    return OllamaProvider(model, transport=httpx.MockTransport(handler), **kwargs)


# --- loopback-only enforcement ---------------------------------------------


def test_loopback_literals_and_names_accepted() -> None:
    assert assert_loopback_host("127.0.0.1") == "127.0.0.1"
    assert assert_loopback_host("::1") == "::1"
    assert assert_loopback_host("localhost") == "localhost"


def test_remote_host_rejected() -> None:
    with pytest.raises(LocalProviderError, match="non-loopback"):
        assert_loopback_host("example.com")
    with pytest.raises(LocalProviderError, match="non-loopback"):
        assert_loopback_host("8.8.8.8")
    with pytest.raises(LocalProviderError, match="non-loopback"):
        assert_loopback_host("192.168.1.5")


def test_remote_host_rejected_at_construction() -> None:
    with pytest.raises(LocalProviderError, match="non-loopback"):
        OllamaProvider("llava:7b", host="api.openai.com")


def test_empty_host_rejected() -> None:
    with pytest.raises(LocalProviderError):
        assert_loopback_host("")


def test_bad_scheme_rejected() -> None:
    with pytest.raises(LocalProviderError, match="scheme"):
        OllamaProvider("llava:7b", scheme="ftp", check_host=False)


def test_invalid_port_timeout_model_rejected() -> None:
    with pytest.raises(LocalProviderError):
        OllamaProvider("llava:7b", port=0, check_host=False)
    with pytest.raises(LocalProviderError):
        OllamaProvider("llava:7b", timeout=0, check_host=False)


# --- strict structured output ----------------------------------------------


def test_streamed_fragments_are_concatenated() -> None:
    provider = provider_with(lambda request: httpx.Response(200, content=STREAMED_OK))
    text = run(provider.complete("prompt"))
    assert text == '{"action": "DENY", "reason": "local deny"}'


def test_malformed_output_raises() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=b"this is not json\n")
    )
    with pytest.raises(LocalProviderError, match="not JSON"):
        run(provider.complete("prompt"))


def test_non_object_line_raises() -> None:
    provider = provider_with(lambda request: httpx.Response(200, content=b"[1,2,3]\n"))
    with pytest.raises(LocalProviderError, match="JSON object"):
        run(provider.complete("prompt"))


def test_missing_response_field_raises() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=b'{"foo": "bar"}\n')
    )
    with pytest.raises(LocalProviderError, match="no 'response' field"):
        run(provider.complete("prompt"))


def test_non_string_fragment_raises() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=b'{"response": 123}\n')
    )
    with pytest.raises(LocalProviderError, match="not a string"):
        run(provider.complete("prompt"))


def test_non_utf8_response_raises() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=b"\xff\xfe\x00bad\n")
    )
    with pytest.raises(LocalProviderError, match="UTF-8"):
        run(provider.complete("prompt"))


def test_empty_prompt_rejected() -> None:
    provider = provider_with(lambda request: httpx.Response(200, content=b"{}"))
    with pytest.raises(LocalProviderError, match="prompt"):
        run(provider.complete(""))


# --- timeouts, redirects, oversized responses, statuses --------------------


def test_timeout_is_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("mock timeout", request=request)

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="request failed"):
        run(provider.complete("prompt"))


def test_redirect_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.example.com/steal"})

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="redirect"):
        run(provider.complete("prompt"))


def test_oversized_response_is_rejected() -> None:
    big = b'{"response":"' + b"a" * (1 << 20) + b'"}\n'
    provider = provider_with(lambda request: httpx.Response(200, content=big))
    with pytest.raises(LocalProviderError, match="exceeded"):
        run(provider.complete("prompt"))


def test_http_error_status_is_rejected() -> None:
    provider = provider_with(lambda request: httpx.Response(500, content=b"oops"))
    with pytest.raises(LocalProviderError, match="HTTP 500"):
        run(provider.complete("prompt"))


def test_hard_call_count_limit() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=STREAMED_OK), max_calls=1
    )
    run(provider.complete("prompt"))
    assert provider.calls_made == 1
    with pytest.raises(LocalProviderError, match="call limit"):
        run(provider.complete("prompt"))
    assert provider.calls_made == 1, "a blocked call must not increment the counter"

    with pytest.raises(LocalProviderError):
        OllamaProvider("", check_host=False)


def test_describe_is_secret_free_loopback_config() -> None:
    provider = provider_with(lambda request: httpx.Response(200, content=b"{}"))
    desc = provider.describe()
    assert desc["provider"] == "ollama-local"
    assert desc["cloud"] is False
    assert desc["host"] == DEFAULT_HOST
    assert desc["port"] == DEFAULT_PORT
    assert desc["base_url"].startswith("http://127.0.0.1:")
    assert desc["model"] == "llava:7b"


# --- availability check (no download) --------------------------------------


def test_ensure_model_available_returns_digest() -> None:
    body = json.dumps({"models": [{"name": "llava:7b", "digest": "sha256:feedbeef"}]}).encode()
    provider = provider_with(lambda request: httpx.Response(200, content=body))
    info = run(provider.ensure_model_available())
    assert info == {"name": "llava:7b", "digest": "sha256:feedbeef"}


def test_ensure_model_available_missing_model_raises() -> None:
    body = json.dumps({"models": [{"name": "other:1b", "digest": "x"}]}).encode()
    provider = provider_with(lambda request: httpx.Response(200, content=body))
    with pytest.raises(LocalProviderError, match="not installed locally"):
        run(provider.ensure_model_available())


def test_ensure_model_available_bad_shape_raises() -> None:
    provider = provider_with(
        lambda request: httpx.Response(200, content=b'{"models": "nope"}')
    )
    with pytest.raises(LocalProviderError, match="unexpected /api/tags shape"):
        run(provider.ensure_model_available())


def test_ensure_model_available_never_downloads() -> None:
    """The availability check is a read-only GET; it must never issue a pull."""
    seen: list[str] = []
    body = json.dumps({"models": [{"name": "llava:7b", "digest": "d"}]}).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, content=body)

    provider = provider_with(handler)
    run(provider.ensure_model_available())
    assert seen == ["/api/tags"], "only the read-only tags endpoint may be hit"


def test_prompt_body_has_no_raw_arguments_or_credentials() -> None:
    """The outbound body carries only the sanitized prompt + model tag."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200, content=STREAMED_OK)

    provider = provider_with(handler)
    run(provider.complete("tool: shell_exec arguments_summary: {}"))
    body = captured["body"]
    assert "temperature" in body
    assert "api_key" not in body and "authorization" not in body


# --- engine integration: hard-deny invariance & precedence -----------------


def test_hard_deny_invariant_through_local_adapter(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    provider = provider_with(lambda request: httpx.Response(200, content=STREAMED_OK))
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("shell_exec", {"command": "id"}, adapter))
    assert decision.action is Action.DENY
    assert provider.calls_made == 0, "hard-deny must never reach the local model"


def test_deterministic_allow_bypasses_local_adapter(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    provider = provider_with(lambda request: httpx.Response(200, content=STREAMED_OK))
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("review_tool", {"ok": True}, adapter))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "grant-ok"
    assert provider.calls_made == 0, "deterministic ALLOW must bypass the model"


def test_local_provider_exception_fails_closed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    provider = provider_with(handler)
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_error"


def test_local_provider_malformed_model_output_fails_closed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    provider = provider_with(
        lambda request: httpx.Response(200, content=b"garbage not json\n")
    )
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    # Malformed wire content is a response-parse failure (adapter_invalid);
    # transport/status failures above stay adapter_error.
    assert decision.rule_id == "adapter_invalid"
    assert "LocalProviderResponseError" in decision.reason


def test_local_model_allow_is_honored_when_undecided(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    allow = b'{"response":"{\\"action\\": \\"ALLOW\\",\\"reason\\": \\"ok\\"}"}\n'
    provider = provider_with(lambda request: httpx.Response(200, content=allow))
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.ALLOW
    assert provider.calls_made == 1


def test_local_adapter_model_name_is_tagged() -> None:
    provider = provider_with(lambda request: httpx.Response(200, content=b"{}"))
    adapter = local_model_adapter(provider)
    assert isinstance(adapter, ModelDecisionAdapter)
    assert adapter.model_name == "ollama-local:llava:7b"



# --- no-network default & opt-in -------------------------------------------


def test_default_proxy_path_is_rules_only_not_local() -> None:
    """Without --local-model the proxy must use the offline rules-only adapter."""
    _params, _observer, _policy, adapter = parse_downstream_args(["--", "python", "s.py"])
    assert isinstance(adapter, RulesOnlyAdapter)


def test_local_model_flag_builds_local_adapter() -> None:
    """--local-model with an invalid (remote) host exits before any network I/O."""
    with pytest.raises(SystemExit) as excinfo:
        parse_downstream_args(
            [
                "--local-model",
                "llava:7b",
                "--local-model-host",
                "example.com",
                "--",
                "python",
                "s.py",
            ]
        )
    assert excinfo.value.code == 2


def test_local_model_precedence_over_replay(tmp_path: Path) -> None:
    fixture = tmp_path / "replay.json"
    fixture.write_text("[]", encoding="utf-8")
    # A remote host is rejected at construction, proving --local-model wins and
    # the (valid) replay fixture is never consulted.
    with pytest.raises(SystemExit) as excinfo:
        parse_downstream_args(
            [
                "--adapter-replay",
                str(fixture),
                "--local-model",
                "llava:7b",
                "--local-model-host",
                "example.com",
                "--",
                "python",
                "s.py",
            ]
        )
    assert excinfo.value.code == 2


# --- experiment manifest records the local model ---------------------------


def test_manifest_records_local_model_config() -> None:
    lm = {
        "model": "llava:7b",
        "host": "127.0.0.1",
        "port": 11434,
        "timeout_seconds": 60.0,
        "max_calls": 256,
        "digest": "sha256:feedbeef",
    }
    manifest = build_manifest(local_model=lm)
    assert manifest["local_model"] == lm
    # The recorded block must not contain credentials.
    blob = json.dumps(manifest).lower()
    assert "api_key" not in blob and "authorization" not in blob


def test_manifest_local_model_none_by_default() -> None:
    manifest = build_manifest()
    assert manifest["local_model"] is None


# --- response-parse failures, hard-rule invariance (Milestone 4d) ------------


def test_response_error_is_both_provider_and_parse_error() -> None:
    assert issubclass(LocalProviderResponseError, LocalProviderError)
    assert issubclass(LocalProviderResponseError, AdapterParseError)


def test_response_shape_failures_raise_response_error() -> None:
    for body in (
        b"garbage not json\n",
        b"\xff\xfe not utf8\n",
        b'"just a string"\n',
        b'{"response": 42}\n',
    ):
        provider = provider_with(lambda request, body=body: httpx.Response(200, content=body))
        with pytest.raises(LocalProviderResponseError):
            run(provider.complete("prompt"))


def test_hard_rule_on_adapter_tool_cannot_be_overridden(tmp_path: Path) -> None:
    """A hard-deny rule on an adapter-tier tool always wins over model ALLOW."""
    policy = dedent(
        """
        version: "1"
        default_deny: true
        adapter_tools: [review_tool]
        rules:
          - id: review-tool-locked
            tool: review_tool
            action: DENY
            when:
              field: ok
              field_exists: true
            reason: "review is locked during the pilot"
            hard: true
        """
    ).lstrip()
    path = tmp_path / "policy.yaml"
    path.write_text(policy, encoding="utf-8")
    engine = PolicyEngine.from_path(path)
    allow_body = json.dumps({"response": json.dumps({"action": "ALLOW", "reason": "ok"})})
    provider = provider_with(
        lambda request: httpx.Response(200, content=(allow_body + "\n").encode("utf-8"))
    )
    adapter = local_model_adapter(provider)
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "review-tool-locked"
    assert provider.calls_made == 0, "hard rules must decide before the adapter tier"

