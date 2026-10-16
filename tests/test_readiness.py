"""Tests for the 4f.6 model-readiness and priming procedure (mocked).

Covers digest validation and model-not-found aborts, already-resident (no
priming) vs nonresident (exactly one priming request) paths, priming timeout /
invalid response / HTTP error / provider error aborts before any scenario
execution, post-priming residency failure, unsafe keep-alive configuration,
the one-priming-request-per-instance cap, and the separation of priming
records from scenario/decision fields.

No test opens a real socket: every HTTP interaction is served by an injected
``httpx.MockTransport``. Mocks validate the procedure logic only — they do
NOT validate live Ollama behavior, and no test issues a real generation
request.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest

from agent44.local_provider import LocalProviderError, LocalProviderResponseError, OllamaProvider
from agent44.readiness import (
    MAX_KEEP_ALIVE_SECONDS,
    MAX_PRIME_TIMEOUT_SECONDS,
    ReadinessError,
    ensure_model_ready,
)

MODEL = "llama3.2:1b"
DIGEST = "baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878"

# A valid streamed Ollama body for the priming prompt.
STREAMED_OK = b'{"response":"OK", "done": false}\n{"done": true}\n'


class TricklingStream(httpx.AsyncByteStream):
    """A streamed Ollama body that keeps yielding valid chunks slowly.

    Every inter-chunk gap stays below the per-phase HTTP read timeout, so no
    phase-level timeout can ever fire; only a total wall-clock deadline can
    stop the stream before it finishes. Records how many chunks were yielded
    (did the total deadline cut the stream short?) and whether the response
    was closed (cleanup attempted on the failure path).
    """

    def __init__(self, *, chunks: int, gap: float) -> None:
        self._chunks = chunks
        self._gap = gap
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for i in range(self._chunks):
            if i:
                await asyncio.sleep(self._gap)
            self.yielded += 1
            if i == self._chunks - 1:
                yield b'{"done": true}\n'
            else:
                yield b'{"response":"warming", "done": false}\n'

    async def aclose(self) -> None:
        self.closed = True


def run(coro):
    return asyncio.run(coro)


def provider_with(handler, *, model: str = MODEL) -> OllamaProvider:
    """Build a provider whose HTTP is served by ``handler`` (no real socket)."""
    return OllamaProvider(model, transport=httpx.MockTransport(handler), check_host=False)


def make_handler(
    *,
    installed_digest: str | None = DIGEST,
    resident_flags: tuple[bool, ...] = (True,),
    generate_response=None,
    tags_status: int = 200,
    ps_shape_bad: bool = False,
) -> tuple[Any, dict[str, Any]]:
    """Return (handler, state); ``resident_flags`` feeds successive /api/ps calls."""
    state: dict[str, Any] = {
        "requests": [],
        "ps_calls": 0,
        "generate_calls": 0,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        state["requests"].append((request.method, path))
        if path == "/api/tags":
            if tags_status != 200:
                return httpx.Response(tags_status, text="tags unavailable")
            models = (
                [] if installed_digest is None else [{"name": MODEL, "digest": installed_digest}]
            )
            return httpx.Response(200, json={"models": models})
        if path == "/api/ps":
            if ps_shape_bad:
                return httpx.Response(200, json={"unexpected": []})
            idx = min(state["ps_calls"], len(resident_flags) - 1)
            resident = resident_flags[idx]
            state["ps_calls"] += 1
            models = [{"name": MODEL, "model": MODEL}] if resident else []
            return httpx.Response(200, json={"models": models})
        if path == "/api/generate":
            state["generate_calls"] += 1
            if generate_response is not None:
                return generate_response(request)
            return httpx.Response(200, content=STREAMED_OK)
        raise AssertionError(f"unexpected request: {request.method} {path}")

    return handler, state


def local_model(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "model": MODEL,
        "digest": DIGEST,
        "keep_alive_seconds": 900.0,
        "prime_timeout_seconds": 30.0,
    }
    base.update(overrides)
    return base


def ensure_ready(handler, **lm_overrides: Any) -> dict[str, Any]:
    provider = provider_with(handler)
    return run(ensure_model_ready(local_model(**lm_overrides), provider=provider))


def ensure_ready_raises(handler, **lm_overrides: Any) -> ReadinessError:
    provider = provider_with(handler)
    with pytest.raises(ReadinessError) as excinfo:
        run(ensure_model_ready(local_model(**lm_overrides), provider=provider))
    return excinfo.value


# --- keep-alive / priming-timeout validation --------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        -1,
        0,
        float("nan"),
        float("inf"),
        -float("inf"),
        "300",
        True,
        False,
        None,
        MAX_KEEP_ALIVE_SECONDS + 1,
    ],
)
def test_validate_keep_alive_rejects_unsafe_values(bad: Any) -> None:
    from agent44.readiness import _validate_keep_alive

    with pytest.raises(ValueError):
        _validate_keep_alive(bad)


@pytest.mark.parametrize("good", [0.5, 60, 900.0, MAX_KEEP_ALIVE_SECONDS])
def test_validate_keep_alive_accepts_bounded_values(good: Any) -> None:
    from agent44.readiness import _validate_keep_alive

    assert _validate_keep_alive(good) == float(good)


@pytest.mark.parametrize(
    "bad",
    [-1, 0, float("nan"), float("inf"), MAX_PRIME_TIMEOUT_SECONDS + 1, "x", True],
)
def test_validate_prime_timeout_rejects_unsafe_values(bad: Any) -> None:
    from agent44.readiness import _validate_prime_timeout

    with pytest.raises(ValueError):
        _validate_prime_timeout(bad)


@pytest.mark.parametrize("good", [1.0, 30, MAX_PRIME_TIMEOUT_SECONDS])
def test_validate_prime_timeout_accepts_bounded_values(good: Any) -> None:
    from agent44.readiness import _validate_prime_timeout

    assert _validate_prime_timeout(good) == float(good)


# --- provider: resident_models (read-only /api/ps) ---------------------------


def test_resident_models_parses_names() -> None:
    handler, _ = make_handler(resident_flags=(True,))
    provider = provider_with(handler)
    assert run(provider.resident_models()) == [MODEL]


def test_resident_models_falls_back_to_model_field() -> None:
    payload = {"models": [{"model": "other:1b"}, {"name": "named:1b"}, {"nope": 1}]}
    body = json.dumps(payload).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    provider = provider_with(handler)
    assert run(provider.resident_models()) == ["other:1b", "named:1b"]


def test_resident_models_http_error_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="HTTP 503"):
        run(provider.resident_models())


def test_resident_models_bad_shape_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="not JSON"):
        run(provider.resident_models())


# --- provider: prime (exactly one bounded generation request) ----------------


def test_prime_sends_declared_keep_alive_and_shape() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, content=STREAMED_OK)

    provider = provider_with(handler)
    outcome = run(
        provider.prime(prompt="Reply OK.", keep_alive_seconds=900.0, timeout_seconds=30.0)
    )
    assert captured["path"] == "/api/generate"
    body = captured["body"]
    assert body["model"] == MODEL
    assert body["prompt"] == "Reply OK."
    assert body["stream"] is True
    assert body["keep_alive"] == 900.0
    assert body["options"] == {"temperature": 0}
    assert outcome["completed"] is True
    assert outcome["response_valid"] is True
    assert outcome["response_chars"] == 2
    assert outcome["elapsed_seconds"] >= 0.0
    # Priming is not an adapter decision call: the adapter-call budget and
    # the one-priming cap are tracked separately.
    assert provider.primes_made == 1
    assert provider.calls_made == 0


def test_prime_refuses_second_request_on_same_instance() -> None:
    handler, state = make_handler()
    provider = provider_with(handler)
    run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0))
    with pytest.raises(LocalProviderError, match="second priming"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0))
    assert state["generate_calls"] == 1
    assert provider.primes_made == 1


def test_prime_timeout_is_wrapped_and_distinguishable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated read timeout")

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="timed out"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0))


def test_prime_http_error_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="HTTP 500"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0))


def test_prime_malformed_response_is_provider_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"garbage\n")

    provider = provider_with(handler)
    with pytest.raises(LocalProviderResponseError):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0))


def test_prime_rejects_invalid_inputs_before_any_request() -> None:
    handler, state = make_handler()
    provider = provider_with(handler)
    with pytest.raises(LocalProviderError, match="prompt"):
        run(provider.prime(prompt="  ", keep_alive_seconds=60.0, timeout_seconds=5.0))
    with pytest.raises(LocalProviderError, match="keep_alive"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=-1, timeout_seconds=5.0))
    with pytest.raises(LocalProviderError, match="timeout"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=0))
    assert state["generate_calls"] == 0
    assert provider.primes_made == 0


def test_prime_total_deadline_bounds_slow_stream() -> None:
    # The stream yields a valid chunk every 0.05 s — always within the 0.2 s
    # per-phase HTTP timeout — so no phase timeout can fire; the full stream
    # would take ~2 s. Only the total deadline can stop it, and the injected
    # 0.2 s deadline keeps the test fast (never waits the production 30 s).
    stream = TricklingStream(chunks=40, gap=0.05)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    provider = provider_with(handler)
    started = time.monotonic()
    with pytest.raises(LocalProviderError, match="timed out"):
        run(provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=0.2))
    elapsed = time.monotonic() - started
    # Aborted at the total deadline (~0.2 s) — never returned success.
    assert elapsed < 1.0
    assert stream.yielded < 40  # deadline cut the stream short mid-body
    assert stream.closed  # response cleanup still ran on the failure path
    assert provider.primes_made == 1  # one attempt, never retried
    assert provider.calls_made == 0  # adapter-call budget untouched


# --- ensure_model_ready: procedure paths ------------------------------------


def test_ready_resident_model_skips_priming() -> None:
    handler, state = make_handler(resident_flags=(True,))
    record = ensure_ready(handler)
    assert record["status"] == "ready"
    assert record["resident_before"] is True
    assert record["resident_after"] is True
    assert record["digest_matched"] is True
    assert record["priming"] is None
    assert record["generation_requests_issued"] == 0
    assert state["generate_calls"] == 0
    assert state["ps_calls"] == 2  # before + re-check


def test_ready_nonresident_model_primes_exactly_once() -> None:
    handler, state = make_handler(resident_flags=(False, True))
    record = ensure_ready(handler)
    assert record["status"] == "ready"
    assert record["resident_before"] is False
    assert record["resident_after"] is True
    assert record["generation_requests_issued"] == 1
    assert state["generate_calls"] == 1  # exactly one priming request, no retry
    priming = record["priming"]
    assert priming["issued"] is True
    assert priming["completed"] is True
    assert priming["response_valid"] is True
    assert priming["timed_out"] is False
    assert priming["error"] is None
    assert priming["elapsed_seconds"] >= 0.0
    assert record["keep_alive_seconds"] == 900.0
    assert record["prime_timeout_seconds"] == 30.0


def test_ready_missing_digest_aborts_before_any_request() -> None:
    handler, state = make_handler()
    with pytest.raises(ReadinessError, match="digest"):
        run(ensure_model_ready({"model": MODEL}, provider=provider_with(handler)))
    assert state["requests"] == []


def test_ready_digest_mismatch_aborts_without_priming() -> None:
    handler, state = make_handler(installed_digest="c" * 64, resident_flags=(False, True))
    exc = ensure_ready_raises(handler)
    assert "does not match" in str(exc)
    assert state["generate_calls"] == 0
    assert exc.record["digest_matched"] is False
    assert exc.record["installed_digest"] == "c" * 64
    assert exc.record["status"] == "aborted"


def test_ready_model_not_installed_aborts() -> None:
    handler, state = make_handler(installed_digest=None)
    exc = ensure_ready_raises(handler)
    assert "availability check failed" in str(exc)
    assert state["generate_calls"] == 0
    assert state["ps_calls"] == 0


def test_ready_tags_http_error_aborts() -> None:
    handler, state = make_handler(tags_status=500)
    exc = ensure_ready_raises(handler)
    assert "availability check failed" in str(exc)
    assert state["generate_calls"] == 0


def test_ready_unsafe_keep_alive_aborts_before_any_request() -> None:
    handler, state = make_handler()
    exc = ensure_ready_raises(handler, keep_alive_seconds=-1)
    assert "invalid readiness configuration" in str(exc)
    assert state["requests"] == []


def test_ready_unsafe_prime_timeout_aborts_before_any_request() -> None:
    handler, state = make_handler()
    exc = ensure_ready_raises(handler, prime_timeout_seconds=MAX_PRIME_TIMEOUT_SECONDS + 1)
    assert "invalid readiness configuration" in str(exc)
    assert state["requests"] == []


def test_ready_non_loopback_host_aborts_before_any_request() -> None:
    # No provider injected: readiness constructs the loopback-only provider
    # itself and must refuse a non-loopback host without any request.
    with pytest.raises(ReadinessError, match="loopback model provider"):
        run(ensure_model_ready(local_model(host="8.8.8.8")))


def test_ready_priming_timeout_aborts_without_retry() -> None:
    def generate(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("simulated read timeout")

    handler, state = make_handler(resident_flags=(False,), generate_response=generate)
    exc = ensure_ready_raises(handler)
    assert "priming request failed" in str(exc)
    assert state["generate_calls"] == 1  # attempted once, never retried
    assert state["ps_calls"] == 1  # no post-priming re-check after failure
    priming = exc.record["priming"]
    assert priming["timed_out"] is True
    assert priming["completed"] is False
    assert priming["response_valid"] is False
    assert priming["elapsed_seconds"] >= 0.0


def test_ready_priming_total_deadline_aborts_without_retry() -> None:
    # A trickling streamed response keeps every inter-chunk gap within the
    # per-phase timeout, so only the TOTAL deadline can fail the prime. The
    # failure must be recorded as a timed-out priming operation and abort
    # readiness (status "aborted") with no retry and no post-prime re-check.
    stream = TricklingStream(chunks=40, gap=0.05)

    def generate(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    handler, state = make_handler(resident_flags=(False,), generate_response=generate)
    exc = ensure_ready_raises(handler, prime_timeout_seconds=0.2)
    assert "priming request failed" in str(exc)
    assert "timed out" in str(exc)
    assert state["generate_calls"] == 1  # attempted once, never retried
    assert state["ps_calls"] == 1  # no post-priming re-check after failure
    assert stream.yielded < 40  # total deadline fired mid-stream
    assert exc.record["status"] == "aborted"
    priming = exc.record["priming"]
    assert priming["timed_out"] is True
    assert priming["completed"] is False
    assert priming["response_valid"] is False
    assert "total deadline" in priming["error"]
    assert priming["elapsed_seconds"] >= 0.0


def test_ready_priming_invalid_response_aborts() -> None:
    def generate(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"garbage\n")

    handler, state = make_handler(resident_flags=(False,), generate_response=generate)
    exc = ensure_ready_raises(handler)
    assert "priming request failed" in str(exc)
    assert state["generate_calls"] == 1
    assert exc.record["priming"]["response_valid"] is False
    assert exc.record["priming"]["completed"] is False


def test_ready_priming_empty_output_aborts() -> None:
    def generate(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"done": true}\n')

    handler, state = make_handler(resident_flags=(False,), generate_response=generate)
    exc = ensure_ready_raises(handler)
    assert "invalid (empty model output)" in str(exc)
    assert state["generate_calls"] == 1
    assert exc.record["priming"]["completed"] is True
    assert exc.record["priming"]["response_valid"] is False


def test_ready_priming_http_error_aborts() -> None:
    def generate(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    handler, state = make_handler(resident_flags=(False,), generate_response=generate)
    exc = ensure_ready_raises(handler)
    assert "priming request failed" in str(exc)
    assert "HTTP 500" in exc.record["priming"]["error"]
    assert exc.record["priming"]["timed_out"] is False
    assert state["generate_calls"] == 1


def test_ready_post_priming_residency_failure_aborts() -> None:
    handler, state = make_handler(resident_flags=(False, False))
    exc = ensure_ready_raises(handler)
    assert "not resident after priming" in str(exc)
    assert state["generate_calls"] == 1
    assert state["ps_calls"] == 2  # before + post-priming re-check
    assert exc.record["resident_after"] is False
    assert exc.record["generation_requests_issued"] == 1


def test_ready_residency_check_failure_aborts() -> None:
    handler, state = make_handler(ps_shape_bad=True)
    exc = ensure_ready_raises(handler)
    assert "residency check failed" in str(exc)
    assert state["generate_calls"] == 0


def test_ready_record_is_separate_from_scenario_decisions() -> None:
    # The readiness record carries only infrastructure fields; decision and
    # scenario fields must never appear in it (priming is not a decision).
    handler, _ = make_handler(resident_flags=(False, True))
    record = ensure_ready(handler)
    decision_fields = {
        "action",
        "rule_id",
        "decision",
        "scenario_id",
        "trial",
        "matches_expected",
        "results",
        "summary",
        "false_allow",
        "false_deny",
    }
    assert not (set(record) & decision_fields)
    assert set(record["priming"]) & decision_fields == set()
    # And the record is JSON-serializable for the report.
    json.dumps(record)


def test_ready_error_attaches_aborted_record() -> None:
    handler, _ = make_handler(installed_digest="c" * 64)
    exc = ensure_ready_raises(handler)
    assert isinstance(exc.record, dict)
    assert exc.record["status"] == "aborted"
    assert exc.record["error"] is not None
    assert exc.record["generation_requests_issued"] == 0


def test_readiness_error_is_value_error_for_fail_closed_paths() -> None:
    # ReadinessError must remain a ValueError so eval_runner's existing
    # fail-closed handling (exit 2, "nothing executed") applies unchanged.
    assert issubclass(ReadinessError, ValueError)




