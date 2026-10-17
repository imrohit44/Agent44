"""Offline cancellation-safety and diagnostic-telemetry regression tests.

No Ollama, no network, no evaluation: every HTTP interaction is served by an
injected ``httpx`` transport and every slow operation blocks on an ``asyncio``
event that the test cancels promptly.
"""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from textwrap import dedent
from typing import Any

import httpx
import pytest

from agent44.local_provider import LocalProviderError, OllamaProvider
from agent44.model_adapter import AdapterTimings, ModelDecisionAdapter
from agent44.policy import Action, PolicyEngine

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

STREAMED_DENY = (
    b'{"response":"{\\"action\\": \\"DENY\\", \\"reason\\": \\"ok\\"}", "done": false}\n'
    b'{"done": true}\n'
)


def run(coro):
    return asyncio.run(coro)


def engine_for(tmp_path: Path, *, adapter_timeout: float = 5.0) -> PolicyEngine:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return PolicyEngine.from_path(path, adapter_timeout_seconds=adapter_timeout)


class BlockingStream(httpx.AsyncByteStream):
    """Async body that blocks until the reader is cancelled."""

    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self):  # type: ignore[override]
        await asyncio.Event().wait()  # never resolved; test cancels promptly
        yield b"unreached"  # pragma: no cover

    async def aclose(self) -> None:
        self.closed = True


class BlockingTransport(httpx.AsyncBaseTransport):
    """Counts requests; blocks on read, or serves one fast OK body."""

    def __init__(self) -> None:
        self.attempts = 0
        self.streams: list[BlockingStream] = []
        self.mode = "block"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        if self.mode == "ok":
            return httpx.Response(200, content=STREAMED_DENY, request=request)
        stream = BlockingStream()
        self.streams.append(stream)
        return httpx.Response(200, stream=stream, request=request)


def make_provider(transport: BlockingTransport) -> OllamaProvider:
    """Build a provider whose HTTP is served by ``transport`` (no socket)."""
    return OllamaProvider("test-model", transport=transport, check_host=False)


def test_deadline_cancels_slow_provider_and_fails_closed(tmp_path: Path) -> None:
    """The engine deadline cancels a slow provider call; DENY, no retry, cleanup."""
    transport = BlockingTransport()
    provider = make_provider(transport)
    adapter = ModelDecisionAdapter(provider.complete)
    engine = engine_for(tmp_path, adapter_timeout=0.2)

    async def scenario() -> None:
        try:
            decision = await engine.decide("review_tool", {"ok": False}, adapter)
            assert decision.action is Action.DENY
            assert decision.rule_id == "adapter_timeout"
            assert transport.attempts == 1  # one request, never retried
            assert provider.calls_made == 1
            assert provider.primes_made == 0
            assert len(transport.streams) == 1
            assert transport.streams[0].closed is True  # cleanup ran despite cancel
        finally:
            await provider.aclose()

    run(scenario())


def test_opened_response_closed_when_reader_cancelled() -> None:
    """Cancelling mid-read closes the opened response (no pooled leak)."""
    transport = BlockingTransport()
    provider = make_provider(transport)

    async def scenario() -> None:
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(provider.complete("hello"), timeout=0.2)
            assert transport.attempts == 1
            assert len(transport.streams) == 1
            assert transport.streams[0].closed is True
            assert provider.calls_made == 1
            assert provider.primes_made == 0
        finally:
            await provider.aclose()

    run(scenario())


def test_cancelled_request_not_retried_and_next_request_isolated() -> None:
    """After a cancel, exactly one new request serves the next call cleanly."""
    transport = BlockingTransport()
    provider = make_provider(transport)

    async def scenario() -> None:
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(provider.complete("slow"), timeout=0.2)
            assert transport.attempts == 1
            transport.mode = "ok"  # server answers fast now; prior state must not leak
            text = await asyncio.wait_for(provider.complete("fast"), timeout=5.0)
            assert transport.attempts == 2  # exactly one new request, no hidden retry
            assert provider.calls_made == 2
            assert '"DENY"' in text
            assert transport.streams[0].closed is True  # first response stayed closed
        finally:
            await provider.aclose()

    run(scenario())


def test_cancellation_not_misclassified_as_provider_error() -> None:
    """Caller cancellation surfaces as CancelledError, never LocalProviderError."""
    transport = BlockingTransport()
    provider = make_provider(transport)

    async def scenario() -> None:
        try:
            task = asyncio.create_task(provider.complete("slow"))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                misclassified = False
            except LocalProviderError:
                misclassified = True  # bug: cancel swallowed into a provider error
            assert misclassified is False
            assert transport.streams[0].closed is True
        finally:
            await provider.aclose()

    run(scenario())


def test_timeout_denial_uses_existing_classification(tmp_path: Path) -> None:
    """The timeout DENY keeps the existing rule id, reason shape, and policy stamp."""
    transport = BlockingTransport()
    provider = make_provider(transport)
    adapter = ModelDecisionAdapter(provider.complete)
    engine = engine_for(tmp_path, adapter_timeout=0.2)

    async def scenario() -> None:
        try:
            decision = await engine.decide("review_tool", {"ok": False}, adapter)
            assert decision.action is Action.DENY
            assert decision.rule_id == "adapter_timeout"
            assert "timed out" in decision.reason
            assert decision.policy_id and decision.policy_version
        finally:
            await provider.aclose()

    run(scenario())


def assert_valid_durations(record: Any) -> None:
    """Every stamped duration is a finite non-negative float; None means unrun."""
    values = record.as_dict().values() if hasattr(record, "as_dict") else record.values()
    for value in values:
        if value is None:
            continue
        if isinstance(value, dict):
            assert_valid_durations(value)
            continue
        if hasattr(value, "as_dict"):
            assert_valid_durations(value)
            continue
        assert isinstance(value, float)
        assert math.isfinite(value) and value >= 0.0


def test_provider_timings_scoped_and_content_free() -> None:
    """Provider stages: send/read stamped, extract stamped, no content recorded."""
    transport = BlockingTransport()
    transport.mode = "ok"
    provider = make_provider(transport)

    async def scenario() -> None:
        try:
            slot: list = []
            text = await provider.complete("hello", timings_out=slot)
            assert len(slot) == 1
            record = slot[0]
            assert record.send_request_s is not None
            assert record.read_body_s is not None
            assert record.extract_text_s is not None  # non-stream shortcut still timed
            assert record.total_s is not None
            assert_valid_durations(record)
            blob = json.dumps(record.as_dict())
            assert "hello" not in blob  # no prompt text
            assert "DENY" not in blob  # no response content
            assert text  # sanity: fast OK body parsed
        finally:
            await provider.aclose()

    run(scenario())


def test_provider_timings_stamped_even_when_cancelled() -> None:
    """A cancelled read still yields exactly one record with total stamped."""
    transport = BlockingTransport()
    provider = make_provider(transport)

    async def scenario() -> None:
        slot: list = []
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    provider.complete("slow", timings_out=slot), timeout=0.2
                )
        finally:
            await provider.aclose()
        assert len(slot) == 1
        record = slot[0]
        assert record.total_s is not None  # finally stamped despite cancellation
        assert_valid_durations(record)
        # read_body never finished; None marks the unrun stage, not zero.
        assert record.read_body_s is None

    run(scenario())


def test_adapter_timings_nest_provider_and_hold_no_content() -> None:
    """Adapter record nests the provider record; both carry durations only."""
    transport = BlockingTransport()
    transport.mode = "ok"
    provider = make_provider(transport)
    adapter = ModelDecisionAdapter(provider.complete)

    async def scenario() -> None:
        slot: list[AdapterTimings] = []
        try:
            decision = await adapter.decide(
                "review_tool", {"ok": False}, [], timings_out=slot
            )
            assert decision.action is Action.DENY
            assert len(slot) == 1
            outer = slot[0]
            assert outer.build_prompt_s is not None
            assert outer.complete_s is not None
            assert outer.parse_s is not None
            assert outer.total_s is not None
            assert_valid_durations(outer)
            assert outer.provider is not None  # nested provider breakdown attached
            assert_valid_durations(outer.provider)
            flat = (
                json.dumps(outer.as_dict())
                + json.dumps(outer.provider.as_dict())
            )
            assert "review_tool" not in flat  # no tool/prompt/response content
            assert "DENY" not in flat
        finally:
            await provider.aclose()

    run(scenario())


def test_adapter_timings_stamped_on_cancel_with_unrun_parse_none() -> None:
    """Cancelled adapter call: complete/total stamped, parse stays None, no retry."""
    transport = BlockingTransport()
    provider = make_provider(transport)
    adapter = ModelDecisionAdapter(provider.complete)

    async def scenario() -> None:
        slot: list[AdapterTimings] = []
        try:
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    adapter.decide(
                        "review_tool", {"ok": False}, [], timings_out=slot
                    ),
                    timeout=0.2,
                )
        finally:
            await provider.aclose()
        assert len(slot) == 1
        outer = slot[0]
        assert outer.complete_s is not None
        assert outer.total_s is not None
        assert outer.parse_s is None  # parse never ran; None, not a fake zero
        assert_valid_durations(outer)
        assert transport.attempts == 1  # no retry, no hidden extra generation call

    run(scenario())


def test_priming_budget_untouched_by_cancelled_adapter_calls(tmp_path: Path) -> None:
    """Cancelled adapter calls never consume the separate one-priming budget."""
    transport = BlockingTransport()
    provider = make_provider(transport)
    adapter = ModelDecisionAdapter(provider.complete)
    engine = engine_for(tmp_path, adapter_timeout=0.2)

    async def scenario() -> None:
        try:
            decision = await engine.decide("review_tool", {"ok": False}, adapter)
            assert decision.rule_id == "adapter_timeout"
            assert provider.calls_made == 1
            assert provider.primes_made == 0  # priming budget untouched
        finally:
            await provider.aclose()

    run(scenario())
