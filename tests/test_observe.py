"""Tests for the Milestone 2 observation foundation.

Unit tests for the observation layer: event serialization, redaction,
observer-failure isolation, and JSONL output.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent44 import observe
from agent44.observe import (
    CallContext,
    JsonlObserver,
    ObservationEvent,
    redact_arguments,
    safe_arguments,
)


def _ctx(**kwargs: object) -> CallContext:
    base: dict[str, object] = {
        "tool_name": "echo",
        "arguments": {"message": "hi"},
        "timestamp": 1000.0,
        "client_name": "pytest",
        "client_version": "1.0",
        "protocol_version": "2025-06-18",
        "request_id": 7,
    }
    base.update(kwargs)
    return CallContext(**base)  # type: ignore[arg-type]


def test_safe_arguments_omit_raw_values() -> None:
    args = {"message": "super-secret-text", "count": 3, "flag": True}
    safe = safe_arguments(args)
    assert "super-secret-text" not in json.dumps(safe)
    assert safe["message"] == {"type": "str", "length": len("super-secret-text")}
    assert safe["count"] == {"type": "int"}
    assert safe["flag"] == {"type": "bool"}


def test_safe_arguments_redact_sensitive_fields() -> None:
    args = {"api_key": "sk-live-abc", "nested": {"x": 1}}
    safe = safe_arguments(args)
    assert safe["api_key"] == {"redacted": True}
    assert "length" not in safe["api_key"]


def test_redact_arguments_marks_values_but_preserves_structure() -> None:
    args = {"token": "abc", "keep": "visible"}
    red = redact_arguments(args)
    assert red["token"] == "<redacted>"
    assert red["keep"] == "visible"


def test_sensitive_matching_is_case_insensitive() -> None:
    args = {"Password": "p", "TOKEN": "t"}
    safe = safe_arguments(args)
    assert safe["Password"] == {"redacted": True}
    assert safe["TOKEN"] == {"redacted": True}


def test_custom_sensitive_fields() -> None:
    args = {"customer_id": "12345"}
    safe = safe_arguments(args, frozenset({"customer_id"}))
    assert safe["customer_id"] == {"redacted": True}


def test_event_from_call_serializes_safe_fields() -> None:
    ctx = _ctx(arguments={"api_key": "sk-live-1", "msg": "hello"})
    event = ObservationEvent.from_call(
        ctx, outcome="success", latency_ms=123.4567, is_error=False
    )
    data = event.to_dict()
    assert data["schema_version"] == observe.EVENT_SCHEMA_VERSION
    assert data["event_type"] == "tool_call"
    assert data["tool_name"] == "echo"
    assert data["outcome"] == "success"
    assert data["is_error"] is False
    assert data["client_name"] == "pytest"
    assert data["latency_ms"] == 123.457
    assert "sk-live-1" not in json.dumps(data)
    assert data["safe_arguments"]["api_key"] == {"redacted": True}


def test_event_to_json_round_trips() -> None:
    ctx = _ctx()
    event = ObservationEvent.from_call(
        ctx, outcome="tool_error", latency_ms=5.0, is_error=True
    )
    parsed = json.loads(event.to_json())
    assert parsed["outcome"] == "tool_error"
    assert parsed["is_error"] is True
    assert parsed["request_id"] == 7


def test_jsonl_observer_writes_and_reads(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "obs.jsonl"
    observer = JsonlObserver(path)
    ctx = _ctx()
    observer.observe(
        ObservationEvent.from_call(ctx, outcome="success", latency_ms=1.0, is_error=False)
    )
    observer.observe(
        ObservationEvent.from_call(ctx, outcome="tool_error", latency_ms=2.0, is_error=True)
    )

    assert path.exists()
    events = observer.read_events()
    assert len(events) == 2
    assert events[0]["outcome"] == "success"
    assert events[1]["outcome"] == "tool_error"
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln]
    assert len(lines) == 2
    for ln in lines:
        json.loads(ln)


def test_jsonl_observer_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "c.jsonl"
    observer = JsonlObserver(path)
    ctx = _ctx()
    observer.observe(
        ObservationEvent.from_call(ctx, outcome="success", latency_ms=1.0, is_error=False)
    )
    assert path.exists()


def test_read_events_missing_file_returns_empty(tmp_path: Path) -> None:
    observer = JsonlObserver(tmp_path / "missing.jsonl")
    assert observer.read_events() == []


def test_record_observation_never_raises_when_observer_fails(tmp_path: Path) -> None:
    class Boom(JsonlObserver):
        def observe(self, event: ObservationEvent) -> None:
            raise RuntimeError("disk on fire")

    ctx = _ctx()
    observe.record_observation(
        Boom(tmp_path / "x.jsonl"), ctx, started=0.0, outcome="success", is_error=False
    )


def test_record_observation_none_observer_is_noop(tmp_path: Path) -> None:
    ctx = _ctx()
    observe.record_observation(None, ctx, started=0.0, outcome="success", is_error=False)
    assert list(tmp_path.iterdir()) == []


def test_context_from_request_context_reads_metadata() -> None:
    class FakeClientInfo:
        name = "cursor"
        version = "1.2.3"

    class FakeParams:
        clientInfo = FakeClientInfo()
        protocolVersion = "2025-03-26"

    class FakeSession:
        _client_params = FakeParams()

    class FakeMeta:
        progressToken = "tok-1"

    class FakeCtx:
        session = FakeSession()
        meta = FakeMeta()
        request_id = 42

    ctx = observe.context_from_request_context(FakeCtx(), "add", {"a": 1})
    assert ctx.tool_name == "add"
    assert ctx.client_name == "cursor"
    assert ctx.client_version == "1.2.3"
    assert ctx.protocol_version == "2025-03-26"
    assert ctx.progress_token == "tok-1"
    assert ctx.request_id == 42
    assert ctx.timestamp > 0


def test_context_from_request_context_tolerates_missing_metadata() -> None:
    class Empty:
        pass

    ctx = observe.context_from_request_context(Empty(), "echo", {"message": "x"})
    assert ctx.client_name is None
    assert ctx.protocol_version is None
    assert ctx.arguments == {"message": "x"}


def test_context_does_not_mutate_caller_arguments() -> None:
    args = {"a": 1}
    observe.context_from_request_context(object(), "add", args)
    assert args == {"a": 1}

