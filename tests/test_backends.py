
"""Regression tests for agent44.backends (Phase 10)."""

from __future__ import annotations

import asyncio

import pytest

from agent44.backends import (
    BackendAvailability,
    BackendIdentity,
    BackendStatus,
    RecordingAdapter,
    config_sha256,
)
from agent44.policy import Action, AdapterDecision, Condition, DecisionAdapter, PolicyRule


class _StubAdapter(DecisionAdapter):
    def __init__(self, action: Action, *, rule_id: str | None = None):
        self._action = action
        self._rule_id = rule_id

    async def decide(self, tool_name, arguments, rules):
        return AdapterDecision(
            action=self._action,
            reason=f"stub {self._action.value}",
            rule_id=self._rule_id,
        )


def _rule(tool: str = "echo", action: Action = Action.ALLOW) -> PolicyRule:
    return PolicyRule(
        id="r1",
        tool=tool,
        action=action,
        hard=False,
        reason="stub reason",
        when=Condition(field="x", field_exists=True),
    )


def test_config_sha256_canonicalizes():
    a = config_sha256({"b": 1, "a": [1, 2]})
    b = config_sha256({"a": [1, 2], "b": 1})
    assert a == b

    with pytest.raises(ValueError):
        config_sha256({"bad": set([1, 2])})


def test_backend_identity_as_dict():
    ident = BackendIdentity(
        name="x",
        version="1",
        config_sha256="deadbeef",
        stochastic=False,
        probability_metadata={"p": "q"},
    )
    assert ident.as_dict()["name"] == "x"
    assert ident.as_dict()["stochastic"] is False
    assert ident.as_dict()["contract_version"] == "phase10-backend-contract-1"


def test_backend_availability_as_dict():
    avail = BackendAvailability(
        status=BackendStatus.UNAVAILABLE,
        reason="no credential",
        documentation="https://example.invalid",
    )
    d = avail.as_dict()
    assert d["status"] == "unavailable"
    assert d["documentation"] == "https://example.invalid"


def test_recording_adapter_records_decision():
    inner = _StubAdapter(Action.ALLOW, rule_id="r1")
    adapter = RecordingAdapter(inner)
    decision = asyncio.run(adapter.decide("echo", {"x": 1}, [_rule()]))
    assert decision.action is Action.ALLOW
    assert adapter.consultations == 1
    assert len(adapter.records) == 1
    record = adapter.records[0]
    assert record.action == "ALLOW"
    assert record.outcome == "decision"
    assert record.rule_id == "r1"


def test_recording_adapter_records_fails_closed():
    def _raise_exc(tool_name, arguments, rules):
        raise RuntimeError("boom")

    inner = _StubAdapter(Action.ALLOW)
    inner.decide = _raise_exc
    adapter = RecordingAdapter(inner)

    with pytest.raises(RuntimeError):
        asyncio.run(adapter.decide("echo", {}, []))

    assert adapter.consultations == 1
    assert len(adapter.records) == 1
    record = adapter.records[0]
    assert record.outcome == "error"
    assert record.detail == "RuntimeError"
    assert adapter.failed_calls == 1


def test_recording_adapter_secret_free():
    inner = _StubAdapter(Action.DENY)
    adapter = RecordingAdapter(inner)

    asyncio.run(
        adapter.decide(
            "echo",
            {"credential": "s3cr3t", "secret_key": "abc"},
            [_rule()],
        )
    )

    record = adapter.records[0]
    data = record.as_dict()
    assert "s3cr3t" not in record.detail
    all_values = " ".join(str(v) for v in data.values())
    assert "s3cr3t" not in all_values
    assert "abc" not in all_values
