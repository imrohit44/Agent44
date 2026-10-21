
"""Regression tests for agent44.judge_backend (Phase 10)."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from agent44.judge_backend import (
    FakeJudgeBackend,
    LLMJudgeAdapter,
    ReplayJudgeBackend,
    build_judge_prompt,
    judge_config_sha256,
    parse_judge_decision,
)
from agent44.model_adapter import AdapterTimings, ModelOutputError, decision_key
from agent44.policy import Action, Condition, PolicyRule


def _rule() -> PolicyRule:
    return PolicyRule(
        id="r1",
        tool="echo",
        action=Action.ALLOW,
        reason="stub",
        when=Condition(field="x", field_exists=True),
    )


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"action": "ALLOW", "reason": "ok"}, Action.ALLOW),
        ({"action": "DENY", "reason": "bad"}, Action.DENY),
        ({"action": "UNDECIDED", "reason": "maybe"}, Action.UNDECIDED),
        ({"action": "ALLOW", "reason": "ok", "confidence": 0.8}, Action.ALLOW),
    ],
)
def test_parse_judge_decision_accepts_valid(payload, expected):
    decision = parse_judge_decision(json.dumps(payload))
    assert decision.action is expected


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "ALLOW", "reason": "x", "extra": 1},
        {"action": "MAYBE", "reason": "x"},
        {"action": "ALLOW", "reason": ""},
        {"action": "ALLOW"},
        {"action": "DENY", "reason": "x", "confidence": 1.1},
        {"action": "DENY", "reason": "x", "confidence": -0.1},
        {"action": "DENY", "reason": "x", "confidence": "high"},
        '{"action": "DENY", "reason": "x"',
    ],
)
def test_parse_judge_decision_rejects_invalid(payload):
    with pytest.raises(ModelOutputError):
        parse_judge_decision(payload)


def test_build_judge_prompt_secret_free():
    arguments = {"user_token": "abc123", "mode": "safe"}
    prompt = build_judge_prompt("review_tool", arguments, [_rule()])
    assert "abc123" not in prompt
    assert "mode" in prompt


def test_judge_config_sha256_deterministic():
    assert (
        judge_config_sha256(
            model_name="llama3.2:1b",
            prompt_version="judge-prompt-v1",
            parser_version="judge-parser-v1",
        )
        ==
        judge_config_sha256(
            model_name="llama3.2:1b",
            prompt_version="judge-prompt-v1",
            parser_version="judge-parser-v1",
        )
    )


async def _fake_complete(prompt: str) -> str:
    return '{"action":"ALLOW","reason":"ok"}'


@pytest.mark.asyncio
async def test_llm_judge_adapter_success():
    adapter = LLMJudgeAdapter(_fake_complete, model_name="test-model")
    decision = await adapter.decide("echo", {"x": 1}, [_rule()])
    assert decision.action is Action.ALLOW
    assert decision.rule_id is None


def test_llm_judge_adapter_captures_timings():
    timings_out = []
    adapter = LLMJudgeAdapter(_fake_complete, model_name="t")
    asyncio.run(adapter.decide("echo", {}, [], timings_out=timings_out))
    assert timings_out
    assert isinstance(timings_out[0], AdapterTimings)


def test_fake_judge_backend_known_and_unknown():
    backend = FakeJudgeBackend({"echo": "ALLOW"})
    decision = asyncio.run(backend.decide("echo", {}, []))
    assert decision.action is Action.ALLOW
    decision = asyncio.run(backend.decide("rm", {}, []))
    assert decision.action is Action.UNDECIDED


def test_fake_judge_backend_coerces_invalid_action():
    backend = FakeJudgeBackend({"echo": "maybe"})
    decision = asyncio.run(backend.decide("echo", {}, []))
    assert decision.action is Action.UNDECIDED


def test_replay_judge_backend_from_file():
    key = decision_key("echo", {"a": 1})
    fixture = {key: '{"action":"ALLOW","reason":"x"}'}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "fixture.json"
        path.write_text(json.dumps(fixture), encoding="utf-8")
        backend = ReplayJudgeBackend.from_file(path)
        decision = asyncio.run(backend.decide("echo", {"a": 1}, []))
        assert decision.action is Action.ALLOW


def test_replay_judge_backend_missing_key():
    backend = ReplayJudgeBackend({"key": '{"action":"ALLOW","reason":"x"}'})
    with pytest.raises(ModelOutputError):
        asyncio.run(backend.decide("unknown", {}, []))
