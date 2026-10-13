"""Tests for the Milestone 4b model-based decision adapters.

Covers strict parsing of untrusted model output, fail-closed behavior for
malformed/invalid/undecided responses, provider exceptions and timeouts,
missing replay entries, hard-deny invariance, adapter-eligibility limits,
secret-safe prompts/keys, and deterministic replay/fake behavior.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from textwrap import dedent

import pytest

from agent44.model_adapter import (
    FakeModelAdapter,
    ModelDecisionAdapter,
    ModelOutputError,
    ReplayAdapter,
    ReplayError,
    decision_key,
    parse_model_decision,
)
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


def write_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    return path


def engine_for(tmp_path: Path) -> PolicyEngine:
    return PolicyEngine.from_path(write_policy(tmp_path))


def make_complete(raw: str, *, raises: BaseException | None = None):
    """Build a deterministic async ``complete`` returning ``raw`` or raising."""

    async def _complete(prompt: str) -> str:
        if raises is not None:
            raise raises
        return raw

    return _complete


def run(coro):
    return asyncio.run(coro)


# --- strict parser ---------------------------------------------------------


def test_parse_valid_allow_and_deny() -> None:
    allow = parse_model_decision('{"action": "ALLOW", "reason": "clean"}')
    assert allow.action is Action.ALLOW and allow.reason == "clean"
    deny = parse_model_decision(
        '{"action": "DENY", "reason": "risky", "rule_id": "m.rule-1"}'
    )
    assert deny.action is Action.DENY and deny.rule_id == "m.rule-1"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "not json at all",
        '{"action": "UNDECIDED", "reason": "x"}',
        '{"action": "MAYBE", "reason": "x"}',
        '{"action": "ALLOW"}',
        '{"action": "ALLOW", "reason": ""}',
        '{"action": "ALLOW", "reason": "ok", "extra": 1}',
        '{"action": "ALLOW", "reason": "ok", "rule_id": "bad id!"}',
        '["ALLOW"]',
        '"ALLOW"',
    ],
)
def test_parse_rejects_invalid_output(text: str) -> None:
    with pytest.raises(ModelOutputError):
        parse_model_decision(text)


def test_parse_truncates_overlong_reason() -> None:
    long_reason = "x" * 5000
    decision = parse_model_decision(
        json.dumps({"action": "ALLOW", "reason": long_reason})
    )
    assert len(decision.reason) <= 200


# --- secret-safe, deterministic decision key ------------------------------


def test_decision_key_is_deterministic_and_secret_safe() -> None:
    args = {"ok": False, "secret": "sk-live-SECRET"}
    k1 = decision_key("review_tool", args)
    k2 = decision_key("review_tool", dict(args))
    assert k1 == k2
    assert "sk-live-SECRET" not in k1
    assert "SECRET" not in k1


def test_decision_key_distinguishes_distinct_values() -> None:
    # safe_arguments would collapse these to {"type": "bool"}; a replay key
    # must not, or two different calls would replay the same decision.
    assert decision_key("review_tool", {"ok": True}) != decision_key(
        "review_tool", {"ok": False}
    )


def test_decision_key_ignores_secret_value() -> None:
    # Distinct secret values must not change the key.
    a = decision_key("echo", {"msg": "hi", "api_key": "A"})
    b = decision_key("echo", {"msg": "hi", "api_key": "B"})
    assert a == b



# --- engine integration (enforcement boundary) -----------------------------


def test_hard_deny_never_reaches_adapter(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    seen: list[str] = []

    async def complete(prompt: str) -> str:
        seen.append(prompt)
        return '{"action": "ALLOW", "reason": "model allows"}'

    adapter = ModelDecisionAdapter(complete)
    decision = run(engine.decide("shell_exec", {"command": "id"}, adapter))
    assert decision.action is Action.DENY
    assert seen == [], "hard-deny call must not reach the adapter"


def test_non_adapter_tool_never_reaches_adapter(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    seen: list[str] = []

    async def complete(prompt: str) -> str:
        seen.append(prompt)
        return '{"action": "ALLOW", "reason": "model allows"}'

    adapter = ModelDecisionAdapter(complete)
    decision = run(engine.decide("unknown_tool", {}, adapter))
    assert decision.action is Action.DENY  # default_deny
    assert seen == [], "tool not in adapter_tools must not reach the adapter"


def test_adapter_allow_honored_when_deterministic_undecided(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    adapter = ModelDecisionAdapter(
        make_complete('{"action": "ALLOW", "reason": "model ok", "rule_id": "m1"}')
    )
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "m1"


def test_deterministic_allow_bypasses_adapter(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    seen: list[str] = []

    async def complete(prompt: str) -> str:
        seen.append(prompt)
        return '{"action": "DENY", "reason": "model denies"}'

    adapter = ModelDecisionAdapter(complete)
    # {"ok": True} matches the deterministic grant-ok rule; adapter must not run
    # and its DENY must not override the deterministic ALLOW.
    decision = run(engine.decide("review_tool", {"ok": True}, adapter))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "grant-ok"
    assert seen == []


def test_adapter_invalid_output_fails_closed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    adapter = ModelDecisionAdapter(make_complete("this is not json"))
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_error"


def test_adapter_undecided_fails_closed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    adapter = FakeModelAdapter({"review_tool": "UNDECIDED"})
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_undecided"


def test_adapter_missing_fails_closed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    decision = run(engine.decide("review_tool", {"ok": False}, None))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_missing"


def test_adapter_timeout_fails_closed(tmp_path: Path) -> None:
    import agent44.policy as policy_mod

    async def slow_complete(prompt: str) -> str:
        await asyncio.sleep(30)
        return '{"action": "ALLOW", "reason": "late"}'

    adapter = ModelDecisionAdapter(slow_complete)
    original = policy_mod.ADAPTER_TIMEOUT_SECONDS
    policy_mod.ADAPTER_TIMEOUT_SECONDS = 0.05
    try:
        engine = engine_for(tmp_path)
        decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    finally:
        policy_mod.ADAPTER_TIMEOUT_SECONDS = original
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_timeout"


def test_replay_adapter_in_engine_fails_closed_on_missing(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    adapter = ReplayAdapter({})  # empty table
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    # ReplayError is an Exception not tied to a timeout -> adapter_error
    assert decision.rule_id == "adapter_error"


def test_reason_never_leaks_argument_values(tmp_path: Path) -> None:
    engine = engine_for(tmp_path)
    adapter = ModelDecisionAdapter(
        make_complete('{"action": "DENY", "reason": "suspicious input"}')
    )
    decision = run(
        engine.decide("review_tool", {"ok": False, "api_key": "sk-live-SECRET"}, adapter)
    )
    assert "sk-live-SECRET" not in decision.reason
    assert "SECRET" not in decision.reason


# --- ModelDecisionAdapter --------------------------------------------------


def test_model_adapter_valid_allow() -> None:
    adapter = ModelDecisionAdapter(
        make_complete('{"action": "ALLOW", "reason": "clean", "rule_id": "m1"}')
    )
    decision = run(adapter.decide("review_tool", {"ok": False}, []))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "m1"


def test_model_adapter_prompt_has_no_raw_arguments() -> None:
    adapter = ModelDecisionAdapter(make_complete('{"action": "ALLOW", "reason": "c"}'))
    prompt = adapter.build_prompt(
        "review_tool", {"ok": False, "api_key": "sk-live-SECRET"}, []
    )
    assert "sk-live-SECRET" not in prompt
    assert "SECRET" not in prompt


def test_model_adapter_malformed_output_raises() -> None:
    adapter = ModelDecisionAdapter(make_complete("garbage"))
    with pytest.raises(ModelOutputError):
        run(adapter.decide("review_tool", {}, []))


def test_model_adapter_provider_exception_propagates() -> None:
    adapter = ModelDecisionAdapter(
        make_complete("", raises=RuntimeError("provider down"))
    )
    with pytest.raises(RuntimeError):
        run(adapter.decide("review_tool", {}, []))


# --- FakeModelAdapter ------------------------------------------------------


def test_fake_adapter_fixed_decisions() -> None:
    adapter = FakeModelAdapter({"review_tool": "ALLOW", "other": "DENY"})
    assert run(adapter.decide("review_tool", {}, [])).action is Action.ALLOW
    assert run(adapter.decide("other", {}, [])).action is Action.DENY
    # Unknown tool is undecided (fail closed by the engine).
    assert run(adapter.decide("unknown", {}, [])).action is Action.UNDECIDED


def test_fake_adapter_is_deterministic() -> None:
    adapter = FakeModelAdapter({"review_tool": "DENY"})
    first = run(adapter.decide("review_tool", {"a": 1}, []))
    second = run(adapter.decide("review_tool", {"a": 1}, []))
    assert first.action is second.action is Action.DENY


# --- ReplayAdapter ---------------------------------------------------------


def _write_fixture(tmp_path: Path, tool: str, args: dict, record: dict) -> Path:
    fixture = tmp_path / "replay.json"
    fixture.write_text(json.dumps({decision_key(tool, args): record}), encoding="utf-8")
    return fixture


def test_replay_adapter_reproduces_decision(tmp_path: Path) -> None:
    args = {"ok": False}
    fixture = _write_fixture(
        tmp_path, "review_tool", args, {"action": "DENY", "reason": "replayed"}
    )
    adapter = ReplayAdapter.from_file(fixture)
    first = run(adapter.decide("review_tool", args, []))
    second = run(adapter.decide("review_tool", dict(args), []))
    assert first.action is second.action is Action.DENY
    assert first.reason == "replayed"


def test_replay_adapter_missing_entry_fails_closed(tmp_path: Path) -> None:
    fixture = tmp_path / "replay.json"
    fixture.write_text(json.dumps({"other:key": {"action": "ALLOW", "reason": "x"}}))
    adapter = ReplayAdapter.from_file(fixture)
    with pytest.raises(ReplayError):
        run(adapter.decide("review_tool", {"ok": False}, []))


def test_replay_adapter_invalid_record_rejected_at_load(tmp_path: Path) -> None:
    fixture = tmp_path / "replay.json"
    fixture.write_text(
        json.dumps({"k": {"action": "UNDECIDED", "reason": "x"}}), encoding="utf-8"
    )
    with pytest.raises(ReplayError):
        ReplayAdapter.from_file(fixture)


def test_replay_adapter_bad_json_rejected(tmp_path: Path) -> None:
    fixture = tmp_path / "replay.json"
    fixture.write_text("{ not json")
    with pytest.raises(ReplayError):
        ReplayAdapter.from_file(fixture)

