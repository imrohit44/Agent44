"""Offline acceptance tests for the Phase 9 decision-backend contract.

Covers the provider-independent contract formalized in ``agent44.policy``:

* hard-deny precedence: no adapter/backend result overrides a hard-deny
* backend never invoked after a deterministic tier decides
* timeout / cancellation / exception / malformed output -> fail-closed DENY
* unavailable backend reporting (missing adapter, error, timeout buckets)
* threshold adapter boundaries integrated through the engine

No live/vendor/network calls: every backend is an injected fake.
"""

from __future__ import annotations

import asyncio

from agent44.policy import (
    Action,
    AdapterDecision,
    AdapterParseError,
    DecisionAdapter,
    PolicyEngine,
)

POLICY = """\
version: \"1\"
name: contract-policy
default_deny: true
allow_tools: [add]
hard_deny_tools: [shell_exec]
adapter_tools: [review_tool]
rules:
  - id: grant-ok
    tool: review_tool
    action: ALLOW
    reason: \"review approved\"
    when: {field: ok, equals: true}
"""

# --- fakes -------------------------------------------------------------------


class AlwaysAllowAdapter:
    async def decide(self, tool_name, arguments, rules):
        return AdapterDecision(action=Action.ALLOW, reason="always allow", rule_id="fake")


class AlwaysDenyAdapter:
    async def decide(self, tool_name, arguments, rules):
        return AdapterDecision(action=Action.DENY, reason="always deny", rule_id="fake")


class UndecidedAdapter:
    async def decide(self, tool_name, arguments, rules):
        return AdapterDecision(action=Action.UNDECIDED, reason="undecided", rule_id="fake")


class InvocationCountingAdapter(DecisionAdapter):
    def __init__(self, decision=None):
        self.decision = decision or AdapterDecision(action=Action.ALLOW, reason="x", rule_id="x")
        self.calls = 0

    async def decide(self, tool_name, arguments, rules):
        self.calls += 1
        return self.decision


# --- hard-deny precedence -----------------------------------------------------


def test_hard_deny_precedes_adapter_allow(tmp_path):
    """A hard-denied tool is denied even if the adapter would ALLOW."""
    engine = engine_for(tmp_path)
    adapter = AlwaysAllowAdapter()
    decision = run(engine.decide("shell_exec", {"cmd": "rm -rf /"}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "hard_deny_tools"


def test_adapter_cannot_override_hard_deny(tmp_path):
    engine = engine_for(tmp_path)
    adapter = InvocationCountingAdapter(
        AdapterDecision(action=Action.ALLOW, reason="fake allow", rule_id="fake")
    )
    decision = run(engine.decide("shell_exec", {"cmd": "x"}, adapter))
    assert decision.action is Action.DENY
    # The adapter must never be consulted for a hard-denied tool.
    assert adapter.calls == 0


# --- backend never invoked post-deterministic ---------------------------------


def test_backend_not_invoked_when_deterministic_rule_matches(tmp_path):
    """The adapter is not consulted when a deterministic tier already decided."""
    engine = engine_for(tmp_path)
    adapter = InvocationCountingAdapter()
    # ok=true matches the grant-ok ALLOW rule, so the adapter is skipped.
    decision = run(engine.decide("review_tool", {"ok": True}, adapter))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "grant-ok"
    assert adapter.calls == 0


def test_backend_not_invoked_when_default_deny_applies(tmp_path):
    """The adapter is not invoked when no tier matches and default is deny."""
# --- fail-closed: timeout -----------------------------------------------------


def test_adapter_timeout_fails_closed(tmp_path):
    engine = engine_for(tmp_path, adapter_timeout=0.2)
    adapter = TimeoutAdapter()
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_timeout"


# --- fail-closed: cancellation ------------------------------------------------


def test_adapter_cancellation_fails_closed(tmp_path):
    engine = engine_for(tmp_path, adapter_timeout=0.2)
    adapter = TimeoutAdapter()
    run(engine.decide("review_tool", {"ok": False}, adapter))
# --- unavailable backend reporting --------------------------------------------


def test_missing_adapter_reports_adapter_missing(tmp_path):
    """An adapter_tool with no configured adapter yields adapter_missing DENY."""
    engine = engine_for(tmp_path)
    decision = run(engine.decide("review_tool", {"ok": False}))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_missing"


def test_adapter_failure_reasons_are_distinct(tmp_path):
    """Each failure mode has a distinct, diagnosable rule_id."""
    engine = engine_for(tmp_path, adapter_timeout=0.2)

    # Timeout
    d = run(engine.decide("review_tool", {"ok": False}, TimeoutAdapter()))
    assert d.rule_id == "adapter_timeout"

    # Exception
    d = run(engine.decide("review_tool", {"ok": False}, RaisingAdapter()))
    assert d.rule_id == "adapter_error"

    # Parse failure
    d = run(engine.decide("review_tool", {"ok": False}, ParseFailingAdapter()))
    assert d.rule_id == "adapter_invalid"

    # Undecided
    d = run(engine.decide("review_tool", {"ok": False}, UndecidedAdapter()))
    assert d.rule_id == "adapter_undecided"

    # Missing
    d = run(engine.decide("review_tool", {"ok": False}))
    assert d.rule_id == "adapter_missing"


# --- threshold adapter through the engine -------------------------------------


def test_threshold_adapter_allow_through_engine(tmp_path):
    from agent44.threshold_adapter import ProbabilityThresholdAdapter, ThresholdConfig

    config = ThresholdConfig(allow_threshold=0.9, deny_threshold=0.1)
    adapter = ProbabilityThresholdAdapter(configs={"review_tool": config})
    engine = engine_for(tmp_path)

    # p >= allow -> ALLOW
    d = run(engine.decide("review_tool", {"probability": 0.95, "ok": False}, adapter))
    assert d.action is Action.ALLOW
    assert d.rule_id == "threshold:allow"

    # p <= deny -> DENY
    d = run(engine.decide("review_tool", {"probability": 0.05, "ok": False}, adapter))
    assert d.action is Action.DENY
    assert d.rule_id == "threshold:deny"

    # band -> UNDECIDED -> engine DENY
    d = run(engine.decide("review_tool", {"probability": 0.5, "ok": False}, adapter))
    assert d.action is Action.DENY
    assert d.rule_id == "adapter_undecided"


# --- fail-closed: exception ---------------------------------------------------


def test_adapter_exception_fails_closed(tmp_path):
    engine = engine_for(tmp_path)
    adapter = RaisingAdapter()
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_error"
    # Exception message is untrusted: class name only, no raw message.
    assert "exploded" not in decision.reason
    assert "RuntimeError" in decision.reason


# --- fail-closed: malformed / invalid output ----------------------------------


def test_adapter_non_decision_return_fails_closed(tmp_path):
    engine = engine_for(tmp_path)
    adapter = MalformedAdapter()
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_invalid"


def test_adapter_parse_error_fails_closed(tmp_path):
    engine = engine_for(tmp_path)
    adapter = ParseFailingAdapter()
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_invalid"


def test_adapter_undecided_fails_closed(tmp_path):
    engine = engine_for(tmp_path)
    adapter = UndecidedAdapter()
    decision = run(engine.decide("review_tool", {"ok": False}, adapter))
    assert decision.action is Action.DENY
    assert decision.rule_id == "adapter_undecided"
    engine = engine_for(tmp_path)
    adapter = InvocationCountingAdapter()
    decision = run(engine.decide("unknown_tool", {"x": 1}, adapter))
    assert decision.action is Action.DENY
    assert adapter.calls == 0


def test_backend_not_invoked_for_non_adapter_tool(tmp_path):
    """The adapter is not consulted for tools not in adapter_tools."""
    engine = engine_for(tmp_path)
    adapter = InvocationCountingAdapter()
    decision = run(engine.decide("add", {"a": 1, "b": 2}, adapter))
    assert decision.action is Action.ALLOW  # allow_tools
    assert adapter.calls == 0
    adapter = InvocationCountingAdapter(
        AdapterDecision(action=Action.ALLOW, reason="fake allow", rule_id="fake")
    )
    decision = run(engine.decide("shell_exec", {"cmd": "x"}, adapter))
    assert decision.action is Action.DENY
    # The adapter must never be consulted for a hard-denied tool.
    assert adapter.calls == 0


class RaisingAdapter:
    async def decide(self, tool_name, arguments, rules):
        raise RuntimeError("backend exploded")


class TimeoutAdapter:
    async def decide(self, tool_name, arguments, rules):
        await asyncio.Event().wait()  # never resolves


class MalformedAdapter:
    async def decide(self, tool_name, arguments, rules):
        return "not an adapter decision"


class ParseFailingAdapter:
    async def decide(self, tool_name, arguments, rules):
        raise AdapterParseError("response was not valid JSON")

def write_policy(tmp_path, text=POLICY, name="policy.yaml"):
    from textwrap import dedent

    path = tmp_path / name
    path.write_text(dedent(text).lstrip(), encoding="utf-8")
    return path


def engine_for(tmp_path, *, adapter_timeout=5.0):
    return PolicyEngine.from_path(write_policy(tmp_path), adapter_timeout_seconds=adapter_timeout)


def run(coro):
    return asyncio.run(coro)