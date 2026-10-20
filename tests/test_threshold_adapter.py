"""Offline unit tests for the Phase 9 probability-threshold decision adapter.

Covers threshold boundaries (inclusive/exclusive), malformed/missing/out-of-
range probability input, label-set validation, config validation, and
determinism. No inference, no network.
"""

from __future__ import annotations

import asyncio

import pytest

from agent44.policy import Action
from agent44.threshold_adapter import (
    ProbabilityThresholdAdapter,
    ThresholdConfig,
)


def run(coro):
    return asyncio.run(coro)


def make_adapter(**config_overrides):
    config = ThresholdConfig(**config_overrides)
    return ProbabilityThresholdAdapter(configs={"review_tool": config})


# --- threshold boundaries (inclusive) ----------------------------------------


def test_at_allow_threshold_is_allow() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    decision = run(adapter.decide("review_tool", {"probability": 0.8}, []))
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "threshold:allow"


def test_just_below_allow_threshold_is_undecided() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    decision = run(adapter.decide("review_tool", {"probability": 0.7999999}, []))
    assert decision.action is Action.UNDECIDED
# --- integer probabilities ---------------------------------------------------


def test_integer_probability_one_is_allow() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": 1}, []))
    assert decision.action is Action.ALLOW
# --- malformed / missing / out-of-range probability --------------------------


def test_missing_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {}, []))
    assert decision.action is Action.UNDECIDED


def test_boolean_probability_is_undecided() -> None:
    adapter = make_adapter()
    assert run(adapter.decide("review_tool", {"probability": True}, [])).action is Action.UNDECIDED
    assert run(adapter.decide("review_tool", {"probability": False}, [])).action is Action.UNDECIDED


def test_string_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": "0.5"}, []))
    assert decision.action is Action.UNDECIDED
# --- label set validation ----------------------------------------------------


def test_label_in_set_allows_threshold_decision() -> None:
    config = ThresholdConfig(allow_threshold=0.9, deny_threshold=0.1)
    adapter = ProbabilityThresholdAdapter(
        configs={"review_tool": config}, labels={"safe", "unsafe"}
    )
    decision = run(
        adapter.decide("review_tool", {"probability": 0.95, "label": "safe"}, [])
    )
    assert decision.action is Action.ALLOW


def test_label_not_in_set_is_undecided() -> None:
    config = ThresholdConfig(allow_threshold=0.9, deny_threshold=0.1)
    adapter = ProbabilityThresholdAdapter(
        configs={"review_tool": config}, labels={"safe", "unsafe"}
    )
    decision = run(
        adapter.decide("review_tool", {"probability": 0.95, "label": "evil"}, [])
    )
    assert decision.action is Action.UNDECIDED
# --- config validation -------------------------------------------------------


def test_allow_threshold_must_exceed_deny_threshold() -> None:
    with pytest.raises(ValueError, match="exceed"):
        ThresholdConfig(allow_threshold=0.5, deny_threshold=0.5)


def test_allow_threshold_below_deny_threshold_rejected() -> None:
    with pytest.raises(ValueError, match="exceed"):
        ThresholdConfig(allow_threshold=0.1, deny_threshold=0.9)


def test_unknown_config_field_rejected() -> None:
    with pytest.raises(ValueError):
        ThresholdConfig(allow_threshold=0.8, deny_threshold=0.2, bogus=1)  # type: ignore[call-arg]


def test_empty_label_field_rejected() -> None:
    with pytest.raises(ValueError):
        ThresholdConfig(label_field="")


def test_empty_probability_field_rejected() -> None:
    with pytest.raises(ValueError):
        ThresholdConfig(probability_field="")


# --- determinism and no-config -----------------------------------------------


def test_deterministic_identical_inputs() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    args = {"probability": 0.5, "label": "safe"}
    d1 = run(adapter.decide("review_tool", args, []))
    d2 = run(adapter.decide("review_tool", dict(args), []))
    assert d1.action == d2.action
    assert d1.reason == d2.reason


def test_tool_without_config_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("other_tool", {"probability": 0.95}, []))
    assert decision.action is Action.UNDECIDED


def test_empty_arguments_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {}, []))
    assert decision.action is Action.UNDECIDED


def test_missing_label_with_label_set_is_undecided() -> None:
    config = ThresholdConfig(allow_threshold=0.9, deny_threshold=0.1)
    adapter = ProbabilityThresholdAdapter(
        configs={"review_tool": config}, labels={"safe", "unsafe"}
    )
    decision = run(adapter.decide("review_tool", {"probability": 0.95}, []))
    assert decision.action is Action.UNDECIDED


def test_no_label_set_accepts_any_label() -> None:
    adapter = make_adapter(allow_threshold=0.9, deny_threshold=0.1)
    decision = run(
        adapter.decide("review_tool", {"probability": 0.95, "label": "anything"}, [])
    )
    assert decision.action is Action.ALLOW


def test_label_field_is_configurable() -> None:
    config = ThresholdConfig(label_field="verdict", allow_threshold=0.9, deny_threshold=0.1)
    adapter = ProbabilityThresholdAdapter(
        configs={"review_tool": config}, labels={"ok"}
    )
    decision = run(
        adapter.decide("review_tool", {"probability": 0.95, "verdict": "ok"}, [])
    )
    assert decision.action is Action.ALLOW


def test_none_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": None}, []))
    assert decision.action is Action.UNDECIDED


def test_nan_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": float("nan")}, []))
    assert decision.action is Action.UNDECIDED


def test_inf_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": float("inf")}, []))
    assert decision.action is Action.UNDECIDED


def test_neg_inf_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": float("-inf")}, []))
    assert decision.action is Action.UNDECIDED


def test_probability_above_one_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": 1.5}, []))
    assert decision.action is Action.UNDECIDED


def test_probability_below_zero_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": -0.5}, []))
    assert decision.action is Action.UNDECIDED


def test_list_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": [0.5]}, []))
    assert decision.action is Action.UNDECIDED


def test_dict_probability_is_undecided() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": {"p": 0.5}}, []))
    assert decision.action is Action.UNDECIDED


def test_integer_probability_zero_is_deny() -> None:
    adapter = make_adapter()
    decision = run(adapter.decide("review_tool", {"probability": 0}, []))
    assert decision.action is Action.DENY


def test_at_deny_threshold_is_deny() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    decision = run(adapter.decide("review_tool", {"probability": 0.2}, []))
    assert decision.action is Action.DENY
    assert decision.rule_id == "threshold:deny"


def test_just_above_deny_threshold_is_undecided() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    decision = run(adapter.decide("review_tool", {"probability": 0.2000001}, []))
    assert decision.action is Action.UNDECIDED


def test_undecided_band_between_thresholds() -> None:
    adapter = make_adapter(allow_threshold=0.8, deny_threshold=0.2)
    for p in (0.21, 0.5, 0.79):
        decision = run(adapter.decide("review_tool", {"probability": p}, []))
        assert decision.action is Action.UNDECIDED, f"p={p}"


def test_default_thresholds_allow_at_0_9_deny_at_0_1() -> None:
    adapter = make_adapter()
    assert run(adapter.decide("review_tool", {"probability": 0.9}, [])).action is Action.ALLOW
    assert run(adapter.decide("review_tool", {"probability": 0.1}, [])).action is Action.DENY
    assert run(adapter.decide("review_tool", {"probability": 0.5}, [])).action is Action.UNDECIDED