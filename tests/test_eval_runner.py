"""Tests for the deterministic evaluation runner metrics (Milestone 4a/4b).

Covers metric denominators, false-allow/false-deny counting, zero-denominator
safety, latency percentiles, and the guarantee that failed/skipped scenarios
cannot inflate reported performance.
"""

from __future__ import annotations

from agent44.eval_runner import _percentiles, summarize


def _rec(
    rid: str,
    *,
    expected: str,
    action: str | None,
    category: str = "benign-basic",
    label: str = "benign",
    error: str | None = None,
    latency: float = 10.0,
) -> dict:
    return {
        "id": rid,
        "tool_name": "t",
        "category": category,
        "label": label,
        "expected": expected,
        "blocked": action == "DENY",
        "policy_action": action,
        "policy_rule_id": "r",
        "adapter_outcome": None,
        "error": error,
        "latency_ms": latency,
    }


# --- denominator / false-allow / false-deny correctness -------------------


def test_false_allow_and_false_deny_counts() -> None:
    results = [
        _rec("fa", expected="DENY", action="ALLOW"),  # false allow
        _rec("fd", expected="ALLOW", action="DENY"),  # false deny
        _rec("ok-deny", expected="DENY", action="DENY"),
        _rec("ok-allow", expected="ALLOW", action="ALLOW"),
    ]
    s = summarize(results)
    assert s["total_scenarios"] == 4
    assert s["executed_scenarios"] == 4
    assert s["false_allows"] == 1
    assert s["false_denies"] == 1
    assert s["allowed"] == 2
    assert s["denied"] == 2
    assert s["expected_outcome_agreement"] == 0.5


def test_failed_scenarios_do_not_inflate_metrics() -> None:
    results = [
        _rec("good", expected="DENY", action="DENY"),
        # Failed scenarios: no policy_action, an error. They must NOT count
        # as executed, allowed, denied, or agreements.
        _rec("boom", expected="ALLOW", action=None, error="harness_exception: X"),
        _rec("skip", expected="DENY", action=None, error="harness_timeout"),
    ]
    s = summarize(results)
    assert s["total_scenarios"] == 3
    assert s["executed_scenarios"] == 1
    assert s["failed_scenarios"] == 2
    assert s["allowed"] == 0
    assert s["denied"] == 1
    assert s["false_allows"] == 0
    assert s["false_denies"] == 0
    # agreement denominator is executed (1), not total (3)
    assert s["expected_outcome_agreement"] == 1.0
    assert s["completed"] is False


def test_zero_denominator_returns_none() -> None:
    s = summarize([])
    assert s["expected_outcome_agreement"] is None
    assert s["attack_block_rate"] is None
    assert s["hard_deny_override_rate"] is None


def test_hard_deny_override_rate_is_invariant() -> None:
    results = [
        _rec("h1", expected="DENY", action="DENY", category="hard-deny", label="malicious"),
        _rec("h2", expected="DENY", action="DENY", category="hard-deny", label="malicious"),
    ]
    s = summarize(results)
    assert s["hard_deny_overrides"] == 0
    assert s["hard_deny_override_rate"] == 0.0


# --- latency percentiles --------------------------------------------------


def test_percentiles_empty() -> None:
    p = _percentiles([])
    assert p["count"] == 0
    assert p["min"] is None and p["p50"] is None and p["p95"] is None and p["max"] is None


def test_percentiles_single_value() -> None:
    p = _percentiles([12.0])
    assert p["count"] == 1
    assert p["min"] == 12.0 and p["p50"] == 12.0 and p["p95"] == 12.0 and p["max"] == 12.0


def test_percentiles_ordered_and_bounded() -> None:
    p = _percentiles([float(x) for x in range(1, 101)])  # 1..100
    assert p["min"] == 1.0
    assert p["max"] == 100.0
    assert p["p50"] is not None and p["p95"] is not None
    assert p["min"] <= p["p50"] <= p["p95"] <= p["max"]
    # inclusive interpolation: p50 of 1..100 -> 50.5, p95 -> 95.05
    assert abs(p["p50"] - 50.5) < 1e-6
    assert abs(p["p95"] - 95.05) < 1e-6


def test_latency_percentiles_exclude_failed_cases() -> None:
    results = [
        _rec("a", expected="ALLOW", action="ALLOW", latency=5.0),
        _rec("b", expected="ALLOW", action="ALLOW", latency=7.0),
        _rec("c", expected="DENY", action="DENY", latency=9.0),
        _rec("boom", expected="ALLOW", action=None, error="harness_timeout", latency=99999.0),
    ]
    s = summarize(results)
    assert s["latency_ms"]["count"] == 3  # failed case excluded
    assert s["latency_ms"]["max"] == 9.0
