"""Tests for the Milestone 4c adversarial corpus, trials, and statistics.

Covers:
- Adversarial corpus integrity: unique IDs, valid vocabularies, >=100
  scenarios, distinct (tool, arguments) inputs, and non-trivial coverage.
- Ground truth is declared independently and never derived from the adapter.
- Wilson confidence intervals, including boundary and zero-denominator cases.
- Scenario-level vs trial-level accounting (repeated trials are not extra
  independent scenarios).
- Deterministic rules-only/replay trials remain decision-identical.
- Hard-deny invariance and fail-closed adapter behavior at the metric layer.
"""

from __future__ import annotations

import dataclasses
from collections import Counter, defaultdict

import pytest

from agent44 import corpus
from agent44.corpus import CorpusCase
from agent44.eval_runner import (
    bootstrap_ci,
    failure_analysis,
    scenario_level_metrics,
    stochastic_aggregation,
    summarize,
    wilson_interval,
    within_scenario_variability,
)

ADVERSARIAL_CATEGORIES = {
    "prompt-injection",
    "policy-bypass",
    "conflicting-rules",
    "ambiguous-adversarial",
    "hard-deny-invariance",
}


def _rec(
    rid: str,
    *,
    expected: str,
    action: str | None,
    category: str = "benign-basic",
    label: str = "benign",
    error: str | None = None,
    latency: float = 10.0,
    trial: int = 0,
) -> dict:
    return {
        "id": rid,
        "trial": trial,
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


# --- adversarial corpus integrity ------------------------------------------


def test_corpus_has_at_least_100_scenarios_and_validates() -> None:
    cases = corpus.load_corpus()
    assert len(cases) >= 100
    corpus.validate_cases(list(corpus.CASES))


def test_adversarial_categories_are_covered() -> None:
    cats = {c.category for c in corpus.load_corpus()}
    missing = ADVERSARIAL_CATEGORIES - cats
    assert not missing, f"missing adversarial categories: {sorted(missing)}"


def test_scenario_ids_are_unique() -> None:
    ids = [c.id for c in corpus.load_corpus()]
    dupes = [i for i, n in Counter(ids).items() if n > 1]
    assert not dupes, f"duplicate scenario ids: {dupes}"


def test_scenario_inputs_are_not_trivially_duplicated() -> None:
    # A "trivial duplicate" is a scenario identical to another in every
    # meaningful dimension (tool, arguments, category, label, expected, and
    # rationale). Scenarios may legitimately share (tool, arguments) while
    # differing in intent -- e.g. the adapter-malformed cases reuse one input
    # to exercise distinct malformed adapter outputs, and several cases reuse
    # the "DROP TABLE users" literal to test different policy paths. Those are
    # distinct behaviors, not trivial duplication.
    records = [
        (
            c.tool_name,
            repr(sorted(c.arguments.items())),
            c.category,
            c.label,
            c.expected,
            c.rationale,
        )
        for c in corpus.load_corpus()
    ]
    dupes = [r for r, n in Counter(records).items() if n > 1]
    assert not dupes, f"trivially duplicated scenarios: {dupes}"


def test_scenarios_sharing_inputs_exercise_distinct_intent() -> None:
    # Guard against a future regression that silently collapses scenarios that
    # share inputs: if two scenarios use the same (tool, arguments) they must
    # differ in at least one of category/label/expected/rationale.
    by_input: dict[tuple, list[CorpusCase]] = defaultdict(list)
    for c in corpus.load_corpus():
        key = (c.tool_name, repr(sorted(c.arguments.items())))
        by_input[key].append(c)
    for (_tool, _args), group in by_input.items():
        if len(group) < 2:
            continue
        intents = {(c.category, c.label, c.expected, c.rationale) for c in group}
        assert len(intents) == len(group), (
            f"scenarios share inputs and intent: {[c.id for c in group]}"
        )


def test_every_scenario_has_rationale_and_provenance() -> None:
    for c in corpus.load_corpus():
        assert c.rationale.strip(), f"{c.id} missing rationale"
        assert c.provenance, f"{c.id} missing provenance"
        assert c.expected in {"ALLOW", "DENY"}
        assert c.label in {"benign", "ambiguous", "malicious", "invalid"}


def test_duplicate_ids_are_rejected() -> None:
    base = corpus.CASES[0]
    clone = dataclasses.replace(base)  # same id
    try:
        corpus.validate_cases([base, clone])
    except ValueError:
        return
    raise AssertionError("expected ValueError for duplicate ids")


def test_invalid_category_is_rejected() -> None:
    base = corpus.CASES[0]
    bad = dataclasses.replace(base, category="not-a-real-category")
    try:
        corpus.validate_cases([bad])
    except ValueError:
        return
    raise AssertionError("expected ValueError for invalid category")


def test_missing_expected_outcome_is_rejected() -> None:
    base = corpus.CASES[0]
    bad = dataclasses.replace(base, expected="")
    try:
        corpus.validate_cases([bad])
    except ValueError:
        return
    raise AssertionError("expected ValueError for missing expected outcome")


def test_malformed_arguments_are_rejected() -> None:
    base = corpus.CASES[0]
    bad = dataclasses.replace(base, arguments=["not", "a", "mapping"])
    try:
        corpus.validate_cases([bad])
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-mapping arguments")


# --- Wilson confidence intervals ---------------------------------------------


def test_wilson_zero_denominator_is_all_none() -> None:
    out = wilson_interval(0, 0)
    assert out == {"point": None, "lower": None, "upper": None, "n": 0, "successes": 0}


def test_wilson_perfect_score_is_bounded_and_below_one() -> None:
    out = wilson_interval(10, 10)
    assert out["point"] == 1.0
    assert 0.0 <= out["lower"] < out["upper"] <= 1.0


def test_wilson_zero_score_is_bounded_and_above_zero() -> None:
    out = wilson_interval(0, 10)
    assert out["point"] == 0.0
    assert 0.0 <= out["lower"] < out["upper"] <= 1.0


def test_wilson_interval_is_ordered_and_contains_point() -> None:
    out = wilson_interval(3, 7)
    assert out["lower"] <= out["point"] <= out["upper"]
    assert 0.0 <= out["lower"] and out["upper"] <= 1.0


def test_wilson_narrows_as_sample_grows() -> None:
    small = wilson_interval(5, 10)
    large = wilson_interval(50, 100)
    assert (large["upper"] - large["lower"]) < (small["upper"] - small["lower"])


# --- scenario-level vs trial-level accounting --------------------------------


def test_repeated_trials_are_not_counted_as_independent_scenarios() -> None:
    results = []
    for trial in range(3):
        results.append(_rec("s1", expected="ALLOW", action="ALLOW", trial=trial))
        results.append(_rec("s2", expected="DENY", action="DENY", trial=trial))
    summary = summarize(results)
    # 6 trial-level records, but only 2 distinct scenarios.
    assert summary["trial_records"] == 6
    assert summary["distinct_scenarios"] == 2
    assert summary["total_scenarios"] == 6
    assert "NOT" in summary["sample_size_note"]


def test_deterministic_trials_remain_decision_identical() -> None:
    results = []
    for trial in range(4):
        results.append(_rec("s1", expected="ALLOW", action="ALLOW", trial=trial))
    summary = summarize(results)
    assert summary["distinct_scenarios"] == 1
    assert summary["trial_records"] == 4
    assert summary["false_allows"] == 0
    assert summary["false_denies"] == 0
    assert summary["expected_outcome_agreement"] == 1.0


# --- false allow / false deny with explicit denominators ----------------------


def test_false_allow_and_false_deny_rates_and_denominators() -> None:
    results = [
        _rec("ok-deny", expected="DENY", action="DENY"),
        _rec("fa", expected="DENY", action="ALLOW"),  # false allow
        _rec("ok-allow", expected="ALLOW", action="ALLOW"),
        _rec("fd", expected="ALLOW", action="DENY"),  # false deny
    ]
    summary = summarize(results)
    ci = summary["confidence_intervals"]
    assert summary["false_allows"] == 1
    assert summary["false_denies"] == 1
    # FA Wilson dict: successes=false_allows, n=denominator (expected DENY, executed)
    assert ci["false_allow_rate"]["successes"] == 1
    assert ci["false_allow_rate"]["n"] == 2
    assert ci["false_allow_rate"]["point"] == 0.5
    assert ci["false_deny_rate"]["successes"] == 1
    assert ci["false_deny_rate"]["n"] == 2
    assert ci["false_deny_rate"]["point"] == 0.5
    assert ci["method"].startswith("Wilson")


def test_failed_cases_do_not_count_as_successes_or_errors() -> None:
    results = [
        _rec("s1", expected="DENY", action=None, error="harness_timeout"),
        _rec("s2", expected="DENY", action="DENY"),
    ]
    summary = summarize(results)
    # The timed-out case has no policy_action; it must not be a false allow
    # nor a false deny, and must not inflate agreement or the FA denominator.
    assert summary["false_allows"] == 0
    assert summary["false_denies"] == 0
    assert summary["executed_scenarios"] == 1
    assert summary["failed_scenarios"] == 1
    assert summary["expected_outcome_agreement"] == 1.0
    assert summary["confidence_intervals"]["false_allow_rate"]["n"] == 1
    assert summary["completed"] is False


# --- zero-denominator safety in summarize ------------------------------------


def test_summarize_empty_results_is_zero_denominator_safe() -> None:
    summary = summarize([])
    assert summary["total_scenarios"] == 0
    assert summary["expected_outcome_agreement"] is None
    assert summary["completed"] is True
    ci = summary["confidence_intervals"]
    assert ci["false_allow_rate"]["point"] is None
    assert ci["false_deny_rate"]["point"] is None
    assert ci["false_allow_rate"]["n"] == 0


# --- category aggregation -----------------------------------------------------


def test_category_aggregation_separates_errors() -> None:
    results = [
        _rec("a", expected="ALLOW", action="ALLOW", category="benign-basic"),
        _rec("b", expected="DENY", action="DENY", category="hard-deny"),
        _rec(
            "c",
            expected="DENY",
            action=None,
            category="prompt-injection",
            error="harness_exception",
        ),
    ]
    summary = summarize(results)
    cats = summary["by_category"]
    assert cats["benign-basic"]["evaluated"] == 1
    assert cats["benign-basic"]["errors"] == 0
    assert cats["prompt-injection"]["errors"] == 1
    assert cats["prompt-injection"]["evaluated"] == 0
    assert cats["hard-deny"]["denied"] == 1


def test_hard_deny_override_rate_is_zero_when_all_denied() -> None:
    results = [
        _rec("h1", expected="DENY", action="DENY", category="hard-deny"),
        _rec("h2", expected="DENY", action="DENY", category="hard-deny"),
    ]
    summary = summarize(results)
    assert summary["hard_deny_overrides"] == 0
    assert summary["hard_deny_override_rate"] == 0.0


def test_hard_deny_override_is_detected_when_allowed() -> None:
    results = [_rec("h1", expected="DENY", action="ALLOW", category="hard-deny")]
    summary = summarize(results)
    assert summary["hard_deny_overrides"] == 1
    assert summary["hard_deny_override_rate"] == 1.0


def test_hard_deny_near_miss_allow_is_not_an_override() -> None:
    """A near-miss correctly ALLOWED is a precision check, not an override."""
    results = [
        _rec("h1", expected="DENY", action="DENY", category="hard-deny"),
        _rec("h2", expected="ALLOW", action="ALLOW", category="hard-deny"),
    ]
    summary = summarize(results)
    assert summary["hard_deny_overrides"] == 0
    assert summary["hard_deny_override_rate"] == 0.0


# --- latency distribution -----------------------------------------------------


def test_latency_percentiles_only_over_executed_cases() -> None:
    results = [
        _rec("a", expected="ALLOW", action="ALLOW", latency=5.0),
        _rec("b", expected="ALLOW", action="ALLOW", latency=15.0),
        _rec("c", expected="ALLOW", action=None, error="harness_timeout", latency=999.0),
    ]
    summary = summarize(results)
    lat = summary["latency_ms"]
    assert lat["count"] == 2  # failed case excluded
    assert lat["min"] == 5.0
    assert lat["max"] == 15.0
    assert "client_observed_ms" in summary["latency_note"]


# --- failure analysis ---------------------------------------------------------


def test_failure_analysis_lists_false_allows_and_denies() -> None:
    results = [
        _rec("fa", expected="DENY", action="ALLOW", category="prompt-injection"),
        _rec("fd", expected="ALLOW", action="DENY", category="benign-basic"),
        _rec("boom", expected="DENY", action=None, error="harness_timeout"),
    ]
    fa = failure_analysis(results)
    assert any(item["id"] == "fa" for item in fa["false_allows"])
    assert any(item["id"] == "fd" for item in fa["false_denies"])
    assert any(item["id"] == "boom" for item in fa["failed_scenarios"])
    # A single blocked call is never claimed as end-to-end prevention.
    assert fa["end_to_end_verified"] is False


def test_failure_analysis_detects_cross_trial_inconsistency() -> None:
    results = [
        _rec("s1", expected="ALLOW", action="ALLOW", trial=0),
        _rec("s1", expected="ALLOW", action="DENY", trial=1),
    ]
    fa = failure_analysis(results)
    assert any(item["id"] == "s1" for item in fa["inconsistent_across_trials"])


# --- scenario-level statistics (Protocol v1.1 amendment) --------------------

def test_wilson_62_scenario_zero_miss_upper_bound() -> None:
    """The worked 62-scenario zero-miss example: upper bound ~= 0.058.

    With 0 false allows across 62 expected-DENY scenarios, the 95% Wilson
    upper bound is approximately 0.058 (the 'rule of three' bound 3/62 is
    0.0485; Wilson is slightly conservative). The point estimate is exactly
    0.0 and the lower bound is exactly 0.0.
    """
    interval = wilson_interval(0, 62)
    assert interval["point"] == 0.0
    assert interval["lower"] == 0.0
    assert interval["successes"] == 0
    assert interval["n"] == 62
    assert 0.05 <= interval["upper"] <= 0.07


def test_scenario_level_metrics_zero_miss_across_62_deny_scenarios() -> None:
    results = [
        _rec(f"deny-{i}", expected="DENY", action="DENY", trial=0)
        for i in range(62)
    ]
    metrics = scenario_level_metrics(results)
    assert metrics["distinct_scenarios"] == 62
    assert metrics["false_allow_denominator"] == 62
    assert metrics["false_allow_numerator"] == 0
    assert metrics["false_allow_interval"]["upper"] <= 0.07
    # No expected-ALLOW scenarios -> false-deny denominator is a real zero.
    assert metrics["false_deny_denominator"] == 0
    assert metrics["false_deny_interval"]["point"] is None


def test_scenario_level_metrics_collapses_trials_to_one_outcome() -> None:
    """Repeated agreeing trials of a scenario are one independent unit."""
    results = []
    for trial in range(5):
        results.append(_rec("d", expected="DENY", action="DENY", trial=trial))
        results.append(_rec("a", expected="ALLOW", action="ALLOW", trial=trial))
    metrics = scenario_level_metrics(results)
    assert metrics["distinct_scenarios"] == 2
    assert metrics["resolved_scenarios"] == 2
    assert metrics["false_allow_denominator"] == 1
    assert metrics["false_deny_denominator"] == 1
    assert metrics["false_allow_numerator"] == 0
    assert metrics["false_deny_numerator"] == 0


def test_scenario_level_metrics_excludes_inconsistent_and_unresolved() -> None:
    results = [
        _rec("flip", expected="DENY", action="ALLOW", trial=0),
        _rec("flip", expected="DENY", action="DENY", trial=1),  # disagrees
        _rec("dead", expected="DENY", action=None, error="harness_timeout", trial=0),
        _rec("fa", expected="DENY", action="ALLOW", trial=0),  # clean false allow
        _rec("ok", expected="DENY", action="DENY", trial=0),
    ]
    metrics = scenario_level_metrics(results)
    # flip is inconsistent (excluded), dead is unresolved (excluded).
    assert metrics["inconsistent_scenarios"] == 1
    assert metrics["unresolved_scenarios"] == 1
    assert metrics["resolved_scenarios"] == 2
    # Denominator counts only resolved expected-DENY scenarios: fa + ok.
    assert metrics["false_allow_denominator"] == 2
    assert metrics["false_allow_numerator"] == 1
    assert metrics["false_allow_interval"]["point"] == 0.5


# --- stochastic-adapter aggregation (Section A: per-scenario first) --------


def test_bootstrap_ci_point_and_reproducible() -> None:
    """Percentile bootstrap reports the mean and is reproducible for a seed."""
    per_scenario = [0.0, 1.0, 0.0, 0.0, 1.0]
    ci = bootstrap_ci(per_scenario, iterations=4000, seed=7)
    assert ci["n"] == 5
    assert ci["iterations"] == 4000
    assert ci["seed"] == 7
    assert ci["point"] == pytest.approx(0.4)
    # Bounds are valid proportions and bracket the point estimate.
    assert 0.0 <= ci["lower"] <= ci["point"] <= ci["upper"] <= 1.0
    # Same seed -> identical interval.
    assert bootstrap_ci(per_scenario, iterations=4000, seed=7) == ci


def test_bootstrap_ci_zero_and_empty() -> None:
    """Zero/empty per-scenario input is handled without dividing by zero."""
    empty = bootstrap_ci([], iterations=1000, seed=0)
    assert empty["point"] is None
    assert empty["n"] == 0
    all_zero = bootstrap_ci([0.0, 0.0, 0.0], iterations=1000, seed=0)
    assert all_zero["point"] == 0.0
    assert all_zero["lower"] == all_zero["upper"] == 0.0


def test_stochastic_aggregation_rates_per_scenario_first() -> None:
    """Rates are computed per scenario then averaged; trials are not samples.

    Expected-DENY scenarios d (0/3 false allow), fa (3/3), flip (1/3) give a
    per-scenario mean of (0 + 1 + 1/3)/3 = 0.444 over 3 independent scenarios,
    with the interval bootstraped over scenarios (unit == "scenario").
    """
    results = []
    for trial in range(3):
        results += [
            _rec("a", expected="ALLOW", action="ALLOW", trial=trial),
            _rec("d", expected="DENY", action="DENY", trial=trial),
            _rec("fa", expected="DENY", action="ALLOW", trial=trial),
            _rec("flip", expected="DENY",
                 action="ALLOW" if trial == 0 else "DENY", trial=trial),
        ]
    agg = stochastic_aggregation(results, iterations=2000, seed=1)
    assert agg["unit"] == "scenario"
    assert agg["false_allow"]["scenarios"] == 3
    assert agg["false_allow"]["n"] == 3
    assert agg["false_allow"]["point"] == pytest.approx(4.0 / 9.0)
    assert agg["false_deny"]["n"] == 1  # only expected-ALLOW scenario 'a'
    assert agg["false_deny"]["point"] == 0.0
    # 3 trials x 4 scenarios = 12 executed trials; none excluded.
    assert agg["excluded_no_executed_trial"] == 0
    # Reproducible for the same seed.
    again = stochastic_aggregation(results, iterations=2000, seed=1)
    assert again["false_allow"] == agg["false_allow"]


def test_within_scenario_variability_flags_only_flipping_scenario() -> None:
    """Trial variability is reported separately; stable scenarios do not flag."""
    results = []
    for trial in range(3):
        results += [
            _rec("stable", expected="DENY", action="DENY", trial=trial),
            _rec("flip", expected="DENY",
                 action="ALLOW" if trial == 0 else "DENY", trial=trial),
        ]
    var = within_scenario_variability(results)
    assert var["scenarios_with_trials"] == 2
    assert var["scenarios_with_varying_decision"] == 1
    assert var["varying_scenario_ids"] == ["flip"]


