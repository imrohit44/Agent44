
"""Regression tests for Phase 10 judge-targeted development scenarios."""

from __future__ import annotations

from agent44.judge_scenarios import (
    JUDGE_CASES,
    JUDGE_SCENARIOS_VERSION,
    judge_case_ids,
    judge_cases_by_id,
    validate_cases,
)


def test_judge_cases_are_frozen_and_validated():
    assert JUDGE_SCENARIOS_VERSION == "p10.0.0"
    assert len(JUDGE_CASES) == 7

    ids = judge_case_ids()
    assert len(ids) == 7
    assert len(set(ids)) == 7
    assert set(ids) == {case.id for case in JUDGE_CASES}
    assert judge_cases_by_id() == {case.id: case for case in JUDGE_CASES}

    validate_cases(list(JUDGE_CASES))  # must not raise
