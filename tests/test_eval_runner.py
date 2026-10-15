"""Tests for the deterministic evaluation runner metrics (Milestone 4a/4b).

Covers metric denominators, false-allow/false-deny counting, zero-denominator
safety, latency percentiles, and the guarantee that failed/skipped scenarios
cannot inflate reported performance.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent44 import corpus
from agent44.eval_runner import (
    _percentiles,
    _run_case,
    build_manifest,
    classify_outcome,
    evaluate,
    inference_provenance,
    main,
    plan_local_model_calls,
    select_cases,
    summarize,
)


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


# --- pilot safeguards: dev-only selection, provenance, per-scenario verdicts -


class _FakeContent:
    """Minimal stand-in for the MCP content block the runner reads."""

    type = "text"

    def __init__(self, text: str = "ok") -> None:
        self.text = text


class _FakeResult:
    def __init__(self, *, is_error: bool = False) -> None:
        self.isError = is_error
        self.content = [_FakeContent("denied by policy (eval-test)" if is_error else "ok")]


class _FakeSession:
    """Answers any call_tool immediately; blocking is decided by the proxy."""

    async def call_tool(self, name: str, arguments: dict) -> _FakeResult:
        return _FakeResult()


class _FakeObserver:
    """Returns the queued observation on the post-call read only."""

    def __init__(self, events: list[dict]) -> None:
        self._events = events
        self._reads = 0

    def read_events(self) -> list[dict]:
        self._reads += 1
        if self._reads == 1:
            return []
        return list(self._events)


def _corpus_case_with_expected(expected: str) -> corpus.CorpusCase:
    for case in corpus.CASES:
        if case.expected == expected:
            return case
    raise AssertionError(f"corpus must contain an expected={expected} scenario")


def test_partition_selection_matches_pre_registered_split() -> None:
    pmap = corpus.partition_map()
    everything = select_cases()
    assert [c.id for c in everything] == [c.id for c in corpus.load_corpus()]

    development = select_cases(corpus.PARTITION_DEVELOPMENT)
    held_out = select_cases(corpus.PARTITION_HELD_OUT)
    assert development and held_out
    assert all(pmap[c.id] == corpus.PARTITION_DEVELOPMENT for c in development)
    assert all(pmap[c.id] == corpus.PARTITION_HELD_OUT for c in held_out)
    # The two partitions are disjoint and together cover the whole corpus.
    dev_ids = {c.id for c in development}
    held_ids = {c.id for c in held_out}
    assert not (dev_ids & held_ids)
    assert dev_ids | held_ids == {c.id for c in everything}


@pytest.mark.parametrize("bad", ["dev", "DEVELOPMENT", "", "development ", "alll", "hold-out"])
def test_select_cases_invalid_partition_fails_closed(bad: str) -> None:
    with pytest.raises(ValueError, match="invalid partition"):
        select_cases(bad)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"local_model": {"model": "llama3.2:1b"}},  # default partition 'all'
        {"local_model": {"model": "llama3.2:1b"}, "partition": "all"},
        {"local_model": {"model": "llama3.2:1b"}, "partition": "held-out"},
    ],
)
def test_evaluate_local_model_requires_development_partition(kwargs: dict) -> None:
    with pytest.raises(ValueError, match="development"):
        asyncio.run(evaluate(**kwargs))  # type: ignore[arg-type]


def test_evaluate_rejects_unknown_partition_in_all_modes() -> None:
    with pytest.raises(ValueError, match="invalid partition"):
        asyncio.run(evaluate(partition="dev"))


def test_evaluate_partition_validation_precedes_execution() -> None:
    # observe_path is only opened after validation; a refused configuration
    # must raise before touching it or contacting any model.
    with pytest.raises(ValueError, match="No model was contacted"):
        asyncio.run(
            evaluate(
                observe_path="definitely/not/created.jsonl",
                local_model={"model": "llama3.2:1b"},
                partition="all",
            )
        )


def test_plan_local_model_calls_within_budget() -> None:
    cases = corpus.load_corpus()
    plan = plan_local_model_calls(
        cases=cases, trials=1, adapter_tools={"review_tool"}, max_calls=256
    )
    assert plan["limit"] == 256
    assert 0 <= plan["planned_worst_case_calls"] <= 256
    assert "hard limit" in plan["note"]


def test_plan_local_model_calls_over_budget_fails_closed() -> None:
    cases = corpus.load_corpus()
    with pytest.raises(ValueError, match="budget exceeded"):
        plan_local_model_calls(
            cases=cases,
            trials=50,
            adapter_tools={c.tool_name for c in cases},
            max_calls=256,
        )


def test_inference_provenance_distinguishes_sources() -> None:
    rules = inference_provenance(adapter_replay=None, local_model=None)
    assert rules["source"] == "rules-only"
    assert rules["live_inference"] is False

    replay = inference_provenance(adapter_replay="fixture.json", local_model=None)
    assert replay["source"] == "fixture-replay"
    assert replay["live_inference"] is False
    assert "NOT model output" in replay["note"]

    live = inference_provenance(adapter_replay=None, local_model={"model": "m"})
    assert live["source"] == "live-local-model"
    assert live["live_inference"] is True


@pytest.mark.parametrize(
    ("expected", "action", "error", "matches", "reason"),
    [
        ("ALLOW", "ALLOW", None, True, None),
        ("DENY", "DENY", None, True, None),
        ("DENY", "ALLOW", None, False, "false_allow"),
        ("ALLOW", "DENY", None, False, "false_deny"),
        ("ALLOW", "ALLOW", "harness_timeout", None, "harness_timeout"),
        ("ALLOW", None, None, None, "missing_decision"),
        ("MAYBE", "ALLOW", None, None, "invalid_expected_value"),
    ],
)
def test_classify_outcome(
    expected: str, action: str | None, error: str | None, matches: bool | None, reason: str | None
) -> None:
    assert classify_outcome(expected=expected, action=action, error=error) == (matches, reason)


def test_run_case_record_has_partition_and_explicit_verdict() -> None:
    case = _corpus_case_with_expected("ALLOW")
    observer = _FakeObserver([{"policy_action": "ALLOW", "policy_rule_id": "default:allow"}])
    record = asyncio.run(
        _run_case(
            _FakeSession(),
            case,
            observer,
            timeout_seconds=5.0,
            partition=corpus.PARTITION_DEVELOPMENT,
        )
    )
    assert record["partition"] == corpus.PARTITION_DEVELOPMENT
    assert record["matches_expected"] is True
    assert record["failure_reason"] is None
    assert record["expected"] == case.expected
    assert record["latency_ms"] >= 0


def test_run_case_mismatch_is_reported_as_false_allow() -> None:
    case = _corpus_case_with_expected("DENY")
    observer = _FakeObserver([{"policy_action": "ALLOW", "policy_rule_id": "adapter"}])
    record = asyncio.run(
        _run_case(
            _FakeSession(),
            case,
            observer,
            timeout_seconds=5.0,
            partition=corpus.PARTITION_DEVELOPMENT,
        )
    )
    assert record["matches_expected"] is False
    assert record["failure_reason"] == "false_allow"
    assert record["adapter_outcome"] == "adapter"


def test_run_case_missing_observation_fails_closed() -> None:
    case = _corpus_case_with_expected("ALLOW")
    record = asyncio.run(
        _run_case(
            _FakeSession(),
            case,
            _FakeObserver([]),
            timeout_seconds=5.0,
            partition=corpus.PARTITION_HELD_OUT,
        )
    )
    assert record["matches_expected"] is None
    assert record["failure_reason"] == "harness_no_observation"
    assert record["partition"] == corpus.PARTITION_HELD_OUT


def test_summarize_adapter_outcome_detail_buckets() -> None:
    rows = []
    for rid, outcome in [
        ("t0", None),
        ("t1", "adapter"),
        ("t2", "adapter_timeout"),
        ("t3", "adapter_invalid"),
        ("t4", "adapter_error"),
        ("t5", "adapter_undecided"),
        ("t6", "adapter_missing"),
    ]:
        row = _rec(rid, expected="DENY", action="DENY")
        row["adapter_outcome"] = outcome
        rows.append(row)
    detail = summarize(rows)["adapter_outcome_detail"]
    assert detail["successful_decisions"] == 1
    assert detail["timeouts"] == 1
    assert detail["malformed_responses"] == 1
    assert detail["provider_errors"] == 1
    assert detail["undecided"] == 1
    assert detail["missing_adapter"] == 1
    assert "fail-closed DENY" in detail["definitions"]["adapter_invalid"]
    assert "fixtures, never model" in detail["note"]


def test_manifest_hashes_decision_relevant_sources() -> None:
    artifacts = build_manifest()["artifacts"]
    for key in (
        "policy_engine",
        "model_adapter",
        "local_provider",
        "proxy",
        "observe",
        "corpus_module",
        "eval_runner",
        "policy",
        "protocol_v1",
        "amendment_v11",
        "replay_fixture",
    ):
        assert artifacts[key]["sha256"], f"missing hash for {key}"


def test_manifest_records_pilot_selection_for_local_model() -> None:
    assert build_manifest()["pilot_selection"] is None
    pilot = build_manifest(local_model={"model": "llama3.2:1b"})["pilot_selection"]
    assert pilot["required_partition"] == corpus.PARTITION_DEVELOPMENT
    assert pilot["enforced"] is True


def test_main_rejects_unknown_partition() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--partition", "dev"])
    assert excinfo.value.code == 2


def test_main_local_model_without_development_partition_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_all = tmp_path / "never_all.json"
    code = main(["run", "--local-model", "llama3.2:1b", "--partition", "all", "-o", str(out_all)])
    assert code == 2
    assert not out_all.exists()
    err = capsys.readouterr().err
    assert "development" in err
    assert "No model was contacted" in err

    out_default = tmp_path / "never_default.json"
    code = main(["run", "--local-model", "llama3.2:1b", "-o", str(out_default)])
    assert code == 2
    assert not out_default.exists()


# --- explicit --select scenario subsets (fail-closed bounded pilots) -------


def test_select_cases_explicit_ids_select_exact_subset_in_corpus_order() -> None:
    development = select_cases(corpus.PARTITION_DEVELOPMENT)
    ids = [development[i].id for i in (0, 5, len(development) - 1)]
    # Supplied out of order; the result must still follow stable corpus order.
    chosen = select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=list(reversed(ids)))
    assert [c.id for c in chosen] == ids
    assert len(chosen) == 3


def test_select_cases_explicit_ids_reject_unknown_id() -> None:
    with pytest.raises(ValueError, match="not in the 'development' selection"):
        select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=["no-such-scenario-00"])


def test_select_cases_explicit_ids_reject_other_partition_id() -> None:
    held = select_cases(corpus.PARTITION_HELD_OUT)[0].id
    with pytest.raises(ValueError, match="not in the 'development' selection"):
        select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=[held])
    # The same id is valid when the requested partition matches its own.
    own = select_cases(corpus.PARTITION_HELD_OUT, select_ids=[held])
    assert [c.id for c in own] == [held]


def test_select_cases_rejects_blank_duplicate_and_empty_ids() -> None:
    dev = select_cases(corpus.PARTITION_DEVELOPMENT)[0].id
    with pytest.raises(ValueError, match="at least one scenario id"):
        select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=[])
    with pytest.raises(ValueError, match="blank scenario id"):
        select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=[" "])
    with pytest.raises(ValueError, match="duplicate scenario id"):
        select_cases(corpus.PARTITION_DEVELOPMENT, select_ids=[dev, dev])


def test_evaluate_bad_select_fails_closed_before_execution(tmp_path: Path) -> None:
    # The bad id must abort before the observer path or any subprocess exists.
    observe = tmp_path / "never.jsonl"
    with pytest.raises(ValueError, match="fail closed"):
        asyncio.run(
            evaluate(
                observe_path=str(observe),
                partition=corpus.PARTITION_DEVELOPMENT,
                select_ids=["no-such-scenario-00"],
            )
        )
    assert not observe.exists()


def test_main_rejects_bad_select(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "never.json"
    code = main(
        ["run", "--partition", "development", "--select", "no-such-scenario-00", "-o", str(out)]
    )
    assert code == 2
    assert not out.exists()
    assert "fail closed" in capsys.readouterr().err


def test_main_manifest_records_explicit_selection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    development = select_cases(corpus.PARTITION_DEVELOPMENT)
    ids = [development[0].id, development[1].id]
    out = tmp_path / "manifest.json"
    code = main(
        [
            "manifest",
            "--partition",
            "development",
            "--select",
            ",".join(ids),
            "-o",
            str(out),
        ]
    )
    assert code == 0
    manifest = json.loads(out.read_text(encoding="utf-8"))
    sel = manifest["explicit_selection"]
    assert sel["ids"] == ids
    assert sel["count"] == 2
    assert sel["validated_partition"] == "development"


def test_main_manifest_rejects_bad_select(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "never.json"
    code = main(["manifest", "--select", "bogus-id", "-o", str(out)])
    assert code == 2
    assert not out.exists()
    assert "fail closed" in capsys.readouterr().err


def test_main_run_with_select_writes_exact_subset(tmp_path: Path) -> None:
    # Full happy path: the runner executes exactly the declared scenarios
    # through the real proxy subprocess and records the resolved ids.
    development = select_cases(corpus.PARTITION_DEVELOPMENT)
    ids = [development[0].id, development[1].id]
    out = tmp_path / "report.json"
    code = main(
        ["run", "--partition", "development", "--select", ",".join(ids), "-o", str(out)]
    )
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["scenarios"] == 2
    assert [r["id"] for r in report["results"]] == ids
    sel = report["partition_selection"]["explicit_selection"]
    assert sel["requested_ids"] == ids
    assert sel["selected_ids"] == ids
    assert sel["count"] == 2
    assert report["partition_selection"]["held_out_scenarios_included"] == 0
    assert report["inference"]["source"] == "rules-only"
