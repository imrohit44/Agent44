"""Deterministic evaluation runner for Agent44 (Milestone 4a).

Replays the versioned corpus through the enforcing proxy (``--policy``) and
compares each observed ALLOW/DENY outcome against the scenario's
pre-registered ``expected`` ground truth. Reports totals, allow/deny counts,
false allows / false denies, per-category results, and adapter-outcome
tallies, plus the protocol's attack-block and false-block rates.

A DENY for one tool call means only that the call was not forwarded
downstream. It is NEVER reported as end-to-end attack prevention.

Deterministic: scenarios run sequentially in corpus order; no model calls,
no network access, no randomness. The machine-readable JSON report is the
stable contract; latency fields are informational only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44 import corpus
from agent44.corpus import CorpusCase
from agent44.observe import JsonlObserver

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_server"]
EVAL_POLICY = (
    Path(__file__).resolve().parent.parent.parent
    / "evaluation"
    / "policy_eval_4a.yaml"
)

# Adapter-outcome rule_ids produced by PolicyEngine.decide for adapter-tier
# calls. Anything else is a deterministic-tier decision.
ADAPTER_RULE_IDS = frozenset(
    {
        "adapter",
        "adapter_timeout",
        "adapter_error",
        "adapter_invalid",
        "adapter_undecided",
        "adapter_missing",
    }
)


def _is_adapter_outcome(rule_id: str | None) -> bool:
    if rule_id is None:
        return False
    return rule_id == "adapter" or rule_id.startswith("adapter_")


async def _run_case(
    session: ClientSession,
    case: CorpusCase,
    observer: JsonlObserver,
    *,
    timeout_seconds: float,
    trial: int = 0,
) -> dict[str, Any]:
    """Run one corpus case and return a normalized result record.

    The authoritative decision comes from the proxy's JSONL observation for
    this call (``policy_action``/``policy_rule_id``); the MCP result only
    tells us whether the call was blocked or executed.
    """
    import time

    started = time.perf_counter()
    obs_before = len(observer.read_events())
    blocked: bool | None = None
    policy_action: str | None = None
    policy_rule_id: str | None = None
    adapter_outcome: str | None = None
    error: str | None = None
    try:
        result = await asyncio.wait_for(
            session.call_tool(case.tool_name, case.arguments),
            timeout=timeout_seconds,
        )
        is_error = bool(result.isError)
        texts = [c.text for c in result.content if c.type == "text"]
        detail = texts[0][:200] if texts else ""
        # The enforcing proxy denies with a CallToolResult whose content
        # starts with a stable prefix; anything else erroring is a
        # downstream tool error, NOT a policy block (protocol caveat).
        if is_error and "policy evaluation failed" in detail:
            blocked = True
            error = "evaluation_error"
        elif is_error and detail.startswith("denied by policy ("):
            blocked = True
        elif is_error:
            blocked = False
        else:
            blocked = False
    except TimeoutError:
        blocked = None
        error = "harness_timeout"
        detail = ""
    except Exception as exc:  # noqa: BLE001 - runner records all failures
        blocked = None
        error = f"harness_exception: {type(exc).__name__}"
        detail = ""
    latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
    events = observer.read_events()
    new_events = events[obs_before:]
    event = new_events[-1] if new_events else None
    if event is not None:
        policy_action = event.get("policy_action")
        policy_rule_id = event.get("policy_rule_id")
        if _is_adapter_outcome(policy_rule_id):
            adapter_outcome = policy_rule_id
        if blocked is None and error is None:
            # Observation exists but classification failed; stay unresolved.
            error = "harness_unresolved"
        elif blocked is not None and policy_action is not None:
            expected_blocked = policy_action == "DENY"
            if blocked != expected_blocked:
                error = "harness_mismatch"
    elif error is None:
        error = "harness_no_observation"
    record: dict[str, Any] = {
        "id": case.id,
        "trial": trial,
        "tool_name": case.tool_name,
        "category": case.category,
        "label": case.label,
        "expected": case.expected,
        "blocked": blocked,
        "policy_action": policy_action,
        "policy_rule_id": policy_rule_id,
        "adapter_outcome": adapter_outcome,
        "error": error,
        "latency_ms": latency_ms,
    }
    return record



def _rate(numerator: int, denominator: int) -> float | None:
    """Return a rate or ``None`` when the denominator is zero."""
    if denominator == 0:
        return None
    return numerator / denominator


def wilson_interval(
    successes: int, n: int, z: float = 1.96
) -> dict[str, float | None]:
    """Return a Wilson score interval for a binomial proportion (protocol §9).

    Wilson intervals behave sensibly at the boundaries (0/n and n/n) and for
    small n, unlike the normal approximation. ``z=1.96`` is the two-sided 95%
    value. Returns ``{"point", "lower", "upper", "n", "successes"}`` with all
    numeric fields ``None`` when ``n == 0`` so a zero denominator can never be
    mistaken for a measured 0% or 100%.
    """
    if n <= 0:
        return {"point": None, "lower": None, "upper": None, "n": 0, "successes": successes}
    phat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (phat + z2 / (2 * n)) / denom
    margin = z * ((phat * (1 - phat) / n + z2 / (4 * n * n)) ** 0.5) / denom
    return {
        "point": phat,
        "lower": max(0.0, center - margin),
        "upper": min(1.0, center + margin),
        "n": n,
        "successes": successes,
    }


def _percentiles(values: list[float]) -> dict[str, float | int | None]:
    """Return min/p50/p95/max percentiles (protocol §10), or ``None`` if empty.

    Uses linear interpolation (the same method as ``statistics.quantiles`` with
    ``method="inclusive"``). Percentiles are only meaningful over executed
    cases; the caller must pass executed-case latencies only.
    """
    if not values:
        return {"count": 0, "min": None, "p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    n = len(ordered)

    def pct(p: float) -> float:
        # inclusive (linear) interpolation on 0-indexed rank
        rank = p * (n - 1)
        lo = int(rank)
        hi = min(lo + 1, n - 1)
        frac = rank - lo
        return ordered[lo] + (ordered[hi] - ordered[lo]) * frac

    return {
        "count": n,
        "min": ordered[0],
        "p50": round(pct(0.50), 3),
        "p95": round(pct(0.95), 3),
        "max": ordered[-1],
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-case records into protocol section 7 metrics."""
    total = len(results)
    executed = sum(1 for r in results if r["error"] is None)
    failed = sum(1 for r in results if r["error"] is not None)
    allowed = sum(1 for r in results if r["policy_action"] == "ALLOW")
    denied = sum(1 for r in results if r["policy_action"] == "DENY")

    false_allows = sum(
        1
        for r in results
        if r["error"] is None
        and r["expected"] == "DENY"
        and r["policy_action"] == "ALLOW"
    )
    false_denies = sum(
        1
        for r in results
        if r["error"] is None
        and r["expected"] == "ALLOW"
        and r["policy_action"] == "DENY"
    )
    agreements = sum(
        1
        for r in results
        if r["error"] is None and r["policy_action"] == r["expected"]
    )
    evaluated = sum(1 for r in results if r["error"] is None)

    # Confidence intervals (Wilson 95%). Denominators are declared explicitly;
    # a zero denominator yields all-None, never a spurious 0/100%.
    false_allow_denom = sum(
        1 for r in results if r["error"] is None and r["expected"] == "DENY"
    )
    false_deny_denom = sum(
        1 for r in results if r["error"] is None and r["expected"] == "ALLOW"
    )

    malicious = [r for r in results if r["label"] == "malicious" and r["error"] is None]
    benign = [r for r in results if r["label"] == "benign" and r["error"] is None]
    blocked_malicious = sum(1 for r in malicious if r["policy_action"] == "DENY")
    blocked_benign = sum(1 for r in benign if r["policy_action"] == "DENY")

    by_category: dict[str, dict[str, int | float | None]] = {}
    categories = sorted({r["category"] for r in results})
    for category in categories:
        rows = [r for r in results if r["category"] == category]
        ok = [r for r in rows if r["error"] is None]
        cat_allowed = sum(1 for r in ok if r["policy_action"] == "ALLOW")
        cat_denied = sum(1 for r in ok if r["policy_action"] == "DENY")
        cat_fa = sum(
            1 for r in ok if r["expected"] == "DENY" and r["policy_action"] == "ALLOW"
        )
        cat_fd = sum(
            1 for r in ok if r["expected"] == "ALLOW" and r["policy_action"] == "DENY"
        )
        by_category[category] = {
            "total": len(rows),
            "evaluated": len(ok),
            "errors": len(rows) - len(ok),
            "allowed": cat_allowed,
            "denied": cat_denied,
            "false_allows": cat_fa,
            "false_denies": cat_fd,
            "agreement_rate": _rate(
                sum(1 for r in ok if r["policy_action"] == r["expected"]), len(ok)
            ),
        }

    adapter_outcomes: dict[str, int] = {}
    for r in results:
        if r["adapter_outcome"] is not None:
            key = str(r["adapter_outcome"])
            adapter_outcomes[key] = adapter_outcomes.get(key, 0) + 1

    # Latency percentiles over executed cases only. This is client-observed
    # wall clock (protocol §10 client_observed_ms): it includes gateway policy
    # evaluation and result shaping. For offline rules-only and replay runs it
    # is NOT a measure of model-inference latency and must not be presented as
    # such. Downstream-only timing is not separated in this harness.
    executed_latencies = [
        float(r["latency_ms"]) for r in results if r["error"] is None
    ]

    # A hard-deny "override" is a call the policy must hard-deny
    # (expected DENY) that was nonetheless ALLOWED. Near-miss scenarios
    # that are correctly ALLOWED (expected ALLOW) are precision checks,
    # not overrides, and must not inflate this security-critical rate.
    hard_rows = [
        r
        for r in results
        if r["category"] in ("hard-deny", "hard-deny-invariance")
        and r["error"] is None
    ]
    hard_overrides = sum(
        1
        for r in hard_rows
        if r["expected"] == "DENY" and r["policy_action"] == "ALLOW"
    )
    hard_deny_denominator = sum(1 for r in hard_rows if r["expected"] == "DENY")

    errors: dict[str, int] = {}
    for r in results:
        if r["error"] is not None:
            key = str(r["error"])
            errors[key] = errors.get(key, 0) + 1

    return {
        "total_scenarios": total,
        "executed_scenarios": executed,
        "failed_scenarios": failed,
        "distinct_scenarios": len({str(r["id"]) for r in results}),
        "trial_records": total,
        "trials_per_scenario": (
            None
            if not results
            else total // max(1, len({str(r["id"]) for r in results}))
        ),
        "sample_size_note": (
            "counts are trial-level records. distinct_scenarios is the number "
            "of unique scenarios; repeated trials of one scenario are NOT "
            "independent scenarios and must not be counted as extra samples. "
            "confidence intervals are computed over executed trial records; "
            "see distinct_scenarios for the independent-scenario denominator."
        ),
        "errors": errors,
        "allowed": allowed,
        "denied": denied,
        "false_allows": false_allows,
        "false_denies": false_denies,
        "expected_outcome_agreement": _rate(agreements, evaluated),
        "attack_block_rate": _rate(blocked_malicious, len(malicious)),
        "attack_block_counts": {"blocked": blocked_malicious, "total": len(malicious)},
        "false_block_rate": _rate(blocked_benign, len(benign)),
        "false_block_counts": {"blocked": blocked_benign, "total": len(benign)},
        "hard_deny_override_rate": _rate(hard_overrides, hard_deny_denominator),
        "hard_deny_overrides": hard_overrides,
        "confidence_intervals": {
            "method": "Wilson score interval, two-sided 95% (z=1.96)",
            "false_allow_rate": wilson_interval(false_allows, false_allow_denom),
            "false_deny_rate": wilson_interval(false_denies, false_deny_denom),
            "expected_outcome_agreement": wilson_interval(agreements, evaluated),
            "attack_block_rate": wilson_interval(blocked_malicious, len(malicious)),
            "note": (
                "Scenario-level proportions over executed scenarios only. "
                "Denominators are declared per interval; a zero denominator "
                "yields nulls, never a spurious 0/100%."
            ),
        },
        "by_category": by_category,
        "adapter_outcomes": adapter_outcomes,
        "latency_ms": _percentiles(executed_latencies),
        "latency_note": (
            "client_observed_ms wall clock over executed cases; includes "
            "gateway overhead. Offline rules-only/replay timing is NOT model "
            "inference latency."
        ),
        "completed": failed == 0,
    }


def _scenario_id(record: dict[str, Any]) -> str:
    """Return the scenario identifier for a result record."""
    return str(record["id"])


def failure_analysis(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Machine- and human-readable failure analysis (protocol §11).

    Reports false allows, false denies, categories with the most errors,
    adapter failure modes, and scenarios whose decision varies across trials.
    Contains only sanitized identifiers (scenario id, category, label,
    expected vs observed action); it never includes raw argument values or
    secrets. Repeated trials of one scenario are aggregated per scenario, so
    a scenario that is inconsistent across trials is reported once with the
    set of observed actions.
    """
    false_allows = [
        {"id": r["id"], "category": r["category"], "label": r["label"]}
        for r in results
        if r["error"] is None and r["expected"] == "DENY" and r["policy_action"] == "ALLOW"
    ]
    false_denies = [
        {"id": r["id"], "category": r["category"], "label": r["label"]}
        for r in results
        if r["error"] is None and r["expected"] == "ALLOW" and r["policy_action"] == "DENY"
    ]

    # Categories with the most decision errors (false allows + false denies).
    error_by_cat: dict[str, int] = {}
    for item in false_allows + false_denies:
        error_by_cat[item["category"]] = error_by_cat.get(item["category"], 0) + 1
    categories_most_errors = sorted(
        ({"category": k, "errors": v} for k, v in error_by_cat.items()),
        key=lambda d: (-int(d["errors"]), str(d["category"])),
    )

    # Adapter failure modes, keyed by the adapter-outcome rule id.
    adapter_failure_modes: dict[str, int] = {}
    for r in results:
        if r["adapter_outcome"] is not None:
            key = str(r["adapter_outcome"])
            adapter_failure_modes[key] = adapter_failure_modes.get(key, 0) + 1

    # Per-scenario variation across repeated trials. A scenario is
    # "inconsistent" if its observed action differs between trials, or if some
    # trials executed and others errored. Decisions are compared per scenario,
    # never across different scenarios.
    by_scenario: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        by_scenario.setdefault(_scenario_id(r), []).append(r)
    inconsistent: list[dict[str, Any]] = []
    for sid in sorted(by_scenario):
        rows = by_scenario[sid]
        actions = {str(r["policy_action"]) for r in rows if r["error"] is None}
        errored = any(r["error"] is not None for r in rows)
        if len(actions) > 1 or (errored and len(actions) >= 1) or (errored and len(rows) > 1):
            inconsistent.append(
                {
                    "id": sid,
                    "category": rows[0]["category"],
                    "observed_actions": sorted(actions),
                    "had_error": errored,
                    "trials": len(rows),
                }
            )

    # Tool-call blocking vs end-to-end objective. This harness forwards single
    # tool calls and does not execute multi-step objectives, so it can only
    # attest that a specific call was blocked. end_to_end_verified is always
    # false here by construction and must not be inferred from a denial.
    blocked_calls = sum(1 for r in results if r["error"] is None and r["blocked"] is True)

    # Failed/skipped scenarios (harness errors) are reported separately so a
    # missing observation can never be mistaken for a decision or silently
    # dropped. Only sanitized identifiers are recorded.
    failed = [
        {"id": r["id"], "category": r["category"], "error": r["error"]}
        for r in results
        if r["error"] is not None
    ]

    return {
        "false_allows": false_allows,
        "false_denies": false_denies,
        "categories_most_errors": categories_most_errors,
        "adapter_failure_modes": adapter_failure_modes,
        "inconsistent_across_trials": inconsistent,
        "failed_scenarios": failed,
        "blocked_tool_calls": blocked_calls,
        "end_to_end_verified": False,
        "end_to_end_note": (
            "The harness executes single tool calls through the proxy; it does "
            "not run multi-step attack objectives. end_to_end_verified is "
            "false by construction and is never inferred from a denied call."
        ),
        "secrets_note": (
            "Failure records contain only scenario id, category, label, and "
            "expected/observed actions. Raw argument values and secrets are "
            "never written."
        ),
    }


async def evaluate(
    observe_path: str | None = None,
    *,
    policy_path: str | Path | None = None,
    adapter_replay: str | Path | None = None,
    timeout_seconds: float = 30.0,
    trials: int = 1,
) -> dict[str, Any]:
    """Run the corpus through the enforcing proxy and return the report.

    ``observe_path`` is an optional caller-facing JSONL copy; the runner
    always uses its own temporary observation file as the authoritative
    decision source so runs are self-contained and reproducible.

    ``trials`` repeats the whole corpus that many times. Each attempt is
    recorded with a trial id and its own scenario id, and every trial's
    observed decision is preserved (never replaced by a majority). For
    deterministic rules-only and replay modes the decisions are identical
    across trials; the trial count is reported so a future stochastic
    adapter can be compared on an equal footing. Execution failures stay
    separate from successful decisions in every aggregate.
    """
    if trials < 1:
        raise ValueError("trials must be >= 1")
    corpus.validate_cases(list(corpus.CASES))
    policy = str(policy_path) if policy_path is not None else str(EVAL_POLICY)
    cases = corpus.load_corpus()  # stable corpus order; no shuffling

    # The proxy's JSONL observation log is the authoritative per-call decision
    # source. The runner ALWAYS runs the proxy with its own observation file so
    # the run is self-contained and reproducible regardless of whether the
    # caller supplied observe_path. The runner reads only its own file; a
    # caller-facing copy is written afterward if observe_path was given.
    with tempfile.TemporaryDirectory() as tmp:
        run_observe = os.path.join(tmp, "run_observations.jsonl")
        proxy_args = [*PROXY_MODULE, "--policy", policy, "--observe", run_observe]
        if adapter_replay:
            proxy_args += ["--adapter-replay", str(adapter_replay)]
        proxy_args += ["--", sys.executable, *DEMO_MODULE]
        params = StdioServerParameters(command=sys.executable, args=proxy_args)
        observer = JsonlObserver(run_observe)

        results: list[dict[str, Any]] = []
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                # Repeat the whole corpus ``trials`` times in a stable order.
                # Each attempt keeps its own trial id and observed decision;
                # repeated trials of one scenario are never merged into a
                # single "correct" outcome.
                for trial in range(trials):
                    for case in cases:
                        results.append(
                            await _run_case(
                                session,
                                case,
                                observer,
                                timeout_seconds=timeout_seconds,
                                trial=trial,
                            )
                        )

        # If the caller requested a specific observation log, copy the run's
        # observations there (best-effort; never affects the run outcome).
        if observe_path:
            try:
                shutil.copyfile(run_observe, str(observe_path))
            except OSError:
                pass

    mode = "adapter-replay" if adapter_replay else "rules-only"
    return {
        "corpus_version": corpus.CORPUS_VERSION,
        "policy": policy,
        "mode": mode,
        "adapter_replay": str(adapter_replay) if adapter_replay else None,
        "trials": trials,
        "scenarios": len(cases),
        "stochastic": False,
        "determinism_note": (
            "Rules-only and replay modes are deterministic; every trial of a "
            "scenario yields an identical decision. trials is reported so a "
            "future stochastic adapter can be compared on an equal footing. A "
            "deterministic replay adapter is NOT evidence of model "
            "reproducibility."
        ),
        "blocking": True,
        "attack_success": None,
        "note": (
            "Policy-enforced evaluation. A DENY means one tool call was not "
            "forwarded downstream; it is NOT a claim of end-to-end attack "
            "prevention."
        ),
        "results": results,
        "summary": summarize(results),
        "failure_analysis": failure_analysis(results),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent44-eval")
    parser.add_argument(
        "-o",
        "--output",
        default="eval_results.json",
        help="Path to write the JSON report (default: eval_results.json).",
    )
    parser.add_argument(
        "--observe",
        default=None,
        help="Optional JSONL observation log to enable while evaluating.",
    )
    parser.add_argument(
        "--adapter-replay",
        default=None,
        help=(
            "Optional JSON replay fixture. When set, the proxy decides "
            "adapter-tier tool calls by replaying recorded decisions."
        ),
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help=(
            "Repeat the whole corpus this many times (default: 1). Each "
            "attempt keeps its own trial id; repeated trials of a scenario "
            "are reported separately and never merged."
        ),
    )
    args = parser.parse_args(argv)

    report = asyncio.run(
        evaluate(
            observe_path=args.observe,
            adapter_replay=args.adapter_replay,
            trials=args.trials,
        )
    )
    out_path = Path(args.output)
    out_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    summary = report["summary"]
    print(f"wrote {out_path}", file=sys.stderr)
    print(
        "mode={mode} total={total} executed={executed} failed={failed} "
        "allowed={allowed} denied={denied} false_allows={fa} false_denies={fd} "
        "completed={completed}".format(
            mode=report["mode"],
            total=summary["total_scenarios"],
            executed=summary["executed_scenarios"],
            failed=summary["failed_scenarios"],
            allowed=summary["allowed"],
            denied=summary["denied"],
            fa=summary["false_allows"],
            fd=summary["false_denies"],
            completed=summary["completed"],
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
