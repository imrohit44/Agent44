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

Pilot safeguards: scenario selection honors the pre-registered development/
held-out partition split (local-model runs are refused unless they select
the development partition explicitly); an explicit ``--select`` id list
further bounds a run to a pre-declared scenario subset and is validated
fail-closed against the selected partition; the report records the decision
source (rules-only, fixture-replay, or live local model), run bounds, and
the local-model call budget so a strictly-local pilot stays bounded and
reproducible.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44 import corpus
from agent44 import policy as policy_module
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

PARTITION_ALL = "all"
# Pilot safety: local-model runs may only target the development partition
# so held-out scenarios can never influence model or prompt tuning.
LOCAL_MODEL_REQUIRED_PARTITION = corpus.PARTITION_DEVELOPMENT
PARTITION_CHOICES = (
    PARTITION_ALL,
    corpus.PARTITION_DEVELOPMENT,
    corpus.PARTITION_HELD_OUT,
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
    partition: str,
    trial: int = 0,
) -> dict[str, Any]:
    """Run one corpus case and return a normalized result record.

    The authoritative decision comes from the proxy's JSONL observation for
    this call (``policy_action``/``policy_rule_id``); the MCP result only
    tells us whether the call was blocked or executed. Every record carries
    its pre-registered ``partition`` plus an explicit per-scenario verdict:
    ``matches_expected`` (True/False, or ``None`` when the record failed at
    the harness level) and ``failure_reason`` (None on success, otherwise
    ``false_allow`` / ``false_deny`` / the harness error). A failure is
    never silently counted as a pass.
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
    matches_expected, failure_reason = classify_outcome(
        expected=case.expected, action=policy_action, error=error
    )
    record: dict[str, Any] = {
        "id": case.id,
        "trial": trial,
        "tool_name": case.tool_name,
        "category": case.category,
        "label": case.label,
        "partition": partition,
        "expected": case.expected,
        "blocked": blocked,
        "policy_action": policy_action,
        "policy_rule_id": policy_rule_id,
        "adapter_outcome": adapter_outcome,
        "matches_expected": matches_expected,
        "failure_reason": failure_reason,
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


def group_by_scenario(
    results: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group trial-level records by scenario id, preserving encounter order.

    The scenario is the independent statistical unit (protocol amendment
    v1.1 §Statistical units). Repeated trials of one scenario are never
    independent samples and must not inflate a denominator.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in results:
        grouped.setdefault(_scenario_id(record), []).append(record)
    return grouped


def scenario_level_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute scenario-level false-allow/false-deny rates (primary unit).

    For a deterministic decision, every scenario contributes exactly one
    outcome. A scenario is a false allow iff it is expected DENY and every
    executed trial was ALLOWed; a false deny iff expected ALLOW and every
    executed trial was DENY. Scenarios whose trials disagree, or that have no
    executed trial, are excluded from the numerator and the denominator and
    reported separately, so failed/skipped/ambiguous trials can never silently
    improve a rate. Returns Wilson intervals with explicit per-interval
    numerators and denominators and null-on-zero-denominator behavior.
    """
    grouped = group_by_scenario(results)
    total = len(grouped)
    expected_deny = expected_allow = resolved = unresolved = 0
    false_allows = false_denies = 0
    inconsistent: list[str] = []

    for sid in sorted(grouped):
        rows = grouped[sid]
        executed = [r for r in rows if r["error"] is None]
        if not executed:
            unresolved += 1
            continue
        actions = {str(r["policy_action"]) for r in executed}
        expected = str(rows[0]["expected"])
        if len(actions) > 1:
            # Stochastic disagreement: not a single deterministic outcome.
            inconsistent.append(sid)
            continue
        resolved += 1
        observed = next(iter(actions))
        if expected == "DENY":
            expected_deny += 1
            if observed == "ALLOW":
                false_allows += 1
        elif expected == "ALLOW":
            expected_allow += 1
            if observed == "DENY":
                false_denies += 1

    return {
        "unit": "scenario",
        "distinct_scenarios": total,
        "resolved_scenarios": resolved,
        "unresolved_scenarios": unresolved,
        "inconsistent_scenarios": len(inconsistent),
        "inconsistent_scenario_ids": inconsistent,
        "false_allow_numerator": false_allows,
        "false_allow_denominator": expected_deny,
        "false_deny_numerator": false_denies,
        "false_deny_denominator": expected_allow,
        "false_allow_interval": wilson_interval(false_allows, expected_deny),
        "false_deny_interval": wilson_interval(false_denies, expected_allow),
        "sample_size_note": (
            "Primary statistical unit is the distinct scenario. Repeated "
            "trials of one scenario are collapsed to a single outcome; a "
            "scenario is counted only when all its executed trials agree and "
            "at least one executed. Unresolved/inconsistent scenarios are "
            "excluded from numerators and denominators, never counted as "
            "successes."
        ),
    }


def bootstrap_ci(
    per_scenario: list[float],
    *,
    iterations: int = 10_000,
    alpha: float = 0.05,
    seed: int = 0,
) -> dict[str, float | int | None]:
    """Percentile bootstrap CI over per-scenario proportions (amendment v1.1).

    ``per_scenario`` holds one proportion in ``[0, 1]`` per scenario (e.g. a
    per-scenario false-allow rate across that scenario's trials). Resampling
    is over scenarios, the independent unit, so repeated trials never inflate
    the sample size. Uses an explicit ``seed`` for reproducibility. Returns
    ``{\"point\", \"lower\", \"upper\", \"n\", \"iterations\", \"seed\"}`` with
    ``None`` point/limits when ``n == 0``.
    """
    n = len(per_scenario)
    if n == 0:
        return {
            "point": None,
            "lower": None,
            "upper": None,
            "n": 0,
            "iterations": iterations,
            "seed": seed,
        }
    rng = random.Random(seed)
    total = sum(per_scenario)
    means: list[float] = []
    for _ in range(iterations):
        acc = 0.0
        for _ in range(n):
            acc += per_scenario[rng.randrange(n)]
        means.append(acc / n)
    means.sort()
    lo_idx = int((alpha / 2) * iterations)
    hi_idx = min(iterations - 1, int((1 - alpha / 2) * iterations))
    return {
        "point": total / n,
        "lower": means[lo_idx],
        "upper": means[hi_idx],
        "n": n,
        "iterations": iterations,
        "seed": seed,
    }


def within_scenario_variability(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize how often a scenario's decision varies across its trials.

    Reported separately from scenario-level rates so deterministic invariance
    (0 variability) is distinguishable from a stochastic adapter that flips
    decisions between trials of the same scenario.
    """
    grouped = group_by_scenario(results)
    varying = 0
    varying_ids: list[str] = []
    for sid in sorted(grouped):
        actions = {
            str(r["policy_action"]) for r in grouped[sid] if r["error"] is None
        }
        if len(actions) > 1:
            varying += 1
            varying_ids.append(sid)
    return {
        "scenarios_with_trials": len(grouped),
        "scenarios_with_varying_decision": varying,
        "varying_scenario_ids": varying_ids,
    }


def stochastic_aggregation(
    results: list[dict[str, Any]],
    *,
    iterations: int = 10_000,
    seed: int = 0,
) -> dict[str, Any]:
    """Aggregate a stochastic adapter at the scenario level (amendment v1.1).

    For each expected-DENY scenario we form the per-scenario false-allow
    proportion = (ALLOWed trials) / (executed trials); likewise false deny for
    expected-ALLOW scenarios. Averaging those per-scenario proportions gives a
    scenario-weighted point estimate, and :func:`bootstrap_ci` resamples over
    scenarios (the independent unit) for an interval. This never treats repeated
    trials of one scenario as independent. Scenarios with no executed trial are
    excluded from both numerator and denominator. Deterministic runs (one
    agreeing outcome per scenario) reduce cleanly to the scenario-level rates.
    """
    grouped = group_by_scenario(results)
    fa_rates: list[float] = []
    fd_rates: list[float] = []
    fa_scenarios = fd_scenarios = 0
    excluded = 0
    for sid in sorted(grouped):
        rows = grouped[sid]
        executed = [r for r in rows if r["error"] is None]
        if not executed:
            excluded += 1
            continue
        expected = str(rows[0]["expected"])
        allow_trials = sum(1 for r in executed if r["policy_action"] == "ALLOW")
        proportion = allow_trials / len(executed)
        if expected == "DENY":
            fa_scenarios += 1
            fa_rates.append(proportion)
        elif expected == "ALLOW":
            fd_scenarios += 1
            fd_rates.append(1.0 - proportion)

    return {
        "unit": "scenario",
        "method": (
            "Per-scenario proportion averaged over scenarios; percentile "
            "bootstrap over scenarios (independent unit) for the interval."
        ),
        "false_allow": {
            **bootstrap_ci(fa_rates, iterations=iterations, seed=seed),
            "scenarios": fa_scenarios,
        },
        "false_deny": {
            **bootstrap_ci(fd_rates, iterations=iterations, seed=seed),
            "scenarios": fd_scenarios,
        },
        "excluded_no_executed_trial": excluded,
        "note": (
            "Within-scenario trial variability is reported separately in "
            "summary.scenario_level.variability; it is not treated as extra "
            "independent samples here."
        ),
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


def summarize(
    results: list[dict[str, Any]], *, bootstrap_seed: int = 0
) -> dict[str, Any]:
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
        "adapter_outcome_detail": {
            "successful_decisions": int(adapter_outcomes.get("adapter", 0)),
            "timeouts": int(adapter_outcomes.get("adapter_timeout", 0)),
            "malformed_responses": int(adapter_outcomes.get("adapter_invalid", 0)),
            "provider_errors": int(adapter_outcomes.get("adapter_error", 0)),
            "undecided": int(adapter_outcomes.get("adapter_undecided", 0)),
            "missing_adapter": int(adapter_outcomes.get("adapter_missing", 0)),
            "definitions": {
                "adapter": "adapter returned a parsed ALLOW or DENY decision",
                "adapter_timeout": "engine adapter deadline exceeded; fail-closed DENY",
                "adapter_invalid": (
                    "response content could not be parsed into a valid decision "
                    "(malformed model output or wire payload); fail-closed DENY"
                ),
                "adapter_error": (
                    "provider, transport, or configuration failure; fail-closed DENY"
                ),
                "adapter_undecided": "adapter returned UNDECIDED; fail-closed DENY",
                "adapter_missing": (
                    "adapter-tier tool with no adapter configured; fail-closed DENY"
                ),
            },
            "note": (
                "Every adapter failure mode maps to a DENY. Mocked or injected "
                "adapter responses used in tests are fixtures, never model "
                "results; only mode=local-model performs live local inference."
            ),
        },
        "latency_ms": _percentiles(executed_latencies),
        "latency_note": (
            "client_observed_ms wall clock over executed cases; includes "
            "gateway overhead. Offline rules-only/replay timing is NOT model "
            "inference latency."
        ),
        "scenario_level": {
            "note": (
                "Primary statistical unit is the DISTINCT scenario. These "
                "rates collapse repeated trials to one outcome per scenario "
                "and use scenario counts as denominators. Use these for "
                "deterministic rules-only conclusions."
            ),
            **scenario_level_metrics(results),
            "variability": within_scenario_variability(results),
        },
        "stochastic_aggregation": stochastic_aggregation(
            results, seed=bootstrap_seed
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


def select_cases(
    partition: str = PARTITION_ALL, select_ids: list[str] | None = None
) -> list[CorpusCase]:
    """Return the corpus scenarios for ``partition``, in stable corpus order.

    ``"all"`` (the default for rules-only and replay runs) selects every
    scenario. ``"development"`` / ``"held-out"`` select exactly the scenarios
    with that pre-registered partition assignment — deterministic, derived
    from scenario ids alone, never re-split or guessed. A scenario without a
    partition assignment, an empty selection, or a partition that leaks a
    non-matching scenario is a hard error: the run fails closed rather than
    silently including an unassigned scenario in a pilot selection.

    ``select_ids`` (an explicit ``--select`` subset) further restricts the
    selection to exactly those scenario ids, still in stable corpus order.
    Blank, duplicate, unknown, and wrong-partition ids are hard errors raised
    before any execution, so a bounded pilot can never smuggle a held-out
    scenario into a development run or run more scenarios than declared.
    """
    if partition not in PARTITION_CHOICES:
        raise ValueError(
            f"invalid partition {partition!r}; must be one of {', '.join(PARTITION_CHOICES)}"
        )
    cases = corpus.load_corpus()  # stable corpus order; no shuffling
    if partition == PARTITION_ALL:
        selected = cases
    else:
        assigned = corpus.partition_map()
        selected = []
        for case in cases:
            case_partition = assigned.get(case.id)
            if case_partition is None:
                raise ValueError(
                    f"scenario {case.id!r} has no partition assignment; refusing to "
                    "guess a selection for a pilot run (fail closed)"
                )
            if case_partition == partition:
                selected.append(case)
        wrong = [c.id for c in selected if assigned.get(c.id) != partition]
        if wrong:  # defensive; unreachable with a consistent partition_map
            raise ValueError(f"partition selection leaked non-{partition} scenarios: {wrong[:5]}")
    if select_ids is not None:
        selected = _restrict_to_explicit_ids(selected, select_ids, partition=partition)
    if not selected:
        raise ValueError(f"partition {partition!r} selects no scenarios; refusing")
    return selected


def _restrict_to_explicit_ids(
    selected: list[CorpusCase], select_ids: list[str], *, partition: str
) -> list[CorpusCase]:
    """Narrow ``selected`` to exactly ``select_ids`` (fail closed on any mismatch).

    Ids are validated against the already partition-filtered selection: an id
    that is unknown, belongs to a different partition, is blank, or is
    repeated raises ``ValueError`` before anything executes. The returned
    subset keeps stable corpus order regardless of the order the ids were
    supplied in.
    """
    if not select_ids:
        raise ValueError("--select requires at least one scenario id; refusing (fail closed)")
    normalized: list[str] = []
    for raw in select_ids:
        text = str(raw).strip()
        if not text:
            raise ValueError("--select contains a blank scenario id; refusing (fail closed)")
        normalized.append(text)
    if len(set(normalized)) != len(normalized):
        raise ValueError("--select contains duplicate scenario ids; refusing (fail closed)")
    available = {case.id for case in selected}
    missing = [sid for sid in normalized if sid not in available]
    if missing:
        raise ValueError(
            f"--select scenario id(s) not in the {partition!r} selection: {missing[:5]}; "
            "ids must exist and belong to the selected partition (fail closed)"
        )
    wanted = set(normalized)
    return [case for case in selected if case.id in wanted]


def plan_local_model_calls(
    *,
    cases: list[CorpusCase],
    trials: int,
    adapter_tools: set[str] | frozenset[str] | list[str],
    max_calls: int,
) -> dict[str, Any]:
    """Return the pre-run call budget for a local-model pilot; fail closed if exceeded.

    Deterministic tiers (hard rules, allow/deny lists, plain rules) never
    reach the model, but the safe worst case is that every adapter-tier
    scenario in the selection consults the model once per trial. If that
    upper bound exceeds ``max_calls`` (the provider's hard per-run cap), the
    run is refused *before* any model call rather than dying part-way with a
    half-finished report.
    """
    tools = set(adapter_tools)
    upper = trials * sum(1 for case in cases if case.tool_name in tools)
    if upper > max_calls:
        raise ValueError(
            f"local-model call budget exceeded before the run: worst case {upper} "
            f"adapter-tier calls ({len(cases)} cases x {trials} trials, "
            f"adapter_tools={sorted(tools)}) > max_calls={max_calls}; raise "
            "--local-model-max-calls or reduce --trials"
        )
    return {
        "limit": int(max_calls),
        "planned_worst_case_calls": int(upper),
        "note": (
            "planned_worst_case_calls counts every adapter-tier scenario in the "
            "selected partition per trial; deterministic tiers may bypass the "
            "model, so actual calls are at most this figure and always at most "
            "the hard limit. The provider refuses further calls once the limit "
            "is reached and the engine fails those calls closed (DENY)."
        ),
    }


def inference_provenance(
    *, adapter_replay: str | Path | None, local_model: dict[str, Any] | None
) -> dict[str, Any]:
    """Describe where decisions came from; never present fixtures as model output.

    Three mutually exclusive sources exist and must never be conflated in a
    report:

    - ``rules-only``: deterministic policy tiers; no model is involved.
    - ``fixture-replay``: recorded decisions replayed from a file; NOT fresh
      model output and NOT evidence of model quality or reproducibility.
    - ``live-local-model``: a real on-disk model served over loopback; the
      only mode in which any inference happens.
    """
    if local_model:
        return {
            "source": "live-local-model",
            "live_inference": True,
            "note": (
                "Decisions for adapter-tier calls come from a real local model "
                "served over loopback only. This is the only mode that performs "
                "inference; it requires the development partition explicitly."
            ),
        }
    if adapter_replay:
        return {
            "source": "fixture-replay",
            "live_inference": False,
            "note": (
                "Adapter-tier decisions are replayed from a recorded fixture "
                "file. Replay output is NOT model output and NOT evidence of "
                "model quality, reproducibility, or inference behaviour."
            ),
        }
    return {
        "source": "rules-only",
        "live_inference": False,
        "note": (
            "All decisions come from deterministic policy rules; no model, "
            "adapter, network, or randomness is involved."
        ),
    }


def classify_outcome(
    *, expected: str, action: str | None, error: str | None
) -> tuple[bool | None, str | None]:
    """Classify one scenario decision as match / false-allow / false-deny / failed.

    Returns ``(matches_expected, failure_reason)``. ``matches_expected`` is
    ``None`` when the record failed at the harness level (``error`` set, or
    no decision was observed): a failure is never silently counted as a pass.
    """
    if error is not None:
        return None, error
    if action is None:
        return None, "missing_decision"
    if expected not in ("ALLOW", "DENY"):
        return None, "invalid_expected_value"
    if action == expected:
        return True, None
    if expected == "DENY":
        return False, "false_allow"
    return False, "false_deny"


async def evaluate(
    observe_path: str | None = None,
    *,
    policy_path: str | Path | None = None,
    adapter_replay: str | Path | None = None,
    local_model: dict[str, Any] | None = None,
    partition: str = PARTITION_ALL,
    select_ids: list[str] | None = None,
    timeout_seconds: float = 30.0,
    trials: int = 1,
    bootstrap_seed: int = 0,
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

    ``partition`` selects scenarios from the pre-registered development/
    held-out split (``"all"`` is the default and selects everything). A
    ``local_model`` run REQUIRES ``partition="development"`` and refuses
    ``"all"`` or ``"held-out"`` *before* any subprocess, proxy, or model
    call happens: held-out scenarios must never influence model or prompt
    tuning. ``ValueError`` (including :class:`~agent44.policy.PolicyError`)
    is raised for any refused configuration; nothing is executed then.

    ``select_ids`` further bounds the run to an explicit scenario-id subset
    (a bounded pilot). Every id must exist and belong to ``partition`` or the
    run fails closed through :func:`select_cases` before any subprocess,
    proxy, or model call; the resolved ids are recorded in the report under
    ``partition_selection.explicit_selection``.
    """
    if trials < 1:
        raise ValueError("trials must be >= 1")
    corpus.validate_cases(list(corpus.CASES))
    if partition not in PARTITION_CHOICES:
        raise ValueError(
            f"invalid partition {partition!r}; must be one of {', '.join(PARTITION_CHOICES)}"
        )
    if local_model and partition != LOCAL_MODEL_REQUIRED_PARTITION:
        raise ValueError(
            "local-model runs are restricted to the development partition: pass "
            "partition='development' (--partition development). Refused "
            f"partition={partition!r} so held-out scenarios (or the full corpus) "
            "can never influence model/prompt tuning. No model was contacted."
        )
    policy = str(policy_path) if policy_path is not None else str(EVAL_POLICY)
    cases = select_cases(partition, select_ids=select_ids)  # stable order; no shuffling
    partition_of = corpus.partition_map()

    call_budget: dict[str, Any] | None = None
    if local_model:
        # Load and validate the policy before any subprocess or model call so
        # a bad policy path fails closed instead of crashing mid-run, then
        # freeze the call budget for this selection and trial count.
        engine = policy_module.PolicyEngine.from_path(policy)
        call_budget = plan_local_model_calls(
            cases=cases,
            trials=trials,
            adapter_tools=engine.policy.adapter_tools,
            max_calls=int(local_model.get("max_calls", 256)),
        )

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
        if local_model:
            lm = local_model
            proxy_args += ["--local-model", str(lm["model"])]
            proxy_args += ["--local-model-host", str(lm.get("host", "127.0.0.1"))]
            proxy_args += ["--local-model-port", str(lm.get("port", 11434))]
            proxy_args += ["--local-model-timeout", str(lm.get("timeout_seconds", 60.0))]
            proxy_args += ["--local-model-max-calls", str(lm.get("max_calls", 256))]
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
                                partition=partition_of.get(case.id, "unassigned"),
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

    mode = "local-model" if local_model else ("adapter-replay" if adapter_replay else "rules-only")
    held_out_selected = sum(
        1 for case in cases if partition_of.get(case.id) == corpus.PARTITION_HELD_OUT
    )
    provenance = inference_provenance(adapter_replay=adapter_replay, local_model=local_model)
    run_bounds: dict[str, Any] = {
        "harness_per_case_timeout_seconds": float(timeout_seconds),
        "adapter_decision_timeout_seconds": float(policy_module.ADAPTER_TIMEOUT_SECONDS),
        "trials": int(trials),
        "selected_scenarios": len(cases),
        "worst_case_harness_seconds": round(len(cases) * trials * float(timeout_seconds), 3),
        "note": (
            "A run that exceeds the harness worst case (every case timing out "
            "at the per-case bound) must be treated as a failure. The adapter "
            "decision timeout is enforced per adapter-tier call inside the "
            "policy engine and fails closed to DENY; harness timeouts are "
            "recorded per record as harness_timeout and never as a pass."
        ),
    }
    return {
        "corpus_version": corpus.CORPUS_VERSION,
        "policy": policy,
        "mode": mode,
        "inference": provenance,
        "adapter_replay": str(adapter_replay) if adapter_replay else None,
        "local_model": local_model,
        "stochastic": bool(local_model),
        "trials": trials,
        "scenarios": len(cases),
        "bootstrap_seed": bootstrap_seed,
        "partition_selection": {
            "requested": partition,
            "held_out_scenarios_included": held_out_selected,
            "explicit_selection": (
                {
                    "requested_ids": list(select_ids),
                    "selected_ids": [case.id for case in cases],
                    "count": len(cases),
                    "note": (
                        "Ids were supplied via --select, validated against the "
                        "selected partition before execution, and are listed in "
                        "stable corpus order."
                    ),
                }
                if select_ids is not None
                else None
            ),
            "note": (
                "Scenarios are selected by the pre-registered, id-derived "
                "partition assignment; nothing is re-split or guessed. "
                "Local-model pilots must request 'development' explicitly and "
                "include zero held-out scenarios; this count makes that "
                "auditable per run."
            ),
        },
        "run_bounds": run_bounds,
        "model_call_budget": call_budget,
        "determinism_note": (
            "Rules-only and replay modes are deterministic; every trial of a "
            "scenario yields an identical decision. trials is reported so a "
            "future stochastic adapter can be compared on an equal footing. A "
            "deterministic replay adapter is NOT evidence of model "
            "reproducibility."
            if not local_model
            else (
                "Local-model mode calls an on-disk Ollama model over loopback "
                "only. It may be stochastic: per-trial decisions are preserved "
                "and scenario-level aggregation + bootstrap are reported. The "
                "local_model block records the exact model tag, host, and call "
                "limit; add the model digest from 'ollama show' to the "
                "manifest for a fully pinned freeze. Local-model runs cover "
                "only the development partition (see partition_selection)."
            )
        ),
        "blocking": True,
        "attack_success": None,
        "note": (
            "Policy-enforced evaluation. A DENY means one tool call was not "
            "forwarded downstream; it is NOT a claim of end-to-end attack "
            "prevention."
        ),
        "results": results,
        "summary": summarize(results, bootstrap_seed=bootstrap_seed),
        "failure_analysis": failure_analysis(results),
    }


def _sha256_file(path: Path) -> str | None:
    """Return the SHA-256 of a file, or ``None`` if it does not exist."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _git_commit() -> str | None:
    """Return the current git commit id, or ``None`` outside a git checkout."""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_manifest(
    policy_path: str | Path | None = None,
    local_model: dict[str, Any] | None = None,
    select_ids: list[str] | None = None,
    select_partition: str | None = None,
) -> dict[str, Any]:
    """Build a reproducible experiment manifest for a freeze.

    Records the git commit id and SHA-256 hashes of the decision-relevant
    sources (runner, corpus, policy engine, model adapter, local provider,
    proxy, observation modules), the evaluation policy, the frozen protocol,
    the amendment, and the replay fixture, plus the dev/held-out partition
    counts. When ``local_model`` is supplied (a strictly-local experiment),
    the exact model tag, loopback endpoint, call limit, and (if provided)
    model digest are recorded so the run is fully pinned, and the
    development-only pilot selection requirement is recorded alongside it, and
    an explicit ``select_ids`` subset is recorded verbatim under
    ``explicit_selection``.
    Contains no credentials or sensitive values: it hashes files, it never
    reads or embeds secrets.
    """
    evaluation_dir = Path(__file__).resolve().parent.parent.parent / "evaluation"
    src_dir = Path(__file__).resolve().parent
    policy = Path(policy_path) if policy_path is not None else EVAL_POLICY
    protocol = evaluation_dir / "PROTOCOL_v1.md"
    amendment = evaluation_dir / "PROTOCOL_v1.1_AMENDMENT.md"
    replay = evaluation_dir / "adapter_replay_fixture.json"
    pilot_selection = (
        {
            "required_partition": LOCAL_MODEL_REQUIRED_PARTITION,
            "enforced": True,
            "note": (
                "Local-model pilot runs may only select the development "
                "partition; the evaluator refuses held-out or full-corpus "
                "local-model runs before contacting any model."
            ),
        }
        if local_model
        else None
    )
    return {
        "protocol": "PROTOCOL_v1.1_AMENDMENT",
        "generated_by": "agent44.eval_runner manifest",
        "git_commit": _git_commit(),
        "corpus_version": corpus.CORPUS_VERSION,
        "artifacts": {
            "corpus_module": {
                "path": "src/agent44/corpus.py",
                "sha256": _sha256_file(src_dir / "corpus.py"),
            },
            "eval_runner": {
                "path": "src/agent44/eval_runner.py",
                "sha256": _sha256_file(Path(__file__).resolve()),
            },
            "policy_engine": {
                "path": "src/agent44/policy.py",
                "sha256": _sha256_file(src_dir / "policy.py"),
            },
            "model_adapter": {
                "path": "src/agent44/model_adapter.py",
                "sha256": _sha256_file(src_dir / "model_adapter.py"),
            },
            "local_provider": {
                "path": "src/agent44/local_provider.py",
                "sha256": _sha256_file(src_dir / "local_provider.py"),
            },
            "proxy": {
                "path": "src/agent44/proxy.py",
                "sha256": _sha256_file(src_dir / "proxy.py"),
            },
            "observe": {
                "path": "src/agent44/observe.py",
                "sha256": _sha256_file(src_dir / "observe.py"),
            },
            "policy": {
                "path": str(policy),
                "sha256": _sha256_file(policy),
            },
            "protocol_v1": {
                "path": str(protocol),
                "sha256": _sha256_file(protocol),
            },
            "amendment_v11": {
                "path": str(amendment),
                "sha256": _sha256_file(amendment),
            },
            "replay_fixture": {
                "path": str(replay),
                "sha256": _sha256_file(replay),
            },
        },
        "partitions": {
            "fraction_held_out": corpus.HELD_OUT_FRACTION,
            "counts": corpus.partition_counts(),
            "label_composition": corpus.partition_label_composition(),
            "note": (
                "Deterministic, label-stratified, reproducible from scenario "
                "ids alone. Ids and ground-truth labels are unchanged."
            ),
        },
        "independent_cases": None,
        "local_model": local_model,
        "pilot_selection": pilot_selection,
        "explicit_selection": (
            {
                "ids": list(select_ids),
                "count": len(select_ids),
                "validated_partition": select_partition,
                "note": (
                    "Exact scenario ids declared via --select for this run; "
                    "each id was validated against the selected partition "
                    "before execution (fail closed)."
                ),
            }
            if select_ids is not None
            else None
        ),
        "limitations": [
            "All scenarios are hand-authored-synthetic; no independent or "
            "external cases exist, so independent-review claims are "
            "unsupported.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent44-eval")
    parser.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=["run", "manifest"],
        help=(
            "'run' (default) executes the corpus; 'manifest' writes a "
            "reproducible experiment manifest (commit id + artifact hashes)."
        ),
    )
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
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help=(
            "Seed for the scenario-level percentile bootstrap used for a "
            "stochastic adapter's intervals (default: 0). Fixed seed makes "
            "bootstrap output reproducible; rules-only/replay modes are "
            "deterministic regardless of seed."
        ),
    )
    parser.add_argument(
        "--partition",
        choices=PARTITION_CHOICES,
        default=PARTITION_ALL,
        help=(
            "Scenario selection: 'all' (default; rules-only/replay runs), or "
            "'development'/'held-out' from the pre-registered id-derived "
            "split. Local-model runs require 'development' and fail closed "
            "(exit 2, nothing executed) on anything else so held-out "
            "scenarios can never tune the model or prompt."
        ),
    )
    parser.add_argument(
        "--select",
        default=None,
        metavar="ID1,ID2,...",
        help=(
            "Comma-separated scenario ids to run as an explicit subset of "
            "--partition (bounded pilots). Fails closed (exit 2, nothing "
            "executed) on blank, duplicate, unknown, or wrong-partition ids; "
            "output records the exact resolved ids."
        ),
    )
    parser.add_argument(
        "--local-model",
        default=None,
        metavar="TAG",
        help=(
            "Opt in to a local Ollama model (e.g. 'llama3.2:1b'). Calls only "
            "http://127.0.0.1:11434. Off by default; default/CI runs stay "
            "offline on the rules-only/replay paths. A model must already be "
            "installed (run 'ollama pull <TAG>' manually); the evaluator "
            "never downloads a model."
        ),
    )
    parser.add_argument(
        "--local-model-host",
        default="127.0.0.1",
        help="Loopback host for the local model (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--local-model-port",
        type=int,
        default=11434,
        help="Loopback port for the local model (default: 11434).",
    )
    parser.add_argument(
        "--local-model-timeout",
        type=float,
        default=60.0,
        help="Per-request timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--local-model-max-calls",
        type=int,
        default=256,
        help="Hard cap on local-model calls for one run (default: 256).",
    )
    parser.add_argument(
        "--local-model-digest",
        default=None,
        help=(
            "Optional model digest (e.g. from 'ollama show --json <TAG>') to "
            "record in the report/manifest for a fully pinned freeze."
        ),
    )
    args = parser.parse_args(argv)

    select_ids: list[str] | None = None
    if args.select is not None:
        # Split verbatim; blank entries are preserved so the fail-closed
        # validator in select_cases rejects them (empty string -> [""]).
        select_ids = args.select.split(",")

    local_model = None
    if args.local_model:
        local_model = {
            "model": args.local_model,
            "host": args.local_model_host,
            "port": args.local_model_port,
            "timeout_seconds": args.local_model_timeout,
            "max_calls": args.local_model_max_calls,
        }
        if args.local_model_digest:
            local_model["digest"] = args.local_model_digest

    if args.command == "manifest":
        try:
            # Validate ids against the selected partition so the manifest can
            # never record a selection a run would refuse (fail closed).
            if select_ids is not None:
                select_cases(args.partition, select_ids=select_ids)
        except ValueError as exc:
            print(f"agent44-eval: {exc}", file=sys.stderr)
            return 2
        manifest = build_manifest(
            local_model=local_model,
            select_ids=select_ids,
            select_partition=args.partition if select_ids is not None else None,
        )
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {out_path}", file=sys.stderr)
        print(
            f"commit={manifest['git_commit']} "
            f"partitions={manifest['partitions']['counts']}",
            file=sys.stderr,
        )
        return 0

    try:
        report = asyncio.run(
            evaluate(
                observe_path=args.observe,
                adapter_replay=args.adapter_replay,
                local_model=local_model,
                partition=args.partition,
                select_ids=select_ids,
                trials=args.trials,
                bootstrap_seed=args.seed,
            )
        )
    except ValueError as exc:
        # Fail-closed configuration errors (invalid partition, local-model
        # partition restriction, bad --select ids, call budget exceeded, bad
        # policy file; PolicyError subclasses ValueError). Nothing executed.
        print(f"agent44-eval: {exc}", file=sys.stderr)
        return 2
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
