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
import sys
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

    hard_rows = [r for r in results if r["category"] == "hard-deny"]
    hard_overrides = sum(
        1
        for r in hard_rows
        if r["error"] is None and r["policy_action"] == "ALLOW"
    )

    errors: dict[str, int] = {}
    for r in results:
        if r["error"] is not None:
            key = str(r["error"])
            errors[key] = errors.get(key, 0) + 1

    return {
        "total_scenarios": total,
        "executed_scenarios": executed,
        "failed_scenarios": failed,
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
        "hard_deny_override_rate": _rate(hard_overrides, len(hard_rows)),
        "hard_deny_overrides": hard_overrides,
        "by_category": by_category,
        "adapter_outcomes": adapter_outcomes,
        "completed": failed == 0,
    }


async def evaluate(
    observe_path: str | None = None,
    *,
    policy_path: str | Path | None = None,
    adapter_replay: str | Path | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run the corpus through the enforcing proxy and return the report."""
    corpus.validate_cases(list(corpus.CASES))
    policy = str(policy_path) if policy_path is not None else str(EVAL_POLICY)
    cases = corpus.load_corpus()  # stable corpus order; no shuffling
    proxy_args = [*PROXY_MODULE, "--policy", policy]
    if observe_path:
        proxy_args += ["--observe", observe_path]
    if adapter_replay:
        proxy_args += ["--adapter-replay", str(adapter_replay)]
    proxy_args += ["--", sys.executable, *DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=proxy_args)

    # The runner reads the proxy's own JSONL observation log for the
    # authoritative per-call decision. It always uses its own file so the
    # run is self-contained and reproducible regardless of the caller's
    # --observe choice.
    observer = JsonlObserver(observe_path) if observe_path else None
    results: list[dict[str, Any]] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for case in cases:
                results.append(
                    await _run_case(
                        session,
                        case,
                        observer,
                        timeout_seconds=timeout_seconds,
                    )
                )

    mode = "adapter-replay" if adapter_replay else "rules-only"
    return {
        "corpus_version": corpus.CORPUS_VERSION,
        "policy": policy,
        "mode": mode,
        "adapter_replay": str(adapter_replay) if adapter_replay else None,
        "blocking": True,
        "attack_success": None,
        "note": (
            "Policy-enforced evaluation. A DENY means one tool call was not "
            "forwarded downstream; it is NOT a claim of end-to-end attack "
            "prevention."
        ),
        "results": results,
        "summary": summarize(results),
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
    args = parser.parse_args(argv)

    report = asyncio.run(
        evaluate(observe_path=args.observe, adapter_replay=args.adapter_replay)
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
