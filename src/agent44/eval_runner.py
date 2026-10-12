"""Minimal evaluation runner for Agent44 (Milestone 2).

Replays the versioned corpus against the demo tools through the transparent
proxy and exports machine-readable JSON results.

IMPORTANT: this runner runs in *observation-only* mode. It records what
happened; it does NOT block anything. Adversarial cases are labelled so their
outcomes are visible, but a non-error outcome for an adversarial case must
never be read as "the attack was blocked" — nothing is enforced in this
milestone.
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

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_server"]


async def _run_case(
    session: ClientSession,
    case: corpus.CorpusCase,
) -> dict[str, Any]:
    """Run one corpus case and return a normalized result record."""
    import time

    started = time.perf_counter()
    outcome = "ok"
    is_error = False
    detail = ""
    try:
        result = await session.call_tool(case.tool_name, case.arguments)
        is_error = bool(result.isError)
        outcome = "tool_error" if is_error else "ok"
        texts = [c.text for c in result.content if c.type == "text"]
        if texts:
            detail = texts[0][:200]
    except Exception as exc:  # noqa: BLE001 - runner records all failures
        outcome = "exception"
        is_error = True
        detail = repr(exc)[:300]
    latency_ms = (time.perf_counter() - started) * 1000.0
    return {
        "id": case.id,
        "tool_name": case.tool_name,
        "category": case.category,
        "outcome": outcome,
        "is_error": is_error,
        "latency_ms": round(latency_ms, 3),
        "detail": detail,
    }


def _percentile(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = pct / 100.0 * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    frac = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    latencies = sorted(r["latency_ms"] for r in results)
    outcomes: dict[str, int] = {}
    for r in results:
        outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
    by_category: dict[str, int] = {}
    for r in results:
        by_category[r["category"]] = by_category.get(r["category"], 0) + 1
    return {
        "total_calls": len(results),
        "outcomes": outcomes,
        "by_category": by_category,
        "latency_ms": {
            "min": round(latencies[0], 3) if latencies else None,
            "p50": round(_percentile(latencies, 50), 3) if latencies else None,
            "p95": round(_percentile(latencies, 95), 3) if latencies else None,
            "max": round(latencies[-1], 3) if latencies else None,
        },
    }


async def evaluate(observe_path: str | None = None) -> dict[str, Any]:
    """Run the corpus through the proxy and return a machine-readable report."""
    proxy_args = [*PROXY_MODULE]
    if observe_path:
        proxy_args += ["--observe", observe_path]
    proxy_args += ["--", sys.executable, *DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=proxy_args)

    results: list[dict[str, Any]] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for case in corpus.load_corpus():
                results.append(await _run_case(session, case))

    return {
        "corpus_version": corpus.CORPUS_VERSION,
        "mode": "observation-only",
        "blocking": False,
        "note": (
            "Observation-only evaluation. No policy is enforced and nothing is "
            "blocked. A non-error outcome for an adversarial case is NOT a "
            "security block."
        ),
        "results": results,
        "summary": _summarize(results),
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
    args = parser.parse_args(argv)

    report = asyncio.run(evaluate(observe_path=args.observe))
    out_path = Path(args.output)
    out_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    summary = report["summary"]
    print(f"wrote {out_path}", file=sys.stderr)
    print(
        f"total={summary['total_calls']} outcomes={summary['outcomes']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
