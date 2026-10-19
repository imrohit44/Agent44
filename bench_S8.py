# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def percentile(sorted_values: list[float], q: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    idx = (len(sorted_values) - 1) * q
    lo = int(idx)
    frac = idx - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[lo + 1] * frac


def _group_a_metrics(records: list[dict[str, Any]], group_label: str) -> dict[str, Any]:
    executed = [r for r in records if r.get("error") is None]
    expected_deny = sum(1 for r in executed if r.get("expected") == "DENY")
    expected_allow = sum(1 for r in executed if r.get("expected") == "ALLOW")
    matches = [r for r in executed if r.get("matches_expected") is True]
    false_allows = [r for r in executed if r.get("matches_expected") is False and r.get("expected") == "DENY"]
    false_denies = [r for r in executed if r.get("matches_expected") is False and r.get("expected") == "ALLOW"]
    blocked = [r for r in executed if r.get("blocked") is True]
    failed = [r for r in records if r.get("error") is not None]
    latencies = sorted(r.get("latency_ms") for r in executed if r.get("latency_ms") is not None)
    return {
        "group": group_label,
        "total_scenarios": len(records),
        "executed_scenarios": len(executed),
        "successful": len(matches),
        "failed_scenarios": len(failed),
        "expected_allow": expected_allow,
        "expected_deny": expected_deny,
        "true_allow": len(matches),
        "true_deny": len(executed) - len(matches),
        "false_allows": len(false_allows),
        "false_denies": len(false_denies),
        "agreement": _rate(len(matches), len(executed)),
        "tool_call_block_rate": _rate(len(blocked), len(executed)),
        "tool_calls_blocked": len(blocked),
        "tool_calls_eligible": len(executed),
        "latencies": {
            "count": len(latencies),
            "median_ms": percentile(latencies, 0.5),
            "p95_ms": percentile(latencies, 0.95),
            "max_ms": max(latencies) if latencies else None,
        },
        "failed_details": [{"id": r["id"], "category": r.get("category"), "error": r["error"]} for r in failed],
    }


def _group_b_metrics(extensions: tuple[ExtensionCase, ...], resolutions: list[dict]) -> dict[str, Any]:
    engine_cases = [c for c in extensions if c.scope == "engine"]
    proxy_cases = [c for c in extensions if c.scope == "proxy"]
    engine_resolved = {r["case"]: r for r in resolutions if r.get("scope") == "engine"}
    proxy_resolved = {r["case"]: r for r in resolutions if r.get("scope") == "proxy"}
    engine_matched = 0
    engine_failures = []
    for case in engine_cases:
        r = engine_resolved.get(case.id)
        if r is None:
            engine_failures.append({"id": case.id, "reason": "no_resolution"})
            continue
        resolved = r["resolved"]
        expected = case.expected
        if isinstance(resolved, tuple):
            ok = resolved == expected
        else:
            ok = str(resolved) == expected
        if ok:
            engine_matched += 1
        else:
            engine_failures.append({"id": case.id, "resolved": resolved, "expected": expected})
    proxy_passed = 0
    proxy_details = []
    for case in proxy_cases:
        r = proxy_resolved.get(case.id)
        if r and not r.get("downstream_called") and (r.get("decision_rule_id") or "").startswith("delegation:add:"):
            proxy_passed += 1
        proxy_details.append(r)
    return {
        "group": "extension_suite",
        "total_scenarios": len(extensions),
        "engine_cases": len(engine_cases),
        "proxy_integration_cases": len(proxy_cases),
        "engine_matched": engine_matched,
        "engine_failures": engine_failures,
        "engine_agreement": _rate(engine_matched, len(engine_cases)),
        "proxy_non_forwarding_verified": proxy_passed,
        "proxy_details": proxy_details,
    }


def _combination_header(group_a: dict, group_b: dict) -> dict[str, Any]:
    return {
        "note": (
            "Combined results mix the 94-scenario legacy development corpus (Group A) "
            "with the Phase 7 synthetic extension suite (Group B). This is a mixed "
            "corpus; metrics are reported per group and combined only for total "
            "execution counts, never as a single correctness rate."
        ),
        "total_scenarios": group_a["total_scenarios"] + group_b["total_scenarios"],
        "total_executed": group_a["executed_scenarios"] + group_b["total_scenarios"],
    }
