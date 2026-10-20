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


def _observed_blocked(record: dict[str, Any]) -> bool | None:
    """Infer whether the call was blocked (DENY) from a result record."""
    blocked = record.get("blocked")
    if blocked is not None:
        return blocked is True
    action = record.get("action")
    if action is not None:
        return action == "DENY"
    return None


def _matches_expected(record: dict[str, Any]) -> bool | None:
    """Return whether the observed decision matches expected ground truth."""
    if "matches_expected" in record:
        return record["matches_expected"]
    expected = record.get("expected")
    blocked = _observed_blocked(record)
    if expected is None or blocked is None:
        return None
    if expected == "DENY":
        return blocked is True
    if expected == "ALLOW":
        return blocked is False
    return None


def _group_a_metrics(records: list[dict[str, Any]], group_label: str) -> dict[str, Any]:
    executed = [r for r in records if r.get("error") is None]
    expected_deny = sum(1 for r in executed if r.get("expected") == "DENY")
    expected_allow = sum(1 for r in executed if r.get("expected") == "ALLOW")
    matches = [r for r in executed if _matches_expected(r) is True]
    false_allows = [r for r in executed if _matches_expected(r) is False and r.get("expected") == "DENY"]
    false_denies = [r for r in executed if _matches_expected(r) is False and r.get("expected") == "ALLOW"]
    blocked = [r for r in executed if r.get("blocked") is True]
    failed = [r for r in records if r.get("error") is not None]
    latencies = sorted(r.get("latency_ms") for r in executed if r.get("latency_ms") is not None)
    return {
        "group": group_label,
        "total_scenarios": len(records),
        "executed_scenarios": len(executed),
        # "successful" counts scenarios that produced a harness-valid decision;
        # verdict quality is reported separately by agreement/false_* and the
        # failed_scenarios count (which tracks harness-level failures only).
        "successful": len(executed),
        "matched": len(matches),
        "failed_scenarios": len(failed),
        "expected_allow": expected_allow,
        "expected_deny": expected_deny,
        # True positives per ground-truth class: only scenarios whose expected
        # value was observed count towards their own class.
        "true_allow": sum(
            1 for r in executed if r.get("expected") == "ALLOW" and _matches_expected(r) is True
        ),
        "true_deny": sum(
            1 for r in executed if r.get("expected") == "DENY" and _matches_expected(r) is True
        ),
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
        expected = r.get("expected", case.expected)
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
            "Combined results mix the pre-declared 30-scenario Group A "
            "selection (drawn from the 94-scenario development partition) "
            "with the Phase 7 synthetic extension suite (Group B). This is a "
            "mixed corpus; metrics are reported per group and combined only "
            "for total execution counts, never as a single correctness rate."
        ),
        "total_scenarios": group_a["total_scenarios"] + group_b["total_scenarios"],
        "total_executed": group_a["executed_scenarios"] + group_b["total_scenarios"],
    }


def _rule_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count observed deny rule ids across the records that were blocked."""
    counts: dict[str, int] = {}
    for record in records:
        if record.get("blocked") is True:
            rule = str(record.get("policy_rule_id"))
            counts[rule] = counts.get(rule, 0) + 1
    return dict(sorted(counts.items()))


def _write_run_outputs(
    output_dir: Path,
    selection: SelectedGroupA,
    g_a_baseline: dict[str, Any],
    g_a_enforcement: dict[str, Any],
    group_b: dict[str, Any],
    combined: dict[str, Any],
    group_a_records: dict[str, list[dict[str, Any]]],
    group_b_resolutions: list[dict[str, Any]],
) -> None:
    """Write results.json, summary.md, manifest.json, and the per-scenario
    decision records needed to independently recompute every reported metric."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Per-scenario decision records: the evidence every Group A/Group B number
    # in results.json is computed from. Written before the aggregates so a
    # reader can recompute agreement / false-allow / false-deny / block rate
    # without re-running the benchmark.
    record_payloads = {
        "group_a_baseline_records.json": group_a_records.get("group_a_baseline", []),
        "group_a_enforcement_records.json": group_a_records.get("group_a_enforcement", []),
        "group_b_resolutions.json": group_b_resolutions,
    }
    for filename, payload in record_payloads.items():
        write_json(output_dir / filename, payload)
    artifact_index = {Path(name).stem: name for name in record_payloads}

    # results.json — detailed machine-readable output
    results = {
        "schema": "agent44.benchmark.v1",
        "generated_at": now_iso(),
        "selection": {
            "label": selection.label,
            "count": selection.count,
            "ids": list(selection.ids),
        },
        "group_a_baseline": g_a_baseline,
        "group_a_enforcement": g_a_enforcement,
        "group_b": group_b,
        "combined": combined,
        "artifacts": artifact_index,
    }
    write_json(output_dir / "results.json", results)

    # summary.md — human-readable summary
    lines = [
        "# Phase 8 Benchmark Results",
        "",
        f"Generated: {now_iso()}",
        f"Revision: {_git_commit()}",
        "",
        "## Group A (development corpus)",
        f"- Selection: {selection.label} ({selection.count} scenarios)",
        f"- Baseline executed: {g_a_baseline['executed_scenarios']}/{g_a_baseline['total_scenarios']}",
        f"- Baseline agreement: {g_a_baseline['agreement']}",
        f"- Baseline false allows: {g_a_baseline['false_allows']}",
        f"- Baseline false denies: {g_a_baseline['false_denies']}",
        f"- Baseline block rate: {g_a_baseline['tool_call_block_rate']}",
        f"- Enforcement executed: {g_a_enforcement['executed_scenarios']}/{g_a_enforcement['total_scenarios']}",
        f"- Enforcement agreement: {g_a_enforcement['agreement']}",
        f"- Enforcement false allows: {g_a_enforcement['false_allows']}",
        f"- Enforcement false denials: {g_a_enforcement['false_denies']}",
        f"- Enforcement block rate: {g_a_enforcement['tool_call_block_rate']}",
        "",
        "### Deny rule ids observed (from group_a_*_records.json)",
        f"- Baseline: {json.dumps(_rule_counts(group_a_records.get('group_a_baseline', [])), ensure_ascii=False)}",
        f"- Enforcement: {json.dumps(_rule_counts(group_a_records.get('group_a_enforcement', [])), ensure_ascii=False)}",
        "",
        "## Group B (extension suite)",
        f"- Engine cases: {group_b['engine_cases']}",
        f"- Engine matched: {group_b['engine_matched']}",
        f"- Engine agreement: {group_b['engine_agreement']}",
        f"- Proxy integration cases: {group_b['proxy_integration_cases']}",
        f"- Proxy non-forwarding verified: {group_b['proxy_non_forwarding_verified']}",
        "",
        "## Combined",
        f"- Total scenarios: {combined['total_scenarios']}",
        f"- Total executed: {combined['total_executed']}",
    ]
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # manifest.json — run configuration manifest
    manifest = {
        "schema": "agent44.benchmark.manifest.v1",
        "generated_at": now_iso(),
        "revision": _git_commit(),
        "policy_file": str(EVAL_DIR / "policy_eval_4a.yaml"),
        "corpus_version": CORPUS_VERSION,
        "selection": {
            "label": selection.label,
            "count": selection.count,
            "ids": list(selection.ids),
        },
        "output_dir": str(output_dir),
    }
    write_json(output_dir / "manifest.json", manifest)
