def _resolve_group_b(extensions: tuple[ExtensionCase, ...]) -> list[dict]:
    resolutions: list[dict] = []
    for case in extensions:
        if case.scope == "engine":
            resolutions.append(resolve_engine_case(case))
        else:
            resolutions.append({"case": case.id, "scope": "proxy"})
    return resolutions


async def _run_group_a_profiles(
    selection: SelectedGroupA,
    output_dir: Path,
    *,
    trials: int = 1,
    adapter_deadline: float = 5.0,
):
    group_a_baselines: list[dict[str, Any]] = []
    group_a_enforcements: list[dict[str, Any]] = []
    g_a_baseline_summary: dict[str, Any] = {}
    g_a_enforcement_summary: dict[str, Any] = {}
    for profile in ("baseline", "enforcement"):
        profile_dir = output_dir / profile
        write_profile_artifacts(profile_dir, enforcement=(profile == "enforcement"), now=int(time.time()))
        records, summary = await _run_profile_once(
            profile,
            profile_dir,
            selection.ids,
            trials=trials,
            adapter_deadline=adapter_deadline,
        )
        if profile == "baseline":
            group_a_baselines = records
            g_a_baseline_summary = summary
        else:
            group_a_enforcements = records
            g_a_enforcement_summary = summary
    return group_a_baselines, group_a_enforcements, g_a_baseline_summary, g_a_enforcement_summary


def _run_group_b(extensions: tuple[ExtensionCase, ...]) -> tuple[list[dict], dict[str, Any], dict[str, Any]]:
    resolutions = _resolve_group_b(extensions)
    group_b = _group_b_metrics(extensions, resolutions)
    resolution_summary = {
        "group_b_engine_total": group_b["engine_cases"],
        "group_b_engine_matched": group_b["engine_matched"],
        "group_b_engine_agreement": group_b["engine_agreement"],
        "group_b_proxy_total": group_b["proxy_integration_cases"],
        "group_b_proxy_non_forwarding_verified": group_b["proxy_non_forwarding_verified"],
    }
    return resolutions, group_b, resolution_summary


async def _execute(
    output_dir: Path,
    *,
    selection: SelectedGroupA,
    trials: int = 1,
    adapter_deadline: float = 5.0,
):
    group_a_baselines, group_a_enforcements, g_a_baseline_summary, g_a_enforcement_summary = await _run_group_a_profiles(
        selection, output_dir, trials=trials, adapter_deadline=adapter_deadline
    )

    extensions = tuple(EXTENSION_CASES)
    resolutions, group_b, resolution_summary = _run_group_b(extensions)

    g_a_baseline = _group_a_metrics(group_a_baselines, group_label="group_a_baseline")
    g_a_enforcement = _group_a_metrics(group_a_enforcements, group_label="group_a_enforcement")
    combined = _combination_header(g_a_baseline, group_b)

    _write_run_outputs(
        output_dir,
        selection,
        g_a_baseline,
        g_a_enforcement,
        group_b,
        combined,
        group_a_records={
            "group_a_baseline": group_a_baselines,
            "group_a_enforcement": group_a_enforcements,
        },
        group_b_resolutions=resolutions,
    )

    return {
        "profiles": {
            "baseline": {"executed": g_a_baseline["executed_scenarios"], "agreement": g_a_baseline["agreement"], "block_rate": g_a_baseline["tool_call_block_rate"]},
            "enforcement": {"executed": g_a_enforcement["executed_scenarios"], "agreement": g_a_enforcement["agreement"], "block_rate": g_a_enforcement["tool_call_block_rate"]},
        },
        "group_b": {
            "engine_total": group_b["engine_cases"],
            "engine_matched": group_b["engine_matched"],
            "engine_agreement": group_b["engine_agreement"],
            "proxy_total": group_b["proxy_integration_cases"],
            "proxy_non_forwarding_verified": group_b["proxy_non_forwarding_verified"],
        },
        "combined_total": combined["total_scenarios"],
        "rev": _git_commit(),
        "output_dir": str(output_dir),
    }
