# --------------------------------------------------------------------------- #
# Profile / configuration builders
# --------------------------------------------------------------------------- #


def _load_eval_policy() -> str:
    return PROTOCOL_V1.read_text(encoding="utf-8")


def build_rule_policy_text() -> str:
    return _load_eval_policy()


def build_enforcement_policy_text() -> str:
    text = _load_eval_policy()
    return (
        text
        + "\n"
        + "provenance:\n"
        + '  enforcement: "required"\n'
        + "  transfer:\n"
        + "    max_transfers_per_call: 8\n"
        + "    ttl_seconds: 600\n"
        + "    max_records_per_workflow: 64\n"
        + "    max_lineage_depth: 8\n"
        + "    max_workflows: 8\n"
        + "    max_record_size: 4096\n"
        + "    max_correlations_per_workflow: 256\n"
        + "delegation:\n"
        + '  enforcement: "required"\n'
        + "  max_active_delegations: 16\n"
        + "  max_ttl_seconds: 3600\n"
    )


def build_delegation_manifest(now: float, granted_tools: tuple[str, ...] | None = None) -> dict:
    grant = tuple(granted_tools) if granted_tools is not None else ("add", "echo", "review_tool", "hit", "counter")
    return {
        "delegation_id": "bench-permissive-1",
        "workflow_id": "bench-wf-1",
        "initiator": {"principal_id": "init-bench", "allowed_tools": tuple(grant)},
        "delegate_principal_id": "deleg-bench",
        "granted_tools": tuple(grant),
        "issued_at": now - 60,
        "expires_at": now + 7200,
        "status": "active",
        "parent_delegation_id": None,
    }


def write_profile_artifacts(profile_dir: Path, *, enforcement: bool, now: float) -> dict:
    profile_dir.mkdir(parents=True, exist_ok=True)
    policy_text = build_enforcement_policy_text() if enforcement else build_rule_policy_text()
    policy_path = profile_dir / ("policy.yaml" if enforcement else "baseline_policy.yaml")
    policy_path.write_text(policy_text, encoding="utf-8")
    manifest_path = profile_dir / "bench_delegation_manifest.json"
    manifest_path.write_text(json.dumps(build_delegation_manifest(now)), encoding="utf-8")
    return {"policy_path": str(policy_path), "manifest_path": str(manifest_path), "enforcement": enforcement}
