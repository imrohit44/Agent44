    if case.id == "ext-delegation-008-missing-manifest":
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=None)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-009-nested-rejected":
        try:
            DelegationContext(
                delegation_id="ext-9",
                workflow_id="wf-x9",
                initiator=Principal("init-x", frozenset({"echo"})),
                delegate_principal_id="del-x",
                granted_tools=frozenset({"echo"}),
                issued_at=now - 60,
                expires_at=now + 3600,
                parent_delegation_id="parent-dlg",
            )
            return {"case": case.id, "resolved": "construction_ok", "expected": case.expected, "scope": "engine"}
        except DelegationValidationError:
            return {"case": case.id, "resolved": "DENY", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-001-valid-import":
        ok, err = transfer_valid_import_outcome()
        return {"case": case.id, "resolved": "ALLOW" if ok else f"DENY:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-002-forged":
        ok, err = transfer_forged_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-003-replay":
        ok, err = transfer_replay_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-004-expired-transfer":
        ok, err = transfer_expired_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-005-unauthorized":
        ok, err = transfer_unauthorized_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-transfer-006-malformed-handle":
        ok, err = transfer_malformed_outcome()
        return {"case": case.id, "resolved": "DENY" if not ok else f"ALLOW:{err}", "expected": case.expected, "scope": "engine"}
    return {"case": case.id, "resolved": "unhandled", "expected": case.expected, "scope": "engine"}


# --------------------------------------------------------------------------- #
# Downstream non-forwarding integration harness (proxy level)
# --------------------------------------------------------------------------- #


async def run_non_forwarding_integration_case(
    profile_dir: Path, delegation_grant: tuple[str, ...]
) -> dict:
    run_dir = profile_dir / "integration_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    counter_path = run_dir / "counter.log"

    manifest = build_delegation_manifest(int(time.time()), granted_tools=list(delegation_grant))
    (profile_dir / "integration_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    observe_path = run_dir / "observations.jsonl"
    args = [
        *eval_runner.PROXY_MODULE,
        "--policy",
        str(profile_dir / "policy.yaml"),
        "--observe",
        str(observe_path),
        "--delegation",
        str(profile_dir / "integration_manifest.json"),
        "--",
        sys.executable,
        *eval_runner.DEMO_MODULE,
    ]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("add", {"a": 1, "b": 2})

    decision: str | None = None
    for event in read_json(observe_path):
        rule_id = event.get("policy_rule_id") or ""
        if rule_id.startswith("delegation:add:"):
            decision = rule_id
            break

    counter = ""
    if counter_path.exists():
        counter = counter_path.read_text(encoding="utf-8")
    downstream_called = "add" in counter
    return {"decision_rule_id": decision, "downstream_called": downstream_called, "counter_file_entries": counter.strip().splitlines() if counter.strip() else []}


TRUST_KEY_PREFIX = "transfer:"
