def resolve_engine_case(case: ExtensionCase) -> dict:
    engine = _build_engine()
    now = time.time()
    if case.id == "ext-delegation-001-within-grant":
        ctx = _delegation_context_for(now)
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": _default_for(engine, "echo") if action is None else action.action.value, "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-002-outside-grant":
        ctx = DelegationContext(
            delegation_id="ext-2",
            workflow_id="wf-x2",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
        )
        action = engine.match_rules("add", {"a": 1, "b": 2}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "add"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-003-attenuation":
        ctx = DelegationContext(
            delegation_id="ext-3",
            workflow_id="wf-x3",
            initiator=Principal("init-x", frozenset({"echo", "add"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
        )
        a = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        b = engine.match_rules("add", {"a": 1, "b": 2}, delegation_context=ctx)
        return {"case": case.id, "resolved": (_default_for(engine, "echo") if a is None else a.action.value, _default_for(engine, "add") if b is None else b.action.value), "expected": (case.expected, "DENY"), "scope": "engine"}
    if case.id == "ext-delegation-004-expired":
        ctx = DelegationContext(
            delegation_id="ext-4",
            workflow_id="wf-x4",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 7200,
            expires_at=now - 60,
        )
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-005-revoked":
        ctx = DelegationContext(
            delegation_id="ext-5",
            workflow_id="wf-x5",
            initiator=Principal("init-x", frozenset({"echo"})),
            delegate_principal_id="del-x",
            granted_tools=frozenset({"echo"}),
            issued_at=now - 60,
            expires_at=now + 3600,
            status=DelegationStatus.REVOKED,
        )
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=ctx)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-006-over-initiator-scope":
        try:
            DelegationContext(
                delegation_id="ext-6",
                workflow_id="wf-x6",
                initiator=Principal("init-x", frozenset({"echo"})),
                delegate_principal_id="del-x",
                granted_tools=frozenset({"echo", "add"}),
                issued_at=now - 60,
                expires_at=now + 3600,
            )
            return {"case": case.id, "resolved": "construction_ok", "expected": case.expected, "scope": "engine"}
        except DelegationValidationError:
            return {"case": case.id, "resolved": "construction_denied", "expected": case.expected, "scope": "engine"}
    if case.id == "ext-delegation-007-missing-context":
        action = engine.match_rules("echo", {"message": "ok"}, delegation_context=None)
        return {"case": case.id, "resolved": action.action.value if action is not None else _default_for(engine, "echo"), "expected": case.expected, "scope": "engine"}
