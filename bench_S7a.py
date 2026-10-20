# --------------------------------------------------------------------------- #
# Group B transfer-store evaluators
# --------------------------------------------------------------------------- #


def _fresh_store() -> ProvenanceTransferStore:
    return ProvenanceTransferStore(TransferConfig(max_workflows=8, max_records_per_workflow=16))


def transfer_valid_import_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-b1", principal_id="p-b1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-b1",
        owner_principal_id="p-b1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    imported = store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id="wf-b1",
        principal_id="p-b1",
        now=time.time(),
    )
    trust = fresh.effective_trust(values[TRUST_KEY_PREFIX + "message"])
    if imported["trust_class"] != trust.value:
        return False, "trust_class divergence"
    return trust is TrustClass.UNTRUSTED, None


def transfer_forged_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-foreign", principal_id="p-foreign")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-foreign",
        owner_principal_id="p-foreign",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-b1",
            principal_id="p-b1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


def transfer_replay_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    store.ensure_workflow(workflow_id="wf-r1", principal_id="p-r1")
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-r1",
        owner_principal_id="p-r1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time(),
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id="wf-r1",
        principal_id="p-r1",
        now=time.time(),
    )
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-r1",
            principal_id="p-r1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code
