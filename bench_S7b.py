def transfer_expired_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-e1",
        owner_principal_id="p-e1",
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=top,
        now=time.time() - 1000,
    )
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id="wf-e1",
            principal_id="p-e1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


def transfer_unauthorized_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    registry = ProvenanceRegistry()
    top = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id="wf-u1",
        owner_principal_id="p-u1",
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


def transfer_malformed_outcome() -> tuple[bool, str | None]:
    store = _fresh_store()
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    try:
        store.import_into(
            "not-a-trusted-handle",
            registry=fresh,
            values=values,
            workflow_id="wf-b1",
            principal_id="p-b1",
            now=time.time(),
        )
        return False, None
    except TransferError as exc:
        return False, exc.code


TRUST_KEY_PREFIX = "transfer:"
