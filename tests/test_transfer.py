"""Unit tests for bounded cross-call provenance transfer (Phase 7).

Covers export/import through the trusted path, fresh-registry semantics,
taint preservation, lineage remapping, forged/expired/scope/replay/capacity
rejections, explicit workflow lifecycle, and the duplicate/correlation
ledger. Offline: no inference, no network.
"""

from __future__ import annotations

import time

import pytest

from agent44.provenance import ProvenanceRegistry, TrustClass
from agent44.transfer import (
    TRANSFER_KEY_PREFIX,
    ProvenanceTransferStore,
    TransferConfig,
    TransferError,
)

WORKFLOW = "wf-1"
PRINCIPAL = "agent-beta"
NOW = time.time()


def live_store(**overrides: object) -> ProvenanceTransferStore:
    """A store with one ensured workflow, ready for export/import."""
    config = TransferConfig(**overrides)  # type: ignore[arg-type]
    store = ProvenanceTransferStore(config)
    store.ensure_workflow(WORKFLOW, PRINCIPAL, now=NOW)
    return store


def export_untrusted(
    store: ProvenanceTransferStore, *, argument: str = "message"
) -> str:
    """Classify one external argument in a throwaway registry and export it."""
    registry = ProvenanceRegistry()
    pid = registry.classify_external(boundary="proxy_input")
    return store.export(
        workflow_id=WORKFLOW,
        owner_principal_id=PRINCIPAL,
        origin_tool="echo",
        argument_name=argument,
        registry=registry,
        provenance_id=pid,
        now=NOW,
    )


def rejected(store: ProvenanceTransferStore, handle: str, **kwargs: object) -> str:
    """Attempt an import and return the stable rejection code."""
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    with pytest.raises(TransferError) as excinfo:
        store.import_into(
            handle,
            registry=fresh,
            values=values,
            workflow_id=kwargs.get("workflow_id", WORKFLOW),  # type: ignore[arg-type]
            principal_id=kwargs.get("principal_id", PRINCIPAL),  # type: ignore[arg-type]
            now=kwargs.get("now", NOW),  # type: ignore[arg-type]
        )
    return excinfo.value.code


# --- round trip ----------------------------------------------------------------


def test_export_import_roundtrip_into_fresh_registry() -> None:
    store = live_store()
    handle = export_untrusted(store)

    fresh = ProvenanceRegistry()
    assert len(fresh) == 0  # the subsequent call starts from a fresh registry
    values: dict[str, str | None] = {}
    evidence = store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )

    key = TRANSFER_KEY_PREFIX + "message"
    imported_pid = values[key]
    assert imported_pid is not None
    # Untrusted taint survives the transfer into the new registry.
    assert fresh.effective_trust(imported_pid) is TrustClass.UNTRUSTED
    assert evidence["transfer_id"] == handle
    assert evidence["argument_name"] == "message"
    assert evidence["trust_class"] == TrustClass.UNTRUSTED.value


def test_transfer_record_contains_no_raw_values() -> None:
    store = live_store()
    registry = ProvenanceRegistry()
    pid = registry.classify_external(boundary="proxy_input")
    handle = store.export(
        workflow_id=WORKFLOW,
        owner_principal_id=PRINCIPAL,
        origin_tool="echo",
        argument_name="message",
        registry=registry,
        provenance_id=pid,
        now=NOW,
    )
    state = store._live_state(WORKFLOW, now=NOW)  # trusted internal state
    record = state.records[handle]
    # Metadata only: the record carries no payload/values field at all.
    serialized = repr(record)
    assert "arguments" not in serialized
    assert record.argument_name == "message"
    assert record.trust_class is TrustClass.UNTRUSTED


def test_trust_is_preserved_not_elevated_by_transfer() -> None:
    store = live_store()
    registry = ProvenanceRegistry()
    trusted_pid = registry.classify_trusted(boundary="operator_input")
    untrusted_pid = registry.classify_external(boundary="proxy_input")
    trusted_handle = store.export(
        workflow_id=WORKFLOW,
        owner_principal_id=PRINCIPAL,
        origin_tool="echo",
        argument_name="clean",
        registry=registry,
        provenance_id=trusted_pid,
        now=NOW,
    )
    untrusted_handle = store.export(
        workflow_id=WORKFLOW,
        owner_principal_id=PRINCIPAL,
        origin_tool="echo",
        argument_name="dirty",
        registry=registry,
        provenance_id=untrusted_pid,
        now=NOW,
    )

    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        trusted_handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    store.import_into(
        untrusted_handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    # The transfer preserves what the source recorded; it never upgrades
    # untrusted into trusted.
    assert (
        fresh.effective_trust(values[TRANSFER_KEY_PREFIX + "clean"]) is TrustClass.TRUSTED
    )
    assert (
        fresh.effective_trust(values[TRANSFER_KEY_PREFIX + "dirty"])
        is TrustClass.UNTRUSTED
    )


def test_derived_lineage_is_recreated_with_parents_in_fresh_registry() -> None:
    store = live_store()
    registry = ProvenanceRegistry()
    parent_pid = registry.classify_external(boundary="proxy_input")
    derived_pid = registry.derive((parent_pid,), boundary="summarize")
    handle = store.export(
        workflow_id=WORKFLOW,
        owner_principal_id=PRINCIPAL,
        origin_tool="derive",
        argument_name="summary",
        registry=registry,
        provenance_id=derived_pid,
        now=NOW,
    )

    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    imported = fresh.get_record(values[TRANSFER_KEY_PREFIX + "summary"])
    assert imported is not None
    assert imported.depth == 2
    assert imported.trust_class is TrustClass.DERIVED_UNTRUSTED
    # Parent lineage exists inside the fresh registry, ids remapped.
    assert len(imported.parent_ids) == 1
    parent = fresh.get_record(imported.parent_ids[0])
    assert parent is not None
    assert parent.trust_class is TrustClass.UNTRUSTED


# --- rejection paths -----------------------------------------------------------


def test_forged_and_unknown_handles_are_rejected() -> None:
    store = live_store()
    assert rejected(store, "tr_" + "f" * 32) == "unknown"
    assert rejected(store, "not-a-handle") == "malformed"
    assert rejected(store, "") == "malformed"
    assert rejected(store, "tr_" + "x" * 200) == "malformed"


def test_replayed_handle_is_rejected_after_use() -> None:
    store = live_store()
    handle = export_untrusted(store)
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    # Single-use: any successful import consumes the record.
    assert rejected(store, handle) == "consumed"


def test_handle_from_another_principal_or_workflow_is_rejected() -> None:
    store = live_store()
    handle = export_untrusted(store)
    assert rejected(store, handle, principal_id="agent-other") == "scope"
    # The record stays unconsumed for its rightful owner after a scope miss.
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    # A different workflow must be registered to import at all.
    store2 = ProvenanceTransferStore()
    store2.ensure_workflow("wf-2", PRINCIPAL, now=NOW)
    assert rejected(store2, handle, workflow_id="wf-2") == "unknown"


def test_expired_record_is_rejected() -> None:
    store = live_store(ttl_seconds=60.0)
    handle = export_untrusted(store)
    later = NOW + 120
    # Keep the workflow itself alive so the record's own expiry is what fires.
    store.ensure_workflow(WORKFLOW, PRINCIPAL, now=later)
    assert rejected(store, handle, now=later) == "expired"


def test_revoked_workflow_rejects_import_and_export() -> None:
    store = live_store()
    handle = export_untrusted(store)
    store.revoke_workflow(WORKFLOW)
    assert rejected(store, handle) == "revoked"
    registry = ProvenanceRegistry()
    pid = registry.classify_external()
    with pytest.raises(TransferError) as excinfo:
        store.export(
            workflow_id=WORKFLOW,
            owner_principal_id=PRINCIPAL,
            origin_tool="echo",
            argument_name="message",
            registry=registry,
            provenance_id=pid,
            now=NOW,
        )
    assert excinfo.value.code == "revoked"


def test_export_with_unknown_provenance_id_is_malformed() -> None:
    store = live_store()
    registry = ProvenanceRegistry()
    with pytest.raises(TransferError) as excinfo:
        store.export(
            workflow_id=WORKFLOW,
            owner_principal_id=PRINCIPAL,
            origin_tool="echo",
            argument_name="message",
            registry=registry,
            provenance_id="forged-id",
            now=NOW,
        )
    assert excinfo.value.code == "malformed"


# --- bounds, capacity, lifecycle ----------------------------------------------


def test_record_capacity_exhaustion_fails_closed_without_trusting_taint() -> None:
    store = live_store(max_records_per_workflow=1)
    handle = export_untrusted(store)
    registry = ProvenanceRegistry()
    pid = registry.classify_external()
    with pytest.raises(TransferError) as excinfo:
        store.export(
            workflow_id=WORKFLOW,
            owner_principal_id=PRINCIPAL,
            origin_tool="echo",
            argument_name="other",
            registry=registry,
            provenance_id=pid,
            now=NOW,
        )
    assert excinfo.value.code == "capacity"
    # The stored lineage was NOT evicted, and its taint still reads untrusted.
    fresh = ProvenanceRegistry()
    values: dict[str, str | None] = {}
    store.import_into(
        handle,
        registry=fresh,
        values=values,
        workflow_id=WORKFLOW,
        principal_id=PRINCIPAL,
        now=NOW,
    )
    assert fresh.effective_trust(values[TRANSFER_KEY_PREFIX + "message"]) is (
        TrustClass.UNTRUSTED
    )


def test_workflow_capacity_exhaustion_fails_closed() -> None:
    store = ProvenanceTransferStore(TransferConfig(max_workflows=1))
    store.ensure_workflow("wf-1", PRINCIPAL, now=NOW)
    with pytest.raises(TransferError) as excinfo:
        store.ensure_workflow("wf-2", PRINCIPAL, now=NOW)
    assert excinfo.value.code == "capacity"


def test_oversized_record_is_rejected_at_export() -> None:
    store = live_store(max_record_size=256)
    registry = ProvenanceRegistry()
    pid = registry.classify_external(boundary="b" * 400)  # blows the size bound
    with pytest.raises(TransferError) as excinfo:
        store.export(
            workflow_id=WORKFLOW,
            owner_principal_id=PRINCIPAL,
            origin_tool="echo",
            argument_name="message",
            registry=registry,
            provenance_id=pid,
            now=NOW,
        )
    assert excinfo.value.code == "oversized"


def test_lineage_depth_beyond_bound_is_rejected() -> None:
    store = live_store(max_lineage_depth=2)
    registry = ProvenanceRegistry()
    p1 = registry.classify_external()
    d2 = registry.derive((p1,))
    d3 = registry.derive((d2,))
    with pytest.raises(TransferError) as excinfo:
        store.export(
            workflow_id=WORKFLOW,
            owner_principal_id=PRINCIPAL,
            origin_tool="derive",
            argument_name="deep",
            registry=registry,
            provenance_id=d3,
            now=NOW,
        )
    assert excinfo.value.code == "depth"


def test_end_workflow_releases_state_without_trusted_stale_records() -> None:
    store = live_store()
    handle = export_untrusted(store)
    store.end_workflow(WORKFLOW)
    assert store.record_count(WORKFLOW) == 0
    # A handle from released state is unknown, never silently trusted.
    assert rejected(store, handle) == "unknown"
    store.end_workflow(WORKFLOW)  # idempotent


def test_idle_workflow_state_expires_and_sweeps() -> None:
    store = live_store(ttl_seconds=30.0)
    handle = export_untrusted(store)
    later = NOW + 60
    assert store.sweep(now=later) == 1
    assert store.workflow_ids() == ()
    # After expiry the old handle cannot import into anything.
    assert rejected(store, handle, now=later) == "unknown"



