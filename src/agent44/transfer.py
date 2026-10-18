"""Bounded cross-call provenance transfer for Agent44 (Phase 7).

Phase 6 keeps one :class:`~agent44.provenance.ProvenanceRegistry` per tool
call. This module is the *only* sanctioned way for provenance to cross a call
boundary: an explicit, bounded, single-use transfer record exported from a
completed call and imported into the fresh registry of a subsequent call
inside the same workflow/delegation scope.

Contract:

* records carry metadata only — trust class, source category, boundary,
  validation transition, and parent relationships. Raw argument values,
  prompts, secrets, and tool response bodies are never copied;
* transfer ids are opaque handles. A handle is never trusted by itself: it is
  validated against trusted in-process workflow state (workflow, owner
  principal, revocation, expiry, consumption) before it can import;
* import is single-use: any successful import consumes the record, so a
  replayed handle fails closed;
* a record is bound to the workflow and principal that exported it and cannot
  be reused by a different delegation, principal, or workflow;
* all state is process-local, in-memory, and bounded (workflow count, records
  per workflow, record size, lineage depth/entries, correlation count).
  Capacity exhaustion raises :class:`TransferError` — fail closed — instead of
  silently evicting lineage that is then treated as trusted;
* the store preserves explicitly recorded lineage. It does not prove semantic
  equivalence between arbitrary transformed strings (no general data-flow
  inference), and nothing here survives a process restart.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agent44.provenance import (
    ProvenanceError,
    ProvenanceLimitError,
    ProvenanceRecord,
    ProvenanceRegistry,
    TrustClass,
)

# Handle format: opaque, fixed-shape, Agent44-generated. Callers may present a
# handle, but it is authoritative only when the trusted store confirms it.
TRANSFER_ID_PREFIX = "tr_"
MAX_TRANSFER_ID_LENGTH = 64
# Provenance-context key under which an imported record is re-attached.
TRANSFER_KEY_PREFIX = "transfer:"
# Synthetic argument name used when exporting a downstream tool result.
RESULT_ARGUMENT_NAME = "result"
# Hard limits on a single exported lineage.
LINEAGE_ENTRY_LIMIT = 64
PARENT_LIMIT = 8
CORRELATION_MAX_LENGTH = 128

# Correlation outcomes recorded by the proxy for duplicate/replay protection.
OUTCOME_PENDING = "pending"
OUTCOME_DENIED = "denied"
OUTCOME_FORWARDED = "forwarded"
OUTCOME_FAILED = "failed"
OUTCOME_AMBIGUOUS = "ambiguous"
_TERMINAL_OUTCOMES = frozenset(
    {OUTCOME_DENIED, OUTCOME_FORWARDED, OUTCOME_FAILED, OUTCOME_AMBIGUOUS}
)


class TransferError(Exception):
    """A transfer/ledger operation was rejected (fail closed).

    ``code`` is a stable reason code surfaced in policy rule ids:
    ``unknown``, ``expired``, ``consumed``, ``scope``, ``revoked``,
    ``capacity``, ``malformed``, ``oversized``, ``depth``, ``duplicate``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_bounded(value: Any, kind: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TransferError("malformed", f"{kind} must be a non-empty string")
    if len(value) > CORRELATION_MAX_LENGTH:
        raise TransferError("malformed", f"{kind} exceeds its length bound")
    return value


@dataclass(frozen=True)
class LineageEntry:
    """Bounded, value-free metadata for one record in an exported lineage.

    ``parent_indices`` reference earlier positions in the ordered lineage list
    (parents always precede children), keeping the record a small DAG.
    """

    trust_class: TrustClass
    source_category: str
    validation_transition: str | None
    boundary: str
    parent_indices: tuple[int, ...]
    depth: int


@dataclass(frozen=True)
class TransferRecord:
    """One exported provenance record: metadata only, bound to a scope."""

    transfer_id: str
    workflow_id: str
    owner_principal_id: str
    argument_name: str
    origin_tool: str
    trust_class: TrustClass
    lineage: tuple[LineageEntry, ...]
    created_at: float
    expires_at: float
    consumed: bool = False


class TransferConfig(BaseModel):
    """Resource bounds for the in-memory transfer store.

    Configured under ``provenance.transfer`` in the policy file. Every bound
    is validated at startup; exceeding a bound at runtime raises
    :class:`TransferError` (fail closed) rather than evicting live state.
    """

    model_config = ConfigDict(extra="forbid")

    max_workflows: int = Field(default=8, ge=1, le=1024)
    max_records_per_workflow: int = Field(default=64, ge=1, le=10_000)
    max_record_size: int = Field(default=4096, ge=256, le=65_536)
    max_lineage_depth: int = Field(default=8, ge=1, le=64)
    max_transfers_per_call: int = Field(default=8, ge=1, le=64)
    max_correlations_per_workflow: int = Field(default=256, ge=1, le=100_000)
    ttl_seconds: float = Field(default=600.0, gt=0, le=86_400.0)


@dataclass
class _WorkflowState:
    """Live security state for one workflow (process-local)."""

    workflow_id: str
    principal_id: str
    created_at: float
    expires_at: float
    revoked: bool = False
    records: dict[str, TransferRecord] = field(default_factory=dict)
    correlations: dict[str, str] = field(default_factory=dict)


class ProvenanceTransferStore:
    """Bounded, in-memory store for cross-call provenance transfer records.

    Lifecycle is explicit: workflows are created by :meth:`ensure_workflow`,
    expire after ``ttl_seconds`` of inactivity, can be revoked with
    :meth:`revoke_workflow`, and are released with :meth:`end_workflow`. The
    state is process-local and does not survive restarts; nothing here is
    durable or distributed.
    """

    def __init__(self, config: TransferConfig | None = None) -> None:
        self.config = config if config is not None else TransferConfig()
        self._workflows: dict[str, _WorkflowState] = {}

    # ------------------------------------------------------------- lifecycle

    def sweep(self, *, now: float | None = None) -> int:
        """Drop expired workflow state; returns the number removed."""
        current = time.time() if now is None else now
        expired = [
            workflow_id
            for workflow_id, state in self._workflows.items()
            if current >= state.expires_at
        ]
        for workflow_id in expired:
            del self._workflows[workflow_id]
        return len(expired)

    def ensure_workflow(
        self,
        workflow_id: str,
        principal_id: str,
        *,
        now: float | None = None,
        ttl_seconds: float | None = None,
    ) -> None:
        """Register (or refresh) the workflow scope for the current delegation.

        A missing workflow is created within capacity bounds; an existing one
        is refreshed with a sliding expiry unless revoked. Raises
        :class:`TransferError` on capacity exhaustion or scope mismatch.
        """
        current = time.time() if now is None else now
        workflow_id = _require_bounded(workflow_id, "workflow_id")
        principal_id = _require_bounded(principal_id, "principal_id")
        ttl = self.config.ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        state = self._workflows.get(workflow_id)
        if state is not None:
            if state.principal_id != principal_id:
                raise TransferError(
                    "scope", "workflow is registered to a different principal"
                )
            # Revive in place: refresh the sliding expiry but keep every
            # record, tombstone, and ledger entry. Deleting and recreating
            # the workflow here would silently evict security-critical
            # lineage and degrade precise fail-closed reasons to unknown.
            if not state.revoked:
                state.expires_at = max(state.expires_at, current + ttl)
            return
        # Reclaim idle workflows before enforcing capacity, so expired
        # state cannot block new workflows.
        self.sweep(now=current)
        if len(self._workflows) >= self.config.max_workflows:
            raise TransferError("capacity", "workflow capacity reached")
        self._workflows[workflow_id] = _WorkflowState(
            workflow_id=workflow_id,
            principal_id=principal_id,
            created_at=current,
            expires_at=current + ttl,
        )

    def revoke_workflow(self, workflow_id: str) -> None:
        """Revoke a workflow: its transfer records and ledger stop working.

        Idempotent; a missing workflow has nothing to revoke.
        """
        state = self._workflows.get(workflow_id)
        if state is not None:
            state.revoked = True

    def end_workflow(self, workflow_id: str) -> None:
        """Release all bounded state for a completed workflow (idempotent)."""
        self._workflows.pop(workflow_id, None)

    # -------------------------------------------------------------- accessors

    def workflow_ids(self) -> tuple[str, ...]:
        return tuple(self._workflows)

    def record_count(self, workflow_id: str) -> int:
        state = self._workflows.get(workflow_id)
        return 0 if state is None else len(state.records)

    def correlation_outcome(self, workflow_id: str, correlation_id: str) -> str | None:
        state = self._workflows.get(workflow_id)
        return None if state is None else state.correlations.get(correlation_id)

    def _live_state(self, workflow_id: str, *, now: float | None) -> _WorkflowState:
        current = time.time() if now is None else now
        state = self._workflows.get(workflow_id)
        if state is None:
            raise TransferError("unknown", "workflow is not registered")
        if state.revoked:
            raise TransferError("revoked", "workflow is revoked")
        if current >= state.expires_at:
            raise TransferError("expired", "workflow state expired")
        return state

    # ---------------------------------------------------------------- export

    @staticmethod
    def _meta_dict(record: TransferRecord) -> dict[str, Any]:
        """Compact, value-free representation used for size accounting."""
        return {
            "w": record.workflow_id,
            "p": record.owner_principal_id,
            "t": record.origin_tool,
            "a": record.argument_name,
            "tr": record.trust_class.value,
            "c": record.created_at,
            "e": record.expires_at,
            "l": [
                {
                    "tc": entry.trust_class.value,
                    "sc": entry.source_category,
                    "vt": entry.validation_transition,
                    "b": entry.boundary,
                    "pi": list(entry.parent_indices),
                    "d": entry.depth,
                }
                for entry in record.lineage
            ],
        }

    def _extract_lineage(
        self, registry: ProvenanceRegistry, top: ProvenanceRecord
    ) -> tuple[LineageEntry, ...]:
        """Flatten the record's ancestry, parents strictly before children."""
        ordered: list[ProvenanceRecord] = []
        positions: dict[str, int] = {}

        def visit(record: ProvenanceRecord, stack: tuple[str, ...]) -> None:
            if record.provenance_id in positions:
                return
            if record.provenance_id in stack:
                raise TransferError("malformed", "cyclic provenance lineage")
            for parent_id in record.parent_ids:
                parent = registry.get_record(parent_id)
                if parent is None:
                    raise TransferError(
                        "malformed", "lineage references an unknown parent record"
                    )
                visit(parent, stack + (record.provenance_id,))
            positions[record.provenance_id] = len(ordered)
            ordered.append(record)

        visit(top, ())

        entries = tuple(
            LineageEntry(
                trust_class=record.trust_class,
                source_category=record.source_category,
                validation_transition=record.validation_transition,
                boundary=record.boundary,
                parent_indices=tuple(
                    positions[parent_id] for parent_id in record.parent_ids
                ),
                depth=record.depth,
            )
            for record in ordered
        )
        if len(entries) > LINEAGE_ENTRY_LIMIT:
            raise TransferError(
                "oversized", f"lineage exceeds {LINEAGE_ENTRY_LIMIT} entries"
            )
        for entry in entries:
            if len(entry.parent_indices) > PARENT_LIMIT:
                raise TransferError(
                    "oversized", f"lineage record exceeds {PARENT_LIMIT} parents"
                )
        return entries

    def export(
        self,
        *,
        workflow_id: str,
        owner_principal_id: str,
        origin_tool: str,
        argument_name: str,
        registry: ProvenanceRegistry,
        provenance_id: str,
        now: float | None = None,
    ) -> str:
        """Export one provenance record from a completed call.

        Returns an opaque single-use handle. The exported record stores only
        bounded lineage metadata: never raw values, prompts, secrets, or
        response bodies. Raises :class:`TransferError` when the workflow is
        unavailable or any bound would be exceeded.
        """
        current = time.time() if now is None else now
        state = self._live_state(workflow_id, now=current)
        origin_tool = _require_bounded(origin_tool, "origin_tool")
        argument_name = _require_bounded(argument_name, "argument_name")
        if not isinstance(provenance_id, str) or not provenance_id:
            raise TransferError("malformed", "provenance_id must be a non-empty string")
        if len(state.records) >= self.config.max_records_per_workflow:
            raise TransferError("capacity", "transfer record capacity reached")

        source = registry.get_record(provenance_id)
        if source is None:
            raise TransferError(
                "malformed", "provenance id is unknown to the per-call registry"
            )
        entries = self._extract_lineage(registry, source)
        if entries[-1].depth > self.config.max_lineage_depth:
            raise TransferError(
                "depth",
                f"lineage depth exceeds bound {self.config.max_lineage_depth}",
            )

        transfer_id = TRANSFER_ID_PREFIX + uuid.uuid4().hex
        record = TransferRecord(
            transfer_id=transfer_id,
            workflow_id=workflow_id,
            owner_principal_id=owner_principal_id,
            argument_name=argument_name,
            origin_tool=origin_tool,
            trust_class=entries[-1].trust_class,
            lineage=entries,
            created_at=current,
            expires_at=current + self.config.ttl_seconds,
        )
        size = len(
            json.dumps(self._meta_dict(record), separators=(",", ":"), ensure_ascii=False)
        )
        if size > self.config.max_record_size:
            raise TransferError(
                "oversized",
                f"transfer record size {size} exceeds bound {self.config.max_record_size}",
            )
        state.records[transfer_id] = record
        return transfer_id

    # ---------------------------------------------------------------- import

    def import_into(
        self,
        transfer_id: str,
        *,
        registry: ProvenanceRegistry,
        values: dict[str, str | None],
        workflow_id: str,
        principal_id: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Validate a handle against trusted state and import its record.

        Recreates the exported lineage inside the fresh per-call registry
        (parents first, ids remapped), re-attaches the record under
        ``transfer:<original argument name>``, and consumes the handle so it
        cannot be replayed. Returns bounded evidence metadata for the
        audit trail. Every rejection raises :class:`TransferError`.
        """
        current = time.time() if now is None else now
        if (
            not isinstance(transfer_id, str)
            or not transfer_id.startswith(TRANSFER_ID_PREFIX)
            or len(transfer_id) > MAX_TRANSFER_ID_LENGTH
        ):
            raise TransferError("malformed", "transfer handle is malformed")

        state = self._live_state(workflow_id, now=current)
        record = state.records.get(transfer_id)
        if record is None:
            raise TransferError("unknown", "transfer record is unknown in this workflow")
        if record.workflow_id != workflow_id or record.owner_principal_id != principal_id:
            raise TransferError(
                "scope", "transfer record belongs to a different workflow or principal"
            )
        if current >= record.expires_at:
            raise TransferError("expired", "transfer record expired")
        if record.consumed:
            raise TransferError("consumed", "transfer record was already consumed")

        # Defense in depth: re-check size/ordering bounds against trusted
        # state before touching the registry.
        if not record.lineage:
            raise TransferError("malformed", "transfer record has no lineage")
        if len(record.lineage) > LINEAGE_ENTRY_LIMIT:
            raise TransferError("oversized", "transfer lineage exceeds its entry bound")
        size = len(
            json.dumps(self._meta_dict(record), separators=(",", ":"), ensure_ascii=False)
        )
        if size > self.config.max_record_size:
            raise TransferError("oversized", "transfer record exceeds its size bound")

        id_by_index: dict[int, str] = {}
        for index, entry in enumerate(record.lineage):
            parents: list[str] = []
            for parent_index in entry.parent_indices:
                if parent_index >= index or parent_index not in id_by_index:
                    raise TransferError("malformed", "lineage parent ordering is invalid")
                parents.append(id_by_index[parent_index])
            if len(parents) > PARENT_LIMIT:
                raise TransferError("oversized", "lineage record exceeds its parent bound")

            predicted_depth = 1
            for parent_id in parents:
                parent_record = registry.get_record(parent_id)
                if parent_record is None:
                    raise TransferError(
                        "malformed", "lineage parent is missing in registry"
                    )
                predicted_depth = max(predicted_depth, parent_record.depth + 1)
            if (
                predicted_depth > self.config.max_lineage_depth
                or predicted_depth > registry.max_depth
            ):
                raise TransferError("depth", "transferred lineage exceeds its depth bound")
            try:
                id_by_index[index] = registry.import_transferred(
                    trust_class=entry.trust_class,
                    source_category=entry.source_category,
                    parent_ids=tuple(parents),
                    validation_transition=entry.validation_transition,
                    boundary=entry.boundary or "provenance_transfer",
                )
            except ProvenanceLimitError as exc:
                raise TransferError(
                    "capacity", "per-call registry capacity reached"
                ) from exc
            except ProvenanceError as exc:
                raise TransferError("malformed", "registry rejected the lineage") from exc

        top_pid = id_by_index[len(record.lineage) - 1]
        key = TRANSFER_KEY_PREFIX + record.argument_name
        values[key] = top_pid
        # Single-use: any successful import consumes the handle.
        state.records[transfer_id] = replace(record, consumed=True)
        return {
            "transfer_id": transfer_id,
            "argument_name": record.argument_name,
            "trust_class": record.trust_class.value,
            "provenance_id": top_pid,
        }

    # ---------------------------------------------------- correlation ledger

    def begin_correlation(
        self, workflow_id: str, correlation_id: str, *, now: float | None = None
    ) -> None:
        """Reserve a correlation id before forwarding (duplicate gate).

        Raises ``duplicate`` when the id was already used for anything other
        than a gateway denial — including in-flight (``pending``) and
        ambiguous outcomes — and ``capacity`` when the ledger is full. A
        ledger at capacity rejects every new id: deterministic fail-closed.
        """
        state = self._live_state(workflow_id, now=now)
        correlation_id = _require_bounded(correlation_id, "correlation_id")
        prior = state.correlations.get(correlation_id)
        if prior is not None and prior != OUTCOME_DENIED:
            raise TransferError("duplicate", "correlation id was already used")
        if (
            prior is None
            and len(state.correlations) >= self.config.max_correlations_per_workflow
        ):
            raise TransferError("capacity", "correlation ledger capacity reached")
        state.correlations[correlation_id] = OUTCOME_PENDING

    def record_denied(
        self, workflow_id: str, correlation_id: str, *, now: float | None = None
    ) -> None:
        """Record that the gateway denied the call (no downstream side effect).

        A previously recorded stronger outcome (pending/forwarded/failed/
        ambiguous) is preserved so duplicate protection is never weakened.
        """
        state = self._live_state(workflow_id, now=now)
        correlation_id = _require_bounded(correlation_id, "correlation_id")
        prior = state.correlations.get(correlation_id)
        if prior is not None and prior != OUTCOME_DENIED:
            return
        if (
            prior is None
            and len(state.correlations) >= self.config.max_correlations_per_workflow
        ):
            raise TransferError("capacity", "correlation ledger capacity reached")
        state.correlations[correlation_id] = OUTCOME_DENIED

    def finish_correlation(
        self,
        workflow_id: str,
        correlation_id: str,
        outcome: Literal["forwarded", "failed", "ambiguous"],
        *,
        now: float | None = None,
    ) -> None:
        """Store the terminal outcome for a reserved correlation id."""
        if outcome not in {OUTCOME_FORWARDED, OUTCOME_FAILED, OUTCOME_AMBIGUOUS}:
            raise TransferError("malformed", "invalid correlation outcome")
        state = self._live_state(workflow_id, now=now)
        correlation_id = _require_bounded(correlation_id, "correlation_id")
        if correlation_id not in state.correlations:
            raise TransferError("malformed", "correlation id was never reserved")
        state.correlations[correlation_id] = outcome




