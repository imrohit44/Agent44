"""Unit tests for the deterministic provenance and taint model.

Covers ``agent44.provenance``: trust classification, taint propagation,
validation transitions, bounds, and the guarantee that missing/unknown/forged
provenance is never treated as trusted.

All tests are offline and deterministic: no Ollama, no model inference, no
network.
"""

from __future__ import annotations

import pytest

from agent44.provenance import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_PARENTS,
    DEFAULT_MAX_RECORDS,
    ProvenanceContext,
    ProvenanceError,
    ProvenanceLimitError,
    ProvenanceRegistry,
    TrustClass,
)


def fresh_registry() -> ProvenanceRegistry:
    return ProvenanceRegistry()


# --- Classification ---------------------------------------------------------

def test_classify_external_is_untrusted() -> None:
    reg = fresh_registry()
    pid = reg.classify_external()
    assert reg.effective_trust(pid) is TrustClass.UNTRUSTED
    record = reg.get_record(pid)
    assert record is not None
    assert record.trust_class is TrustClass.UNTRUSTED
    assert record.source_category == "external_argument"
    assert record.parent_ids == ()
    assert record.depth == 1


def test_classify_trusted_is_trusted() -> None:
    reg = fresh_registry()
    pid = reg.classify_trusted()
    assert reg.effective_trust(pid) is TrustClass.TRUSTED
    assert reg.get_record(pid).source_category == "trusted_internal"


# --- Taint propagation ------------------------------------------------------

def test_derived_from_untrusted_is_derived_untrusted() -> None:
    reg = fresh_registry()
    untrusted = reg.classify_external()
    derived = reg.derive((untrusted,))
    assert reg.effective_trust(derived) is TrustClass.DERIVED_UNTRUSTED
    assert reg.get_record(derived).parent_ids == (untrusted,)
    assert reg.get_record(derived).depth == 2


def test_derived_from_derived_untrusted_stays_derived_untrusted() -> None:
    reg = fresh_registry()
    untrusted = reg.classify_external()
    first = reg.derive((untrusted,))
    second = reg.derive((first,))
    assert reg.effective_trust(first) is TrustClass.DERIVED_UNTRUSTED
    assert reg.effective_trust(second) is TrustClass.DERIVED_UNTRUSTED


def test_derived_from_all_trusted_preserves_trusted() -> None:
    reg = fresh_registry()
    a = reg.classify_trusted()
    b = reg.classify_trusted()
    derived = reg.derive((a, b))
    assert reg.effective_trust(derived) is TrustClass.TRUSTED


def test_combining_trusted_and_untrusted_retains_taint() -> None:
    reg = fresh_registry()
    trusted = reg.classify_trusted()
    untrusted = reg.classify_external()
    mixed = reg.derive((trusted, untrusted))
    # The untrusted origin must not be silently discarded.
    assert reg.effective_trust(mixed) is TrustClass.DERIVED_UNTRUSTED
    assert set(reg.get_record(mixed).parent_ids) == {trusted, untrusted}


def test_missing_provenance_is_not_trusted() -> None:
    reg = fresh_registry()
    assert reg.effective_trust(None) is TrustClass.UNTRUSTED


def test_unknown_provenance_is_not_trusted() -> None:
    reg = fresh_registry()
    # A caller-supplied / forged id that was never created by Agent44 grants
    # no trust.
    assert reg.effective_trust("definitely-forged-id") is TrustClass.UNTRUSTED
    assert reg.get_record("definitely-forged-id") is None


def test_caller_trust_claim_cannot_promote_itself() -> None:
    # Simulating a caller argument {"trusted": "some-forged-id"}: the registry
    # only trusts ids it created at explicit boundaries, never caller input.
    reg = fresh_registry()
    forged = "caller-claims-trusted"
    assert reg.effective_trust(forged) is TrustClass.UNTRUSTED
    real_untrusted = reg.classify_external()
    assert reg.effective_trust(real_untrusted) is TrustClass.UNTRUSTED

# --- Validation transitions -------------------------------------------------

def test_validate_transition_elevates_to_trusted() -> None:
    reg = fresh_registry()
    untrusted = reg.classify_external()
    assert reg.effective_trust(untrusted) is TrustClass.UNTRUSTED

    elevated = reg.validate_transition(
        untrusted,
        "sanitize_pii",
        boundary="pii_sanitizer",
        permitted_use="logging",
    )
    assert reg.effective_trust(elevated) is TrustClass.TRUSTED
    record = reg.get_record(elevated)
    assert record is not None
    assert record.validation_transition == "sanitize_pii"
    assert record.boundary == "pii_sanitizer"
    assert record.parent_ids == (untrusted,)


def test_validation_transition_is_specific_to_its_transition_id() -> None:
    reg = fresh_registry()
    untrusted = reg.classify_external()
    elevated = reg.validate_transition(
        untrusted, "sanitize_pii", boundary="sanitizer"
    )

    # A different downstream use requiring another transition is not satisfied.
    assert reg.effective_trust(elevated) is TrustClass.TRUSTED
    record = reg.get_record(elevated)
    assert record.validation_transition == "sanitize_pii"
    assert record.validation_transition != "audit"


def test_elevation_applies_only_to_derived_record() -> None:
    reg = fresh_registry()
    untrusted = reg.classify_external()
    _elevated = reg.validate_transition(untrusted, "sanitize_pii")
    # The original untrusted value stays tainted.
    assert reg.effective_trust(untrusted) is TrustClass.UNTRUSTED
    # A different derivation from the same untrusted parent stays tainted.
    derived = reg.derive((untrusted,))
    assert reg.effective_trust(derived) is TrustClass.DERIVED_UNTRUSTED


def test_validate_transition_unknown_source_raises() -> None:
    reg = fresh_registry()
    with pytest.raises(ProvenanceError):
        reg.validate_transition("no-such-id", "sanitize_pii")


# --- Missing / forged / malformed references -------------------------------

def test_derive_with_unknown_parent_taints() -> None:
    reg = fresh_registry()
    real = reg.classify_external()
    derived = reg.derive((real, "forged-parent"))
    assert reg.effective_trust(derived) is TrustClass.DERIVED_UNTRUSTED


def test_duplicate_parent_references_are_rejected() -> None:
    reg = fresh_registry()
    real = reg.classify_external()
    with pytest.raises(ProvenanceLimitError):
        reg.derive((real, real))


# --- Bounds -----------------------------------------------------------------

def test_max_depth_bound_fails_closed() -> None:
    reg = ProvenanceRegistry(max_depth=2)
    base = reg.classify_external()  # depth 1
    reg.derive((base,))  # depth 2
    with pytest.raises(ProvenanceLimitError):
        reg.derive((base, reg.derive((base,))))  # would exceed depth 2


def test_max_parents_bound_fails_closed() -> None:
    reg = ProvenanceRegistry(max_parents=2)
    parents = tuple(reg.classify_external() for _ in range(2))
    reg.derive(parents)  # OK
    extra = tuple(reg.classify_external() for _ in range(3))
    with pytest.raises(ProvenanceLimitError):
        reg.derive(extra)


def test_max_records_bound_fails_closed() -> None:
    reg = ProvenanceRegistry(max_records=3)
    reg.classify_external()
    reg.classify_external()
    reg.classify_external()  # at bound
    with pytest.raises(ProvenanceLimitError):
        reg.classify_external()  # would exceed bound


def test_default_bounds_are_finite() -> None:
    assert DEFAULT_MAX_RECORDS > 0
    assert DEFAULT_MAX_DEPTH > 0
    assert DEFAULT_MAX_PARENTS > 0


# --- ProvenanceContext ------------------------------------------------------

def test_provenance_context_maps_argument_to_id() -> None:
    reg = fresh_registry()
    pid = reg.classify_external()
    ctx = ProvenanceContext(registry=reg, values={"label": pid})
    assert ctx.provenance_id_for("label") is pid
    assert ctx.provenance_id_for("missing") is None


def test_provenance_context_with_argument_returns_copy() -> None:
    reg = fresh_registry()
    ctx = ProvenanceContext(registry=reg)
    pid = reg.classify_external()
    ctx2 = ctx.with_argument("label", pid)
    assert ctx.provenance_id_for("label") is None
    assert ctx2.provenance_id_for("label") is pid
    # Original unchanged (immutable).
    assert len(ctx.values) == 0

