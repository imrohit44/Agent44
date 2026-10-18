"""Unit tests for the Phase 7 delegation security model (principals, grants).

Covers identity bounds, authority attenuation, revocation/expiry, explicit
rejection of nested delegation, manifest validation (the trusted local
boundary), and the policy configuration contract. Offline: no inference, no
network.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from agent44.delegation import (
    MAX_ID_LENGTH,
    MAX_MANIFEST_BYTES,
    MAX_TOOLS_PER_SET,
    DelegationConfig,
    DelegationConfigError,
    DelegationContext,
    DelegationSource,
    DelegationStatus,
    DelegationValidationError,
    Principal,
    parse_delegation_manifest,
)

NOW = time.time()


def make_context(
    *,
    granted: set[str] | frozenset[str] = frozenset({"add"}),
    initiator_tools: set[str] | frozenset[str] = frozenset({"add", "echo"}),
    status: DelegationStatus = DelegationStatus.ACTIVE,
    expires_at: float | None = None,
    issued_at: float | None = None,
) -> DelegationContext:
    """Build a valid delegation context with optional overrides."""
    return DelegationContext(
        delegation_id="del-1",
        workflow_id="wf-1",
        initiator=Principal("agent-alpha", frozenset(initiator_tools)),
        delegate_principal_id="agent-beta",
        granted_tools=frozenset(granted),
        issued_at=NOW - 60 if issued_at is None else issued_at,
        expires_at=NOW + 3600 if expires_at is None else expires_at,
        status=status,
    )


def manifest_dict(**overrides: object) -> dict[str, object]:
    """A valid manifest as plain JSON data with per-field overrides."""
    data: dict[str, object] = {
        "delegation_id": "del-1",
        "workflow_id": "wf-1",
        "initiator": {
            "principal_id": "agent-alpha",
            "allowed_tools": ["add", "echo"],
        },
        "delegate_principal_id": "agent-beta",
        "granted_tools": ["add"],
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "status": "active",
        "parent_delegation_id": None,
    }
    data.update(overrides)
    return data


# --- principals and identities -------------------------------------------------


def test_principal_rejects_empty_and_oversized_ids() -> None:
    with pytest.raises(DelegationValidationError):
        Principal("", frozenset({"add"}))
    with pytest.raises(DelegationValidationError):
        Principal("x" * (MAX_ID_LENGTH + 1), frozenset({"add"}))


def test_principal_rejects_tool_set_over_bound() -> None:
    tools = {f"tool-{i}" for i in range(MAX_TOOLS_PER_SET + 1)}
    with pytest.raises(DelegationValidationError):
        Principal("agent", frozenset(tools))


def test_principal_rejects_blank_tool_names() -> None:
    with pytest.raises(DelegationValidationError):
        Principal("agent", frozenset({"add", "  "}))


# --- authority attenuation -----------------------------------------------------


def test_delegate_cannot_invoke_outside_grant() -> None:
    context = make_context()
    assert context.check("add") is None
    assert context.check("echo") == "not_granted"
    assert context.check("unheard-of") == "not_granted"


def test_effective_tools_is_intersection_with_initiator() -> None:
    context = make_context(granted={"add"}, initiator_tools={"add"})
    assert context.effective_tools == frozenset({"add"})


def test_grant_exceeding_initiator_is_rejected_at_construction() -> None:
    with pytest.raises(DelegationValidationError, match="exceeds the initiating"):
        make_context(granted={"add", "admin"}, initiator_tools={"add"})


def test_nested_delegation_is_rejected_explicitly() -> None:
    with pytest.raises(DelegationValidationError, match="nested delegation"):
        DelegationContext(
            delegation_id="del-2",
            workflow_id="wf-1",
            initiator=Principal("agent-alpha", frozenset({"add"})),
            delegate_principal_id="agent-gamma",
            granted_tools=frozenset({"add"}),
            issued_at=NOW - 1,
            expires_at=NOW + 60,
            parent_delegation_id="del-1",
        )


def test_revoked_status_denies_every_tool() -> None:
    context = make_context(status=DelegationStatus.REVOKED)
    assert context.check("add") == "revoked"


def test_expired_context_denies_granted_tool() -> None:
    context = make_context(issued_at=NOW - 120, expires_at=NOW - 60)
    assert context.check("add") == "expired"


# --- manifest (trusted local boundary) ----------------------------------------


def test_valid_manifest_parses_to_context() -> None:
    context = parse_delegation_manifest(json.dumps(manifest_dict()))
    assert context.delegation_id == "del-1"
    assert context.initiator.principal_id == "agent-alpha"
    assert context.delegate_principal_id == "agent-beta"
    assert context.granted_tools == frozenset({"add"})
    assert context.status is DelegationStatus.ACTIVE
    assert context.parent_delegation_id is None


def test_manifest_rejects_unknown_keys() -> None:
    raw = json.dumps(manifest_dict(admin=True))
    with pytest.raises(DelegationConfigError, match="invalid delegation manifest"):
        parse_delegation_manifest(raw)


def test_manifest_rejects_overprivileged_grant() -> None:
    raw = json.dumps(manifest_dict(granted_tools=["add", "shred"]))
    with pytest.raises(DelegationConfigError, match="exceeds the initiating"):
        parse_delegation_manifest(raw)


def test_manifest_rejects_nested_delegation_pointer() -> None:
    raw = json.dumps(manifest_dict(parent_delegation_id="del-0"))
    with pytest.raises(DelegationConfigError, match="nested delegation"):
        parse_delegation_manifest(raw)


def test_manifest_rejects_malformed_payloads() -> None:
    with pytest.raises(DelegationConfigError, match="not valid JSON"):
        parse_delegation_manifest("{nope")
    with pytest.raises(DelegationConfigError, match="not valid UTF-8"):
        parse_delegation_manifest(b"\xff\xfe\x00")
    with pytest.raises(DelegationConfigError, match="exceeds"):
        parse_delegation_manifest("x" * (MAX_MANIFEST_BYTES + 1))


def test_manifest_rejects_invalid_validity_window() -> None:
    with pytest.raises(DelegationConfigError, match="expires_at"):
        parse_delegation_manifest(
            json.dumps(manifest_dict(issued_at=NOW - 10, expires_at=NOW - 10))
        )
    with pytest.raises(DelegationConfigError, match="not yet valid"):
        parse_delegation_manifest(
            json.dumps(manifest_dict(issued_at=NOW + 600, expires_at=NOW + 900))
        )


def test_manifest_rejects_revoked_enum_garbage_and_bad_status() -> None:
    with pytest.raises(DelegationConfigError):
        parse_delegation_manifest(json.dumps(manifest_dict(status="maybe")))


# --- source lifecycle ----------------------------------------------------------


def test_source_missing_file_returns_none(tmp_path: Path) -> None:
    source = DelegationSource(tmp_path / "absent.json")
    assert source.current() is None
    with pytest.raises(DelegationConfigError, match="not found"):
        source.require()


def test_source_rereads_manifest_so_revocation_takes_effect(tmp_path: Path) -> None:
    path = tmp_path / "delegation.json"
    path.write_text(json.dumps(manifest_dict()), encoding="utf-8")
    source = DelegationSource(path)
    assert source.current() is not None
    assert source.current().status is DelegationStatus.ACTIVE

    path.write_text(
        json.dumps(manifest_dict(status="revoked")), encoding="utf-8"
    )
    assert source.current().status is DelegationStatus.REVOKED


def test_source_invalid_manifest_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "delegation.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(DelegationConfigError):
        DelegationSource(path).current()


# --- policy configuration ------------------------------------------------------


def test_delegation_config_defaults_to_off() -> None:
    config = DelegationConfig()
    assert config.enforcement == "off"


def test_delegation_config_rejects_bare_yaml_off_boolean() -> None:
    # YAML parses bare ``off`` as False; only the quoted string is accepted.
    with pytest.raises(ValueError, match="quote"):
        DelegationConfig(enforcement=False)  # type: ignore[arg-type]


def test_delegation_config_bounds_are_validated() -> None:
    with pytest.raises(ValueError):
        DelegationConfig(max_active_delegations=0)
    with pytest.raises(ValueError):
        DelegationConfig(max_ttl_seconds=0)
    with pytest.raises(ValueError):
        DelegationConfig(enforcement="maybe")  # type: ignore[arg-type]

