"""Delegation security model for Agent44 (Phase 7).

Defines *who* may act, *on whose behalf*, and *with what authority* for a
multi-step tool-call workflow. It deliberately distinguishes three notions:

1. An identity asserted by an untrusted caller — tool arguments such as
   ``{"agent_role": "admin", "trusted": true}`` are business data. Agent44
   never reads principal or authority claims out of them.
2. An identity established by a trusted integration boundary — the delegation
   manifest file passed via ``--delegation``. Like the policy file, it is
   operator-controlled local state, read with strict size and schema
   validation. It is *not* an authentication service and performs no
   cryptographic identity verification.
3. A delegation authorization verified by Agent44 — the validated
   :class:`DelegationContext` checked deterministically against the
   configured policy before any tool call is forwarded.

Authority attenuation rules:

* a delegate may only invoke tools inside its explicit ``granted_tools`` set;
* a grant exceeding the initiating principal's own permissions is rejected at
  construction (a grant can never widen initiator authority);
* ``effective_tools`` is the explicit intersection of grant and initiator
  authority;
* nested delegation itself (a non-null ``parent_delegation_id``) is rejected
  explicitly rather than silently granting inherited permissions.

All state here is process-local; nothing in this module is durable across
restarts.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Bounds that keep identifiers and grants small and auditable.
MAX_ID_LENGTH = 128
MAX_TOOL_NAME_LENGTH = 128
MAX_TOOLS_PER_SET = 64
MAX_MANIFEST_BYTES = 8192


class DelegationError(Exception):
    """Base class for delegation failures."""


class DelegationConfigError(DelegationError):
    """The delegation manifest/configuration is invalid (fail at startup)."""


class DelegationValidationError(DelegationError):
    """A delegation context failed validation (fail closed at runtime)."""


class DelegationStatus(StrEnum):
    """Lifecycle state of a delegation authorization."""

    ACTIVE = "active"
    REVOKED = "revoked"


def _require_id(value: Any, kind: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DelegationValidationError(f"{kind} must be a non-empty string")
    if len(value) > MAX_ID_LENGTH:
        raise DelegationValidationError(
            f"{kind} exceeds the {MAX_ID_LENGTH}-character bound"
        )
    return value


def _require_tool_names(tools: Any, kind: str) -> frozenset[str]:
    if not isinstance(tools, (set, frozenset, list, tuple)):
        raise DelegationValidationError(f"{kind} must be a collection of tool names")
    if len(tools) > MAX_TOOLS_PER_SET:
        raise DelegationValidationError(
            f"{kind} exceeds the {MAX_TOOLS_PER_SET}-tool bound"
        )
    result: set[str] = set()
    for tool in tools:
        if not isinstance(tool, str) or not tool.strip():
            raise DelegationValidationError(f"{kind} contains an invalid tool name")
        if len(tool) > MAX_TOOL_NAME_LENGTH:
            raise DelegationValidationError(
                f"{kind} contains a tool name over {MAX_TOOL_NAME_LENGTH} characters"
            )
        result.add(tool)
    return frozenset(result)


@dataclass(frozen=True)
class Principal:
    """An agent identity established by a trusted integration boundary.

    ``allowed_tools`` is the principal's own permission set. Principals are
    never built from caller-supplied tool arguments.
    """

    principal_id: str
    allowed_tools: frozenset[str]

    def __post_init__(self) -> None:
        _require_id(self.principal_id, "principal_id")
        object.__setattr__(
            self,
            "allowed_tools",
            _require_tool_names(self.allowed_tools, "allowed_tools"),
        )

    @classmethod
    def from_manifest(cls, data: Any, kind: str = "principal") -> Principal:
        """Strictly parse a principal from manifest JSON (unknown keys rejected)."""
        if not isinstance(data, dict):
            raise DelegationConfigError(f"{kind} must be an object")
        try:
            return cls(
                principal_id=_require_id(data.get("principal_id"), "principal_id"),
                allowed_tools=_require_tool_names(
                    data.get("allowed_tools"), "allowed_tools"
                ),
            )
        except DelegationValidationError as exc:
            raise DelegationConfigError(f"invalid {kind}: {exc}") from exc


@dataclass(frozen=True)
class DelegationContext:
    """A validated, immutable delegation authorization for one workflow.

    Attributes:
        delegation_id: Stable identifier of this delegation grant.
        workflow_id: Workflow scope binding provenance transfer and
            duplicate-request state.
        initiator: The initiating principal and its permission set.
        delegate_principal_id: The delegated agent's identity.
        granted_tools: The explicit, attenuated subset granted to the delegate.
        issued_at / expires_at: Validity window (seconds since epoch).
        status: ``active`` or ``revoked``.
        parent_delegation_id: Always ``None``; nested delegation is rejected.
    """

    delegation_id: str
    workflow_id: str
    initiator: Principal
    delegate_principal_id: str
    granted_tools: frozenset[str]
    issued_at: float
    expires_at: float
    status: DelegationStatus = DelegationStatus.ACTIVE
    parent_delegation_id: str | None = None

    def __post_init__(self) -> None:
        _require_id(self.delegation_id, "delegation_id")
        _require_id(self.workflow_id, "workflow_id")
        _require_id(self.delegate_principal_id, "delegate_principal_id")
        if not isinstance(self.initiator, Principal):
            raise DelegationValidationError("initiator must be a Principal")
        object.__setattr__(
            self,
            "granted_tools",
            _require_tool_names(self.granted_tools, "granted_tools"),
        )
        if not isinstance(self.issued_at, float) or not isinstance(self.expires_at, float):
            raise DelegationValidationError("issued_at/expires_at must be floats")
        if not (self.issued_at < self.expires_at):
            raise DelegationValidationError("expires_at must be after issued_at")
        if self.parent_delegation_id is not None:
            raise DelegationValidationError(
                "nested delegation is not supported; parent_delegation_id must be null"
            )
        if not self.granted_tools <= self.initiator.allowed_tools:
            excess = sorted(self.granted_tools - self.initiator.allowed_tools)
            raise DelegationValidationError(
                f"grant exceeds the initiating principal's authority: {excess}"
            )

    @property
    def effective_tools(self) -> frozenset[str]:
        """The attenuated authority: grant intersected with initiator authority."""
        return frozenset(self.granted_tools) & frozenset(self.initiator.allowed_tools)

    def check(self, tool_name: str, *, now: float | None = None) -> str | None:
        """Return ``None`` when the call is within delegated authority.

        Otherwise return a stable denial code consumed by the policy engine:
        ``revoked``, ``expired``, ``not_granted``, or ``exceeds_initiator``.
        """
        current = time.time() if now is None else now
        if self.status is not DelegationStatus.ACTIVE:
            return "revoked"
        if current >= self.expires_at:
            return "expired"
        if not isinstance(tool_name, str) or not tool_name:
            return "not_granted"
        if tool_name not in self.granted_tools:
            return "not_granted"
        if tool_name not in self.initiator.allowed_tools:
            return "exceeds_initiator"


class DelegationConfig(BaseModel):
    """Delegation policy configuration (the ``delegation:`` YAML section).

    ``enforcement=off`` (default) preserves legacy behavior: the delegation
    tier is never consulted and no delegation-aware denial can occur.
    ``enforcement=required`` activates fail-closed evaluation: a missing,
    malformed, revoked, expired, or unknown delegation context denies the call.

    The runtime grant itself (identities, granted tools, validity) lives in
    the trusted manifest referenced by ``--delegation``; this section only
    controls enforcement mode and resource bounds.
    """

    model_config = ConfigDict(extra="forbid")

    enforcement: Literal["off", "required"] = "off"
    max_active_delegations: int = Field(default=16, ge=1, le=1024)
    max_ttl_seconds: float = Field(default=3600.0, gt=0, le=86400.0)

    @field_validator("enforcement", mode="before")
    @classmethod
    def _reject_bare_off(cls, value: Any) -> Any:
        # YAML parses bare ``off`` as boolean False; require the quoted form.
        if isinstance(value, bool):
            raise ValueError(
                'enforcement must be the string "off" or "required" '
                '(quote "off" in YAML)'
            )
        return value


# ------------------------------------------------------------------ manifest


class _ManifestPrincipal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(min_length=1, max_length=MAX_ID_LENGTH)
    allowed_tools: list[str] = Field(min_length=1, max_length=MAX_TOOLS_PER_SET)

    @field_validator("allowed_tools")
    @classmethod
    def _tool_names(cls, value: list[str]) -> list[str]:
        for tool in value:
            if (
                not isinstance(tool, str)
                or not tool.strip()
                or len(tool) > MAX_TOOL_NAME_LENGTH
            ):
                raise ValueError("tool names must be non-empty strings within bounds")
        return value


class _DelegationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delegation_id: str = Field(min_length=1, max_length=MAX_ID_LENGTH)
    workflow_id: str = Field(min_length=1, max_length=MAX_ID_LENGTH)
    initiator: _ManifestPrincipal
    delegate_principal_id: str = Field(min_length=1, max_length=MAX_ID_LENGTH)
    granted_tools: list[str] = Field(min_length=1, max_length=MAX_TOOLS_PER_SET)
    issued_at: float
    expires_at: float
    status: Literal["active", "revoked"] = "active"
    parent_delegation_id: str | None = None

    @field_validator("granted_tools")
    @classmethod
    def _grant_names(cls, value: list[str]) -> list[str]:
        for tool in value:
            if (
                not isinstance(tool, str)
                or not tool.strip()
                or len(tool) > MAX_TOOL_NAME_LENGTH
            ):
                raise ValueError("tool names must be non-empty strings within bounds")
        return value

        return None


def parse_delegation_manifest(
    raw: str | bytes, *, now: float | None = None
) -> DelegationContext:
    """Parse manifest JSON into a validated context, or raise config error.

    Applies strict schema (unknown keys rejected), size, validity-window, and
    attenuation checks. Nested delegation is rejected here.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DelegationConfigError("delegation manifest is not valid UTF-8") from exc
    if len(raw.encode("utf-8", errors="ignore")) > MAX_MANIFEST_BYTES:
        raise DelegationConfigError(
            f"delegation manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise DelegationConfigError(
            f"delegation manifest is not valid JSON: {exc}"
        ) from exc
    try:
        manifest = _DelegationManifest.model_validate(data)
    except Exception as exc:  # noqa: BLE001 - pydantic ValidationError family
        raise DelegationConfigError(f"invalid delegation manifest: {exc}") from exc

    current = time.time() if now is None else now
    if manifest.issued_at > current:
        raise DelegationConfigError(
            "delegation manifest is not yet valid (issued_at in the future)"
        )
    if manifest.expires_at <= manifest.issued_at:
        raise DelegationConfigError(
            "delegation manifest expires_at must be after issued_at"
        )

    try:
        initiator = Principal(
            principal_id=manifest.initiator.principal_id,
            allowed_tools=frozenset(manifest.initiator.allowed_tools),
        )
        return DelegationContext(
            delegation_id=manifest.delegation_id,
            workflow_id=manifest.workflow_id,
            initiator=initiator,
            delegate_principal_id=manifest.delegate_principal_id,
            granted_tools=frozenset(manifest.granted_tools),
            issued_at=float(manifest.issued_at),
            expires_at=float(manifest.expires_at),
            status=DelegationStatus(manifest.status),
            parent_delegation_id=manifest.parent_delegation_id,
        )
    except (DelegationValidationError, ValueError) as exc:
        raise DelegationConfigError(f"invalid delegation manifest: {exc}") from exc


class DelegationSource:
    """Trusted local integration boundary for delegation identity.

    The manifest file path is supplied by the operator (``--delegation``).
    The file is re-read and re-validated on every access so that revocation
    and expiry edits take effect for subsequent calls. It is never derived
    from caller-supplied request data.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def current(self, *, now: float | None = None) -> DelegationContext | None:
        """Return the current context, ``None`` when the file is absent.

        Raises :class:`DelegationConfigError` for an invalid manifest; the
        proxy maps both ``None`` and raised errors to a fail-closed denial.
        """
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise DelegationConfigError(
                f"cannot read delegation manifest: {type(exc).__name__}"
            ) from exc
        return parse_delegation_manifest(raw, now=now)

    def require(self, *, now: float | None = None) -> DelegationContext:
        """Like :meth:`current`, but a missing file is also a config error."""
        context = self.current(now=now)
        if context is None:
            raise DelegationConfigError("delegation manifest file not found")
        return context

