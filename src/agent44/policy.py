"""Deterministic policy engine for Agent44 (Milestone 4a).

Loads a small, versioned YAML policy, validates it eagerly, and evaluates a
typed ALLOW/DENY/UNDECIDED decision *before* a tool call is forwarded
downstream.

Decision contract, highest precedence first:

  * Hard-deny rules (explicit ``hard_deny_tools`` or rules with
    ``hard: true``) > delegated authority (only when ``delegation.enforcement``
    is ``required``) > provenance-aware restrictions (only when
    ``provenance.enforcement`` is ``required``) >
    argument constraints for the tool >
    explicit ``deny_tools`` > matching DENY argument rules
    (first declared wins) > ``allow_tools`` > matching ALLOW argument rules
    (first declared wins) > adapter evaluation (only for calls explicitly
    listed in ``adapter_tools``) > configured default.

  * ``UNDECIDED`` is an internal outcome, never authorization to execute a
    tool. Enforcement resolves it to ``DENY`` before any downstream call.
  * Only calls explicitly configured via ``adapter_tools`` may reach a
    decision adapter. Adapter errors, timeouts, missing adapters, and invalid
    adapter outputs fail closed to ``DENY``.
  * No adapter may override a hard-deny decision, and no adapter or allow
    rule may broaden delegated authority or override a delegation,
    provenance, or argument-policy denial.

Policy evaluation stays independent of MCP response construction:
``PolicyEngine.evaluate`` returns a ``Decision`` and never builds protocol
objects.

No expression language: an argument rule is either an exact-value match on a
dotted field path or a "field is present" check.
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agent44.argument_policy import (
    ArgumentPolicy,
    ArgumentPolicyConfigError,
    ToolArgumentConstraints,
)
from agent44.delegation import DelegationConfig, DelegationContext
from agent44.provenance import ProvenanceContext, ProvenanceRegistry, TrustClass
from agent44.transfer import TransferConfig

SUPPORTED_POLICY_VERSIONS = frozenset({"1"})

_FIELD_SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
_FIELD_PATH_RE = re.compile(rf"^{_FIELD_SEGMENT}(\.{_FIELD_SEGMENT})*$")

_POLICY_KEYS = frozenset(
    {
        "version",
        "name",
        "default_deny",
        "default",
        "allow_tools",
        "deny_tools",
        "hard_deny_tools",
        "adapter_tools",
        "argument_constraints",
        "provenance",
        "delegation",
        "rules",
    }
)


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed, or inconsistent."""


class Action(StrEnum):
    """The three decision states.

    ALLOW and DENY are final authorizations. UNDECIDED is an internal
    outcome only: it is never authorization to execute a tool, and
    enforcement resolves it to DENY before any downstream call.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNDECIDED = "UNDECIDED"


class Decision(BaseModel):
    """A typed policy decision, independent of MCP response construction.

    ``action`` and ``rule_id`` are always populated. Provenance-aware tiers
    additionally populate ``provenance_id``, ``trust_class`` and
    ``validation_transition`` when a provenance-aware rule affected the
    decision. These fields are safe observation metadata: they never embed raw
    argument values or secrets.
    """

    action: Action
    reason: str
    rule_id: str
    policy_id: str
    policy_version: str | None = None
    provenance_id: str | None = None
    trust_class: TrustClass | None = None
    validation_transition: str | None = None


def _lookup(arguments: dict[str, Any], path: str) -> tuple[Any, bool]:
    """Resolve a dotted field path inside nested dicts; report presence."""
    current: Any = arguments
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return None, False
    return current, True


def _strict_equals(value: Any, expected: Any) -> bool:
    """Exact match that does not treat ``True == 1`` or ``1 == 1.0`` as equal."""
    return type(value) is type(expected) and value == expected


class Condition(BaseModel):
    """Exactly one argument constraint: exact value or field presence."""

    field: str
    equals: Any = None
    field_exists: bool | None = None

    @model_validator(mode="after")
    def _exactly_one_constraint(self) -> Condition:
        has_equals = self.equals is not None
        has_exists = self.field_exists is not None
        if has_equals == has_exists:
            raise ValueError("condition must set exactly one of 'equals' or 'field_exists'")
        if has_exists and self.field_exists is not True:
            raise ValueError("'field_exists' must be true")
        if not _FIELD_PATH_RE.match(self.field):
            raise ValueError(f"invalid argument path {self.field!r}")
        if has_equals and isinstance(self.equals, (list, dict)):
            raise ValueError("'equals' must be a scalar value")
        return self

    def matches(self, arguments: dict[str, Any]) -> bool:
        value, found = _lookup(arguments, self.field)
        if self.field_exists is not None:
            return found
        return found and _strict_equals(value, self.equals)


class PolicyRule(BaseModel):
    """One argument-level rule scoped to a single tool."""

    id: str
    tool: str
    action: Action
    hard: bool = False
    reason: str
    when: Condition

    @field_validator("action", mode="before")
    @classmethod
    def _normalize_action(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _require_identity(self) -> PolicyRule:
        if not self.id.strip():
            raise ValueError("rule 'id' must be non-empty")
        if not self.tool.strip():
            raise ValueError(f"rule '{self.id}': 'tool' must be non-empty")
        if not self.reason.strip():
            raise ValueError(f"rule '{self.id}': 'reason' must be non-empty")
        if self.action is Action.UNDECIDED:
            raise ValueError(
                f"rule '{self.id}': 'action' must be ALLOW or DENY; "
                "UNDECIDED is an internal evaluation state"
            )
        if self.hard and self.action is not Action.DENY:
            raise ValueError(f"rule '{self.id}': 'hard' requires action DENY")
        return self

    def matches(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        return self.tool == tool_name and self.when.matches(arguments)


class ProvenanceArgumentRule(BaseModel):
    """Provenance restrictions for the arguments of a single tool.

    Every clause is a *restriction*: it can only deny a call, never grant
    authority that another tier has withheld. A call satisfies the rule only
    when every applicable clause passes.
    """

    model_config = ConfigDict(extra="forbid")

    # Deny the argument when its effective provenance is untrusted or
    # derived-untrusted.
    deny_untrusted: list[str] = Field(default_factory=list)
    # Deny the argument when no provenance record has been established for it.
    require_known: list[str] = Field(default_factory=list)
    # Allow only the listed trust classes for the argument.
    allowed_trust_classes: dict[str, list[TrustClass]] = Field(
        default_factory=dict
    )
    # Require the argument's record to carry this validation transition.
    require_transition: dict[str, str] = Field(default_factory=dict)

    @field_validator("deny_untrusted", "require_known")
    @classmethod
    def _non_empty_argument_names(cls, value: list[str]) -> list[str]:
        for name in value:
            if not isinstance(name, str) or not name.strip():
                raise ValueError("argument names must be non-empty strings")
        return value

    @field_validator("allowed_trust_classes")
    @classmethod
    def _valid_trust_classes(
        cls, value: dict[str, list[TrustClass]]
    ) -> dict[str, list[TrustClass]]:
        for arg_name, classes in value.items():
            if not arg_name.strip():
                raise ValueError("argument names must be non-empty strings")
            if not classes:
                raise ValueError(f"trust classes for {arg_name!r} must be non-empty")
        return value

    @field_validator("require_transition")
    @classmethod
    def _non_empty_transitions(cls, value: dict[str, str]) -> dict[str, str]:
        for arg_name, transition_id in value.items():
            if not arg_name.strip():
                raise ValueError("argument names must be non-empty strings")
            if not transition_id or not transition_id.strip():
                raise ValueError(f"transition id for {arg_name!r} must be non-empty")
        return value


class ProvenanceConfig(BaseModel):
    """Provenance policy configuration.

    ``enforcement=off`` preserves legacy behavior: provenance metadata is not
    consulted and no provenance-aware denial can occur. ``enforcement=required``
    activates the provenance tier: configured restrictions are evaluated before
    argument constraints and a missing/invalid provenance reference fails
    closed.
    """

    model_config = ConfigDict(extra="forbid")

    enforcement: Literal["off", "required"] = "off"
    transfer: TransferConfig = Field(default_factory=TransferConfig)
    rules: dict[str, ProvenanceArgumentRule] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def _tool_names(
        cls, value: dict[str, ProvenanceArgumentRule]
    ) -> dict[str, ProvenanceArgumentRule]:
        for name in value:
            if not isinstance(name, str) or not name.strip():
                raise ValueError("tool names must be non-empty strings")
        return value


class Policy(BaseModel):
    """A validated, versioned policy configuration."""

    version: str
    name: str = "unnamed-policy"
    default_deny: bool = False
    default: Action | None = None
    allow_tools: list[str] = Field(default_factory=list)
    deny_tools: list[str] = Field(default_factory=list)
    hard_deny_tools: list[str] = Field(default_factory=list)
    adapter_tools: list[str] = Field(default_factory=list)
    argument_constraints: dict[str, ToolArgumentConstraints] = Field(
        default_factory=dict
    )
    provenance: ProvenanceConfig = Field(default_factory=ProvenanceConfig)
    delegation: DelegationConfig = Field(default_factory=DelegationConfig)
    rules: list[PolicyRule] = Field(default_factory=list)

    @field_validator("version", mode="before")
    @classmethod
    def _supported_version(cls, value: Any) -> Any:
        text = str(value)
        if text not in SUPPORTED_POLICY_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_POLICY_VERSIONS))
            raise ValueError(f"unsupported policy version {value!r}; supported: {supported}")
        return text

    @field_validator("default", mode="before")
    @classmethod
    def _normalize_default(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _reject_conflicts(self) -> Policy:
        if self.default is not None and "default_deny" in self.model_fields_set:
            raise ValueError("specify only one of 'default' and 'default_deny'")
        if self.default is Action.UNDECIDED:
            raise ValueError("'default' must be ALLOW or DENY, not UNDECIDED")
        both = sorted(set(self.allow_tools) & set(self.deny_tools))
        if both:
            raise ValueError(f"tools listed in both allow_tools and deny_tools: {both}")
        hard_conflict = sorted(set(self.hard_deny_tools) & set(self.allow_tools))
        if hard_conflict:
            raise ValueError(
                f"tools listed in both hard_deny_tools and allow_tools: {hard_conflict}"
            )
        tool_lists = (
            ("allow_tools", self.allow_tools),
            ("deny_tools", self.deny_tools),
            ("hard_deny_tools", self.hard_deny_tools),
            ("adapter_tools", self.adapter_tools),
        )
        for label, tools in tool_lists:
            if len(set(tools)) != len(tools):
                raise ValueError(f"duplicate entries in {label}")
        rule_ids = [rule.id for rule in self.rules]
        duplicated = sorted({rid for rid in rule_ids if rule_ids.count(rid) > 1})
        if duplicated:
            raise ValueError(f"duplicate rule ids: {duplicated}")
        return self

    @property
    def default_action(self) -> Action:
        """The configured default outcome, exposed for the engine.

        An explicit ``default`` wins; otherwise an explicitly set
        ``default_deny`` keeps its legacy meaning; a policy that configures
        neither gets the safe default DENY.
        """
        if self.default is not None:
            return self.default
        if "default_deny" in self.model_fields_set:
            return Action.DENY if self.default_deny else Action.ALLOW
        return Action.DENY

def load_policy(path: str | Path) -> Policy:
    """Read and validate a YAML policy file, raising ``PolicyError`` on any problem.

    Validation is strict: unknown top-level keys, unknown actions, malformed
    rules, invalid argument paths, conflicting lists, and unsupported versions
    are all rejected rather than being silently ignored.
    """
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError(f"policy file not found: {policy_path}")
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file is not valid YAML: {policy_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy root must be a mapping, got {type(raw).__name__}")
    unknown = sorted(set(raw) - set(_POLICY_KEYS))
    if unknown:
        raise PolicyError(f"unknown policy keys: {', '.join(unknown)}")
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"invalid policy {policy_path}: {exc}") from exc


ADAPTER_TIMEOUT_SECONDS = 5.0
"""Maximum time the engine waits for one adapter call before failing closed.

The default is also the effective value for every engine construction path
that does not pass ``adapter_timeout_seconds`` explicitly. The module
constant is documentation of the default combined with a validation hook;
engines carry their effective deadline as an instance attribute and are
never configured through a mutable global.

Configuration rule: the effective deadline must be strictly positive and
must not exceed the outer timeouts (the provider request timeout at
``agent44.local_provider.DEFAULT_TIMEOUT_SECONDS`` and the downstream call
timeout at ``agent44.proxy.DOWNSTREAM_CALL_TIMEOUT_SECONDS``, both 60 s).
A deadline beyond that bound would be indistinguishable, at classification
time, from a provider/transport timeout and would mask the engine's own
``adapter_timeout`` classification.
"""


# Outer harness / provider bound. A deadline beyond this value would fire at,
# or be masked by, the outer timeouts, so timeouts could no longer be
# classified as the engine's own ``adapter_timeout``.
_MAX_ADAPTER_TIMEOUT_SECONDS = 60.0


def _validate_adapter_timeout(seconds: float) -> float:
    """Validate and normalise an adapter deadline.

    Rejected: non-finite values, zero, negative values, and values greater
    than the outer bound (provider and downstream call timeout), which would
    make engine timeouts indistinguishable from provider/transport timeouts.

    Returns the value as a float when valid.
    """
    if not math.isfinite(seconds):
        raise ValueError("adapter timeout must be a finite number")
    if seconds <= 0:
        raise ValueError("adapter timeout must be strictly positive")
    if seconds > _MAX_ADAPTER_TIMEOUT_SECONDS:
        raise ValueError(
            f"adapter timeout {seconds}s exceeds the outer bound of "
            f"{_MAX_ADAPTER_TIMEOUT_SECONDS}s (provider and downstream call "
            f"timeout of 60 s); a larger deadline would mask the engine's "
            f"'adapter_timeout' classification with a provider/transport "
            f"timeout"
        )
    return float(seconds)


class AdapterParseError(ValueError):
    """Raised when an adapter received a response but could not parse it.

    Adapters raise this when a response arrived but could not be converted
    into a valid decision — malformed JSON, an unexpected wire shape, or
    out-of-policy fields. The engine maps it to the fail-closed
    ``adapter_invalid`` outcome (a DENY), keeping parser failures distinct
    from provider/transport failures (``adapter_error``, class ``Exception``)
    and timeouts (``adapter_timeout``, class ``TimeoutError``).

    Contract: message text must never embed raw argument values or other
    secrets. The engine includes a defensively sanitized, bounded excerpt of
    the message in the decision reason to aid pilot diagnosis; raise sites
    must keep messages bounded and secret-free themselves.
    """


class AdapterDecision(BaseModel):
    """A decision returned by a :class:`DecisionAdapter`.

    Reuses :class:`Action`, so adapters speak the same three-state language
    as the engine. ``UNDECIDED`` is an internal outcome: it is never
    authorization to execute a tool, and enforcement resolves it to ``DENY``.
    """

    action: Action
    reason: str
    rule_id: str | None = None


@runtime_checkable
class DecisionAdapter(Protocol):
    """Interface for an auxiliary decision backend consulted by the engine.

    The engine consults an adapter only for calls explicitly configured via
    ``adapter_tools``, only after the deterministic tiers produced no
    decision, and never for a call a hard-deny rule already denied. Adapter
    failures (exceptions, timeouts, invalid outputs) fail closed to ``DENY``.
    """

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        """Return ALLOW, DENY, or UNDECIDED for one tool call."""
        ...


class RulesOnlyAdapter(DecisionAdapter):
    """Reference adapter that follows only deterministic ``PolicyRule``s.

    Replays deterministic precedence over the provided rules: the first
    matching DENY rule wins, then the first matching ALLOW rule. When no
    rule matches it returns ``UNDECIDED`` rather than inventing
    authorization.
    """

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        args = dict(arguments or {})
        for rule in rules:
            if rule.action is Action.DENY and rule.matches(tool_name, args):
                return AdapterDecision(
                    action=Action.DENY, reason=rule.reason, rule_id=rule.id
                )
        for rule in rules:
            if rule.action is Action.ALLOW and rule.matches(tool_name, args):
                return AdapterDecision(
                    action=Action.ALLOW, reason=rule.reason, rule_id=rule.id
                )
        return AdapterDecision(
            action=Action.UNDECIDED,
            reason=f"no adapter rule matched tool '{tool_name}'",
        )


class PolicyEngine:
    """Deterministic evaluator over a validated ``Policy``."""

    def __init__(self, policy: Policy, *, adapter_timeout_seconds: float = 5.0) -> None:
        self.policy = policy
        self.adapter_timeout_seconds = _validate_adapter_timeout(adapter_timeout_seconds)
        try:
            self._argument_policy = ArgumentPolicy.from_config(
                {
                    "tools": {
                        name: tc.model_dump()
                        for name, tc in policy.argument_constraints.items()
                    }
                }
            )
        except ArgumentPolicyConfigError as exc:
            raise PolicyError(f"invalid argument constraints: {exc}") from exc

    @classmethod
    def from_path(
        cls, path: str | Path, *, adapter_timeout_seconds: float = 5.0
    ) -> PolicyEngine:
        """Load a policy file and return an engine, or raise ``PolicyError``.

        ``adapter_timeout_seconds`` overrides the module-level default
        (``ADAPTER_TIMEOUT_SECONDS``) for this engine only.
        """
        return cls(load_policy(path), adapter_timeout_seconds=adapter_timeout_seconds)

    @property
    def policy_id(self) -> str:
        return self.policy.name

    @property
    def policy_version(self) -> str:
        return self.policy.version

    @property
    def provenance(self) -> ProvenanceConfig:
        """The validated provenance configuration for this engine."""
        return self.policy.provenance

    @property
    def delegation(self) -> DelegationConfig:
        """The validated delegation configuration for this engine."""
        return self.policy.delegation

    def match_rules(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        provenance_context: ProvenanceContext | None = None,
        delegation_context: DelegationContext | None = None,
    ) -> Decision | None:
        """Apply the deterministic tiers; return ``None`` when none matches.

        Precedence, highest first: ``hard_deny_tools``, delegated authority
        (only when ``delegation.enforcement`` is ``required``),
        provenance-aware rules, argument constraints, matching hard DENY
        rules, ``deny_tools``, matching DENY argument rules, ``allow_tools``,
        matching ALLOW argument rules. Pure and synchronous: never consults
        an adapter, and no allow rule or adapter can broaden delegated
        authority or override a delegation/provenance denial.
        """
        policy = self.policy
        args = dict(arguments or {})
        base: dict[str, Any] = {
            "policy_id": policy.name,
            "policy_version": policy.version,
        }

        if tool_name in set(policy.hard_deny_tools):
            return Decision(
                action=Action.DENY,
                reason=f"tool '{tool_name}' is hard-denied by policy",
                rule_id="hard_deny_tools",
                **base,
            )

        delegation_decision = self._delegation_decision(
            tool_name, delegation_context, base
        )
        if delegation_decision is not None:
            return delegation_decision

        provenance_decision = self._provenance_decision(
            tool_name, args, provenance_context, base
        )
        if provenance_decision is not None:
            return provenance_decision

        argument_decision = self._argument_constraint_decision(tool_name, args, base)
        if argument_decision is not None:
            return argument_decision

        for rule in policy.rules:
            if rule.hard and rule.action is Action.DENY and rule.matches(tool_name, args):
                return Decision(
                    action=Action.DENY,
                    reason=rule.reason,
                    rule_id=rule.id,
                    **base,
                )

        if tool_name in set(policy.deny_tools):
            return Decision(
                action=Action.DENY,
                reason=f"tool '{tool_name}' is denied by policy",
                rule_id="deny_tools",
                **base,
            )

        for rule in policy.rules:
            if (
                not rule.hard
                and rule.action is Action.DENY
                and rule.matches(tool_name, args)
            ):
                return Decision(
                    action=Action.DENY,
                    reason=rule.reason,
                    rule_id=rule.id,
                    **base,
                )

        if tool_name in set(policy.allow_tools):
            return Decision(
                action=Action.ALLOW,
                reason=f"tool '{tool_name}' is allowed by policy",
                rule_id="allow_tools",
                **base,
            )

        for rule in policy.rules:
            if (
                not rule.hard
                and rule.action is Action.ALLOW
                and rule.matches(tool_name, args)
            ):
                return Decision(
                    action=Action.ALLOW,
                    reason=rule.reason,
                    rule_id=rule.id,
                    **base,
                )
        return None

    def _delegation_decision(
        self,
        tool_name: str,
        delegation_context: DelegationContext | None,
        base: dict[str, Any],
    ) -> Decision | None:
        """Evaluate delegated authority for one tool call.

        When ``delegation.enforcement`` is ``required``, a missing, malformed,
        revoked, expired, or out-of-grant context fails closed with a stable
        ``delegation:{tool}:{code}`` rule id. When enforcement is off the tier
        is skipped and legacy behavior is unchanged. This tier sits only
        below hard-deny: no allow rule, argument constraint, provenance
        clause, or adapter can broaden delegated authority. Reasons never
        embed raw argument values.
        """
        delegation = self.policy.delegation
        if delegation.enforcement != "required":
            return None

        if isinstance(delegation_context, DelegationContext):
            code = delegation_context.check(tool_name, now=time.time())
        else:
            # Missing or invalid context: fail closed.
            code = "no_context"
        if code is None:
            return None

        reasons = {
            "no_context": "delegation context missing or invalid; call denied",
            "revoked": f"delegation is revoked; tool '{tool_name}' denied",
            "expired": f"delegation expired; tool '{tool_name}' denied",
            "not_granted": f"tool '{tool_name}' is not within the delegated authority",
            "exceeds_initiator": (
                f"tool '{tool_name}' exceeds the initiating principal's authority"
            ),
        }
        reason = reasons.get(code, f"delegation check failed ({code}); call denied")
        return Decision(
            action=Action.DENY,
            reason=reason,
            rule_id=f"delegation:{tool_name}:{code}",
            **base,
        )

    def _provenance_decision(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        provenance_context: ProvenanceContext | None,
        base: dict[str, Any],
    ) -> Decision | None:
        """Evaluate provenance-aware restrictions for one tool call.

        Returns a fail-closed DENY when any configured provenance restriction
        is violated, or ``None`` when the call satisfies every restriction (or
        the tool is unconfigured / provenance enforcement is off).

        Denials here cannot be overridden by any lower tier: hard-deny is the
        only tier above provenance-aware rules. Reasons never embed raw
        argument values.
        """
        policy = self.policy
        provenance = policy.provenance
        if provenance.enforcement != "required":
            return None

        rule = provenance.rules.get(tool_name)
        if rule is None:
            # No provenance restriction configured for this tool: no denial.
            return None

        if provenance_context is not None:
            registry = provenance_context.registry
            values = provenance_context.values
        else:
            # Enforcement is required but no provenance context was supplied:
            # fail closed by evaluating every restriction against an empty
            # context, so no argument can be established or trusted.
            registry = ProvenanceRegistry()
            values = {}

        def denial(
            argument_name: str,
            category: str,
            trust_class: TrustClass | None = None,
            provenance_id: str | None = None,
            validation_transition: str | None = None,
        ) -> Decision:
            return Decision(
                action=Action.DENY,
                reason=(
                    f"provenance policy denied argument {argument_name!r} ({category})"
                ),
                rule_id=f"provenance:{tool_name}:{category}:{argument_name}",
                provenance_id=provenance_id,
                trust_class=trust_class,
                validation_transition=validation_transition,
                **base,
            )

        # Check each configured clause in a deterministic order.
        for argument_name in sorted(rule.deny_untrusted):
            pid = values.get(argument_name)
            trust = registry.effective_trust(pid)
            if trust in (TrustClass.UNTRUSTED, TrustClass.DERIVED_UNTRUSTED):
                return denial(
                    argument_name,
                    "deny_untrusted",
                    trust_class=trust,
                    provenance_id=pid,
                )

        for argument_name in sorted(rule.require_known):
            pid = values.get(argument_name)
            if pid is None:
                return denial(argument_name, "require_known")

        for argument_name in sorted(rule.allowed_trust_classes):
            pid = values.get(argument_name)
            trust = registry.effective_trust(pid)
            allowed = set(rule.allowed_trust_classes[argument_name])
            if trust not in allowed:
                return denial(
                    argument_name,
                    "allowed_trust_classes",
                    trust_class=trust,
                    provenance_id=pid,
                )

        for argument_name in sorted(rule.require_transition):
            pid = values.get(argument_name)
            record = registry.get_record(pid)
            required = rule.require_transition[argument_name]
            if record is None or record.validation_transition != required:
                return denial(
                    argument_name,
                    "require_transition",
                    provenance_id=pid,
                    validation_transition=record.validation_transition
                    if record is not None
                    else None,
                )

        return None

    def _argument_constraint_decision(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        base: dict[str, Any],
    ) -> Decision | None:
        """Evaluate declared argument constraints for one tool call.

        Returns a fail-closed DENY when any constraint is violated, or
        ``None`` when the call satisfies every constraint (or the tool is
        unconfigured). Reasons never embed raw argument values.
        """
        result = self._argument_policy.evaluate(tool_name, arguments)
        if result.allowed:
            return None
        return Decision(
            action=Action.DENY,
            reason=result.reason,
            rule_id=result.rule_id,
            **base,
        )

    def _default_decision(self, tool_name: str) -> Decision:
        """Return the configured-default outcome for one tool call."""
        policy = self.policy
        base: dict[str, Any] = {
            "policy_id": policy.name,
            "policy_version": policy.version,
        }
        action = policy.default_action
        if action is Action.DENY:
            if policy.default is None and "default_deny" in policy.model_fields_set:
                return Decision(
                    action=Action.DENY,
                    reason="no rule matched and default_deny is enabled",
                    rule_id="default_deny",
                    **base,
                )
            return Decision(
                action=Action.DENY,
                reason="no rule matched and the policy default is deny",
                rule_id="default:deny",
                **base,
            )
        if policy.default is None and "default_deny" in policy.model_fields_set:
            return Decision(
                action=Action.ALLOW,
                reason="no rule matched and default_deny is disabled",
                rule_id="default_allow",
                **base,
            )
        return Decision(
            action=Action.ALLOW,
            reason="no rule matched and the policy default is allow",
            rule_id="default:allow",
            **base,
        )

    def _adapter_rules(self) -> list[PolicyRule]:
        """Return the rule subset an adapter may consult.

        Hard rules decide before the adapter tier and are never passed on,
        so no adapter can reinterpret or override a hard-deny decision.
        """
        return [rule for rule in self.policy.rules if not rule.hard]

    @staticmethod
    def _bounded_detail(exc: BaseException) -> str:
        """Return a bounded, printable excerpt of an adapter parse failure.

        Defensive bound: even a third-party adapter raising an oversized or
        control-character-laden message can never flood the decision reason
        (which flows into the JSONL observation log). Contract for
        :class:`AdapterParseError` raisers: never embed raw argument values.
        """
        text = "".join(ch if ch.isprintable() else " " for ch in str(exc))
        text = " ".join(text.split())
        if len(text) > 160:
            text = text[:157].rstrip() + "..."
        if not text:
            return type(exc).__name__
        return f"{type(exc).__name__}: {text}"

    @staticmethod
    def _adapter_failure(
        tool_name: str, reason: str, rule_id: str, policy: Policy
    ) -> Decision:
        """Build a fail-closed DENY with bounded, value-free reason text."""
        return Decision(
            action=Action.DENY,
            reason=f"adapter decision for tool '{tool_name}' {reason}; call denied",
            rule_id=rule_id,
            policy_id=policy.name,
            policy_version=policy.version,
        )

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        adapter: DecisionAdapter | None = None,
        provenance_context: ProvenanceContext | None = None,
        delegation_context: DelegationContext | None = None,
    ) -> Decision:

        """Apply the full Milestone 4a decision contract for one tool call.

        Deterministic tiers run first via :meth:`match_rules`. Only when no
        tier matches, the tool is explicitly listed in ``adapter_tools``, and
        an adapter is configured is the adapter consulted (bounded by
        ``ADAPTER_TIMEOUT_SECONDS``). Adapter failures, invalid outputs, and
        ``UNDECIDED`` all fail closed to ``DENY``; the ``rule_id`` keeps the
        buckets distinguishable: ``adapter_timeout`` (engine deadline),
        ``adapter_invalid`` (a response arrived but could not be parsed),
        ``adapter_error`` (provider/transport/configuration failure),
        ``adapter_undecided``, and ``adapter_missing``. Unresolved calls fall
        through to the configured policy default. Never returns ``UNDECIDED``.
        """
        policy = self.policy
        matched = self.match_rules(tool_name, arguments, provenance_context, delegation_context)
        if matched is not None:
            return matched

        args = dict(arguments or {})
        if tool_name in set(policy.adapter_tools) and adapter is not None:
            try:
                raw = await asyncio.wait_for(
                    adapter.decide(tool_name, args, self._adapter_rules()),
                    timeout=self.adapter_timeout_seconds,
                )
            except TimeoutError:
                return self._adapter_failure(tool_name, "timed out", "adapter_timeout", policy)
            except asyncio.CancelledError:
                raise
            except AdapterParseError as exc:
                # A response arrived but could not be parsed into a decision
                # (malformed model output or wire payload): report it as
                # adapter_invalid with a sanitized, bounded excerpt so parser
                # failures are diagnosable without logging raw responses.
                return self._adapter_failure(
                    tool_name,
                    f"received a response that could not be parsed ({self._bounded_detail(exc)})",
                    "adapter_invalid",
                    policy,
                )
            except Exception as exc:
                # Generic adapter/provider failures: class name only. Exception
                # messages are untrusted and may embed arbitrary data.
                return self._adapter_failure(
                    tool_name,
                    f"raised an error ({type(exc).__name__})",
                    "adapter_error",
                    policy,
                )
            if not isinstance(raw, AdapterDecision):
                return self._adapter_failure(
                    tool_name, "returned an invalid decision", "adapter_invalid", policy
                )
            if raw.action is Action.ALLOW:
                return Decision(
                    action=Action.ALLOW,
                    reason=raw.reason,
                    rule_id=raw.rule_id or "adapter",
                    policy_id=policy.name,
                    policy_version=policy.version,
                )
            if raw.action is Action.DENY:
                return Decision(
                    action=Action.DENY,
                    reason=raw.reason,
                    rule_id=raw.rule_id or "adapter",
                    policy_id=policy.name,
                    policy_version=policy.version,
                )
            return self._adapter_failure(
                tool_name, "was undecided", "adapter_undecided", policy
            )
        elif tool_name in set(policy.adapter_tools):
            # Adapter-tier tool with no adapter configured: unresolved, so deny
            # rather than silently falling back to the policy default.
            return self._adapter_failure(
                tool_name, "has no configured adapter", "adapter_missing", policy
            )

        return self._default_decision(tool_name)

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        provenance_context: ProvenanceContext | None = None,
        delegation_context: DelegationContext | None = None,
    ) -> Decision:
        """Return the ALLOW/DENY decision for one tool call.

        Synchronous compatibility entry point: applies the deterministic
        tiers and the configured default without consulting any adapter.
        Never returns ``UNDECIDED``.
        """
        matched = self.match_rules(tool_name, arguments, provenance_context, delegation_context)
        if matched is not None:
            return matched
        return self._default_decision(tool_name)

