"""Deterministic policy engine for Agent44 (Milestone 3).

Loads a small, versioned YAML policy, validates it eagerly, and evaluates a
typed ALLOW/DENY decision *before* a tool call is forwarded downstream.

Design rules:
  * Evaluation is independent of MCP response construction:
    ``PolicyEngine.evaluate`` returns a ``Decision`` and never builds
    protocol objects.
  * Deterministic precedence (highest first): explicit ``deny_tools`` >
    matching DENY argument rules (first declared wins) > ``allow_tools`` >
    matching ALLOW argument rules (first declared wins) > default action.
  * Only ``ALLOW`` and ``DENY`` exist. ``REVIEW`` is deliberately not
    modelled, so there is no silently-permissive fallback outcome.
  * A missing or invalid policy raises ``PolicyError``. When enforcement is
    enabled the proxy fails startup instead of running unprotected.

No expression language: an argument rule is either an exact-value match on a
dotted field path or a "field is present" check.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

SUPPORTED_POLICY_VERSIONS = frozenset({"1"})

_FIELD_SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
_FIELD_PATH_RE = re.compile(rf"^{_FIELD_SEGMENT}(\.{_FIELD_SEGMENT})*$")

_POLICY_KEYS = frozenset(
    {"version", "name", "default_deny", "allow_tools", "deny_tools", "rules"}
)


class PolicyError(ValueError):
    """Raised when a policy file is missing, malformed, or inconsistent."""


class Action(StrEnum):
    """The only two policy outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNDECIDED = "UNDECIDED"


class Decision(BaseModel):
    """A typed policy decision, independent of MCP response construction."""

    action: Action
    reason: str
    rule_id: str
    policy_id: str
    policy_version: str | None = None


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
        return self

    def matches(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        return self.tool == tool_name and self.when.matches(arguments)


class Policy(BaseModel):
    """A validated, versioned policy configuration."""

    version: str
    name: str = "unnamed-policy"
    default_deny: bool = False
    allow_tools: list[str] = Field(default_factory=list)
    deny_tools: list[str] = Field(default_factory=list)
    rules: list[PolicyRule] = Field(default_factory=list)

    @field_validator("version", mode="before")
    @classmethod
    def _supported_version(cls, value: Any) -> Any:
        text = str(value)
        if text not in SUPPORTED_POLICY_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_POLICY_VERSIONS))
            raise ValueError(f"unsupported policy version {value!r}; supported: {supported}")
        return text

    @model_validator(mode="after")
    def _reject_conflicts(self) -> Policy:
        both = sorted(set(self.allow_tools) & set(self.deny_tools))
        if both:
            raise ValueError(f"tools listed in both allow_tools and deny_tools: {both}")
        for label, tools in (("allow_tools", self.allow_tools), ("deny_tools", self.deny_tools)):
            if len(set(tools)) != len(tools):
                raise ValueError(f"duplicate entries in {label}")
        rule_ids = [rule.id for rule in self.rules]
        duplicated = sorted({rid for rid in rule_ids if rule_ids.count(rid) > 1})
        if duplicated:
            raise ValueError(f"duplicate rule ids: {duplicated}")
        return self

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


class PolicyEngine:
    """Deterministic evaluator over a validated ``Policy``."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    @classmethod
    def from_path(cls, path: str | Path) -> PolicyEngine:
        """Load a policy file and return an engine, or raise ``PolicyError``."""
        return cls(load_policy(path))

    @property
    def policy_id(self) -> str:
        return self.policy.name

    @property
    def policy_version(self) -> str:
        return self.policy.version

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None) -> Decision:
        """Return the ALLOW/DENY decision for one tool call.

        Precedence, highest first: explicit deny list, then DENY argument
        rules in declaration order, then explicit allow list, then ALLOW
        argument rules in declaration order, then the configured default.
        """
        policy = self.policy
        args = dict(arguments or {})
        base: dict[str, Any] = {
            "policy_id": policy.name,
            "policy_version": policy.version,
        }

        if tool_name in set(policy.deny_tools):
            return Decision(
                action=Action.DENY,
                reason=f"tool '{tool_name}' is denied by policy",
                rule_id="deny_tools",
                **base,
            )

        for rule in policy.rules:
            if rule.action is Action.DENY and rule.matches(tool_name, args):
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
            if rule.action is Action.ALLOW and rule.matches(tool_name, args):
                return Decision(
                    action=Action.ALLOW,
                    reason=rule.reason,
                    rule_id=rule.id,
                    **base,
                )

        if policy.default_deny:
            return Decision(
                action=Action.DENY,
                reason="no rule matched and default_deny is enabled",
                rule_id="default_deny",
                **base,
            )
        return Decision(
            action=Action.ALLOW,
            reason="no rule matched and default_deny is disabled",
            rule_id="default_allow",
            **base,
        )


