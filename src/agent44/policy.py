"""Deterministic policy engine for Agent44 (Milestone 4a).

Loads a small, versioned YAML policy, validates it eagerly, and evaluates a
typed ALLOW/DENY/UNDECIDED decision *before* a tool call is forwarded
downstream.

Decision contract, highest precedence first:

  * Hard-deny rules (explicit ``hard_deny_tools`` or rules with
    ``hard: true``) > explicit ``deny_tools`` > matching DENY argument rules
    (first declared wins) > ``allow_tools`` > matching ALLOW argument rules
    (first declared wins) > adapter evaluation (only for calls explicitly
    listed in ``adapter_tools``) > configured default.

  * ``UNDECIDED`` is an internal outcome, never authorization to execute a
    tool. Enforcement resolves it to ``DENY`` before any downstream call.
  * Only calls explicitly configured via ``adapter_tools`` may reach a
    decision adapter. Adapter errors, timeouts, missing adapters, and invalid
    adapter outputs fail closed to ``DENY``.
  * No adapter may override a hard-deny decision.

Policy evaluation stays independent of MCP response construction:
``PolicyEngine.evaluate`` returns a ``Decision`` and never builds protocol
objects.

No expression language: an argument rule is either an exact-value match on a
dotted field path or a "field is present" check.
"""

from __future__ import annotations

import asyncio
import re
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

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
"""Maximum time the engine waits for one adapter call before failing closed."""


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

    def match_rules(self, tool_name: str, arguments: dict[str, Any] | None) -> Decision | None:
        """Apply the deterministic tiers; return ``None`` when none matches.

        Precedence, highest first: ``hard_deny_tools``, matching hard DENY
        rules, ``deny_tools``, matching DENY argument rules, ``allow_tools``,
        matching ALLOW argument rules. Pure and synchronous: never consults
        an adapter.
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
        matched = self.match_rules(tool_name, arguments)
        if matched is not None:
            return matched

        args = dict(arguments or {})
        if tool_name in set(policy.adapter_tools) and adapter is not None:
            try:
                raw = await asyncio.wait_for(
                    adapter.decide(tool_name, args, self._adapter_rules()),
                    timeout=ADAPTER_TIMEOUT_SECONDS,
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

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None) -> Decision:
        """Return the ALLOW/DENY decision for one tool call.

        Synchronous compatibility entry point: applies the deterministic
        tiers and the configured default without consulting any adapter.
        Never returns ``UNDECIDED``.
        """
        matched = self.match_rules(tool_name, arguments)
        if matched is not None:
            return matched
        return self._default_decision(tool_name)

