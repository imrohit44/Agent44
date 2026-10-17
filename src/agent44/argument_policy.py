"""Deterministic argument-schema policy enforcement for MCP tool calls.

This module lets a policy author declare constraints on the *arguments* of
specific MCP tools. Validation is purely deterministic -- there is no model,
no eval, and no regex-based evaluation of argument values. A call that
violates a constraint is never forwarded downstream.

Supported constraint categories, declared per argument:

  * ``required``: the argument must be present in the call.
  * ``type``: expected primitive type -- ``bool``, ``int``, ``float`` or
    ``str`` (booleans are never accepted where ``int`` or ``float`` is
    declared, and vice versa).
  * ``enum``: the value must be one of the declared literals.
  * ``minimum`` / ``maximum``: inclusive numeric bounds.
  * ``min_length`` / ``max_length``: inclusive string length bounds.

Tool-level option:

  * ``unknown_arguments``: ``"allow"`` (default) or ``"deny"`` -- reject
    arguments that are not declared in the tool's constraint set.

Fail-closed behavior:

  * Malformed configuration raises :class:`ArgumentPolicyConfigError` at load
    time so the proxy refuses to start without a valid policy.
  * A call whose arguments are not a mapping is denied.
  * Tools without a configured constraint set are not constrained -- existing
    behavior is preserved for them.

Raw argument values never appear in denial reasons or in observation logs;
reasons are static policy text only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ArgumentPolicyConfigError(Exception):
    """Raised when argument-policy configuration is malformed or invalid."""


class ArgumentPolicyError(Exception):
    """Raised when argument-policy evaluation cannot be completed safely."""


@dataclass(frozen=True)
class ArgumentPolicyResult:
    """Outcome of evaluating one tool call against its argument constraints.

    Attributes:
        allowed: True when every configured constraint is satisfied.
        rule_id: Stable identifier of the constraint set that decided.
        constraint_category: The category that failed, or None when allowed.
        reason: Human-readable, value-free explanation of the decision.
        forwarding_prevented: True when the call must not be forwarded.
    """

    allowed: bool
    rule_id: str
    constraint_category: str | None
    reason: str
    forwarding_prevented: bool = True


class ArgumentConstraint(BaseModel):
    """Constraints on a single tool argument.

    Only checks relevant to the declared ``type`` are applied: numeric bounds
    apply to ``int``/``float`` values, length bounds to ``str`` values. A
    missing argument simply fails the ``required`` check (when declared);
    it is not type-checked.
    """

    model_config = ConfigDict(extra="forbid")

    required: bool = False
    type: Literal["bool", "int", "float", "str"] | None = None
    enum: list[Any] | None = None
    minimum: float | None = None
    maximum: float | None = None
    min_length: int | None = None
    max_length: int | None = None

    @field_validator("enum")
    @classmethod
    def _enum_must_be_list(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, list):
            raise ValueError("'enum' must be a list")
        return value

    @field_validator("minimum", "maximum")
    @classmethod
    def _bounds_must_be_numbers(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, (int, float)):
            raise ValueError("'minimum' and 'maximum' must be numbers")
        return value

    @field_validator("min_length", "max_length")
    @classmethod
    def _lengths_must_be_ints(cls, value: Any) -> Any:
        if value is not None and not isinstance(value, int):
            raise ValueError("'min_length' and 'max_length' must be integers")
        return value

    @model_validator(mode="after")
    def _bounds_and_lengths(self) -> ArgumentConstraint:
        if self.minimum is not None and self.maximum is not None:
            if self.minimum > self.maximum:
                raise ValueError("'minimum' must not exceed 'maximum'")
        if self.min_length is not None and self.max_length is not None:
            if self.min_length > self.max_length:
                raise ValueError("'min_length' must not exceed 'max_length'")
        return self


class ToolArgumentConstraints(BaseModel):
    """Constraints for one tool: per-argument rules plus unknown-arg mode."""

    model_config = ConfigDict(extra="forbid")

    arguments: dict[str, ArgumentConstraint] = Field(default_factory=dict)
    unknown_arguments: Literal["allow", "deny"] = "allow"

    @field_validator("arguments")
    @classmethod
    def _argument_names(cls, value: dict[str, ArgumentConstraint]) -> dict[str, ArgumentConstraint]:
        for name in value:
            if not isinstance(name, str) or not name:
                raise ValueError("argument names must be non-empty strings")
        return value


class ArgumentPolicyConfig(BaseModel):
    """Top-level argument-policy configuration: ``{"tools": {...}}``."""

    model_config = ConfigDict(extra="forbid")

    tools: dict[str, ToolArgumentConstraints] = Field(default_factory=dict)

    @field_validator("tools")
    @classmethod
    def _tool_names(
        cls, value: dict[str, ToolArgumentConstraints]
    ) -> dict[str, ToolArgumentConstraints]:
        for name in value:
            if not isinstance(name, str) or not name:
                raise ValueError("tool names must be non-empty strings")
        return value


@dataclass
class ArgumentPolicy:
    """Deterministic argument-policy engine for MCP tool calls.

    Evaluation is order-independent within a tool (arguments are visited in
    sorted order) and short-circuits on the first failure.
    """

    _tools: dict[str, ToolArgumentConstraints] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> ArgumentPolicy:
        """Build an engine from a raw configuration mapping."""
        try:
            parsed = ArgumentPolicyConfig.model_validate(config)
        except Exception as exc:  # pydantic ValidationError or ValueError
            raise ArgumentPolicyConfigError(str(exc)) from exc
        return cls(_tools=dict(parsed.tools))

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> ArgumentPolicyResult:
        """Evaluate one tool call against its configured argument constraints.

        Returns an allowance when the tool is unconfigured or every
        constraint is satisfied; returns a denial (fail-closed) on any
        violation or on non-mapping arguments.
        """
        rule_id = f"argument_constraints:{tool_name}"

        constraints = self._tools.get(tool_name)
        if constraints is None:
            return ArgumentPolicyResult(
                allowed=True,
                rule_id=rule_id,
                constraint_category=None,
                reason=f"no argument constraints configured for {tool_name}",
                forwarding_prevented=False,
            )

        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return ArgumentPolicyResult(
                allowed=False,
                rule_id=rule_id,
                constraint_category="type",
                reason="arguments must be a mapping",
                forwarding_prevented=True,
            )

        declared = set(constraints.arguments)
        supplied = set(arguments)

        if constraints.unknown_arguments == "deny":
            unknown = supplied - declared
            if unknown:
                return ArgumentPolicyResult(
                    allowed=False,
                    rule_id=rule_id,
                    constraint_category="unknown_argument",
                    reason="unknown arguments supplied",
                    forwarding_prevented=True,
                )

        for arg_name in sorted(supplied & declared):
            constraint = constraints.arguments[arg_name]
            failure = _check_constraint(constraint, arguments[arg_name])
            if failure is not None:
                category, reason = failure
                return ArgumentPolicyResult(
                    allowed=False,
                    rule_id=rule_id,
                    constraint_category=category,
                    reason=reason,
                    forwarding_prevented=True,
                )

        for arg_name in sorted(declared - supplied):
            if constraints.arguments[arg_name].required:
                return ArgumentPolicyResult(
                    allowed=False,
                    rule_id=rule_id,
                    constraint_category="required_argument",
                    reason=f"required argument {arg_name} is missing",
                    forwarding_prevented=True,
                )

        return ArgumentPolicyResult(
            allowed=True,
            rule_id=rule_id,
            constraint_category=None,
            reason="all argument constraints satisfied",
            forwarding_prevented=False,
        )


def _check_constraint(
    constraint: ArgumentConstraint,
    value: Any,
) -> tuple[str, str] | None:
    """Check one supplied argument against its constraint.

    Returns ``(category, reason)`` on failure, ``None`` on success. Reasons
    never embed raw argument values.
    """
    # ``bool`` is a subclass of ``int`` in Python: check booleans before
    # integers so that ``True`` is never mistaken for an integer. Since no
    # int is an instance of ``bool``, a plain ``isinstance`` check is exact.
    if constraint.type == "bool":
        if not isinstance(value, bool):
            return ("type", "argument is not a boolean")
    elif constraint.type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            return ("type", "argument is not an integer")
    elif constraint.type == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return ("type", "argument is not a number")
    elif constraint.type == "str":
        if not isinstance(value, str):
            return ("type", "argument is not a string")

    if constraint.enum is not None and value not in constraint.enum:
        return ("enum", "argument value is not in the allowed set")

    if constraint.type in ("int", "float") and not isinstance(value, bool):
        if constraint.minimum is not None and value < constraint.minimum:
            return ("minimum", "argument is below the minimum")
        if constraint.maximum is not None and value > constraint.maximum:
            return ("maximum", "argument exceeds the maximum")

    if isinstance(value, str):
        if constraint.min_length is not None and len(value) < constraint.min_length:
            return ("min_length", "argument is shorter than the minimum length")
        if constraint.max_length is not None and len(value) > constraint.max_length:
            return ("max_length", "argument exceeds the maximum length")

    return None