"""Unit tests for the deterministic argument-schema policy engine.

Covers ``agent44.argument_policy``: constraint parsing, evaluation
precedence, fail-closed behaviour, and the guarantee that denial reasons
never embed raw argument values.
"""

from __future__ import annotations

import pytest

from agent44.argument_policy import (
    ArgumentPolicy,
    ArgumentPolicyConfigError,
    ArgumentPolicyResult,
)


def policy_with(**tools: object) -> ArgumentPolicy:
    """Build an engine from a ``{"tools": {...}}`` mapping."""
    return ArgumentPolicy.from_config({"tools": dict(tools)})


# --- Loading and validation -------------------------------------------------


def test_valid_minimal_config_loads() -> None:
    policy = policy_with(echo={"arguments": {"message": {"type": "str"}}})
    result = policy.evaluate("echo", {"message": "hello"})
    assert isinstance(result, ArgumentPolicyResult)
    assert result.allowed is True


def test_unconfigured_tool_passes_through() -> None:
    policy = policy_with(echo={"arguments": {"message": {"type": "str"}}})
    result = policy.evaluate("undeclared_tool", {"anything": 1})
    assert result.allowed is True
    assert result.forwarding_prevented is False
    assert result.constraint_category is None
    assert result.rule_id == "argument_constraints:undeclared_tool"


def test_empty_config_constrains_nothing() -> None:
    policy = ArgumentPolicy.from_config({"tools": {}})
    result = policy.evaluate("any_tool", {"any": "args"})
    assert result.allowed is True
    assert result.forwarding_prevented is False


# --- Type checking ----------------------------------------------------------


def test_bool_type_accepts_only_booleans() -> None:
    policy = policy_with(flag={"arguments": {"flag": {"type": "bool"}}})
    assert policy.evaluate("flag", {"flag": True}).allowed is True
    assert policy.evaluate("flag", {"flag": False}).allowed is True
    assert policy.evaluate("flag", {"flag": 1}).allowed is False
    assert policy.evaluate("flag", {"flag": 0}).allowed is False
    assert policy.evaluate("flag", {"flag": "true"}).allowed is False
    for result in (
        policy.evaluate("flag", {"flag": 1}),
        policy.evaluate("flag", {"flag": "true"}),
    ):
        assert result.constraint_category == "type"


def test_int_type_rejects_booleans() -> None:
    policy = policy_with(count={"arguments": {"count": {"type": "int"}}})
    assert policy.evaluate("count", {"count": 7}).allowed is True
    assert policy.evaluate("count", {"count": 0}).allowed is True
    assert policy.evaluate("count", {"count": True}).allowed is False
    assert policy.evaluate("count", {"count": 2.5}).allowed is False
    assert policy.evaluate("count", {"count": "7"}).allowed is False


def test_float_type_accepts_numbers_rejects_booleans() -> None:
    policy = policy_with(rate={"arguments": {"rate": {"type": "float"}}})
    assert policy.evaluate("rate", {"rate": 1.5}).allowed is True
    assert policy.evaluate("rate", {"rate": 2}).allowed is True  # int is a number
    assert policy.evaluate("rate", {"rate": True}).allowed is False
    assert policy.evaluate("rate", {"rate": "fast"}).allowed is False


def test_str_type_accepts_only_strings() -> None:
    policy = policy_with(msg={"arguments": {"msg": {"type": "str"}}})
    assert policy.evaluate("msg", {"msg": "x"}).allowed is True
    assert policy.evaluate("msg", {"msg": 5}).allowed is False
    assert policy.evaluate("msg", {"msg": None}).allowed is False


# --- Enumerations -----------------------------------------------------------


def test_enum_allows_declared_values_only() -> None:
    policy = policy_with(op={"arguments": {"op": {"enum": ["read", "write"]}}})
    assert policy.evaluate("op", {"op": "read"}).allowed is True
    assert policy.evaluate("op", {"op": "write"}).allowed is True
    result = policy.evaluate("op", {"op": "delete"})
    assert result.allowed is False
    assert result.constraint_category == "enum"
    assert "delete" not in result.reason  # raw values never leak


# --- Numeric bounds ---------------------------------------------------------


def test_minimum_and_maximum_are_inclusive() -> None:
    policy = policy_with(
        level={"arguments": {"level": {"type": "int", "minimum": 1, "maximum": 10}}}
    )
    assert policy.evaluate("level", {"level": 1}).allowed is True
    assert policy.evaluate("level", {"level": 10}).allowed is True
    assert policy.evaluate("level", {"level": 5}).allowed is True

    below = policy.evaluate("level", {"level": 0})
    assert below.allowed is False and below.constraint_category == "minimum"

    above = policy.evaluate("level", {"level": 11})
    assert above.allowed is False and above.constraint_category == "maximum"


def test_bounds_apply_to_float_too() -> None:
    policy = policy_with(
        pct={"arguments": {"pct": {"type": "float", "minimum": 0.0, "maximum": 1.0}}}
    )
    assert policy.evaluate("pct", {"pct": 0.5}).allowed is True
    assert policy.evaluate("pct", {"pct": -0.1}).allowed is False
    assert policy.evaluate("pct", {"pct": 1.0001}).allowed is False


# --- String lengths ---------------------------------------------------------


def test_min_length_and_max_length() -> None:
    policy = policy_with(
        name={"arguments": {"name": {"type": "str", "min_length": 2, "max_length": 5}}}
    )
    assert policy.evaluate("name", {"name": "ab"}).allowed is True
    assert policy.evaluate("name", {"name": "abcde"}).allowed is True
    assert policy.evaluate("name", {"name": "a"}).allowed is False
    assert policy.evaluate("name", {"name": "abcdef"}).allowed is False
    short = policy.evaluate("name", {"name": "a"})
    assert short.constraint_category == "min_length"
    long = policy.evaluate("name", {"name": "abcdef"})
    assert long.constraint_category == "max_length"


# --- Required arguments -----------------------------------------------------


def test_required_argument_must_be_present() -> None:
    policy = policy_with(
        create={"arguments": {"key": {"required": True, "type": "str"}}}
    )
    assert policy.evaluate("create", {"key": "k"}).allowed is True
    result = policy.evaluate("create", {})
    assert result.allowed is False
    assert result.constraint_category == "required_argument"
    assert result.reason == "required argument key is missing"


def test_optional_argument_may_be_missing() -> None:
    policy = policy_with(
        create={"arguments": {"key": {"required": False, "type": "str"}}}
    )
    assert policy.evaluate("create", {}).allowed is True
    assert policy.evaluate("create", {"key": "k"}).allowed is True


# --- Unknown arguments -------------------------------------------------------


def test_unknown_arguments_deny_rejects_undeclared_keys() -> None:
    policy = policy_with(
        echo={
            "arguments": {"message": {"type": "str"}},
            "unknown_arguments": "deny",
        }
    )
    assert policy.evaluate("echo", {"message": "hi"}).allowed is True
    result = policy.evaluate("echo", {"message": "hi", "secret": "x"})
    assert result.allowed is False
    assert result.constraint_category == "unknown_argument"
    assert "secret" not in result.reason  # raw names are static too


def test_unknown_arguments_allow_passes_undeclared_keys() -> None:
    policy = policy_with(
        echo={
            "arguments": {"message": {"type": "str"}},
            "unknown_arguments": "allow",
        }
    )
    assert policy.evaluate("echo", {"message": "hi", "extra": 1}).allowed is True


def test_unknown_arguments_defaults_to_allow() -> None:
    policy = policy_with(echo={"arguments": {"message": {"type": "str"}}})
    assert policy.evaluate("echo", {"message": "hi", "extra": 1}).allowed is True


# --- Combination and determinism --------------------------------------------


def test_first_failure_wins_in_sorted_argument_order() -> None:
    policy = policy_with(
        echo={
            "arguments": {
                "zebra": {"type": "int"},
                "alpha": {"type": "str"},
            }
        }
    )
    # Both violate: ``alpha`` sorts first, so its failure is reported.
    result = policy.evaluate("echo", {"zebra": True, "alpha": 1})
    assert result.allowed is False
    assert result.reason == "argument is not a string"


def test_all_constraints_satisfied_returns_allow() -> None:
    policy = policy_with(
        add={
            "arguments": {
                "a": {"type": "int", "minimum": 0},
                "b": {"type": "int", "maximum": 100},
                "label": {"type": "str", "min_length": 1},
            },
            "unknown_arguments": "deny",
        }
    )
    result = policy.evaluate("add", {"a": 1, "b": 2, "label": "x"})
    assert result.allowed is True
    assert result.forwarding_prevented is False


# --- Malformed inputs -------------------------------------------------------


def test_non_mapping_arguments_are_denied() -> None:
    policy = policy_with(echo={"arguments": {"message": {"type": "str"}}})
    for bad in ("string", 5, ["a"], 3.14):
        result = policy.evaluate("echo", bad)  # type: ignore[arg-type]
        assert result.allowed is False
        assert result.constraint_category == "type"
        assert result.forwarding_prevented is True


def test_none_arguments_treated_as_empty() -> None:
    policy = policy_with(echo={"arguments": {"message": {"type": "str"}}})
    # No required arguments: nothing to violate.
    assert policy.evaluate("echo", None).allowed is True

    required = policy_with(
        echo={"arguments": {"message": {"required": True, "type": "str"}}}
    )
    result = required.evaluate("echo", None)
    assert result.allowed is False
    assert result.constraint_category == "required_argument"


def test_reason_leaks_no_argument_values() -> None:
    secret = "sk-live-DO-NOT-LEAK"
    policy = policy_with(
        echo={
            "arguments": {"message": {"type": "str", "max_length": 3}},
            "unknown_arguments": "deny",
        }
    )
    result = policy.evaluate("echo", {"message": secret, "token": secret})
    assert result.allowed is False
    assert secret not in result.reason
    assert "token" not in result.reason


# --- Config validation ------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"tools": {"t": {"arguments": {"x": {"type": "bogus"}}}}},
        {"tools": {"t": {"arguments": {"x": {"minimum": 5, "maximum": 1}}}}},
        {"tools": {"t": {"arguments": {"x": {"min_length": 5, "max_length": 1}}}}},
        {"tools": {"t": {"unknown_arguments": "maybe"}}},
        {"tools": {"t": {"arguments": {"x": {"enum": "not-a-list"}}}}},
        {"tools": {"t": {"arguments": {"x": {"minimum": "five"}}}}},
        {"tools": {"t": {"arguments": {"x": {"min_length": 1.5}}}}},
        {"tools": {"": {}}},
        {"tools": {"t": {"arguments": {"" : {}}}}},
        {"tools": {"t": {"surprise_key": True}}},
        {"tools": {"t": {"arguments": {"x": {"type": "int", "surprise": 1}}}}},
        "not-a-mapping",
        {"tools": "not-a-mapping"},
    ],
)
def test_malformed_config_raises(bad: object) -> None:
    with pytest.raises(ArgumentPolicyConfigError):
        ArgumentPolicy.from_config(bad)  # type: ignore[arg-type]


def test_config_error_message_is_text() -> None:
    try:
        ArgumentPolicy.from_config(
            {"tools": {"t": {"arguments": {"x": {"type": "nope"}}}}}
        )
    except ArgumentPolicyConfigError as exc:
        assert isinstance(str(exc), str) and str(exc)
    else:  # pragma: no cover - the raise above is expected
        raise AssertionError("expected ArgumentPolicyConfigError")