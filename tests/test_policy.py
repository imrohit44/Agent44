"""Tests for the Milestone 3 deterministic policy engine and enforcement.

Unit tests cover loading, validation, and precedence in ``agent44.policy``.
Integration tests drive a real MCP client through the proxy with ``--policy``
enabled and use an invocation-counting downstream server to prove that a
denied call never reaches the downstream tool.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from textwrap import dedent

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44.policy import Action, PolicyEngine, PolicyError, load_policy

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_server"]
COUNTER_SERVER = Path(__file__).resolve().parent / "counter_server.py"


def write_policy(tmp_path: Path, text: str, name: str = "policy.yaml") -> Path:
    """Write a dedented YAML policy to ``tmp_path`` and return its path."""
    path = tmp_path / name
    path.write_text(dedent(text).lstrip(), encoding="utf-8")
    return path


def engine_for(tmp_path: Path, text: str) -> PolicyEngine:
    """Build an engine from inline YAML, failing the test on a bad policy."""
    return PolicyEngine.from_path(write_policy(tmp_path, text))


def expect_policy_error(tmp_path: Path, text: str) -> PolicyError:
    """Assert that loading ``text`` as a policy raises PolicyError."""
    path = write_policy(tmp_path, text)
    try:
        load_policy(path)
    except PolicyError as exc:
        return exc
    raise AssertionError("expected PolicyError, but the policy loaded cleanly")


@asynccontextmanager
async def policy_session(
    policy_path: Path,
    *,
    observe_path: Path | None = None,
    downstream: list[str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Yield an initialized session connected through the enforcing proxy."""
    if downstream is None:
        downstream = [sys.executable, *DEMO_MODULE]
    args = [*PROXY_MODULE, "--policy", str(policy_path)]
    if observe_path is not None:
        args += ["--observe", str(observe_path)]
    args += ["--", *downstream]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


# --- Loading and validation -------------------------------------------------


def test_load_valid_policy_and_defaults(tmp_path: Path) -> None:
    policy = load_policy(
        write_policy(
            tmp_path,
            """
            version: "1"
            name: unit-policy
            default_deny: true
            allow_tools: [add, echo]
            deny_tools: [rm_rf]
            """,
        )
    )
    assert policy.name == "unit-policy"
    assert policy.version == "1"
    assert policy.default_deny is True
    assert policy.allow_tools == ["add", "echo"]
    assert policy.deny_tools == ["rm_rf"]
    assert policy.rules == []


def test_missing_policy_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: '1'\n  broken: [unterminated\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="YAML"):
        load_policy(path)


def test_non_mapping_root_raises(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(path)


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        allow_tools: [add]
        surprise: true
        """,
    )


def test_unsupported_version_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "99"
        allow_tools: [add]
        """,
    )


def test_unknown_action_raises(tmp_path: Path) -> None:
    exc = expect_policy_error(
        tmp_path,
        """
        version: "1"
        deny_tools: [add]
        rules:
          - id: bad-action
            tool: echo
            action: REVIEW
            reason: not a real action
            when: {field: message, equals: x}
        """,
    )
    assert "REVIEW" in str(exc)


def test_rule_missing_when_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: no-condition
            tool: echo
            action: DENY
            reason: missing its condition
        """,
    )


def test_rule_with_both_constraints_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: ambiguous
            tool: echo
            action: DENY
            reason: sets both conditions
            when:
              field: message
              equals: x
              field_exists: true
        """,
    )


def test_rule_with_neither_constraint_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: no-constraint
            tool: echo
            action: DENY
            reason: sets neither condition
            when:
              field: message
        """,
    )


def test_invalid_field_path_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: bad-path
            tool: echo
            action: DENY
            reason: malformed dotted path
            when:
              field: "a..b"
              equals: 1
        """,
    )


def test_conflicting_tool_lists_raise(tmp_path: Path) -> None:
    exc = expect_policy_error(
        tmp_path,
        """
        version: "1"
        allow_tools: [add, echo]
        deny_tools: [add]
        """,
    )
    assert "both allow_tools and deny_tools" in str(exc)


def test_duplicate_rule_ids_raise(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: same
            tool: echo
            action: DENY
            reason: first
            when: {field: a, equals: 1}
          - id: same
            tool: echo
            action: ALLOW
            reason: second
            when: {field: b, equals: 2}
        """,
    )


def test_duplicate_entries_in_tool_lists_raise(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        allow_tools: [add, add]
        """,
    )


def test_empty_rule_identity_raises(tmp_path: Path) -> None:
    expect_policy_error(
        tmp_path,
        """
        version: "1"
        rules:
          - id: "   "
            tool: echo
            action: DENY
            reason: blank id
            when: {field: a, equals: 1}
        """,
    )


# --- Precedence and matching -----------------------------------------------


def test_explicit_allow(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [add]
        """,
    )
    decision = engine.evaluate("add", {"a": 1, "b": 2})
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "allow_tools"


def test_explicit_deny(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: deny-list
        allow_tools: [add]
        deny_tools: [echo]
        """,
    )
    decision = engine.evaluate("echo", {"message": "hi"})
    assert decision.action is Action.DENY
    assert decision.rule_id == "deny_tools"
    assert decision.policy_id == "deny-list"


def test_default_deny(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [add]
        """,
    )
    decision = engine.evaluate("unknown_tool", {})
    assert decision.action is Action.DENY
    assert decision.rule_id == "default_deny"


def test_default_allow_when_disabled(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: false
        """,
    )
    decision = engine.evaluate("anything", {})
    assert decision.action is Action.ALLOW
    assert decision.rule_id == "default_allow"


def test_deny_rule_overrides_allow_list(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [echo]
        rules:
          - id: no-eval-flag
            tool: echo
            action: DENY
            reason: "argument 'eval' is not permitted"
            when:
              field: eval
              field_exists: true
        """,
    )
    decision = engine.evaluate("echo", {"eval": True})
    assert decision.action is Action.DENY
    assert decision.rule_id == "no-eval-flag"
    assert decision.reason == "argument 'eval' is not permitted"
    # Without the flagged argument the same tool is allowed.
    assert engine.evaluate("echo", {"message": "hi"}).action is Action.ALLOW


def test_deny_rule_applies_even_when_tool_not_allowed(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: false
        rules:
          - id: block-literal
            tool: echo
            action: DENY
            reason: "blocked literal value"
            when:
              field: message
              equals: "DROP TABLE users"
        """,
    )
    assert engine.evaluate("echo", {"message": "DROP TABLE users"}).action is Action.DENY
    assert engine.evaluate("echo", {"message": "hello"}).action is Action.ALLOW


def test_allow_rule_can_grant_when_default_deny(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        rules:
          - id: allow-nested
            tool: echo
            action: ALLOW
            reason: "specific shape permitted"
            when:
              field: auth.token
              field_exists: true
        """,
    )
    assert engine.evaluate("echo", {"auth": {"token": "x"}}).action is Action.ALLOW
    assert engine.evaluate("echo", {"message": "hi"}).action is Action.DENY


def test_deny_rule_beats_allow_rule_for_same_tool(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        rules:
          - id: allow-all-echo
            tool: echo
            action: ALLOW
            reason: broad allow
            when: {field: anything, field_exists: true}
          - id: deny-narrow
            tool: echo
            action: DENY
            reason: narrow deny
            when: {field: anything, equals: "boom"}
        """,
    )
    # Deny rules are evaluated before allow rules regardless of declaration
    # order, so the narrow deny wins.
    decision = engine.evaluate("echo", {"anything": "boom"})
    assert decision.action is Action.DENY
    assert decision.rule_id == "deny-narrow"
    assert engine.evaluate("echo", {"anything": "safe"}).action is Action.ALLOW


def test_equals_match_is_type_strict(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: false
        rules:
          - id: strict
            tool: echo
            action: DENY
            reason: strict scalar comparison
            when: {field: count, equals: 1}
        """,
    )
    assert engine.evaluate("echo", {"count": 1}).action is Action.DENY
    # 1 == 1.0 in Python and True == 1; the matcher must not accept those.
    assert engine.evaluate("echo", {"count": 1.0}).action is Action.ALLOW
    assert engine.evaluate("echo", {"count": True}).action is Action.ALLOW


def test_dotted_path_matches_nested_argument(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: false
        rules:
          - id: nested
            tool: echo
            action: DENY
            reason: nested credential
            when: {field: auth.token, field_exists: true}
        """,
    )
    assert engine.evaluate("echo", {"auth": {"token": "t"}}).action is Action.DENY
    assert engine.evaluate("echo", {"auth": {}}).action is Action.ALLOW
    assert engine.evaluate("echo", {"auth": "not-a-dict"}).action is Action.ALLOW


def test_evaluator_tolerates_missing_arguments(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [add]
        """,
    )
    assert engine.evaluate("add", None).action is Action.ALLOW
    assert engine.evaluate("add", {}).action is Action.ALLOW


# --- Enforcement through the proxy -----------------------------------------


@pytest.mark.asyncio
async def test_denied_call_never_reaches_downstream(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: counter-deny
        default_deny: true
        deny_tools: [hit]
        """,
    )
    downstream = [sys.executable, str(COUNTER_SERVER), str(counter)]
    async with policy_session(policy, downstream=downstream) as session:
        result = await session.call_tool("hit", {"label": "should-not-run"})
        assert result.isError is True
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts and "denied by policy" in texts[0]

    # The counting server never executed: no file was ever created.
    assert not counter.exists()


@pytest.mark.asyncio
async def test_allowed_call_reaches_downstream(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: counter-allow
        default_deny: true
        allow_tools: [hit]
        """,
    )
    downstream = [sys.executable, str(COUNTER_SERVER), str(counter)]
    async with policy_session(policy, downstream=downstream) as session:
        result = await session.call_tool("hit", {"label": "ran"})
        assert result.isError is False
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts == ["recorded"]

    assert counter.read_text(encoding="utf-8").splitlines() == ["ran"]


@pytest.mark.asyncio
async def test_allowed_call_preserves_result_shape(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [add]
        """,
    )
    async with policy_session(policy) as session:
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert result.isError is False
        assert [c.text for c in result.content if c.type == "text"] == ["5"]
        assert result.structuredContent == {"result": 5}


@pytest.mark.asyncio
async def test_arg_level_deny_blocks_before_downstream(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: arg-deny
        default_deny: true
        allow_tools: [echo]
        rules:
          - id: deny-eval-flag
            tool: echo
            action: DENY
            reason: "argument 'eval' is not permitted"
            when: {field: eval, field_exists: true}
        """,
    )
    async with policy_session(policy) as session:
        denied = await session.call_tool("echo", {"message": "hi", "eval": True})
        assert denied.isError is True
        texts = [c.text for c in denied.content if c.type == "text"]
        assert texts and "deny-eval-flag" in texts[0]
        assert "not permitted" in texts[0]

        allowed = await session.call_tool("echo", {"message": "hi"})
        assert allowed.isError is False
        assert [c.text for c in allowed.content if c.type == "text"] == ["hi"]


@pytest.mark.asyncio
async def test_denied_call_is_a_tool_error_not_protocol_error(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        default_deny: true
        deny_tools: [rm_rf]
        """,
    )
    async with policy_session(policy) as session:
        # Must return a CallToolResult with isError, not raise McpError.
        result = await session.call_tool("rm_rf", {"path": "/"})
        assert result.isError is True
        assert all(c.type == "text" for c in result.content)


# --- Policy decisions in observations --------------------------------------


@pytest.mark.asyncio
async def test_observation_records_policy_reason(tmp_path: Path) -> None:
    from agent44.observe import JsonlObserver

    observe_path = tmp_path / "obs.jsonl"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: observed-policy
        default_deny: true
        allow_tools: [add, echo]
        deny_tools: [rm_rf]
        """,
    )
    async with policy_session(policy, observe_path=observe_path) as session:
        await session.call_tool("add", {"a": 1, "b": 2})
        await session.call_tool("rm_rf", {"path": "/"})

    events = JsonlObserver(observe_path).read_events()
    by_tool = {e["tool_name"]: e for e in events}
    allowed = by_tool["add"]
    denied = by_tool["rm_rf"]

    assert allowed["policy_action"] == "ALLOW"
    assert allowed["policy_rule_id"] == "allow_tools"
    assert allowed["outcome"] == "success"

    assert denied["policy_action"] == "DENY"
    assert denied["policy_rule_id"] == "deny_tools"
    assert denied["policy_reason"]
    assert denied["outcome"] == "denied"
    assert denied["is_error"] is True


@pytest.mark.asyncio
async def test_denial_message_and_jsonl_leak_no_argument_values(tmp_path: Path) -> None:
    from agent44.observe import JsonlObserver

    observe_path = tmp_path / "obs.jsonl"
    secret = "sk-live-DO-NOT-LEAK"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [echo]
        rules:
          - id: deny-api-key
            tool: echo
            action: DENY
            reason: "sensitive argument is not permitted"
            when: {field: api_key, field_exists: true}
        """,
    )
    async with policy_session(policy, observe_path=observe_path) as session:
        result = await session.call_tool(
            "echo", {"message": secret, "api_key": secret}
        )
        assert result.isError is True
        denial_text = "".join(c.text for c in result.content if c.type == "text")
        # The denial reason is static policy text, never an argument value.
        assert secret not in denial_text

    payload = Path(observe_path).read_text(encoding="utf-8")
    assert secret not in payload
    events = JsonlObserver(observe_path).read_events()
    assert events[-1]["policy_action"] == "DENY"
    assert events[-1]["safe_arguments"]["api_key"] == {"redacted": True}


@pytest.mark.asyncio
async def test_observer_failure_does_not_change_call_outcome(tmp_path: Path) -> None:
    # Pre-create the observe path as a *directory*: startup succeeds, but every
    # attempt to append an event fails. Observation must swallow that failure.
    bad_observe = tmp_path / "obs-as-directory"
    bad_observe.mkdir()
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        default_deny: true
        allow_tools: [add]
        deny_tools: [rm_rf]
        """,
    )
    async with policy_session(policy, observe_path=bad_observe) as session:
        # An allowed call still succeeds despite the observer failing.
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert result.isError is False
        assert [c.text for c in result.content if c.type == "text"] == ["5"]
        # Enforcement still applies despite the observer failing.
        denied = await session.call_tool("rm_rf", {"path": "/"})
        assert denied.isError is True
        assert bad_observe.is_dir()


@pytest.mark.asyncio
async def test_observation_only_mode_never_labels_a_policy_block(tmp_path: Path) -> None:
    from agent44.observe import JsonlObserver

    observe_path = tmp_path / "obs.jsonl"
    # No --policy: the proxy must stay in observation-only mode and record
    # nothing that could be read as a policy decision.
    args = [*PROXY_MODULE, "--observe", str(observe_path), "--", sys.executable, *DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("add", {"a": 1, "b": 2})
            # Unknown tool -> downstream tool-level error, still not a block.
            await session.call_tool("rm_rf", {"path": "/"})

    events = JsonlObserver(observe_path).read_events()
    assert len(events) == 2
    for event in events:
        assert event["policy_action"] is None
        assert event["policy_rule_id"] is None
        assert event["policy_reason"] is None
        assert event["outcome"] != "denied"
    # The unknown tool errored downstream, but that is an error, not a denial.
    errored = [e for e in events if e["tool_name"] == "rm_rf"][0]
    assert errored["outcome"] == "error"


def test_invalid_policy_fails_startup(tmp_path: Path) -> None:
    policy = tmp_path / "broken.yaml"
    policy.write_text(
        'version: "1"\nallow_tools: [add]\nsurprise: true\n', encoding="utf-8"
    )
    proc = subprocess.run(
        [sys.executable, *PROXY_MODULE, "--policy", str(policy), "--",
         sys.executable, *DEMO_MODULE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert "policy error" in proc.stderr
    # Enforcement must not silently start with a bad policy.
    assert "surprise" in proc.stderr


def test_missing_policy_fails_startup(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, *PROXY_MODULE, "--policy", str(tmp_path / "nope.yaml"), "--",
         sys.executable, *DEMO_MODULE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert "policy error" in proc.stderr


# --- Argument constraints -----------------------------------------------------


def test_argument_constraints_load_from_yaml(tmp_path: Path) -> None:
    load_policy(
        write_policy(
            tmp_path,
            """
            version: "1"
            name: arg-constraints
            default_deny: true
            allow_tools: [hit]
            argument_constraints:
              hit:
                unknown_arguments: deny
                arguments:
                  label:
                    type: str
                    max_length: 5
            """,
        )
    )
    engine = engine_for(tmp_path, """
        version: "1"
        name: arg-constraints
        default_deny: true
        allow_tools: [hit]
        argument_constraints:
          hit:
            unknown_arguments: deny
            arguments:
              label:
                type: str
                max_length: 5
        """)
    allowed = engine.evaluate("hit", {"label": "hi"})
    assert allowed.action is Action.ALLOW
    assert allowed.rule_id == "allow_tools"

    denied = engine.evaluate("hit", {"label": "way-too-long-label"})
    assert denied.action is Action.DENY
    assert denied.rule_id == "argument_constraints:hit"
    assert "way-too-long-label" not in denied.reason

    missing = engine.evaluate("hit", {})
    assert missing.action is Action.ALLOW  # constraints satisfied, tool allowed
    assert missing.rule_id == "allow_tools"


def test_argument_constraint_required_argument(tmp_path: Path) -> None:
    policy = engine_for(
        tmp_path,
        """
        version: "1"
        name: required-arg
        default_deny: true
        allow_tools: [hit]
        argument_constraints:
          hit:
            arguments:
              label:
                required: true
                type: str
        """,
    )
    assert policy.evaluate("hit", {"label": "hi"}).action is Action.ALLOW
    denied = policy.evaluate("hit", {})
    assert denied.action is Action.DENY
    assert denied.rule_id == "argument_constraints:hit"
    assert "label" in denied.reason


@pytest.mark.asyncio
async def test_argument_constraint_denial_blocks_before_downstream(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: constraint-block
        default_deny: true
        allow_tools: [hit]
        argument_constraints:
          hit:
            unknown_arguments: deny
            arguments:
              label:
                type: str
                max_length: 5
        """,
    )
    async with policy_session(
        policy, downstream=[sys.executable, str(COUNTER_SERVER), str(counter)]
    ) as session:
        ok = await session.call_tool("hit", {"label": "hi"})
        assert ok.isError is False
        assert [c.text for c in ok.content if c.type == "text"] == ["recorded"]
        assert counter.read_text(encoding="utf-8") == "hi\n"

        denied = await session.call_tool("hit", {"label": "way-too-long-label"})
        assert denied.isError is True
        # The oversized call never reached the downstream tool.
        assert counter.read_text(encoding="utf-8") == "hi\n"

        texts = [c.text for c in denied.content if c.type == "text"]
        assert texts and "argument_constraints:hit" in texts[0]
        assert "way-too-long-label" not in texts[0]


@pytest.mark.asyncio
async def test_argument_constraint_unknown_argument_blocked(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: unknown-arg-block
        default_deny: true
        allow_tools: [hit]
        argument_constraints:
          hit:
            unknown_arguments: deny
            arguments:
              label:
                type: str
        """,
    )
    async with policy_session(
        policy, downstream=[sys.executable, str(COUNTER_SERVER), str(counter)]
    ) as session:
        declared = await session.call_tool("hit", {"label": "hi"})
        assert declared.isError is False
        extra = await session.call_tool("hit", {"label": "hi", "secret": "x"})
        assert extra.isError is True
        assert counter.read_text(encoding="utf-8") == "hi\n"


def test_invalid_argument_constraints_fail_startup(tmp_path: Path) -> None:
    policy = tmp_path / "broken.yaml"
    policy.write_text(
        "version: \"1\"\nallow_tools: [hit]\n"
        "argument_constraints:\n  hit:\n    unknown_arguments: maybe\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, *PROXY_MODULE, "--policy", str(policy), "--",
         sys.executable, *DEMO_MODULE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    assert "policy error" in proc.stderr


@pytest.mark.asyncio
async def test_observation_records_argument_constraint_denial(tmp_path: Path) -> None:
    from agent44.observe import JsonlObserver

    observe_path = tmp_path / "obs.jsonl"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: observed-constraints
        default_deny: true
        allow_tools: [hit]
        argument_constraints:
          hit:
            arguments:
              label:
                type: str
                max_length: 3
        """,
    )
    counter = tmp_path / "counter.log"
    async with policy_session(
        policy,
        observe_path=observe_path,
        downstream=[sys.executable, str(COUNTER_SERVER), str(counter)],
    ) as session:
        await session.call_tool("hit", {"label": "hi"})
        denied = await session.call_tool("hit", {"label": "way too long"})
        assert denied.isError is True

    events = JsonlObserver(observe_path).read_events()
    assert len(events) == 2
    allowed, blocked = events[0], events[1]
    assert allowed["tool_name"] == "hit"
    assert allowed["policy_action"] == "ALLOW"
    assert allowed["outcome"] == "success"
    assert blocked["policy_action"] == "DENY"
    assert blocked["policy_rule_id"] == "argument_constraints:hit"
    assert blocked["policy_reason"]
    assert blocked["outcome"] == "denied"
    assert blocked["is_error"] is True




