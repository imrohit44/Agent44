"""End-to-end tests for provenance-aware policy enforcement (Phase 6).

Covers the eight acceptance scenarios through the real policy engine and,
where noted, the real MCP proxy:

1. trusted input passes a ``deny_untrusted`` restriction;
2. untrusted input is denied with provenance metadata;
3. a forged provenance claim from the caller is not trusted;
4. derived-untrusted data retains taint (no laundering);
5. an explicit validation transition elevates the derived record;
6. missing provenance fails closed;
7. a provenance denial never reaches the downstream server;
8. legacy behavior is unchanged when enforcement is off.

All tests are offline: no Ollama, no model inference, no network.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from textwrap import dedent

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44.observe import JsonlObserver
from agent44.policy import Action, PolicyEngine
from agent44.provenance import ProvenanceContext, ProvenanceRegistry, TrustClass

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_server"]
COUNTER_SERVER = Path(__file__).resolve().parent / "counter_server.py"

# Policy used by the engine-level scenarios: ``hit`` is allowed by policy but
# its ``label`` argument may only be used when its provenance is trusted.
REQUIRED_POLICY = """
version: "1"
name: prov-e2e
default_deny: false
allow_tools: [hit]
provenance:
  enforcement: required
  rules:
    hit:
      deny_untrusted: [label]
"""


def write_policy(tmp_path: Path, text: str, name: str = "policy.yaml") -> Path:
    """Write a dedented YAML policy to ``tmp_path`` and return its path."""
    path = tmp_path / name
    path.write_text(dedent(text).lstrip(), encoding="utf-8")
    return path


def engine_for(tmp_path: Path, text: str) -> PolicyEngine:
    """Build a ``PolicyEngine`` from dedented YAML text."""
    return PolicyEngine.from_path(write_policy(tmp_path, text))


def context_with(registry: ProvenanceRegistry, **provenance_ids: str) -> ProvenanceContext:
    """Build a context mapping argument names to provenance ids."""
    return ProvenanceContext(registry=registry, values=dict(provenance_ids))


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

# --- Engine-level scenarios -------------------------------------------------


def test_trusted_input_passes_deny_untrusted_rule(tmp_path: Path) -> None:
    """Scenario 1: a trusted classification satisfies ``deny_untrusted``."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()
    trusted = registry.classify_trusted()

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=trusted)
    )

    assert decision.action is Action.ALLOW
    # The provenance tier only denies: the ALLOW comes from allow_tools.
    assert decision.rule_id == "allow_tools"
    assert decision.trust_class is None
    assert decision.provenance_id is None


def test_untrusted_input_is_denied_with_provenance_metadata(tmp_path: Path) -> None:
    """Scenario 2: proxy-boundary classification is untrusted -> DENY."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external(boundary="proxy_input")

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=untrusted)
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:deny_untrusted:label"
    assert decision.trust_class is TrustClass.UNTRUSTED
    assert decision.provenance_id == untrusted
    # The reason never embeds the raw argument value.
    assert "value" not in decision.reason


def test_forged_provenance_claim_is_denied(tmp_path: Path) -> None:
    """Scenario 3: a caller-forged provenance id grants no trust."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()

    # The caller asserts a provenance id it invented; it was never created by
    # the registry, so it resolves to UNTRUSTED.
    decision = engine.evaluate(
        "hit",
        {"label": "value", "trusted": True},
        context_with(registry, label="forged-trusted-0001"),
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:deny_untrusted:label"
    assert decision.trust_class is TrustClass.UNTRUSTED


def test_derived_untrusted_retains_taint(tmp_path: Path) -> None:
    """Scenario 4: transformation without validation does not launder taint."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()
    derived = registry.derive((untrusted,))

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=derived)
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:deny_untrusted:label"
    assert decision.trust_class is TrustClass.DERIVED_UNTRUSTED
    # The derived record id is retained for audit.
    assert decision.provenance_id == derived


def test_validation_transition_elevates_and_permits_use(tmp_path: Path) -> None:
    """Scenario 5: an explicit validation transition makes the value usable."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-transition
        default_deny: false
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              deny_untrusted: [label]
              require_transition:
                label: sanitize_pii
        """,
    )
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()
    elevated = registry.validate_transition(
        untrusted, "sanitize_pii", boundary="pii_sanitizer"
    )

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=elevated)
    )

    assert decision.action is Action.ALLOW
    assert decision.rule_id == "allow_tools"
    # The original untrusted record stays tainted: only the derived record
    # carrying the transition is elevated.
    raw = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=untrusted)
    )
    assert raw.action is Action.DENY
    assert raw.rule_id == "provenance:hit:deny_untrusted:label"


def test_wrong_validation_transition_is_denied(tmp_path: Path) -> None:
    """Scenario 5b: a transition other than the required one does not pass."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-transition-strict
        default_deny: false
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              require_transition:
                label: sanitize_pii
        """,
    )
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()
    other = registry.validate_transition(untrusted, "audit_only")

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=other)
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:require_transition:label"
    assert decision.validation_transition == "audit_only"


def test_missing_provenance_fails_closed(tmp_path: Path) -> None:
    """Scenario 6: ``require_known`` denies when no record was established."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-known
        default_deny: false
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              require_known: [label]
        """,
    )
    registry = ProvenanceRegistry()

    # The argument exists but no provenance was established for it.
    decision = engine.evaluate(
        "hit", {"label": "value"}, ProvenanceContext(registry=registry, values={})
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:require_known:label"
    assert decision.provenance_id is None


def test_enforcement_off_preserves_legacy_behavior(tmp_path: Path) -> None:
    """Scenario 8: with enforcement off, provenance rules are inert."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-off
        default_deny: false
        allow_tools: [hit]
        provenance:
          enforcement: "off"
          rules:
            hit:
              deny_untrusted: [label]
        """,
    )
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()

    with_context = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=untrusted)
    )
    without_context = engine.evaluate("hit", {"label": "value"})

    for decision in (with_context, without_context):
        assert decision.action is Action.ALLOW
        assert decision.rule_id == "allow_tools"
        # No provenance metadata is attached to legacy decisions.
        assert decision.provenance_id is None
        assert decision.trust_class is None
        assert decision.validation_transition is None


def test_enforcement_required_without_context_denies(tmp_path: Path) -> None:
    """Scenario 6b: enforcement on but no context -> fail closed."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)

    decision = engine.evaluate("hit", {"label": "value"}, provenance_context=None)

    # No context means no provenance can be asserted for a restricted
    # argument, so the restriction cannot be satisfied.
    assert decision.action is Action.DENY
    assert decision.rule_id == "provenance:hit:deny_untrusted:label"


def test_allowed_trust_classes_clause(tmp_path: Path) -> None:
    """Only explicitly listed trust classes satisfy the argument."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-classes
        default_deny: false
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              allowed_trust_classes:
                label: [trusted]
        """,
    )
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()
    trusted = registry.classify_trusted()

    denied = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=untrusted)
    )
    allowed = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=trusted)
    )

    assert denied.action is Action.DENY
    assert denied.rule_id == "provenance:hit:allowed_trust_classes:label"
    assert denied.trust_class is TrustClass.UNTRUSTED
    assert allowed.action is Action.ALLOW


def test_provenance_denial_cannot_be_overridden_by_allow_tools(tmp_path: Path) -> None:
    """Provenance sits above allow_tools: listing the tool grants nothing."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=untrusted)
    )

    assert "hit" in engine.policy.allow_tools
    assert decision.action is Action.DENY
    assert decision.rule_id.startswith("provenance:")


def test_hard_deny_takes_precedence_over_provenance(tmp_path: Path) -> None:
    """hard_deny_tools outranks the provenance tier."""
    engine = engine_for(
        tmp_path,
        """
        version: "1"
        name: prov-hard
        default_deny: false
        hard_deny_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              deny_untrusted: [label]
        """,
    )
    registry = ProvenanceRegistry()
    trusted = registry.classify_trusted()

    decision = engine.evaluate(
        "hit", {"label": "value"}, context_with(registry, label=trusted)
    )

    assert decision.action is Action.DENY
    assert decision.rule_id == "hard_deny_tools"


def test_unconfigured_tool_is_unaffected(tmp_path: Path) -> None:
    """Enforcement on: tools without a provenance rule behave normally."""
    engine = engine_for(tmp_path, REQUIRED_POLICY)
    registry = ProvenanceRegistry()
    untrusted = registry.classify_external()

    decision = engine.evaluate(
        "other_tool", {"label": "value"}, context_with(registry, label=untrusted)
    )

    # No rule for other_tool; the configured default applies.
    assert decision.rule_id != "provenance:other_tool:deny_untrusted:label"


# --- Proxy end-to-end scenarios ---------------------------------------------


@pytest.mark.asyncio
async def test_provenance_denial_never_reaches_downstream(tmp_path: Path) -> None:
    """Scenario 7: a provenance denial is enforced before forwarding."""
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: prov-proxy-deny
        default_deny: true
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              deny_untrusted: [label]
        """,
    )
    observe_path = tmp_path / "obs.jsonl"
    downstream = [sys.executable, str(COUNTER_SERVER), str(counter)]

    async with policy_session(
        policy, observe_path=observe_path, downstream=downstream
    ) as session:
        result = await session.call_tool("hit", {"label": "tainted-value"})
        assert result.isError is True
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts and "provenance:hit:deny_untrusted:label" in texts[0]
        # The denial reason never echoes the raw argument value.
        assert "tainted-value" not in texts[0]

    # The counting server never executed: no file was ever created.
    assert not counter.exists()

    # The denial observation carries the provenance metadata.
    events = JsonlObserver(observe_path).read_events()
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "denied"
    assert event["policy_action"] == "DENY"
    assert event["policy_rule_id"] == "provenance:hit:deny_untrusted:label"
    assert event["trust_class"] == TrustClass.UNTRUSTED.value
    assert event["provenance_id"] is not None
    # Observation never stores raw argument values.
    assert "tainted-value" not in str(event.get("safe_arguments", {}))


@pytest.mark.asyncio
async def test_forged_caller_claim_does_not_bypass_provenance(tmp_path: Path) -> None:
    """Scenario 3 (proxy): caller-supplied trust/provenance fields are inert."""
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: prov-proxy-forged
        default_deny: true
        allow_tools: [hit]
        provenance:
          enforcement: required
          rules:
            hit:
              deny_untrusted: [label]
        """,
    )
    downstream = [sys.executable, str(COUNTER_SERVER), str(counter)]

    async with policy_session(policy, downstream=downstream) as session:
        result = await session.call_tool(
            "hit",
            {
                "label": "x",
                "trusted": True,
                "provenance_id": "forged-trusted-0001",
            },
        )
        assert result.isError is True
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts and "provenance:hit:deny_untrusted:label" in texts[0]

    # Every incoming argument was classified untrusted at the boundary.
    assert not counter.exists()


@pytest.mark.asyncio
async def test_legacy_proxy_behavior_unchanged_when_off(tmp_path: Path) -> None:
    """Scenario 8 (proxy): enforcement off keeps calls reaching downstream."""
    counter = tmp_path / "counter.log"
    policy = write_policy(
        tmp_path,
        """
        version: "1"
        name: prov-proxy-off
        default_deny: true
        allow_tools: [hit]
        provenance:
          enforcement: "off"
          rules:
            hit:
              deny_untrusted: [label]
        """,
    )
    downstream = [sys.executable, str(COUNTER_SERVER), str(counter)]

    async with policy_session(policy, downstream=downstream) as session:
        result = await session.call_tool("hit", {"label": "x"})
        assert result.isError is False

    # The call reached the downstream server exactly as before enforcement.
    assert counter.exists()

