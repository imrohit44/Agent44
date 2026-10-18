"""Agent44 — transparent MCP stdio proxy (Milestone 1).

Agent44 runs as an MCP *server* on stdio for an upstream client, while acting
as an MCP *client* toward a downstream MCP server that it spawns as a
subprocess. Tool discovery and tool calls are forwarded with their original
names, arguments, and result semantics preserved.

All diagnostics go to stderr. stdout is reserved exclusively for the MCP
protocol carried by the upstream connection.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal

import anyio
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from agent44 import observe
from agent44.delegation import DelegationConfigError, DelegationContext, DelegationSource
from agent44.local_provider import (
    DEFAULT_HOST,
    DEFAULT_MAX_CALLS,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT_SECONDS,
    LocalProviderError,
    OllamaProvider,
    local_model_adapter,
)
from agent44.model_adapter import ReplayAdapter, ReplayError
from agent44.observe import JsonlObserver
from agent44.policy import (
    Action,
    Decision,
    DecisionAdapter,
    PolicyEngine,
    PolicyError,
    RulesOnlyAdapter,
    _validate_adapter_timeout,
)
from agent44.provenance import ProvenanceContext, ProvenanceRegistry
from agent44.transfer import (
    CORRELATION_MAX_LENGTH,
    MAX_TRANSFER_ID_LENGTH,
    RESULT_ARGUMENT_NAME,
    ProvenanceTransferStore,
    TransferError,
)

logger = logging.getLogger("agent44.proxy")

# Maximum time to wait for the downstream server to initialize.
DOWNSTREAM_INIT_TIMEOUT_SECONDS = 30.0
# Maximum time to wait for a single forwarded tool call.
DOWNSTREAM_CALL_TIMEOUT_SECONDS = 60.0

# Agent44-internal control fields for delegated calls. They are interpreted
# (and stripped before forwarding) only when delegation enforcement is
# active; their values are never trusted without validation against trusted
# local state.
CONTROL_TRANSFER_FIELD = "__agent44__transfer"
CONTROL_CORRELATION_FIELD = "__agent44__correlation_id"
CONTROL_FIELDS = frozenset({CONTROL_TRANSFER_FIELD, CONTROL_CORRELATION_FIELD})


def _finish_quietly(
    state: ProxyState,
    delegation_context: DelegationContext | None,
    correlation_id: str | None,
    outcome: Literal["forwarded", "failed", "ambiguous"],
) -> None:
    """Record a terminal correlation outcome, never raising.

    Called only after the outcome is known; failures are logged because they
    must not change a tool call's result or error semantics. A missing
    terminal record leaves the id at ``pending``, which the duplicate gate
    still rejects (fail closed).
    """
    if (
        state.transfer_store is None
        or delegation_context is None
        or correlation_id is None
    ):
        return
    try:
        state.transfer_store.finish_correlation(
            delegation_context.workflow_id, correlation_id, outcome
        )
    except TransferError:
        logger.warning("could not record correlation outcome", exc_info=True)


@dataclass
class ProxyState:
    """Shared state for the lifetime of one proxy connection."""

    session: ClientSession
    params: StdioServerParameters
    observer: JsonlObserver | None = None
    policy: PolicyEngine | None = None
    adapter: DecisionAdapter | None = None
    delegation_source: DelegationSource | None = None
    transfer_store: ProvenanceTransferStore | None = None


def build_server(
    params: StdioServerParameters,
    observer: JsonlObserver | None = None,
    policy: PolicyEngine | None = None,
    adapter: DecisionAdapter | None = None,
    delegation_source: DelegationSource | None = None,
) -> Server:
    """Create a low-level MCP server that proxies the given downstream server.

    The downstream server is spawned and initialized once, inside the server
    lifespan, and reused for every upstream request on this connection. An
    optional ``observer`` records non-intrusive observations of tool calls;
    it never changes results, error semantics, or protocol behavior.

    When ``policy`` is provided, enforcement is enabled: each ``tools/call``
    is evaluated *before* it is forwarded, and a DENY decision returns a
    tool-level error without ever invoking the downstream server. Without a
    policy the proxy stays in observation-only mode.
    """

    @asynccontextmanager
    async def lifespan(server: Server) -> AsyncIterator[ProxyState]:
        logger.info("spawning downstream server: %s %s", params.command, " ".join(params.args))
        try:
            async with stdio_client(params) as (read_stream, write_stream):
                session = ClientSession(read_stream, write_stream)
                async with session:
                    try:
                        with anyio.fail_after(DOWNSTREAM_INIT_TIMEOUT_SECONDS):
                            await session.initialize()
                    except TimeoutError as exc:
                        raise RuntimeError(
                            "downstream server did not initialize within "
                            f"{DOWNSTREAM_INIT_TIMEOUT_SECONDS}s"
                        ) from exc
                    logger.info("downstream server initialized")
                    # Phase 7: the transfer store is created only when
                    # delegation enforcement is required, and all of its
                    # process-local workflow state is released on shutdown.
                    transfer_store: ProvenanceTransferStore | None = None
                    if (
                        policy is not None
                        and policy.delegation.enforcement == "required"
                    ):
                        transfer_store = ProvenanceTransferStore(
                            policy.provenance.transfer
                        )
                    try:
                        yield ProxyState(
                            session=session,
                            params=params,
                            observer=observer,
                            policy=policy,
                            adapter=adapter,
                            delegation_source=delegation_source,
                            transfer_store=transfer_store,
                        )
                    finally:
                        if transfer_store is not None:
                            for workflow_id in transfer_store.workflow_ids():
                                transfer_store.end_workflow(workflow_id)
        except (OSError, RuntimeError) as exc:
            # Startup / initialization failure: surface a clear, diagnosable
            # error instead of hanging or silently succeeding.
            logger.error("failed to start downstream server: %s", exc)
            raise
        logger.info("downstream server shut down cleanly")

    server: Server = Server(
        "agent44-proxy",
        instructions="Transparent MCP stdio proxy.",
        lifespan=lifespan,
    )

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        state: ProxyState = server.request_context.lifespan_context
        result = await state.session.list_tools()
        # Forward the downstream tool descriptors verbatim, including
        # annotations, input/output schemas, and other supported metadata.
        return list(result.tools)

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, object]) -> types.CallToolResult:
        state: ProxyState = server.request_context.lifespan_context
        started = time.perf_counter()

        # Build the observation context up front. Context building only reads
        # MCP metadata and never raises for missing fields; it is additionally
        # guarded so observation can never affect the call outcome.
        context = None
        try:
            context = observe.context_from_request_context(
                server.request_context, name, arguments
            )
        except Exception:  # noqa: BLE001 - observation must never break the call
            logger.exception("failed to build observation context; continuing")

        # ---- Phase 7: delegation wiring, control fields, transfer import.

        # Delegation enforcement is a strict opt-in: when it is off (the
        # default), every argument passes through untouched and behavior is
        # identical to Phases 5 and 6.
        enforcement_active = (
            state.policy is not None
            and state.policy.delegation.enforcement == "required"
        )

        # Business arguments vs Agent44-internal control fields. Control
        # fields are interpreted (and stripped before forwarding) only when
        # enforcement is active; a caller-supplied value is never trusted on
        # its own — only validation against trusted local state matters.
        forward_args: dict[str, object] = dict(arguments or {})
        correlation_id: str | None = None
        transfer_handles: list[object] = []
        delegation_context: DelegationContext | None = None
        authority_result: str | None = None
        transfer_import_evidence: list[dict[str, Any]] = []
        correlation_reserved = False
        early_rule: str | None = None
        early_reason: str | None = None

        if enforcement_active:
            store = state.transfer_store

            # The delegation context comes from the trusted local manifest
            # file, never from request metadata. Missing/invalid manifests
            # fail closed through the engine's delegation tier.
            try:
                delegation_context = (
                    state.delegation_source.current()
                    if state.delegation_source is not None
                    else None
                )
            except DelegationConfigError:
                logger.exception("delegation manifest invalid; failing closed")
                delegation_context = None
            if delegation_context is not None:
                authority_result = (
                    "granted" if delegation_context.check(name) is None else "denied"
                )

            raw_correlation = forward_args.pop(CONTROL_CORRELATION_FIELD, None)
            raw_handles = forward_args.pop(CONTROL_TRANSFER_FIELD, None)

            # A correlation id is mandatory for delegated calls so duplicate
            # and retry behavior is always auditable and protected.
            if raw_correlation is None:
                early_rule = f"request:{name}:missing_correlation"
                early_reason = "a correlation id is required for delegated calls"
            elif (
                not isinstance(raw_correlation, str)
                or not raw_correlation.strip()
                or len(raw_correlation) > CORRELATION_MAX_LENGTH
            ):
                early_rule = f"request:{name}:malformed_correlation"
                early_reason = "the correlation id is malformed"
            else:
                correlation_id = raw_correlation

            # Transfer handles: a bounded list of opaque strings; anything
            # else is malformed and fails closed.
            if early_rule is None and raw_handles is not None:
                if (
                    not isinstance(raw_handles, list)
                    or len(raw_handles)
                    > state.policy.provenance.transfer.max_transfers_per_call
                    or any(
                        not isinstance(handle, str)
                        or len(handle) > MAX_TRANSFER_ID_LENGTH
                        for handle in raw_handles
                    )
                ):
                    early_rule = f"transfer:{name}:malformed"
                    early_reason = "the transfer handle list is malformed"
                else:
                    transfer_handles = list(raw_handles)

            # Workflow scope: one bounded, process-local security scope per
            # delegation, shared by transfer records and the duplicate guard.
            if early_rule is None and delegation_context is not None:
                if store is None:  # defensive: the lifespan creates it
                    early_rule = f"transfer:{name}:unavailable"
                    early_reason = "workflow security state is unavailable"
                else:
                    try:
                        store.ensure_workflow(
                            delegation_context.workflow_id,
                            delegation_context.delegate_principal_id,
                        )
                    except TransferError as exc:
                        early_rule = f"transfer:{name}:{exc.code}"
                        early_reason = f"workflow state unavailable ({exc.code})"

        # Build the per-call provenance context. Every business argument is
        # externally controlled and therefore untrusted at the proxy input
        # boundary. The registry is fresh per call: metadata stays bounded
        # and no taint carries over implicitly. Caller-supplied fields (e.g.
        # "trusted": true) are business arguments, not provenance claims, and
        # are never accepted as authoritative here. The registry is also
        # built when only delegation enforcement is active, because the
        # cross-call transfer mechanism needs it.
        provenance_context: ProvenanceContext | None = None
        provenance_unavailable = False
        registry: ProvenanceRegistry | None = None
        if state.policy is not None and (
            state.policy.provenance.enforcement == "required" or enforcement_active
        ):
            try:
                registry = ProvenanceRegistry()
                values: dict[str, str | None] = {}
                for argument_name in forward_args:
                    values[argument_name] = registry.classify_external(
                        boundary="proxy_input"
                    )
                provenance_context = ProvenanceContext(
                    registry=registry, values=values
                )
            except Exception:  # noqa: BLE001 - provenance setup must fail closed
                logger.exception("failed to build provenance context; failing closed")
                registry = None
                provenance_context = None
                provenance_unavailable = True

        # Import requested transfer records into the fresh registry. Each
        # handle is validated against trusted workflow state (workflow scope,
        # owner principal, expiry, revocation, single-use) and consumed on
        # success; any rejection fails closed with a stable rule id.
        if (
            early_rule is None
            and transfer_handles
            and registry is not None
            and provenance_context is not None
            and delegation_context is not None
            and state.transfer_store is not None
        ):
            for handle in transfer_handles:
                try:
                    imported = state.transfer_store.import_into(
                        handle,
                        registry=registry,
                        values=provenance_context.values,
                        workflow_id=delegation_context.workflow_id,
                        principal_id=delegation_context.delegate_principal_id,
                    )
                except TransferError as exc:
                    early_rule = f"transfer:{name}:{exc.code}"
                    early_reason = f"transfer record rejected ({exc.code})"
                    break
                transfer_import_evidence.append(
                    {
                        "transfer_id": imported["transfer_id"],
                        "argument_name": imported["argument_name"],
                        "trust_class": imported["trust_class"],
                    }
                )

        # Audit evidence for this call: identifier metadata only (no raw
        # argument values, prompts, secrets, or response bodies). Populated
        # only when delegation enforcement is active, so legacy event shapes
        # remain unchanged otherwise.
        evidence: dict[str, Any] = {}
        if enforcement_active:
            evidence = {
                "initiator_principal": (
                    delegation_context.initiator.principal_id
                    if delegation_context is not None
                    else None
                ),
                "delegate_principal": (
                    delegation_context.delegate_principal_id
                    if delegation_context is not None
                    else None
                ),
                "delegation_id": (
                    delegation_context.delegation_id
                    if delegation_context is not None
                    else None
                ),
                "parent_delegation_id": None,
                "correlation_id": correlation_id,
                "authority_result": authority_result,
                "transfer_imports": transfer_import_evidence or None,
            }

        # Evaluate the policy *before* forwarding. Any evaluation failure
        # fails closed: enforcement must never silently become a no-op. Early
        # request/transfer validation denials flow through the exact same
        # denial path below: the downstream is never invoked either way.
        decision: Decision | None = None
        if early_rule is not None:
            decision = Decision(
                action=Action.DENY,
                reason=early_reason or "request validation failed; call denied",
                rule_id=early_rule,
                policy_id=state.policy.policy_id,
                policy_version=state.policy.policy_version,
            )
        elif state.policy is not None:
            try:
                if provenance_unavailable:
                    decision = Decision(
                        action=Action.DENY,
                        reason="provenance context unavailable; call denied",
                        rule_id="provenance:fail_closed",
                        policy_id=state.policy.policy_id,
                        policy_version=state.policy.policy_version,
                    )
                else:
                    decision = await state.policy.decide(
                        name,
                        forward_args,
                        state.adapter,
                        provenance_context=provenance_context,
                        delegation_context=delegation_context,
                    )
            except Exception:  # noqa: BLE001 - enforcement must fail closed
                logger.exception("policy evaluation failed; denying call")
                decision = Decision(
                    action=Action.DENY,
                    reason="policy evaluation failed; call denied",
                    rule_id="fail_closed",
                    policy_id=state.policy.policy_id,
                    policy_version=state.policy.policy_version,
                )

        # Duplicate/replay gate: once every deterministic authority check has
        # passed, reserve the correlation id immediately before forwarding.
        # A previously forwarded/failed/ambiguous (or in-flight) id is denied
        # here; a prior gateway denial may be retried because it never
        # reached the downstream server.
        if (
            enforcement_active
            and early_rule is None
            and decision is not None
            and decision.action is Action.ALLOW
            and correlation_id is not None
            and delegation_context is not None
            and state.transfer_store is not None
        ):
            try:
                state.transfer_store.begin_correlation(
                    delegation_context.workflow_id, correlation_id
                )
                correlation_reserved = True
            except TransferError as exc:
                decision = Decision(
                    action=Action.DENY,
                    reason=f"duplicate-request check rejected the call ({exc.code})",
                    rule_id=f"request:{name}:{exc.code}",
                    policy_id=state.policy.policy_id,
                    policy_version=state.policy.policy_version,
                )

        if decision is not None and decision.action is Action.DENY:
            # Record the gateway denial for duplicate protection. A denial
            # never reached the downstream server, so its correlation id may
            # be retried; a stronger previously recorded outcome (forwarded /
            # failed / ambiguous / pending) is never weakened here.
            if (
                enforcement_active
                and correlation_id is not None
                and delegation_context is not None
                and state.transfer_store is not None
            ):
                try:
                    state.transfer_store.record_denied(
                        delegation_context.workflow_id, correlation_id
                    )
                except TransferError:
                    logger.warning(
                        "could not record denial outcome for the duplicate guard",
                        exc_info=True,
                    )
            deny_evidence: dict[str, Any] = {}
            if enforcement_active:
                deny_evidence = {
                    **evidence,
                    "forwarded": False,
                    "result_state": "denied",
                }
            # Record the denial, then return a tool-level error. The
            # downstream server is never invoked for a denied call.
            if context is not None:
                observe.record_observation(
                    state.observer,
                    context,
                    started=started,
                    outcome="denied",
                    is_error=True,
                    policy_action=decision.action.value,
                    policy_rule_id=decision.rule_id,
                    policy_reason=decision.reason,
                    provenance_id=decision.provenance_id,
                    trust_class=(
                        decision.trust_class.value
                        if decision.trust_class is not None
                        else None
                    ),
                    validation_transition=decision.validation_transition,
                    **deny_evidence,
                )
            # Reason only: raw argument values are never echoed back.
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"denied by policy ({decision.rule_id}): {decision.reason}",
                    )
                ],
                isError=True,
            )

        # Forward the *business* arguments; control fields never reach the
        # downstream tool. Correlation outcomes are recorded so retries can
        # be governed: a forwarded call (success or error) must not be
        # silently repeated, and a timeout/exception is *ambiguous* — the
        # gateway cannot know whether the side effect occurred, so the same
        # correlation id is denied rather than blindly retried.
        transfer_export_evidence: list[dict[str, Any]] = []
        try:
            with anyio.fail_after(DOWNSTREAM_CALL_TIMEOUT_SECONDS):
                result = await state.session.call_tool(name, forward_args)
        except TimeoutError as exc:
            if correlation_reserved:
                _finish_quietly(state, delegation_context, correlation_id, "ambiguous")
            if context is not None:
                timeout_evidence: dict[str, Any] = (
                    {**evidence, "forwarded": True, "result_state": "ambiguous"}
                    if enforcement_active
                    else {}
                )
                observe.record_observation(
                    state.observer,
                    context,
                    started=started,
                    outcome="timeout",
                    is_error=True,
                    policy_action=None if decision is None else decision.action.value,
                    policy_rule_id=None if decision is None else decision.rule_id,
                    policy_reason=None if decision is None else decision.reason,
                    **timeout_evidence,
                )
            raise RuntimeError(
                f"downstream tool call '{name}' timed out after {DOWNSTREAM_CALL_TIMEOUT_SECONDS}s"
            ) from exc
        except Exception:
            if correlation_reserved:
                _finish_quietly(state, delegation_context, correlation_id, "ambiguous")
            raise

        # The downstream returned: the correlation outcome is now known.
        if correlation_reserved:
            _finish_quietly(
                state,
                delegation_context,
                correlation_id,
                "failed" if result.isError else "forwarded",
            )

        # Phase 7: export bounded transfer records for a subsequent authorized
        # call — the tool result first (downstream output is external data),
        # then business arguments. Export failures are logged and never
        # change a successful result; a missing export simply leaves that
        # lineage call-local, and any later call that requires it fails
        # closed.
        if (
            enforcement_active
            and delegation_context is not None
            and registry is not None
            and provenance_context is not None
            and state.transfer_store is not None
        ):
            try:
                result_pid = registry.classify_external(
                    boundary="proxy_result",
                    source_category="external_result",
                )
                attempts: list[tuple[str, str | None]] = [
                    (RESULT_ARGUMENT_NAME, result_pid)
                ]
                attempts.extend(
                    (argument_name, provenance_context.values.get(argument_name))
                    for argument_name in sorted(forward_args)
                )
                export_budget = state.policy.provenance.transfer.max_transfers_per_call
                used = 0
                for argument_name, pid in attempts:
                    if used >= export_budget:
                        logger.warning(
                            "transfer export budget reached; remaining lineage "
                            "stays call-local and later imports fail closed"
                        )
                        break
                    if pid is None:
                        continue
                    try:
                        handle = state.transfer_store.export(
                            workflow_id=delegation_context.workflow_id,
                            owner_principal_id=delegation_context.delegate_principal_id,
                            origin_tool=name,
                            argument_name=argument_name,
                            registry=registry,
                            provenance_id=pid,
                        )
                    except TransferError as exc:
                        logger.warning(
                            "transfer export rejected (%s); lineage stays call-local",
                            exc.code,
                        )
                        if exc.code == "capacity":
                            break
                        continue
                    used += 1
                    transfer_export_evidence.append(
                        {
                            "transfer_id": handle,
                            "argument_name": argument_name,
                            "trust_class": registry.effective_trust(pid).value,
                        }
                    )
            except Exception:  # noqa: BLE001 - export must never break a result
                logger.exception("transfer export failed; lineage stays call-local")

        # Record the observed call. This runs after the downstream result is
        # known and can never change the returned result or its error semantics.
        if context is not None:
            outcome = "error" if result.isError else "success"
            success_evidence: dict[str, Any] = {}
            if enforcement_active:
                success_evidence = {
                    **evidence,
                    "forwarded": True,
                    "result_state": "failed" if result.isError else "known",
                    "transfer_exports": transfer_export_evidence or None,
                }
            observe.record_observation(
                state.observer,
                context,
                started=started,
                outcome=outcome,
                is_error=bool(result.isError),
                policy_action=None if decision is None else decision.action.value,
                policy_rule_id=None if decision is None else decision.rule_id,
                policy_reason=None if decision is None else decision.reason,
                **success_evidence,
            )

        # Return the downstream CallToolResult unchanged so that text and
        # non-text content, isError, structuredContent, and meta are preserved.
        return result

    return server


def parse_downstream_args(
    argv: list[str],
) -> tuple[
    StdioServerParameters,
    JsonlObserver | None,
    PolicyEngine | None,
    DecisionAdapter,
    DelegationSource | None,
]:
    """Split CLI arguments into the downstream command, observer, and policy.

    Accepts: [--observe PATH] [--policy PATH] [--delegation PATH] --
    <command> [args...]
    Everything after ``--`` is the downstream server command and its arguments.

    * ``--observe PATH`` enables JSONL observation of tool calls.
    * ``--policy PATH`` enables enforcement. A missing or invalid policy file
      raises :class:`PolicyError` so that startup fails loudly instead of
      silently disabling enforcement.
    * ``--delegation PATH`` binds the trusted delegation manifest (the
      identity/authority boundary). It requires ``--policy`` with
      ``delegation.enforcement: required``; an invalid or missing manifest
      fails at startup (exit 2) instead of running without delegation state.

    A default :class:`RulesOnlyAdapter` is always returned so adapter-tier
    tools are evaluated deterministically when configured.
    """
    parser = argparse.ArgumentParser(
        prog="agent44",
        description=(
            "Transparent MCP stdio proxy. Everything after '--' is the "
            "downstream server command and its arguments."
        ),
    )
    parser.add_argument(
        "--observe",
        metavar="PATH",
        default=None,
        help="Optional JSONL file to record non-intrusive tool-call observations.",
    )
    parser.add_argument(
        "--policy",
        metavar="PATH",
        default=None,
        help="YAML policy file; enables ALLOW/DENY enforcement of tool calls.",
    )
    parser.add_argument(
        "--delegation",
        metavar="PATH",
        default=None,
        help=(
            "Delegation manifest JSON: the trusted local identity/authority "
            "boundary for delegated calls. Requires --policy with "
            'delegation.enforcement: "required"; an invalid manifest fails '
            "at startup (exit 2)."
        ),
    )
    parser.add_argument(
        "--adapter-replay",
        metavar="PATH",
        default=None,
        help=(
            "JSON replay fixture for a deterministic model adapter. When set, "
            "adapter-tier tool calls are decided by replaying recorded "
            "decisions instead of the rules-only adapter. Missing/invalid "
            "entries fail closed."
        ),
    )
    parser.add_argument(
        "--adapter-deadline",
        metavar="SECONDS",
        type=float,
        default=5.0,
        help=(
            "Per-adapter-call deadline for the policy engine (default: 5.0, "
            "the module default ADAPTER_TIMEOUT_SECONDS). Must be finite and "
            "strictly positive and cannot exceed the provider and downstream "
            "call timeouts (60 s); see agent44.policy for validation rules."
        ),
    )
    parser.add_argument(
        "--local-model",
        metavar="TAG",
        default=None,
        help=(
            "OPT-IN local-model adapter. Provide an Ollama model tag to decide "
            "adapter-tier tool calls with a strictly-local, loopback-only "
            "provider (http://127.0.0.1:11434). No cloud calls, no fallback, "
            "no automatic download; the model must already be installed. "
            "Omitting this flag keeps the deterministic offline path."
        ),
    )
    parser.add_argument(
        "--local-model-host",
        metavar="HOST",
        default=DEFAULT_HOST,
        help="Loopback host for the local model server (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--local-model-port",
        metavar="PORT",
        type=int,
        default=DEFAULT_PORT,
        help="Loopback port for the local model server (default: 11434).",
    )
    parser.add_argument(
        "--local-model-timeout",
        metavar="SECONDS",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout for local model calls (default: 60).",
    )
    parser.add_argument(
        "--local-model-max-calls",
        metavar="N",
        type=int,
        default=DEFAULT_MAX_CALLS,
        help="Hard cap on local model calls for this process (default: 256).",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Downstream server command and arguments (after '--').",
    )
    args = parser.parse_args(argv)

    # Reject invalid deadlines before any subprocess or provider activity.
    try:
        _validate_adapter_timeout(args.adapter_deadline)
    except ValueError as exc:
        parser.error(str(exc))

    downstream = args.command
    # argparse.REMAINDER keeps a leading '--' when present; drop it.
    if downstream and downstream[0] == "--":
        downstream = downstream[1:]
    if not downstream:
        parser.error("no downstream command provided; usage: agent44 -- <command> [args...]")

    params = StdioServerParameters(command=downstream[0], args=downstream[1:])
    observer = JsonlObserver(args.observe) if args.observe else None
    # Raises PolicyError when --policy is given but the file is unusable.
    policy = PolicyEngine.from_path(
        args.policy, adapter_timeout_seconds=args.adapter_deadline
    ) if args.policy else None
    # Delegation binds identity/authority to this process only through the
    # trusted manifest; misconfiguration fails loudly at startup.
    delegation_source: DelegationSource | None = None
    if args.delegation is not None:
        if policy is None:
            parser.error("the --delegation option requires --policy")
        if policy.delegation.enforcement != "required":
            parser.error(
                "--delegation requires delegation enforcement: required "
                'in the policy (set delegation.enforcement: "required")'
            )
        delegation_source = DelegationSource(args.delegation)
        try:
            delegation_source.require()
        except DelegationConfigError as exc:
            parser.error(str(exc))
    adapter: DecisionAdapter
    if args.local_model:
        try:
            provider = OllamaProvider(
                args.local_model,
                host=args.local_model_host,
                port=args.local_model_port,
                timeout=args.local_model_timeout,
                max_calls=args.local_model_max_calls,
            )
            adapter = local_model_adapter(provider)
        except LocalProviderError as exc:
            print(f"agent44: local model provider error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    elif args.adapter_replay:
        try:
            adapter = ReplayAdapter.from_file(args.adapter_replay)
        except ReplayError as exc:
            print(f"agent44: adapter replay error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    else:
        adapter = RulesOnlyAdapter()
    return params, observer, policy, adapter, delegation_source


async def _run(
    params: StdioServerParameters,
    observer: JsonlObserver | None,
    policy: PolicyEngine | None,
    adapter: DecisionAdapter,
    delegation_source: DelegationSource | None,
) -> None:
    server = build_server(
        params,
        observer=observer,
        policy=policy,
        adapter=adapter,
        delegation_source=delegation_source,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    argv = sys.argv[1:] if argv is None else argv
    try:
        params, observer, policy, adapter, delegation_source = parse_downstream_args(argv)
    except SystemExit as exc:  # argparse already printed the message to stderr
        return int(exc.code or 2)
    except PolicyError as exc:
        # Enforcement was requested but the policy is unusable: refuse to
        # start rather than run without a policy.
        print(f"agent44: policy error: {exc}", file=sys.stderr)
        return 2

    try:
        anyio.run(_run, params, observer, policy, adapter, delegation_source)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        logger.error("proxy terminated with error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
