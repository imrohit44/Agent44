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

import anyio
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from agent44 import observe
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

logger = logging.getLogger("agent44.proxy")

# Maximum time to wait for the downstream server to initialize.
DOWNSTREAM_INIT_TIMEOUT_SECONDS = 30.0
# Maximum time to wait for a single forwarded tool call.
DOWNSTREAM_CALL_TIMEOUT_SECONDS = 60.0


@dataclass
class ProxyState:
    """Shared state for the lifetime of one proxy connection."""

    session: ClientSession
    params: StdioServerParameters
    observer: JsonlObserver | None = None
    policy: PolicyEngine | None = None
    adapter: DecisionAdapter | None = None


def build_server(
    params: StdioServerParameters,
    observer: JsonlObserver | None = None,
    policy: PolicyEngine | None = None,
    adapter: DecisionAdapter | None = None,
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
                    yield ProxyState(
                        session=session,
                        params=params,
                        observer=observer,
                        policy=policy,
                        adapter=adapter,
                    )
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

        # Build the per-call provenance context. Every incoming tool-call
        # argument is externally controlled and therefore untrusted at the
        # proxy input boundary. The registry is fresh per call: metadata stays
        # bounded and no taint carries over between calls. Caller-supplied
        # fields (e.g. "trusted": true) are business arguments, not provenance
        # claims, and are never accepted as authoritative here.
        provenance_context: ProvenanceContext | None = None
        provenance_unavailable = False
        if (
            state.policy is not None
            and state.policy.provenance.enforcement == "required"
        ):
            try:
                registry = ProvenanceRegistry()
                values: dict[str, str | None] = {}
                for argument_name in (arguments or {}):
                    values[argument_name] = registry.classify_external(
                        boundary="proxy_input"
                    )
                provenance_context = ProvenanceContext(
                    registry=registry, values=values
                )
            except Exception:  # noqa: BLE001 - provenance setup must fail closed
                logger.exception("failed to build provenance context; failing closed")
                provenance_unavailable = True

        # Evaluate the policy *before* forwarding. Any evaluation failure
        # fails closed: enforcement must never silently become a no-op.
        decision: Decision | None = None
        if state.policy is not None:
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
                        arguments,
                        state.adapter,
                        provenance_context=provenance_context,
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

        if decision is not None and decision.action is Action.DENY:
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

        try:
            with anyio.fail_after(DOWNSTREAM_CALL_TIMEOUT_SECONDS):
                result = await state.session.call_tool(name, arguments)
        except TimeoutError as exc:
            if context is not None:
                observe.record_observation(
                    state.observer,
                    context,
                    started=started,
                    outcome="timeout",
                    is_error=True,
                    policy_action=None if decision is None else decision.action.value,
                    policy_rule_id=None if decision is None else decision.rule_id,
                    policy_reason=None if decision is None else decision.reason,
                )
            raise RuntimeError(
                f"downstream tool call '{name}' timed out after {DOWNSTREAM_CALL_TIMEOUT_SECONDS}s"
            ) from exc

        # Record the observed call. This runs after the downstream result is
        # known and can never change the returned result or its error semantics.
        if context is not None:
            outcome = "error" if result.isError else "success"
            observe.record_observation(
                state.observer,
                context,
                started=started,
                outcome=outcome,
                is_error=bool(result.isError),
                policy_action=None if decision is None else decision.action.value,
                policy_rule_id=None if decision is None else decision.rule_id,
                policy_reason=None if decision is None else decision.reason,
            )

        # Return the downstream CallToolResult unchanged so that text and
        # non-text content, isError, structuredContent, and meta are preserved.
        return result

    return server


def parse_downstream_args(
    argv: list[str],
) -> tuple[
    StdioServerParameters, JsonlObserver | None, PolicyEngine | None, DecisionAdapter
]:
    """Split CLI arguments into the downstream command, observer, and policy.

    Accepts: [--observe PATH] [--policy PATH] -- <command> [args...]
    Everything after ``--`` is the downstream server command and its arguments.

    * ``--observe PATH`` enables JSONL observation of tool calls.
    * ``--policy PATH`` enables enforcement. A missing or invalid policy file
      raises :class:`PolicyError` so that startup fails loudly instead of
      silently disabling enforcement.

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
    return params, observer, policy, adapter


async def _run(
    params: StdioServerParameters,
    observer: JsonlObserver | None,
    policy: PolicyEngine | None,
    adapter: DecisionAdapter,
) -> None:
    server = build_server(params, observer=observer, policy=policy, adapter=adapter)
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
        params, observer, policy, adapter = parse_downstream_args(argv)
    except SystemExit as exc:  # argparse already printed the message to stderr
        return int(exc.code or 2)
    except PolicyError as exc:
        # Enforcement was requested but the policy is unusable: refuse to
        # start rather than run without a policy.
        print(f"agent44: policy error: {exc}", file=sys.stderr)
        return 2

    try:
        anyio.run(_run, params, observer, policy, adapter)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        logger.error("proxy terminated with error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
