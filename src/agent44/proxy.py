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
from agent44.observe import JsonlObserver

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


def build_server(
    params: StdioServerParameters,
    observer: JsonlObserver | None = None,
) -> Server:
    """Create a low-level MCP server that proxies the given downstream server.

    The downstream server is spawned and initialized once, inside the server
    lifespan, and reused for every upstream request on this connection. An
    optional ``observer`` records non-intrusive observations of tool calls;
    it never changes results, error semantics, or protocol behavior.
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
                    yield ProxyState(session=session, params=params, observer=observer)
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
            )

        # Return the downstream CallToolResult unchanged so that text and
        # non-text content, isError, structuredContent, and meta are preserved.
        return result

    return server


def parse_downstream_args(
    argv: list[str],
) -> tuple[StdioServerParameters, JsonlObserver | None]:
    """Split CLI arguments into the downstream command and optional observer.

    Accepts: [--observe PATH] -- <command> [args...]
    Everything after ``--`` is the downstream server command and its arguments.
    ``--observe PATH`` (if given) enables JSONL observation of tool calls.
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
        "command",
        nargs=argparse.REMAINDER,
        help="Downstream server command and arguments (after '--').",
    )
    args = parser.parse_args(argv)

    downstream = args.command
    # argparse.REMAINDER keeps a leading '--' when present; drop it.
    if downstream and downstream[0] == "--":
        downstream = downstream[1:]
    if not downstream:
        parser.error("no downstream command provided; usage: agent44 -- <command> [args...]")

    params = StdioServerParameters(command=downstream[0], args=downstream[1:])
    observer = JsonlObserver(args.observe) if args.observe else None
    return params, observer


async def _run(params: StdioServerParameters, observer: JsonlObserver | None) -> None:
    server = build_server(params, observer=observer)
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
        params, observer = parse_downstream_args(argv)
    except SystemExit as exc:  # argparse already printed the message to stderr
        return int(exc.code or 2)

    try:
        anyio.run(_run, params, observer)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        logger.error("proxy terminated with error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
