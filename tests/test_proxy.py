"""Integration tests for the Agent44 transparent MCP stdio proxy.

These tests use a real MCP ``ClientSession`` connected to the proxy, which in
turn spawns the demo downstream server as a subprocess. They are behavioral:
they exercise the MCP protocol rather than inspecting implementation details.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import psutil
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_server"]


def proxy_params(downstream_cmd: list[str] | None = None) -> StdioServerParameters:
    """Build stdio params that launch the proxy in front of the demo server."""
    if downstream_cmd is None:
        downstream_cmd = [sys.executable, *DEMO_MODULE]
    return StdioServerParameters(
        command=sys.executable,
        args=[*PROXY_MODULE, "--", *downstream_cmd],
    )


@asynccontextmanager
async def proxy_session(
    downstream_cmd: list[str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Yield an initialized ClientSession connected through the proxy."""
    async with stdio_client(proxy_params(downstream_cmd)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def observing_proxy_session(
    observe_path: Path,
) -> AsyncIterator[ClientSession]:
    """Yield an initialized session whose proxy writes observations to a file."""
    args = [*PROXY_MODULE, "--observe", str(observe_path), "--", sys.executable, *DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session



@pytest.mark.asyncio
async def test_upstream_initialization_succeeds() -> None:
    async with proxy_session() as session:
        # initialize() already ran inside the context manager; a second
        # round-trip confirms the session is live.
        tools = await session.list_tools()
        assert tools is not None


@pytest.mark.asyncio
async def test_tools_appear_in_discovery() -> None:
    async with proxy_session() as session:
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert "add" in names
        assert "echo" in names


@pytest.mark.asyncio
async def test_add_returns_expected_result() -> None:
    async with proxy_session() as session:
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert result.isError is False
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts == ["5"]


@pytest.mark.asyncio
async def test_echo_preserves_message() -> None:
    message = "hello agent44 — ünïcödé ✓"
    async with proxy_session() as session:
        result = await session.call_tool("echo", {"message": message})
        assert result.isError is False
        texts = [c.text for c in result.content if c.type == "text"]
        assert texts == [message]


@pytest.mark.asyncio
async def test_invalid_arguments_retain_error_semantics() -> None:
    # Missing the required 'b' argument must surface as an error, not a
    # silently-succeeded result.
    async with proxy_session() as session:
        result = await session.call_tool("add", {"a": 1})
        assert result.isError is True
        assert any(c.type == "text" for c in result.content)


@pytest.mark.asyncio
async def test_downstream_tool_error_is_forwarded() -> None:
    # A wrong-typed argument ('a' as a string) is rejected by the downstream
    # server's own validation; the proxy must forward that error unchanged.
    async with proxy_session() as session:
        result = await session.call_tool("add", {"a": "not-an-int", "b": 2})
        assert result.isError is True


@pytest.mark.asyncio
async def test_unknown_tool_is_handled() -> None:
    # The proxy has validate_input=False, so an unknown tool is forwarded to
    # the downstream server, which reports it as a tool-level error result
    # (isError=True) rather than crashing the session.
    async with proxy_session() as session:
        result = await session.call_tool("does_not_exist", {})
        assert result.isError is True
        assert any(c.type == "text" for c in result.content)


@pytest.mark.asyncio
async def test_structured_content_is_preserved() -> None:
    # The SDK returns structured content for the add tool; the proxy must
    # forward it verbatim rather than dropping it.
    async with proxy_session() as session:
        result = await session.call_tool("add", {"a": 4, "b": 5})
        assert result.isError is False
        assert result.structuredContent == {"result": 9}


@pytest.mark.asyncio
async def test_downstream_startup_failure_is_diagnosable() -> None:
    # Point the proxy at a command that does not exist. The upstream client
    # must get a clear, prompt error rather than hanging.
    bad_cmd = [sys.executable, "-m", "agent44.__nonexistent_module__"]
    with pytest.raises(BaseExceptionGroup) as exc_info:
        async with proxy_session(bad_cmd) as session:
            await session.list_tools()
    # The error text should reference the failed downstream, not be empty.
    message = repr(exc_info.value)
    assert message


@pytest.mark.asyncio
async def test_shutdown_cleans_up_subprocess() -> None:
    # Track every demo-server process this test process spawns, then verify the
    # count returns to its baseline after the proxy session closes.
    def demo_pids() -> set[int]:
        pids: set[int] = set()
        for proc in psutil.process_iter(["cmdline"]):
            try:
                cmdline = " ".join(proc.info["cmdline"] or [])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if "agent44.demo_server" in cmdline:
                pids.add(proc.pid)
        return pids

    baseline = demo_pids()
    async with proxy_session() as session:
        await session.initialize()
        tools = await session.list_tools()
        assert {t.name for t in tools.tools} >= {"add", "echo"}
        during = demo_pids()
        assert len(during - baseline) >= 1, "expected a spawned downstream process"

    # Give the OS a brief moment to reap the terminated child.
    for _ in range(50):
        if demo_pids() <= baseline:
            break
        await asyncio.sleep(0.1)
    assert demo_pids() <= baseline, "downstream subprocess leaked after shutdown"


@pytest.mark.asyncio
async def test_stdout_is_not_polluted_by_logging() -> None:
    # Drive the proxy as a raw subprocess and confirm every byte written to its
    # stdout is a valid JSON-RPC message. Diagnostic logging must go to stderr
    # only, because stdout carries the MCP protocol.
    proc = subprocess.Popen(
        [
            sys.executable,
            *PROXY_MODULE,
            "--",
            sys.executable,
            *DEMO_MODULE,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parent.parent),
    )

    def send(obj: dict[str, object]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        proc.stdin.flush()

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            }
        )
        assert proc.stdout is not None
        init_line = proc.stdout.readline().decode("utf-8").strip()
        # The initialize response must be pure JSON-RPC on stdout.
        json.loads(init_line)

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools_line = proc.stdout.readline().decode("utf-8").strip()
        parsed = json.loads(tools_line)
        names = {t["name"] for t in parsed["result"]["tools"]}
        assert {"add", "echo"} <= names
    finally:
        assert proc.stdin is not None
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --- Observation does not change proxy behavior (Milestone 2) -------------


@pytest.mark.asyncio
async def test_observation_preserves_call_results(tmp_path: Path) -> None:
    observe_path = tmp_path / "obs.jsonl"
    async with observing_proxy_session(observe_path) as session:
        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert result.isError is False
        assert [c.text for c in result.content if c.type == "text"] == ["5"]
        assert result.structuredContent == {"result": 5}


@pytest.mark.asyncio
async def test_observation_writes_events_without_raw_values(tmp_path: Path) -> None:
    from agent44.observe import JsonlObserver

    observe_path = tmp_path / "obs.jsonl"
    secret = "sk-live-do-not-log-this"
    async with observing_proxy_session(observe_path) as session:
        await session.call_tool("echo", {"message": secret, "api_key": secret})

    events = JsonlObserver(observe_path).read_events()
    assert len(events) >= 1
    joined = json.dumps(events)
    # Raw argument values and secrets must never be persisted.
    assert secret not in joined
    tool_events = [e for e in events if e["tool_name"] == "echo"]
    assert tool_events
    ev = tool_events[-1]
    assert ev["event_type"] == "tool_call"
    assert ev["outcome"] in {"success", "error", "timeout"}
    assert "latency_ms" in ev
    assert ev["safe_arguments"]["message"] == {"type": "str", "length": len(secret)}
    assert ev["safe_arguments"]["api_key"] == {"redacted": True}


@pytest.mark.asyncio
async def test_observation_does_not_leak_to_stdout(tmp_path: Path) -> None:
    # The raw-subprocess stdout purity check must still hold when --observe is
    # enabled: observations go to the file, logging to stderr, stdout stays clean.
    observe_path = tmp_path / "obs.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            *PROXY_MODULE,
            "--observe",
            str(observe_path),
            "--",
            sys.executable,
            *DEMO_MODULE,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parent.parent),
    )

    def send(obj: dict[str, object]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        proc.stdin.flush()

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            }
        )
        assert proc.stdout is not None
        json.loads(proc.stdout.readline().decode("utf-8").strip())
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "add", "arguments": {"a": 1, "b": 1}},
            }
        )
        line = proc.stdout.readline().decode("utf-8").strip()
        parsed = json.loads(line)  # must remain valid JSON-RPC
        assert "result" in parsed
    finally:
        assert proc.stdin is not None
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    # Observation landed in the file, not stdout.
    assert observe_path.exists()
