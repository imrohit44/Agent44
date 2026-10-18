"""Proxy integration tests for Phase 7 delegation (offline, part 1).

Exercises the real MCP proxy through the delegated-authority tier and the
correlation duplicate guard. No Ollama, no model inference, no network.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from textwrap import dedent

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44.observe import JsonlObserver

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_delegation_server"]

NOW = time.time()

# The delegate may use ``echo`` and ``hit`` only. ``add`` is allowed to the
# initiating principal (and the policy) but never granted to the delegate,
# so it exercises the attenuation boundary.
POLICY_TEXT = """
version: "1"
name: delegation-e2e
default_deny: true
allow_tools: [add, echo, hit]
delegation:
  enforcement: required
"""


def manifest_dict(**overrides: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "delegation_id": "del-e2e-1",
        "workflow_id": "wf-e2e-1",
        "initiator": {
            "principal_id": "agent-alpha",
            "allowed_tools": ["add", "echo", "hit"],
        },
        "delegate_principal_id": "agent-beta",
        "granted_tools": ["echo", "hit"],
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "status": "active",
        "parent_delegation_id": None,
    }
    manifest.update(overrides)
    return manifest


def write_text(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(dedent(text).lstrip(), encoding="utf-8")
    return path


def write_policy(tmp_path: Path) -> Path:
    return write_text(tmp_path, "policy.yaml", POLICY_TEXT)


def write_manifest(tmp_path: Path, **overrides: object) -> Path:
    return write_text(
        tmp_path, "delegation.json", json.dumps(manifest_dict(**overrides))
    )


@asynccontextmanager
async def delegation_session(
    policy_path: Path,
    manifest_path: Path,
    counter_path: Path,
    observe_path: Path | None = None,
) -> AsyncIterator[ClientSession]:
    args = [
        *PROXY_MODULE,
        "--policy",
        str(policy_path),
        "--delegation",
        str(manifest_path),
    ]
    if observe_path is not None:
        args += ["--observe", str(observe_path)]
    downstream = [sys.executable, *DEMO_MODULE, str(counter_path)]
    args += ["--", *downstream]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def counter_lines(counter: Path) -> list[str]:
    if not counter.exists():
        return []
    return counter.read_text(encoding="utf-8").split()


def first_text(result: object) -> str:
    content = getattr(result, "content", [])
    texts = [c.text for c in content if getattr(c, "type", "") == "text"]
    assert texts, "expected a text payload in the tool result"
    return texts[0]


@pytest.mark.asyncio
async def test_permitted_delegated_call_reaches_downstream(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        result = await session.call_tool(
            "echo",
            {"message": "hello", "__agent44__correlation_id": "corr-allow-1"},
        )
        assert result.isError is False
    assert counter_lines(counter) == ["echo"]


@pytest.mark.asyncio
async def test_forbidden_delegated_call_denied_before_forwarding(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    observe_path = tmp_path / "obs.jsonl"
    async with delegation_session(
        write_policy(tmp_path),
        write_manifest(tmp_path),
        counter,
        observe_path=observe_path,
    ) as session:
        result = await session.call_tool(
            "add",
            {"a": 1, "b": 2, "__agent44__correlation_id": "corr-deny-1"},
        )
        assert result.isError is True
        assert "delegation:add:not_granted" in first_text(result)
    assert not counter.exists()
    events = JsonlObserver(observe_path).read_events()
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "denied"
    assert event["forwarded"] is False
    assert event["initiator_principal"] == "agent-alpha"
    assert event["delegate_principal"] == "agent-beta"
    assert event["delegation_id"] == "del-e2e-1"
    assert event["correlation_id"] == "corr-deny-1"


@pytest.mark.asyncio
async def test_missing_correlation_id_fails_closed(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        result = await session.call_tool("echo", {"message": "hello"})
        assert result.isError is True
        assert "missing_correlation" in first_text(result)
    assert not counter.exists()


@pytest.mark.asyncio
async def test_duplicate_correlation_id_denied_downstream_runs_once(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        first = await session.call_tool(
            "hit",
            {"label": "once", "__agent44__correlation_id": "corr-dup-1"},
        )
        assert first.isError is False
        second = await session.call_tool(
            "hit",
            {"label": "once", "__agent44__correlation_id": "corr-dup-1"},
        )
        assert second.isError is True
        assert "duplicate" in first_text(second)
    assert counter_lines(counter) == ["hit"]


@pytest.mark.asyncio
async def test_denied_call_correlation_may_be_retried(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        denied = await session.call_tool(
            "add",
            {"a": 1, "b": 2, "__agent44__correlation_id": "corr-retry-1"},
        )
        assert denied.isError is True
        # The denial never reached downstream, so reusing the correlation id
        # for a permitted call is safe and succeeds.
        allowed = await session.call_tool(
            "echo",
            {"message": "retry", "__agent44__correlation_id": "corr-retry-1"},
        )
        assert allowed.isError is False
    assert counter_lines(counter) == ["echo"]


@pytest.mark.asyncio
async def test_forged_transfer_handle_rejected_before_forwarding(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        result = await session.call_tool(
            "echo",
            {
                "message": "x",
                "__agent44__correlation_id": "corr-forge-1",
                "__agent44__transfer": ["tr-forged-not-real"],
            },
        )
        assert result.isError is True
        assert "transfer:echo:malformed" in first_text(result)
    assert not counter.exists()


@pytest.mark.asyncio
async def test_caller_supplied_identity_fields_do_not_grant_authority(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    async with delegation_session(
        write_policy(tmp_path), write_manifest(tmp_path), counter
    ) as session:
        result = await session.call_tool(
            "add",
            {
                "a": 1,
                "b": 2,
                "agent_role": "admin",
                "trusted": True,
                "__agent44__correlation_id": "corr-forge-id-1",
            },
        )
        assert result.isError is True
        assert "delegation:add:not_granted" in first_text(result)
    assert not counter.exists()


@pytest.mark.asyncio
async def test_legacy_behavior_unchanged_when_delegation_off(
    tmp_path: Path,
) -> None:
    counter = tmp_path / "counter.log"
    policy = write_text(
        tmp_path,
        "policy.yaml",
        """
        version: "1"
        name: delegation-off
        default_deny: true
        allow_tools: [add]
        delegation:
          enforcement: "off"
        """,
    )
    args = [*PROXY_MODULE, "--policy", str(policy), "--"]
    downstream = [sys.executable, *DEMO_MODULE, str(counter)]
    params = StdioServerParameters(
        command=sys.executable, args=[*args, *downstream]
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # No correlation id is needed and control-field-free arguments
            # pass through exactly as in Phases 5/6.
            result = await session.call_tool("add", {"a": 2, "b": 3})
            assert result.isError is False
    assert counter_lines(counter) == ["add"]

