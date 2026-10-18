"""Proxy transfer tests: export then import in one session (offline 1/2)."""

from __future__ import annotations

import json
import re
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

POLICY_TEXT = """
version: "1"
name: transfer-e2e
default_deny: true
allow_tools: [echo, hit]
provenance:
  enforcement: required
  rules:
    hit:
      deny_untrusted: [label]
delegation:
  enforcement: required
"""


def manifest_dict(**overrides: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "delegation_id": "del-xfer-1",
        "workflow_id": "wf-xfer-1",
        "initiator": {
            "principal_id": "agent-alpha",
            "allowed_tools": ["echo", "hit"],
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
async def transfer_session(
    policy_path: Path,
    manifest_path: Path,
    counter_path: Path,
    observe_path: Path,
) -> AsyncIterator[ClientSession]:
    args = [
        *PROXY_MODULE,
        "--policy",
        str(policy_path),
        "--delegation",
        str(manifest_path),
        "--observe",
        str(observe_path),
        "--",
        sys.executable,
        *DEMO_MODULE,
        str(counter_path),
    ]
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


def exported_handle(observe_path: Path, argument: str = "result") -> str:
    events = JsonlObserver(observe_path).read_events()
    for event in events:
        for export in event.get("transfer_exports") or []:
            if export.get("argument_name") == argument:
                return str(export["transfer_id"])
    raise AssertionError(f"no transfer export for {argument!r}")


HANDLE_RE = re.compile(r"tr_[0-9a-f]{32}")


@pytest.mark.asyncio
async def test_echo_exports_untrusted_result_lineage(tmp_path: Path) -> None:
    counter = tmp_path / "counter.log"
    observe_path = tmp_path / "obs.jsonl"
    async with transfer_session(
        write_policy(tmp_path),
        write_manifest(tmp_path),
        counter,
        observe_path,
    ) as session:
        result = await session.call_tool(
            "echo",
            {"message": "hello", "__agent44__correlation_id": "corr-x1"},
        )
        assert result.isError is False
    assert counter_lines(counter) == ["echo"]
    handle = exported_handle(observe_path)
    assert HANDLE_RE.fullmatch(handle), handle
    events = JsonlObserver(observe_path).read_events()
    assert events[0]["transfer_exports"][0]["trust_class"] == "untrusted"


@pytest.mark.asyncio
async def test_untrusted_transfer_blocks_protected_call(tmp_path: Path) -> None:
    """Taint survives export/import: the guarded call never forwards."""
    counter = tmp_path / "counter.log"
    observe_path = tmp_path / "obs.jsonl"
    async with transfer_session(
        write_policy(tmp_path),
        write_manifest(tmp_path),
        counter,
        observe_path,
    ) as session:
        echo_result = await session.call_tool(
            "echo",
            {"message": "hello", "__agent44__correlation_id": "corr-x2"},
        )
        assert echo_result.isError is False
        handle = exported_handle(observe_path)
        assert HANDLE_RE.fullmatch(handle)
        # Import the exported result lineage as the guarded argument.
        denied = await session.call_tool(
            "hit",
            {
                "label": "echoed-value",
                "__agent44__correlation_id": "corr-x3",
                "__agent44__transfer": [handle],
            },
        )
        assert denied.isError is True
        text = first_text(denied)
        assert "provenance:hit:deny_untrusted:label" in text
        assert "hello" not in text
    # Only echo reached downstream; the guarded call never forwarded.
    assert counter_lines(counter) == ["echo"]
    events = JsonlObserver(observe_path).read_events()
    assert len(events) == 2
    assert events[1]["outcome"] == "denied"
    assert events[1]["forwarded"] is False
    assert events[1]["trust_class"] == "untrusted"
    imports = events[1]["transfer_imports"]
    assert imports and imports[0]["transfer_id"] == handle

