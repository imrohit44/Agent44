from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path
from textwrap import dedent

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent44.observe import JsonlObserver

PROXY_MODULE = ["-m", "agent44.proxy"]
DEMO_MODULE = ["-m", "agent44.demo_delegation_server"]

POLICY_TEXT = """
version: "1"
name: delegation-demo
default_deny: true
allow_tools: [add, echo, hit]
provenance:
  enforcement: required
  rules:
    hit:
      deny_untrusted: [label]
delegation:
  enforcement: required
"""

SECRET = "s3cret-demo-payload-marker"


def step(number: int, title: str) -> None:
    print(f"\n--- step {number}: {title} ---")


def show(label: str, value: object) -> None:
    print(f"  {label}: {value}")


async def run_demo() -> int:
    now = time.time()
    manifest = {
        "delegation_id": "del-demo-1",
        "workflow_id": "wf-demo-1",
        "initiator": {
            "principal_id": "agent-alpha",
            "allowed_tools": ["add", "echo", "hit"],
        },
        "delegate_principal_id": "agent-beta",
        "granted_tools": ["echo", "hit"],
        "issued_at": now - 60,
        "expires_at": now + 3600,
        "status": "active",
        "parent_delegation_id": None,
    }
    with tempfile.TemporaryDirectory(prefix="agent44-demo-") as tmp:
        work = Path(tmp)
        policy_path = work / "policy.yaml"
        policy_path.write_text(dedent(POLICY_TEXT).lstrip(), encoding="utf-8")
        manifest_path = work / "delegation.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        counter = work / "counter.log"
        observe_path = work / "obs.jsonl"
        args = [
            *PROXY_MODULE, "--policy", str(policy_path),
            "--delegation", str(manifest_path),
            "--observe", str(observe_path),
            "--", sys.executable, *DEMO_MODULE, str(counter),
        ]
        params = StdioServerParameters(command=sys.executable, args=args)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                step(1, "initiator agent-alpha holds [add, echo, hit]")
                step(2, "agent-alpha delegates [echo, hit] to agent-beta")
                step(3, "delegate echo (granted) succeeds")
                ok = await session.call_tool(
                    "echo",
                    {"message": "hello", "__agent44__correlation_id": "d1"},
                )
                show("isError", ok.isError)
                assert ok.isError is False
                step(4, "delegate add (not granted) denied before forward")
                denied = await session.call_tool(
                    "add",
                    {"a": 1, "b": 2, "__agent44__correlation_id": "d2"},
                )
                show("isError", denied.isError)
                assert denied.isError is True
                step(5, "echo result lineage exported; import into next call")
                handle = None
                for event in JsonlObserver(observe_path).read_events():
                    for export in event.get("transfer_exports") or []:
                        handle = str(export["transfer_id"])
                show("transfer handle", handle)
                assert handle is not None
                step(6, "hit guarded by deny_untrusted rejects the taint")
                blocked = await session.call_tool(
                    "hit",
                    {"label": SECRET, "__agent44__correlation_id": "d3",
                     "__agent44__transfer": [handle]},
                )
                show("isError", blocked.isError)
                assert blocked.isError is True
                step(7, "forged and replayed handles rejected")
                forged = await session.call_tool(
                    "hit",
                    {"label": "x", "__agent44__correlation_id": "d4",
                     "__agent44__transfer": ["tr_" + "0" * 32]},
                )
                assert forged.isError is True
                replay = await session.call_tool(
                    "hit",
                    {"label": "x", "__agent44__correlation_id": "d5",
                     "__agent44__transfer": [handle]},
                )
                assert replay.isError is True
                show("replay denied", replay.isError)
                step(8, "duplicate correlation ids cannot re-execute")
                dup = await session.call_tool(
                    "echo",
                    {"message": "again", "__agent44__correlation_id": "d1"},
                )
                assert dup.isError is True
                show("duplicate denied", dup.isError)
        show("downstream executions", counter.read_text().split())
        assert counter.read_text().split() == ["echo"]
        step(9, "audit trail carries ids and lineage, no raw payloads")
        events = JsonlObserver(observe_path).read_events()
        for event in events:
            show("event", {k: event.get(k) for k in (
                "tool", "outcome", "policy_rule_id",
                "delegation_id", "correlation_id")})
        assert SECRET not in observe_path.read_text(encoding="utf-8")
        print("\ndemo complete: delegation + provenance transfer enforced")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run_demo()))
