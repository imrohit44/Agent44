"""Live demo: run the proxy with --policy and exercise ALLOW and DENY paths."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent
OBS = ROOT / "demo_enforce.jsonl"


async def main() -> int:
    if OBS.exists():
        OBS.unlink()
    args = [
        "-m",
        "agent44.proxy",
        "--observe",
        str(OBS),
        "--policy",
        str(ROOT / "policies" / "demo.yaml"),
        "--",
        sys.executable,
        "-m",
        "agent44.demo_server",
    ]
    params = StdioServerParameters(command=sys.executable, args=args)

    allowed = 0
    denied = 0
    calls: list[tuple[str, dict, bool, str]] = [
        ("add", {"a": 2, "b": 3}, True, "simple arithmetic"),
        ("echo", {"message": "hello agent44"}, True, "benign echo"),
        ("echo", {"message": "hi", "eval": True}, False, "deny-eval-flag rule"),
        ("rm_rf", {"path": "/"}, False, "explicit deny_tools"),
        ("shell_exec", {"cmd": "ls"}, False, "explicit deny_tools"),
        ("totally_unknown_tool", {}, False, "default_deny"),
    ]

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for name, arguments, expect_allow, why in calls:
                result = await session.call_tool(name, arguments)
                got_error = bool(result.isError)
                outcome_ok = (not got_error) == expect_allow
                text = " | ".join(c.text for c in result.content if c.type == "text")
                if expect_allow and not got_error:
                    allowed += 1
                    label = "ALLOW"
                elif got_error:
                    denied += 1
                    label = "DENY "
                else:
                    label = "???  "
                flag = "ok " if outcome_ok else "BAD"
                print(f"  [{flag}] {label} {name:<22} {text[:70]}   <- {why}")

    print(f"\nallowed={allowed} denied={denied} total={allowed + denied}")

    print("\nJSONL policy labels:")
    for line in OBS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        import json

        ev = json.loads(line)
        print(
            f"  {ev['tool_name']:<22} outcome={ev['outcome']:<8} "
            f"policy_action={ev['policy_action']} rule={ev['policy_rule_id']}"
        )
    return 0 if (allowed and denied) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
