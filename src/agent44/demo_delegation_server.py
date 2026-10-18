"""Safe downstream demo MCP server for the Phase 7 delegation demonstration.

Exposes only harmless tools over stdio:

    - add(a: int, b: int) -> int
    - echo(message: str) -> str
    - hit(label: str = "hit") -> str

Every tool that actually executes appends its name to the counter file given
as the first CLI argument, so a demonstration or test can prove which calls
reached downstream (and which policy denials never did).

No shell execution, no network access, no reads; the only write is one append
per executed tool to the single counter path it is given.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

COUNTER_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("delegation_counter.log")

mcp: FastMCP = FastMCP(
    name="agent44-delegation-demo",
    instructions="Harmless demo tools: add, echo, and hit (counted).",
)


def _count(tool_name: str) -> None:
    with COUNTER_PATH.open("a", encoding="utf-8") as handle:
        handle.write(tool_name + "\n")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    _count("add")
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Return the supplied message unchanged."""
    _count("echo")
    return message


@mcp.tool()
def hit(label: str = "hit") -> str:
    """Record one invocation of this tool and return 'recorded'."""
    _count("hit")
    return "recorded"


def main() -> None:
    """Run the demo server on stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
