"""Downstream MCP test double that counts tool invocations.

Writes one line to the file named in ``sys.argv[1]`` every time the ``hit``
tool executes. Enforcement tests use it to prove that a policy-denied call
never reaches the downstream tool: the file must stay untouched.

Harmless by construction: no shell, no network, no reads, and it only ever
appends to the single file path it is given.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

COUNTER_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("counter.log")

mcp: FastMCP = FastMCP(
    name="agent44-counter",
    instructions="Counts how many times the hit tool actually ran.",
)


@mcp.tool()
def hit(label: str = "hit") -> str:
    """Record one invocation of this tool and return 'recorded'."""
    with COUNTER_PATH.open("a", encoding="utf-8") as handle:
        handle.write(label + "\n")
    return "recorded"


def main() -> None:
    """Run the counting server on stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
