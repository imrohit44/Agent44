"""Safe downstream demo MCP server.

Exposes only harmless tools over stdio:
    - add(a: int, b: int) -> int
    - echo(message: str) -> str

No shell execution, file access, network access, or destructive operations.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp: FastMCP = FastMCP(
    name="agent44-demo",
    instructions="Harmless demo tools: add and echo.",
)


@mcp.tool()
def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


@mcp.tool()
def echo(message: str) -> str:
    """Return the supplied message unchanged."""
    return message


def main() -> None:
    """Run the demo server on stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
