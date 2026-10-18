"""Downstream MCP test double that records raw ``tools/call`` request params.

Implements the minimal MCP stdio handshake by hand so that the *exact* JSON
the proxy forwarded — including any unexpected fields — can be asserted on.
Every ``tools/call`` request's ``params`` (tool name + arguments) is appended
as one JSON line to the file given as the first CLI argument.

Harmless by construction: no shell, no network, no reads, and it only ever
appends to the single dump path it is given.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DUMP_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("raw_dump.jsonl")

TOOLS = [
    {
        "name": "echo",
        "description": "Echo the message unchanged.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    },
]


def send(message: dict) -> None:
    print(json.dumps(message), flush=True)


def main() -> None:
    """Serve MCP requests on stdio until stdin closes."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": request["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "agent44-raw-dump", "version": "0.0.0"},
                    },
                }
            )
        elif method == "tools/list":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": TOOLS},
                }
            )
        elif method == "tools/call":
            params = request.get("params") or {}
            with DUMP_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(params, sort_keys=True) + "\n")
            arguments = params.get("arguments") or {}
            send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": str(arguments.get("message", "ok")),
                            }
                        ],
                        "isError": False,
                    },
                }
            )
        elif request_id is not None:
            # Unknown request without side effects (e.g. ping): empty result.
            send({"jsonrpc": "2.0", "id": request_id, "result": {}})
        # Notifications (e.g. initialized) need no response.


if __name__ == "__main__":
    main()
