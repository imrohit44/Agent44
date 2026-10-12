# Agent44 — Milestone 1: Transparent MCP stdio Proxy

Agent44 is a reproducible experiment investigating whether a policy/decision
layer in front of AI-agent tool calls can improve safety, explainability, and
efficiency. This milestone implements **only** a transparent MCP stdio proxy.

## Run the demo

```bash
uv run python -m agent44.proxy -- python -m agent44.demo_server
```

The command launches Agent44 as an MCP server on stdio. It, in turn, spawns the
demo server (`agent44.demo_server`) as a downstream subprocess, forwards tool
discovery and tool calls, and returns results unchanged.

Point any MCP stdio client at the above command to talk to Agent44.

## Tests

```bash
uv run pytest -q
uv run ruff check .
```
