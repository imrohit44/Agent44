# Agent44  Transparent MCP stdio Proxy + Observation Foundation

Agent44 is a reproducible experiment investigating whether a policy/decision
layer in front of AI-agent tool calls can improve safety, explainability, and
efficiency.

**Milestone 1** implements a transparent MCP stdio proxy. **Milestone 2** adds
an observation-only foundation: a typed `CallContext`, a non-intrusive
observation hook, redacted JSONL logging, a versioned test corpus, and an
evaluation runner. No policy is enforced and nothing is blocked yet.

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

## Observation (Milestone 2)

Run the proxy with an observation log. Observations never change results,
errors, or protocol behavior; diagnostics stay on stderr and the protocol stays
on stdout.

```bash
uv run python -m agent44.proxy --observe obs.jsonl -- python -m agent44.demo_server
```

Each tool call appends one JSONL record with event type, tool name, timing,
outcome, and *safe* argument metadata (type/length summaries only). Raw
argument values and raw tool results are never persisted; sensitive fields
(configured in `agent44.observe.DEFAULT_SENSITIVE_FIELDS`, e.g. `api_key`,
`password`, `token`) are recorded as `{"redacted": true}`.

## Evaluation runner

Replays the versioned corpus (`agent44.corpus`) through the proxy and writes a
machine-readable JSON report.

```bash
uv run python -m agent44.eval_runner -o eval_results.json --observe eval_observations.jsonl
```

This is **observation-only** (`"blocking": false`). It reports total calls,
outcomes, and latency percentiles (min/p50/p95/max). A non-error outcome for an
adversarial case is **not** a security block  no policy runs in this milestone.
