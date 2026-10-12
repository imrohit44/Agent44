# Agent44  Transparent MCP stdio Proxy, Observation, and Policy Enforcement

Agent44 is a reproducible experiment investigating whether a policy/decision
layer in front of AI-agent tool calls can improve safety, explainability, and
efficiency.

**Milestone 1** implements a transparent MCP stdio proxy. **Milestone 2** adds
an observation-only foundation: a typed `CallContext`, a non-intrusive
observation hook, redacted JSONL logging, a versioned test corpus, and an
evaluation runner. **Milestone 3** adds a minimal deterministic YAML policy
engine with `ALLOW`/`DENY` enforcement in the proxy. The evaluation runner
still runs observation-only: nothing is blocked there.

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
adversarial case is **not** a security block  no policy runs in this mode.

## Policy enforcement (Milestone 3)

Pass `--policy PATH` to enable enforcement. Every `tools/call` is evaluated
*before* it is forwarded downstream:

* `ALLOW`  the call is forwarded unchanged; results and error semantics are
  preserved exactly as when no policy is configured.
* `DENY`   the downstream server is **never invoked**. The proxy returns a
  tool-level `isError` result whose text carries only the static rule id and
  reason  never raw argument values.

```bash
uv run python -m agent44.proxy --policy policies/demo.yaml -- python -m agent44.demo_server
```

Add `--observe obs.jsonl` to record decisions alongside observations. Each
JSONL record gains `policy_action`, `policy_rule_id`, and `policy_reason`.
Without `--policy` these fields stay `null`, so an observation-only run can
never be misread as a policy block.

### Policy file

```yaml
version: "1"
name: demo-policy
default_deny: true
allow_tools: [add, echo]
deny_tools: [rm_rf]
rules:
  - id: deny-eval-flag
    tool: echo
    action: DENY
    reason: "argument 'eval' is not permitted on echo"
    when:
      field: eval
      field_exists: true
```

Deterministic precedence, highest first: explicit `deny_tools`  DENY rules
(first declared wins)  `allow_tools`  ALLOW rules (first declared wins)
 the `default_deny` default. A rule's `when` block takes exactly one of
`equals:` (type-strict scalar match on a dotted field path) or
`field_exists: true`.

`REVIEW` is deliberately **not** a valid action: there is no silently
permissive fallback and no dependency on a reviewer being available.

Validation is strict and happens at startup. An unknown action, malformed
rule, invalid field path, duplicate rule id, a tool listed in both
`allow_tools` and `deny_tools`, an unsupported version, an unknown key, or a
missing/unreadable file causes a non-zero exit with `policy error` on stderr
 enforcement never silently starts disabled. If evaluation itself throws at
runtime the proxy fails closed and denies the call.

### Enforced demo run

```bash
uv run python demo_enforce.py
```

Six real MCP calls through the proxy with `policies/demo.yaml`:
`allowed=2 denied=4 total=6`.
