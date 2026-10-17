# Phase 5 — Argument-Level Policy Enforcement

**Milestone:** 4a (deterministic policy engine)
**Branch/commit:** `main`, HEAD `9910536` — working tree clean, all 349 tests passing, `ruff check` clean.

## Goal

Extend the enforcement proxy with **argument-level policy constraints**: a declarative, config-driven
mechanism that validates the *arguments* of an MCP tool call *before* it is forwarded downstream.
A call that violates any constraint is denied with a tool-level error and never reaches the
downstream server. The layer is deterministic (no model, no eval, no regex evaluation of values),
fail-closed, and cannot be overridden by any later tier (adapter or default).

## What changed

### New file: `src/agent44/argument_policy.py`

Standalone, dependency-light engine (only pydantic for config validation):

- `ArgumentPolicy.from_config(config)` — builds an engine from a `{"tools": {...}}` mapping.
  Every structural problem (bad type, non-list enum, `minimum > maximum`, empty names, unknown
  keys, …) raises `ArgumentPolicyConfigError` so the proxy refuses to start with invalid config.
- `ArgumentPolicy.evaluate(tool_name, arguments) -> ArgumentPolicyResult` — deterministic,
  order-independent (arguments visited in sorted order), short-circuiting on the first failure.
  Unconfigured tools are not constrained (existing behavior preserved). Non-mapping arguments are
  denied. Reasons never embed raw argument values or names.

Constraint categories:

| Category | Meaning |
|---|---|
| `required` | argument must be present |
| `type` | `bool`, `int`, `float`, `str` — booleans are never accepted as `int`/`float` and vice versa |
| `enum` | value must be one of the declared literals |
| `minimum` / `maximum` | inclusive numeric bounds |
| `min_length` / `max_length` | inclusive string-length bounds |

Tool-level option `unknown_arguments: "allow" \| "deny"` (default `allow`) rejects arguments not
declared in the tool's constraint set.

### Modified file: `src/agent44/policy.py`

- New top-level policy key `argument_constraints` (added to `_POLICY_KEYS`; unknown keys still
  rejected at load). Schema validated with pydantic models imported from `argument_policy`
  (`extra="forbid"` on all constraint models).
- `PolicyEngine` compiles an `ArgumentPolicy` from the configured constraints at construction;
  invalid constraints raise `PolicyError`, so enforcement never silently starts without them.
- New decision tier in `match_rules` (used by both `decide` and sync `evaluate`), placed **after**
  `hard_deny_tools` and **before** `deny_tools`:

  `hard_deny_tools` > **argument constraints** > hard DENY rules > `deny_tools` > DENY rules >
  `allow_tools` > ALLOW rules > adapter > default.

  Argument constraints refine, never loosen: a tool in `allow_tools` is still denied when its
  arguments violate a constraint; a hard-denied tool is denied regardless of arguments. No adapter
  can override an argument-constraint denial.
- Denial reasons are static policy text (`"<category>: <static message>"`); rule id
  `argument_constraints:<tool>`. No raw values leak into decisions or observation logs.

### No change required: `src/agent44/proxy.py`

The proxy already evaluates `PolicyEngine.decide` before forwarding and returns a tool-level error
for DENY, so argument denials flow through the existing path with the same observation recording
(`policy_action`, `policy_rule_id`, `policy_reason`).

## Config example

```yaml
version: "1"
name: agent-constraints
default_deny: true
allow_tools: [add, echo]
argument_constraints:
  add:
    unknown_arguments: deny
    arguments:
      a:
        type: int
        minimum: 0
        maximum: 1000
      b:
        type: int
        required: true
  echo:
    arguments:
      message:
        type: str
        max_length: 1000
```

## Fail-closed properties verified

- Malformed `argument_constraints` → proxy exits with `policy error` at startup (never runs
  without a valid policy).
- Engine/config errors during evaluation are impossible by construction (config validated at
  load); non-mapping arguments deny rather than crash.
- DENY returns `types.CallToolResult(isError=True)` — never an MCP protocol error, never a
  downstream call.
- Denial text and JSONL observations contain no argument values.
- Observer failures never change call outcomes (pre-existing guarantee, still holds).

## Tests

**`tests/test_argument_policy.py`** (35 unit tests): config loading, passthrough of unconfigured
tools, strict type checking (bool vs int/float, str), enums, inclusive numeric bounds, string
lengths, required/optional arguments, unknown-arguments allow/deny/default, sorted deterministic
first-failure reporting, non-mapping/None arguments, no value leakage in reasons, and 13 malformed
config cases.

**`tests/test_policy.py`** (6 new tests): YAML loading of `argument_constraints`, engine-level
allow/deny decisions, required-argument denial, proxy integration proving a denied call never
reaches the downstream counter tool, unknown-argument blocking, startup refusal for invalid
constraints, and JSONL observation of argument denials.

## Verification

- `python -m pytest -q`: **349 passed** (pre-existing 342 + 7 new).
- `python -m ruff check src/ tests/`: clean.

## Limitations / scope notes

- Cross-argument constraints (e.g. "if `mode` is `write` then `target` is required") are not
  supported; each argument is validated independently.
- Tools without an entry in `argument_constraints` are not constrained — this preserves existing
  behavior and keeps the layer opt-in per tool.
- Exact-value/presence argument rules remain available via `PolicyRule` (`when: {field, equals
  \| field_exists}`); the new layer is for typed/schema-style constraints.