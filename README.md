# Agent44

Transparent MCP stdio proxy, observation, and policy enforcement.

Agent44 is a small, reproducible experiment investigating whether a policy and
decision layer in front of AI-agent tool calls can improve safety, explainability,
and efficiency.

## Overview

The project evaluates a deterministic policy engine positioned between an MCP
client and downstream tools. The central research question is whether inserting
a policy tier that validates, tags, and potentially blocks tool calls before they
reach the agent reduces unsafe or unintended behavior.

## Why this matters

AI agents routinely make tool calls without a structured safety boundary. A
policy layer can enforce allow-lists, deny-lists, and argument-level checks,
## How Agent44 works

Agent44 intercepts MCP tools/call requests through a stdio proxy. Before any
downstream tool execution, a deterministic policy engine evaluates the call:

1. **Argument validation** – argument shapes are checked against expected types
   and lengths; sensitive fields are redacted in observations.
2. **Deterministic rule evaluation** – YAML-declared ALLOW/DENY rules are matched
   using exact field equality and field_exists predicates. Hard-deny lists take
   absolute precedence.
3. **Adapter consultation** -- if the deterministic policy engine returns
   UNDECIDED for a tool that is listed in ``adapter_tools``, a configurable
   decision adapter may be consulted. Only tool names explicitly listed in
   ``adapter_tools`` in the policy are eligible for adapter consultation. An
   adapter ALLOW cannot override a deterministic DENY or hard-deny decision.
    
   
4. **Fail-closed** – any adapter timeout, error, or invalid output maps to a
   distinct DENY rule-id; no adapter output can override a deterministic DENY.

## Architecture

<details>
<summary>Architecture diagram (Mermaid flowchart)</summary>

```mermaid
flowchart TD
    MCPclient[MCP client / request] -->|tools/call| Proxy[Agent44 proxy]
    Proxy -->|Validate & route| Policy[Deterministic policy engine]
    Policy -->|ALLOW| Tool[Downstream tool execution]
    Policy -->|DENY| NoTool[Call denied; isError result]
    Policy -->|UNDECIDED| Adapter[Decision adapter / backend]
    Adapter -->|ALLOW| Tool
    Adapter -->|DENY| NoTool
    Adapter -->|UNDECIDED| NoTool
    style HardDeny fill:#ffdddd,stroke:#cc0000
    style DenyRule fill:#ffe5e5,stroke:#cc4444
    style Allow fill:#e6ffec,stroke:#44aa55
    style Undecided fill:#fff4c4,stroke:#aaaa22]
```

**Key boundaries:**
- Deterministic denials (hard-deny lists, explicit DENY rules) are always
  authoritative; an adapter can never override them.
- Backend errors, timeouts, and invalid outputs fail closed into DENY with a
  distinct rule-id bucket.
## Security model and trust boundaries

- **Deterministic tiers are authoritative.** Hard-deny lists and declared DENY rules
  are evaluated first and cannot be overridden by an adapter.
- **Adapters are untrusted.** The threshold adapter, LLM judge, or any remote
  backend can time out, return malformed output, or return UNDECIDED. Every
  such outcome is mapped to a DENY with a distinct rule-id; none can produce an
  ALLOW outside its configured band.
- **External tool content is untrusted.** Argument values from tool results are
  never persisted; observations record only safe metadata (type/length summaries).
- **Fail-closed decisions may reduce availability.** Denials block calls that
  might otherwise succeed, but this is intentional — the system never silently
  permits a call that a tier cannot decisively authorize.
- **A denied tool call does not prove end-to-end attack prevention.** Agent44
  evaluates individual tool calls in isolation; it does not secure an entire agent
  application against multi-step objectives.
  permits a call that a tier cannot decisively authorize.therwise succeed, but this is intentional — the system never silently
  permits a call that a tier cannot decisively authorize.
## Current capabilities

- **MCP stdio proxy** – forwards tools/list and tools/call between an MCP client
  and a downstream server via stdio.
- **Argument validation** – type/length checks at startup; sensitive fields
  configurable via agent44.observe.DEFAULT_SENSITIVE_FIELDS.
- **Deterministic policy engine** – YAML-declared ALLOW/DENY rules with
  when: equals: (dotted-field scalar match) or when: field_exists: true; hard-deny
  list; default_deny default.
- **Probability-threshold adapter** – maps a numeric probability from call
  arguments to ALLOW (p >= allow_threshold), DENY (p <= deny_threshold), or
  UNDECIDED (strictly between thresholds).
- **Observation-only logging** – JSONL logs of tool calls with redacted arguments;
  raw argument values and raw tool results are never persisted.
- **Evaluation runner** – replays a versioned corpus through the proxy and
  produces a machine-readable JSON report (call counts, outcomes, latency
  percentiles).
- **Release-check workflow** – single offline command (python release_check.py)
  that verifies assemble/test/lint/import/hash integrity without network calls.
## Quick start

### Prerequisites

- Python >=3.11, <3.14
- [UV](https://astral.sh/uv) (recommended) or pip

### Environment setup

```bash
# Clone and enter the repository
git clone <repo-url>
cd Agent44

# Create a virtual environment (UV recommended)
uv venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate

# Install dependencies
uv sync  # or: pip install -e ".[dev]"
```

### Running tests

```bash
uv run pytest -q
uv run ruff check .
```

### Running the release check

```bash
python release_check.py
```

### Running the offline evaluation

```bash
uv run python -m agent44.proxy -- python -m agent44.demo_server
```

 Runs the demo server behind the proxy (no policy enforcement).

```bash
uv run python -m agent44.proxy --policy policies/demo.yaml -- python -m agent44.demo_server
```

 Enables policy enforcement with the demo policy (blocks rm_rf and the eval
 argument on echo).

```bash
uv run python -m agent44.eval_runner -o eval_results.json --observe eval_observations.jsonl
```

 ## Configuration

Policy files are YAML documents read at proxy startup via `--policy PATH`.

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

- `default_deny` (bool) – if true, any tool not explicitly listed in
  `allow_tools` is denied unless an ALLOW rule matches.
- `allow_tools` (list of strings) – tools explicitly allowed; first-declared
  rule wins for a matching tool.
- `deny_tools` (list of strings) – tools explicitly denied; first-declared
  DENY rule wins for a matching tool.
- `rules[].id` – unique rule identifier; duplicate ids are rejected at startup.
- `rules[].tool` – the tool name the rule applies to.
- `rules[].action` – must be `ALLOW` or `DENY` (any other value causes a
  startup error).
- `rules[].reason` – free-text string carried in the `isError` result for DENY
  decisions.
- `rules[].when` – condition that must be satisfied for the rule to fire;
  exactly one of `equals:` (type-strict scalar match on a dotted field path)
  or `field_exists: true`.
- `rules[].when.equals:` – takes a value literal of the appropriate Python
  type (string, integer, boolean) for type-strict comparison against the
  corresponding dotted field in the call arguments.

## Benchmark methodology and metrics

The evaluation uses a versioned synthetic corpus (`agent44.corpus`) comprising
development scenarios that cover policy-eligible and adversarial tool-call cases.
Each scenario specifies expected deterministic rule behavior and provenance
tracking. The corpus is replayed through the proxy, and outcomes are recorded.

**Metrics reported:**
- Total calls, allowed, denied
- Decision accuracy (agreement between the engine's decision and the expected
  decision per scenario)
- False-block rate (0.0 = no tool hard-denied or DENY-ruled when ALLOW was
  expected)
## Current experimental findings

All results below come from synthetic development experiments. Scenarios are not
generalizable beyond the development corpus.

**Rules-only condition** (94 scenarios, development partition):

- Decision accuracy: 94/94 (1.000) — every scenario's expected decision matched
  the deterministic policy's output.
- False-block rate: 0/94 (0.0)
- False-allow rate: 0/94 (0)

**Rules plus local judge condition** (94 scenarios, development partition;

- Decision accuracy: 90/94 (~0.957), four false allows relative to expected
  labels.
- The judge was consulted on 6 scenarios (18 model calls across 3 trials per
  scenario). Of the 94 scenarios, 88 were decided solely by deterministic rules
  with `adapter=None`; the judge was not consulted for these.
- The local judge did not improve decision accuracy in this experiment.
- Four false allows occurred when the deterministic policy returned
  UNDECIDED and the judge returned ALLOW despite the expected label being DENY.
  These scenarios included ambiguous-adversarial, adapter-failure, ambiguous-label,
  and prompt-injection categories.
- Jev and ScaleDown adapters are implemented and documentation-verified, but no
  comparative live results are claimed for them while they remain unavailable.

**Important caveats:**

- Scenarios are synthetic and development results do not establish generalization.
- Tool-call blocking is not proof of end-to-end attack prevention.
- A passing test suite is not proof of production-grade security.
- Cost and latency claims apply only to the measured configuration.
- Held-out evaluation has not yet been authorized or performed.
- The local judge uses a versioned, fixed prompt and a strict JSON parser; its
  behavior with different models or temperatures is untested.
- Remote backends (Jev `noul`, ScaleDown `/classify`) remain `status=unavailable`
  without confirmed API keys; no live access checks or live calls were made.

## Evaluation results

The development corpus contains 94 scenarios. Results are reported at the
per-scenario level, collapsing repeated trials to one outcome per scenario.

### Condition B — rules only (deterministic policy engine, no adapter)

- **94/94 scenarios resolved** — every scenario has a definitive ALLOW or DENY
  outcome from the deterministic policy.
- **0 false allows** — 0 scenarios where the policy returned ALLOW but the
  expected label was DENY.
- **0 false denies** — 0 scenarios where the policy returned DENY but the
  expected label was ALLOW.
- **Decision accuracy: 1.000 (94/94)**. Denominator: 94 distinct scenarios.

The source data is `evaluation/phase10_runs/condition_b_rules_only.json`.

### Condition C — rules + local judge (deterministic policy + LLM judge adapter)

- **94/94 scenarios resolved** — every scenario has a definitive outcome.
- **90/94 correct decisions** — 90 scenarios where the final decision (deterministic
  policy + judge when consulted) matched the expected label.
- **4 false allows** — 4 scenarios where the deterministic policy returned DENY (or
  UNDECIDED) and the judge returned ALLOW, resulting in a decision that expected DENY.
  These scenarios included: ambiguous-adversarial (label ambiguous), adapter-failure
  (label invalid), adapter-eligible (label ambiguous), and prompt-injection (label
  malicious, `pi-review-injection-persuade-01`).
- **0 false denies** — 0 scenarios where the final decision incorrectly denied a
  scenario expected to be allowed.
- **Decision accuracy: 0.957 (90/94)**. Denominator: 94 distinct scenarios.

**Model call volume:** The judge was consulted on 6 `review_tool` scenarios (where
deterministic policy returned UNDECIDED), each with 3 trials aggregated by majority
vote. Total model calls: 6 × 3 = 18. Of the 19 `review_tool` scenarios in the
corpus, 13 were decided by deterministic rules alone (with specific rule IDs such
as `hard-review-eval`, `deny-inject-*`, `adapter-grant-ok`) and `adapter=None`;
the judge was not consulted for these.

**Backend contribution:** The judge overturned the rules-only decision in 4 scenarios,
all of which were cases where the deterministic policy had returned UNDECIDED and
the judge returned ALLOW. All 4 are false allows relative to the expected DENY
label. No scenario had the judge override a deterministic ALLOW or a hard-deny.

**Latency:** p50=0.041 ms, p95=3011 ms, max=5017 ms (n=94, all scenarios). Model
inference latency is included only for the 6 consulted scenarios; the rules-only
path has effectively zero additional latency.

The source data is `evaluation/phase10_runs/condition_c_judge.json`.

**Important caveats:**

- The corpus is synthetic and used for development only; results do not establish
  generalization.
- Tool-call blocking is not proof of end-to-end attack prevention.
- A passing test suite is not proof of production-grade security.
- Cost and latency claims apply only to the measured configuration.
- Held-out evaluation has not yet been authorized or performed.
- The local judge uses a versioned, fixed prompt and a strict JSON parser; its
  behavior with different models or temperatures is untested.
- Remote backends (Jev `noul`, ScaleDown `/classify`) remain `status=unavailable`
  without confirmed API keys; no live access checks or live calls were made.

## Limitations and threat model

- The synthetic development corpus does not represent all possible tool-call
  patterns or adversarial inputs.
- Threshold adapter probability is read from call arguments; it does not itself
  score or model anything. A model-backed scoring backend can be added later
  behind the same `DecisionAdapter` seam.
- The local judge uses a versioned, fixed prompt and a strict JSON parser; its
  behavior with different models or temperatures is untested.
- Deterministic denials are authoritative, but an insufficiently broad rule set
  can leave gaps.
- Fail-closed decisions reduce availability: some calls that could be safe are
  blocked because no tier could decisively authorize them.
- External tool content (both arguments and results) is treated as untrusted.

## Security reporting

This project is an experimental security research implementation. If you
discover a vulnerability, **do not** disclose it in a public issue tracker.

Report vulnerabilities privately by opening a private security advisory through
the repository's security settings (if available) or by contacting the maintainers
directly. Include:

- A clear description of the issue, including the policy configuration and
  corpus scenario involved.
- Steps to reproduce the observed behavior.
- The expected and actual decisions, with scenario identifiers.
- Any relevant logs or evaluation artifacts.

Public issue trackers should not be used to disclose exploitable vulnerabilities
before maintainers can respond.

## License

Copyright 2026 Agent44 contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Contributing

See `CONTRIBUTING.md` for guidelines on setting up the development environment,
coding and formatting expectations, how to run focused tests and the full suite,
how to add a synthetic scenario, and requirements for preserving benchmark integrity.

## Acknowledgements

The MCP stdio proxy architecture draws on the Model Context Protocol (MCP)
specification. The policy engine uses YAML for declarative rule definitions.
Observation logging uses JSONL with redaction consistent with privacy best
practices.
```
</details>