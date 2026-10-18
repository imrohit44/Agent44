# Phase 6 — Deterministic Provenance / Taint Tracking with Trust-Boundary Policy Enforcement

## 1. Goal

Add deterministic, Agent44-owned provenance (taint) tracking for MCP tool-call
arguments, and make trust boundaries enforceable by policy *before* a call is
forwarded downstream. Provenance answers, for every argument of every call:

* where the value came from (which trust boundary),
* how trustworthy it is right now (`trusted`, `untrusted`, `derived_untrusted`),
* and whether an explicit validation/sanitization transition has elevated it.

The feature is opt-in: with `provenance.enforcement: off` (the default),
behavior is bit-for-bit the legacy behavior verified in Phase 5. No model
inference, network access, or pilot artifacts are involved anywhere in this
phase.

## 2. Trust model

* **Trust is Agent44-internal only.** Provenance ids are generated exclusively
  by `ProvenanceRegistry` (`uuid4().hex`). Callers can never mint, supply, or
  rename a provenance id; a caller field such as `{"trusted": true}` or
  `{"provenance_id": "..."}` is an ordinary *business argument* and is never
  interpreted as a provenance claim.
* **Every incoming tool-call argument is untrusted at the proxy input
  boundary.** The proxy classifies each argument with
  `classify_external(boundary="proxy_input")` before policy evaluation.
* **Taint is sticky.** `derive()` on any untrusted (or derived-untrusted)
  parent yields `DERIVED_UNTRUSTED`; combining trusted and untrusted parents
  retains the taint. Only `validate_transition()` — an explicit, recorded
  sanitization/validation boundary — may elevate a record to `TRUSTED`, and it
  elevates only the derived record, never its parents.
* **Missing or unknown provenance is never trusted.** `effective_trust(None)`
  and `effective_trust(forged_id)` both resolve to `UNTRUSTED`.
* **Fresh registry per call.** Each call builds its own registry, so metadata
  is bounded and no taint carries across calls (cross-call taint is explicitly
  out of scope, see §13).

## 3. New file: `src/agent44/provenance.py`

| Element | Purpose |
| --- | --- |
| `TrustClass` (StrEnum) | `trusted`, `untrusted`, `derived_untrusted` |
| `ProvenanceRecord` (frozen dataclass) | `provenance_id`, `trust_class`, `source_category`, `parent_ids`, `validation_transition`, `boundary`, `depth`, `timestamp` — immutable, no raw values |
| `ProvenanceRegistry` | Per-call store with `classify_external`, `classify_trusted`, `derive`, `validate_transition`, `effective_trust`, `get_record` |
| `ProvenanceContext` | Immutable `registry` + `values: dict[argument_name, provenance_id]`; `with_argument()` returns a copy |
| `ProvenanceError` / `ProvenanceLimitError` | Forged/unknown/malformed references and bound violations |

Fail-closed registry properties:

* unknown provenance ids resolve to `UNTRUSTED` (never trusted);
* duplicate parent references are rejected (`ProvenanceLimitError`);
* cycles are impossible by construction (records are immutable, ids generated
  fresh, parents must already exist);
* bounds are enforced: `max_records=10_000`, `max_depth=16`, `max_parents=8`;
  exceeding any bound raises `ProvenanceLimitError`.

## 4. Modified file: `src/agent44/policy.py`

* **`ProvenanceArgumentRule`** — per-tool restrictions; every clause can only
  *deny*, never grant authority:
  * `deny_untrusted: [arg, ...]` — deny when effective trust is `untrusted` or
    `derived_untrusted`;
  * `require_known: [arg, ...]` — deny when no provenance record is mapped;
  * `allowed_trust_classes: {arg: [classes...]}` — deny when the effective
    class is not listed;
  * `require_transition: {arg: transition_id}` — deny unless the record was
    elevated through exactly that validation transition.
* **`ProvenanceConfig`** — `enforcement: off|required` (default `off`) plus
  `rules: {tool: ProvenanceArgumentRule}`; `extra="forbid"` on both models.
* **`Policy.provenance`** field and `"provenance"` accepted as a valid
  top-level policy key; unknown provenance keys still fail validation.
* **`Decision`** gained optional `provenance_id`, `trust_class`,
  `validation_transition` fields — populated only when a provenance-aware
  denial occurred; never contain raw argument values.
* **`PolicyEngine._provenance_decision`** — a fail-closed DENY tier inserted
  between `hard_deny_tools` and argument constraints. When
  `enforcement == "required"` and a rule exists for the tool:
  * a missing context is treated as an *empty* context, so every restriction
    fails closed rather than being skipped;
  * an unconfigured tool is unaffected;
  * with `enforcement: off` or no context needed, the tier returns `None`
    (legacy behavior).
* `match_rules`, `decide`, and `evaluate` accept an optional
  `provenance_context` keyword (default `None`) — fully backwards
  compatible; Phase 5 call sites are unchanged.
* `PolicyEngine` exposes `provenance`, `policy_id`, `policy_version`
  properties for proxy-side checks.

## 5. Modified file: `src/agent44/proxy.py`

`call_tool` now, **before forwarding**:

1. If a policy is loaded and `provenance.enforcement == "required"`, build a
   fresh `ProvenanceRegistry` and classify every incoming argument as
   untrusted (`boundary="proxy_input"`), producing a `ProvenanceContext`.
2. Any exception while building the context sets `provenance_unavailable`
   and yields an explicit DENY with `rule_id="provenance:fail_closed"`
   *before* the policy decision — enforcement can never silently become a
   no-op.
3. The context is passed to `state.policy.decide(...)`.
4. A DENY at any tier is recorded (with provenance metadata) and returned as
   a tool-level error; **the downstream server is never invoked**.
5. `enforcement: off` (or no policy) skips provenance setup entirely —
   identical to Phase 5 behavior.

Caller-supplied fields are never inspected for trust semantics: only the
registry's own records decide classification.

## 6. Modified file: `src/agent44/observe.py`

* `ObservationEvent`, `to_dict`, `from_call`, and `record_observation` accept
  optional `provenance_id`, `trust_class`, `validation_transition`.
* These keys are serialized **only when non-None**, so all existing
  observation fixtures and Phase 4/5 consumers are unaffected.
* The proxy denial path forwards the decision's provenance metadata into the
  observation, giving an auditable record of *why* a call was blocked
  (rule id, trust class, provenance id, transition) without ever storing raw
  argument values (the existing `safe_arguments` type-shape redaction is
  unchanged).


## 7. Config example

```yaml
version: "1"
name: prov-demo
default_deny: true
allow_tools: [add, hit]
provenance:
  enforcement: required        # "off" (default) preserves legacy behavior
  rules:
    hit:
      deny_untrusted: [label]            # untrusted / derived-untrusted => deny
      require_known: [context]           # no record established => deny
      allowed_trust_classes:
        source: [trusted]                # only listed classes may pass
      require_transition:
        payload: sanitize_pii            # must be validated via this transition
```

Note: YAML scalars `off`/`on` are booleans in YAML 1.1 — write
`enforcement: "off"` when quoting is desired; pydantic rejects a bare
`enforcement: false`.

## 8. Decision precedence and rule-id contract

Tier order in `match_rules` (highest first):

1. `hard_deny_tools`
2. **provenance restrictions** (Phase 6, only when `enforcement: required`)
3. argument constraints (Phase 5)
4. hard DENY matching rules
5. `deny_tools`
6. soft DENY matching rules
7. `allow_tools`
8. soft ALLOW matching rules → default decision

Provenance denials therefore cannot be overridden by `allow_tools` or any
lower tier; only `hard_deny_tools` outranks them. Rule-id format:

```
provenance:{tool}:{category}:{argument_name}
```

where `category ∈ {deny_untrusted, require_known, allowed_trust_classes,
require_transition}`, plus `provenance:fail_closed` for the proxy's
context-unavailable guard. Reasons are static policy text
(`provenance policy denied argument 'label' (deny_untrusted)`) — raw
argument values are never embedded in reasons, decisions, or observations.

## 9. Fail-closed properties verified

* **Forged claims**: caller-supplied `trusted`/`provenance_id` fields are
  business arguments; unknown ids resolve to `UNTRUSTED` → deny.
* **Missing provenance**: `require_known` denies; enforcement `required` with
  no context evaluates against an empty context (deny, not skip).
* **Proxy context failure**: any exception during context construction
  → `provenance:fail_closed` DENY before forwarding.
* **Policy evaluation failure**: unchanged Phase 5 guard → `fail_closed` DENY.
* **Bounds**: record/depth/parent limits raise `ProvenanceLimitError`;
  duplicate parents rejected; registry graph is acyclic by construction.
* **Taint stickiness**: any untrusted parent ⇒ `derived_untrusted` outcome;
  only an explicit recorded transition elevates, and it does not launder the
  source record.
* **Opt-out is explicit**: `enforcement: off` is the default and performs no
  provenance evaluation at all.


## 10. Acceptance scenarios (traceability)

| # | Scenario | Test |
| --- | --- | --- |
| 1 | Trusted input passes a `deny_untrusted` rule | `test_provenance_policy.py::test_trusted_input_passes_deny_untrusted_rule` |
| 2 | Untrusted input denied with provenance metadata | `test_provenance_policy.py::test_untrusted_input_is_denied_with_provenance_metadata` |
| 3 | Forged provenance claim not trusted (engine + proxy) | `test_forged_provenance_claim_is_denied`, `test_forged_caller_claim_does_not_bypass_provenance` |
| 4 | Derived-untrusted retains taint (no laundering) | `test_derived_untrusted_retains_taint` |
| 5 | Validation transition elevates use | `test_validation_transition_elevates_and_permits_use`, `test_wrong_validation_transition_is_denied` |
| 6 | Missing provenance fails closed | `test_missing_provenance_fails_closed`, `test_enforcement_required_without_context_denies` |
| 7 | Denial prevents downstream forwarding | `test_provenance_denial_never_reaches_downstream` (counter server never runs) |
| 8 | Legacy behavior unchanged when off | `test_enforcement_off_preserves_legacy_behavior`, `test_legacy_proxy_behavior_unchanged_when_off` |

Precedence and scope checks: `test_provenance_denial_cannot_be_overridden_by_allow_tools`,
`test_hard_deny_takes_precedence_over_provenance`,
`test_unconfigured_tool_is_unaffected`,
`test_allowed_trust_classes_clause`.

## 11. Tests

* `tests/test_provenance.py` — **21 tests** (unit): classification,
  propagation/derivation, forged/unknown/missing refs, validation
  transitions, registry bounds, `ProvenanceContext`.
* `tests/test_provenance_policy.py` — **16 tests**: the 8 acceptance
  scenarios (engine-level and real-proxy, async MCP sessions) plus
  precedence/scope checks; observation assertions confirm provenance
  metadata and absence of raw values.
* Full suite: **386 passed** (349 Phase 5 baseline + 37 new) — 0 failures,
  0 regressions.
* `ruff check src/ tests/` — clean.

## 12. Verification

* `python -m pytest -q` → `386 passed in ~149s`.
* `ruff check src/ tests/` → `All checks passed!`.
* Frozen artifacts unchanged (`git status`/`git diff` clean for
  `evaluation/PROTOCOL_v1.md`, `evaluation/PILOT_PLAN_4f.6_v1.md`,
  `evaluation/PROTOCOL_v1.1_AMENDMENT.md`, `evaluation/PHASE_5_ARGUMENT_POLICY_REPORT.md`,
  `README.md`).
* No inference run: no Ollama/LLM calls, no network; tests are offline MCP
  stdio sessions against the in-repo demo/counting servers.
* Temp sanity scripts (`tmp_prov_sanity.py`, `tmp_proxy_obs_test.py`)
  deleted before commit.

## 13. Limitations / scope notes

* **Per-call registry only.** No cross-call taint carryover; provenance from
  call N is invisible to call N+1 (bounded metadata by design).
* **Caller fields are inert.** Only classification by Agent44 code creates
  trust; there is no path for an external system to attest a value yet —
  `classify_trusted`/`validate_transition` are intended for trusted internal
  code paths (e.g., a sanitizer step) wired in later phases.
* **`enforcement: required` is opt-in.** Existing policies without a
  provenance block behave exactly as before; the demo policy is unchanged.
* **Successful (ALLOW) observations do not yet carry provenance metadata** —
  only denials populate it; extending the success path is trivial and
  intentionally deferred.
* **Provenance ids are opaque uuid4 handles** — classification, propagation,
  and decisions are deterministic; id strings themselves are not stable
  across runs.
* **JSON-Schema validation of downstream argument sanitization** and
  cross-boundary (multi-hop) taint remain future work.

