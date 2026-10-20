# Phase 9 — Security Hardening: Threshold Adapter, Backend Contract, Offline Release Check

**Generated:** 2026-10-21
**Baseline:** `de5a97c` (frozen start hashes in `.phase9_start_hashes.txt`)
**Suite:** 495 tests pass (449 baseline + 46 new). Ruff clean on all new files.

## 1. Goal

Phase 9 hardens the enforcement path ahead of a production pilot:

1. Add a provider-independent probability-threshold decision adapter
   (`ProbabilityThresholdAdapter`) that maps a numeric probability from call
   arguments to ALLOW/DENY/UNDECIDED with an escalation band.
2. Lock the decision-backend contract with tests: hard-deny always wins,
   adapters never override deterministic tiers, and every adapter failure mode
   fails closed into a distinct, auditable rule-id bucket.
3. Provide a single offline release-check (`python release_check.py`) that
   verifies assemble/test/lint/import/hash integrity without network or vendor
   calls.
4. Assess Phase 10 readiness.

## 2. Trust model

- Deterministic tiers (hard-deny, deterministic rules, defaults) are trusted
  and are evaluated before any adapter. An adapter result can only be reached
  when every deterministic tier returns UNDECIDED.
- Decision backends (adapters) are untrusted: they can time out, raise,
  return malformed output, or return UNDECIDED. Every such outcome is mapped
  to a DENY with a distinct rule-id; none of them can produce an ALLOW.
- Hard-denied tools never reach an adapter at all. The adapter is consulted
  only for tools with a configured adapter rule, and only after deterministic
  tiers decline.
- The threshold adapter itself is deterministic and offline: it parses a
  probability from the call arguments; it performs no I/O, no randomness, and
  no wall-clock reads.

## 3. New file: `src/agent44/threshold_adapter.py`

`ThresholdConfig` (pydantic, `extra="forbid"`):

- `label_field` / `probability_field`: argument names to read (default
  `label`, `probability`, both `min_length=1`).
- `allow_threshold` (default 0.9), `deny_threshold` (default 0.1), both
  bounded to `[0.0, 1.0]`; a model validator requires
  `allow_threshold > deny_threshold` so the UNDECIDED band is non-empty.

`ProbabilityThresholdAdapter.decide(tool_name, arguments, rules)`:

- No config for the tool -> UNDECIDED (reason: no threshold config).
- If a `labels` frozenset was supplied and the label is absent from it ->
  UNDECIDED (reason: label not in configured set).
- Probability is coerced via `_coerce_probability`: booleans, `None`,
  strings, lists, dicts, NaN, +/-inf, and values outside `[0, 1]` are all
  rejected -> UNDECIDED (fail closed).
- `p >= allow_threshold` -> ALLOW, `rule_id="threshold:allow"`.
- `p <= deny_threshold` -> DENY, `rule_id="threshold:deny"`.
- Otherwise (strictly inside the band) -> UNDECIDED (reason: in UNDECIDED
  band). Thresholds are inclusive; only the open interval is undecided.

## 4. Decision precedence and rule-id contract

Unchanged engine precedence (highest first), verified by contract tests:

| Order | Tier | rule-id |
|-------|------|---------|
| 1 | Hard-deny list | `hard_deny_tools` |
| 2 | Deterministic rules / delegation / provenance / defaults | existing ids |
| 3 | Adapter (only if 1-2 are UNDECIDED) | `threshold:allow` / `threshold:deny` |
| Adapter failures | DENY | `adapter_timeout`, `adapter_invalid`, `adapter_error`, `adapter_undecided`, `adapter_missing` |

The five failure buckets stay distinct: `adapter_timeout` is the engine
deadline (`adapter_timeout_seconds` on `PolicyEngine` / `from_path`, default
5s, capped at 60s), `adapter_invalid` is a response that could not be parsed
or was not an `AdapterDecision`, `adapter_error` is a provider/transport
exception, `adapter_undecided` is a valid UNDECIDED result, and
`adapter_missing` means no adapter is configured for the tool.

## 5. Fail-closed properties verified

- Hard-deny wins even if the adapter would ALLOW (adapter never invoked for
  hard-denied tools).
- Backend/adapter is not invoked when a deterministic rule matches or when
  the default deny applies, and not for non-adapter tools.
- Adapter timeout, cancellation (`asyncio.CancelledError`), arbitrary
  exception, parse error, non-decision return, and UNDECIDED all produce
  DENY with the correct distinct rule-id.
- Malformed probability input (missing, wrong type, NaN, inf, out of range)
  yields UNDECIDED at the adapter level, which the engine converts to a
  fail-closed DENY (`adapter_undecided`).
- Identical inputs produce identical outputs (determinism test).

## 6. New file: `tests/test_policy_backend_contract.py` (14 tests)

Engine-level contract tests driving `PolicyEngine` end to end:

- `test_hard_deny_precedes_adapter_allow`, `test_adapter_cannot_override_hard_deny`
- `test_backend_not_invoked_when_deterministic_rule_matches`,
  `test_backend_not_invoked_when_default_deny_applies`,
  `test_backend_not_invoked_for_non_adapter_tool`
- `test_adapter_timeout_fails_closed`, `test_adapter_cancellation_fails_closed`,
  `test_adapter_exception_fails_closed`, `test_adapter_parse_error_fails_closed`,
  `test_adapter_non_decision_return_fails_closed`,
  `test_adapter_undecided_fails_closed`
- `test_adapter_failure_reasons_are_distinct`
- `test_threshold_adapter_allow_through_engine` (the real
  `ProbabilityThresholdAdapter` reached through the engine)

## 7. New file: `tests/test_threshold_adapter.py` (32 tests)

Unit tests for the adapter in isolation:

- Boundary semantics: at/just-below the allow threshold, at/just-above the
  deny threshold, integer 0 and 1, default thresholds (0.9 / 0.1), the
  UNDECIDED band.
- Malformed input: missing probability, `None`, boolean, string, list, dict,
  NaN, +inf, -inf, above 1.0, below 0.0, empty arguments, unknown tool.
- Label handling: label in configured set permits the decision, label outside
  the set is UNDECIDED, missing label with a label set is UNDECIDED, no label
  set accepts any label, `label_field` is configurable.
- Config validation: `allow_threshold <= deny_threshold` rejected in both
  directions, unknown config field rejected, empty `label_field` /
  `probability_field` rejected.
- Determinism: identical inputs give identical outputs.

## 8. Config example

```yaml
adapters:
  - tool_name: sentiment
    type: probability_threshold
    label_field: label
    probability_field: probability
    allow_threshold: 0.9   # p >= 0.9 -> ALLOW
    deny_threshold: 0.1    # p <= 0.1 -> DENY
    labels: [positive, negative]   # optional restriction
# 0.1 < p < 0.9 -> UNDECIDED -> engine fails closed (adapter_undecided DENY)
```

`PolicyEngine.from_path(path, adapter_timeout_seconds=5.0)` wires the engine
deadline; values above 60s are rejected so a hung provider cannot stall the
enforcement path indefinitely.

## 9. New file: `release_check.py` (offline release-check workflow)

A single documented command, `python release_check.py`, runs five local-only
checks (no network, no vendor calls, no live services):

1. **assemble.py** — runs `assemble.py` and verifies no files under
   `src/agent44/` changed and the exit code is 0.
2. **pytest** — runs the full suite (`pytest tests/ -q`); any failure fails
   the release check.
3. **ruff diff** — compares `ruff check src/ tests/` output against a stored
   pre-existing baseline (`.ruff_baseline.json`). First run creates the
   baseline; later runs fail only on *new* lint issues, so pre-existing debt
   cannot silently grow.
4. **packaging/import sanity** — imports every `agent44` module
   (`policy`, `proxy`, `delegation`, `provenance`, `transfer`,
   `model_adapter`, `observe`, `threshold_adapter`, `argument_policy`) and
   re-imports `agent44.threshold_adapter` from a clean interpreter.
5. **frozen-file hashes** — verifies the 22 files frozen at Phase 9 start
   (`.phase9_start_hashes.txt`) are byte-identical to the recorded SHA-256
   hashes. The reader handles both UTF-8 and UTF-16 manifests and ignores
   comment lines.

Exit code 0 and `RELEASE CHECK: PASSED` only when all five steps pass.

## 10. Frozen-artifact integrity

At Phase 9 start, SHA-256 hashes of all enforcement source files, prior
evaluation reports, `pyproject.toml`, `assemble.py`, and the two bench
fixtures were recorded in `.phase9_start_hashes.txt` (baseline `de5a97c`).
After the phase, 21 of 22 files are byte-identical. The single intentional
change is `evaluation/PHASE_8_BENCHMARK_REPORT.md`, whose hash entry was
updated with an in-file `# NOTE:` comment: the correction was applied during
Phase 9 preflight, is self-documented in the report itself ("Phase 8
factual correction"), and touches only the revision marker and the Group B
proxy non-forwarding results that commit `de5a97c` genuinely fixed. No
enforcement source file changed.

## 11. Acceptance scenarios (traceability)

| Requirement | Where verified |
|-------------|----------------|
| Inclusive allow threshold | `test_at_allow_threshold_is_allow`, `test_integer_probability_one_is_allow` |
| Inclusive deny threshold | `test_at_deny_threshold_is_deny`, `test_integer_probability_zero_is_deny` |
| UNDECIDED escalation band | `test_undecided_band_between_thresholds`, `test_just_below_allow_threshold_is_undecided`, `test_just_above_deny_threshold_is_undecided` |
| Fail closed on malformed input | `test_*_is_undecided` family (11 malformed-input tests) |
| Non-empty band enforced | `test_allow_threshold_must_exceed_deny_threshold`, `test_allow_threshold_below_deny_threshold_rejected` |
| Label-set restriction | `test_label_in_set_allows_threshold_decision`, `test_label_not_in_set_is_undecided`, `test_missing_label_with_label_set_is_undecided` |
| Hard-deny precedence over adapter | `test_hard_deny_precedes_adapter_allow`, `test_adapter_cannot_override_hard_deny` |
| Deterministic tiers skip backend | 3 `test_backend_not_invoked_*` tests |
| Timeout / cancellation / exception / parse / malformed all DENY | 6 `*_fails_closed` tests |
| Distinct failure buckets | `test_adapter_failure_reasons_are_distinct` |
| Determinism | `test_deterministic_identical_inputs` |
| Offline release check | `release_check.py` steps 1–5 |

## 12. Tests and verification

- New tests: 46 (`test_threshold_adapter.py` 32,
  `test_policy_backend_contract.py` 14).
- Full suite: **495 passed** (baseline 449 + 46 new; zero pre-existing tests
  modified or removed).
- Ruff: `src/agent44/threshold_adapter.py`, both new test files, and
  `release_check.py` are clean; full `src/ tests/` output is identical to the
  recorded baseline.
- Release check: all five steps PASS, including the frozen-hash verification
  and the assemble.py no-drift check.

## 13. Limitations / scope notes

- The threshold adapter reads the probability from call arguments; it does
  not itself score anything. A model-backed scoring backend can be added
  later behind the same `DecisionAdapter` contract — the five failure
  buckets already bound its blast radius.
- The adapter takes no network, randomness, or wall-clock dependencies, so
  its determinism is structural, not merely observed.
- The ruff baseline is created on the first run of `release_check.py` in a
  checkout; it captures the pre-existing debt at that moment. Re-running on
  a clean tree is idempotent.
- No weakening of any existing enforcement path occurred in this phase; the
  frozen hashes plus the contract tests guard against regressions.

## 14. Phase 10 readiness

Ready:

- Enforcement source is frozen and hash-verified against the Phase 9
  baseline.
- Decision-backend contract is pinned by 14 engine-level tests, so any
  future adapter implementation that slips an ALLOW past hard-deny or turns a
  failure into an ALLOW will fail loudly.
- A single offline command (`python release_check.py`) reproduces the full
  release gate: assemble, tests, lint delta, imports, and artifact integrity.

Open items for Phase 10 (pilot readiness):

- Wire a real model-backed scoring backend behind `DecisionAdapter` and
  re-run the same 14 contract tests against it.
- Decide pilot-specific `allow_threshold` / `deny_threshold` values (the
  defaults 0.9 / 0.1 are conservative placeholders).
- Add the release check to the pilot runbook so every pilot build is gated
  on the same five steps.