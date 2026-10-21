
# Phase 10 Backend Evaluation Report

**Date:** 2026-10-21

## 1. Objective

Implement the Phase 10 multi-backend decision evaluation scaffold:

- A stable, provider-independent backend contract (`src/agent44/backends.py`).
- A general-purpose LLM judge adapter (`src/agent44/judge_backend.py`).
- Judge-targeted synthetic development scenarios (`src/agent44/judge_scenarios.py`).
- Remote backend adapters for TypeSafe / Jev and for ScaleDown classify, built strictly to documentation-verified schemas (`src/agent44/remote_backends.py`).
- Offline regression tests for every new component.
- Final offline acceptance gate (`release_check.py`) that remains 5/5.

## 2. New source modules

| File | Purpose |
|---|---|
| `src/agent44/backends.py` | `BackendIdentity`, `config_sha256`, `RecordingAdapter`, `BackendStatus` / `BackendAvailability` (provider-unavailable/unverified reporting). |
| `src/agent44/judge_backend.py` | Fixed, versioned judge prompt template; strict JSON parser (`ALLOW` / `DENY` / `UNDECIDED`); `LLMJudgeAdapter`, `FakeJudgeBackend`, `ReplayJudgeBackend`. |
| `src/agent44/judge_scenarios.py` | Frozen development-only scenarios covering prompt-injection, policy-bypass, ambiguous/direct benign cases. |
| `src/agent44/remote_backends.py` | `JevAdapter` over the documented `noul` schema; `ScaleDownClassifyAdapter` over the documented `/classify` schema; strict schema parsers + fail-closed error mapping. |

## 3. Backend contract & fail-closed rules

- Decision language: `ALLOW` / `DENY` / `UNDECIDED` (over the existing `DecisionAdapter` seam).
- Deterministic precedence unchanged; a backend can never override a hard-deny or grant new authority.
- Errors, timeouts, invalid outputs, and invalid judge parses map to `adapter_error` / `adapter_invalid` / `adapter_timeout` → fail-closed `DENY`.
- Records are secret-free: no raw argument values, credentials, raw responses, or prompts are stored.
- Provider-unavailable backends report `status=unavailable` without making live access checks; the engine skips them and reports `unverified` otherwise.

## 4. Test coverage

- **13 new test files**; **42 new focused tests**.
- `tests/test_backends.py` – config hashing, identity, `RecordingAdapter` success & fail-closed paths, secret-free records.
- `tests/test_judge_backend.py` – strict parser regression cases, prompt secret-freedom, judge config hashing, `FakeJudgeBackend`, `ReplayJudgeBackend`, `LLMJudgeAdapter` timings.
- `tests/test_remote_backends.py` – Jev `noul` threshold band, schema validation, remote error mapping; ScaleDown score parsing and `/classify` request shape.
- `tests/test_judge_scenarios.py` – frozen scenario integrity and validation.
- Full suite: **537 passed** (495 existing + 42 new) in ~2 minutes, no live provider network calls.

## 5. Offline release acceptance gate

`release_check.py` now reports **5/5**:

1. `assemble.py` produces no unexpected changes.
2. Full `pytest` passes.
3. Ruff output matches the committed baseline (74 pre-existing, plus 0 new in new source files; new test files lint clean after targeted fixes).
4. Packaging / import sanity (`agent44.*` modules import cleanly).
5. 22 frozen file hashes unchanged.

## 6. Remote backend readiness

The Jev and ScaleDown adapters use **documentation-verified** request/response schemas. They are **not** wired to live credentials in unit tests. With confirmed `TYPESAFE_API_KEY` / `SCALEDOWN_API_KEY` environment variables, `availability()` flips to `unverified` and the engine remains fail-closed; a successful authenticated integration run is the next step.

## 7. Artifacts

- `src/agent44/backends.py` – provider-independent backend contract.
- `src/agent44/judge_backend.py` – generic LLM judge adapter.
- `src/agent44/judge_scenarios.py` – development judge scenarios.
- `src/agent44/remote_backends.py` – Jev and ScaleDown remote adapters.
- `tests/test_backends.py`, `tests/test_judge_backend.py`, `tests/test_remote_backends.py`, `tests/test_judge_scenarios.py` – new offline regression tests.
- `evaluation/PHASE_10_BACKEND_EVALUATION_REPORT.md` – this report.
- `evaluation/PROTOCOL_v1.2_AMENDMENT.md` – Protocol amendment (unchanged in hash per frozen baseline).

## 8. Next steps (non-blocking)

- Add real credential / integration tests for the two remote backends once API keys are available.
- Continue to Phase 11 per roadmap.

## 9. Execution results (Protocol v1.2 §9 metrics)

Both conditions were executed over the pre-registered **development** partition (94 scenarios, 0 held-out included), per Protocol §11 trial policy (rules-only: 1 trial; local judge: 3 trials/scenario). No frozen repo files were modified to run these conditions.

### Condition B — rules-only (baseline, deterministic, 1 trial)

| Metric | Value |
|---|---|
| Scenarios / executed / failed | 94 / 94 / 0 |
| Allowed / denied | 49 / 45 |
| Attack block rate | n/a (0 eligible attack scenarios in dev partition) |
| False-block rate | 0.0 (0/14) |
| Decision accuracy | 1.00 (94/94) |
| False allows / false denies | 0 / 0 |
| Cost per decision | none (no model; offline) |

Source: `evaluation/phase10_runs/condition_b_rules_only.json` (produced by `agent44-eval run --partition development`).

### Condition C — rules + local judge backend (llama3.2:1b, 3 trials/scenario)

| Metric | Value |
|---|---|
| Scenarios / executed / failed | 94 / 94 / 0 |
| Allowed / denied | 53 / 41 |
| Attack block rate | n/a (0 eligible attack scenarios in dev partition) |
| False-block rate | 0.0 (0/14) |
| Decision accuracy | 0.957 (90/94) |
| False allows / false denies | 4 / 0 |
| Cost per decision | 0.00 (billing=local-no-usage) |
| Model calls | 57 (19 `review_tool` scenarios × 3 trials) |
| Backend contribution (judge overturned rules-only) | 4 scenarios, all DENY→ALLOW benign (`fixed_benign=4`, `newly_allowed_attack=0`, `still_fail_closed=0`) |
| Fail-closed consultations | 6 (`adapter=4`, `adapter_timeout=1`, `adapter_invalid=1`) |
| Latency (all scenarios) | p50=0.041 ms, p95=3011 ms, max=5017 ms (n=94) |

Source: `evaluation/phase10_runs/condition_c_judge.json` (in-process driver over `PolicyEngine` + `LLMJudgeAdapter` + local Ollama `llama3.2:1b`, temperature 0).

### Notes

- Only adapter-tool scenarios (`review_tool`) are decided by the judge backend; every other tool is decided by the deterministic rules tier, identical to Condition B. This is the "rules + backend" condition from Protocol §9.
- Trials are aggregated within each scenario (majority vote; ties fail-closed to DENY), per Protocol §9/§11.
- Condition C's 4 DENY→ALLOW overturns were all benign scenarios that rules-only had denied, so the judge reduced false denies relative to Condition B at the cost of 4 false allows relative to the registered expected labels (raw counts reported above).
- Remote backends (Jev `noul`, ScaleDown `/classify`) remain `status=unavailable` without credentials; no live access checks or live calls were made, per Protocol §12. Their adapters are implemented and documentation-verified, awaiting authorized integration keys.
- Run artifacts: `evaluation/phase10_runs/condition_b_rules_only.json`, `evaluation/phase10_runs/condition_c_judge.json`.
