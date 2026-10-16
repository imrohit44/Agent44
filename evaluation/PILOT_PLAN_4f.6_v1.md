# Agent44 Development Pilot Plan — 4f.6 v1 (Predeclared, Warm-Start Aware)

**Status: DRAFT — NOT APPROVED FOR EXECUTION.**
This plan is prepared for review only. The 20-scenario live-model pilot must
not be executed without separate, explicit approval. It lives outside the
frozen protocol (`PROTOCOL_v1.md`) and does not amend it; it is an
operational plan for one bounded development-partition pilot.

## 1. Purpose and scope

A strictly-local, explicitly bounded development pilot of the Agent44
enforcement proxy with a live local Ollama model (`llama3.2:1b`) as the
adapter-tier decision backend, using the 20 predeclared development
scenarios. The purpose is infrastructure validation and descriptive
measurement of live-model behavior — **not** a claim about model quality.

Cold-start model loading (measured at 5–10+ s on this machine, exceeding the
5.0 s adapter deadline) is made explicit and separated from decision quality
by the readiness/priming procedure in `agent44.readiness`, so adapter
timeouts cannot be silently attributed to the model's decisions.

## 2. Exact scenario set (20) and source

Source: `D:\Agent44Pilot4e\SELECTION_IDS.txt` and the `explicit_selection`
block of `D:\Agent44Pilot4e\manifest.json` (pre-registered 2026-10-16,
before any inference). Selection rule (verbatim from PRECHECK): *all
development adapter-tier (review_tool) scenarios (19) + first non-adapter
development scenario in stable corpus order (benign-add-basic-02); decided
before any inference.*

```
hard-deny-beats-adapter-01
adapter-grant-02
adapter-undecided-01
adapter-deny-rule-01
adapter-grant-flag-false-01
adapter-missing-tool-arg-01
adapter-malformed-string-01
adapter-malformed-action-01
adapter-malformed-undecided-01
adapter-failure-timeout-01
adapter-failure-missing-01
adapter-failure-missing-02
pi-review-injection-persuade-01
pb-review-spoof-hard-01
pb-review-eval-spoof-01
cr-review-eval-blocked-01
cr-review-token-blocked-01
aa-review-neutral-01
hdi-review-grant-with-hard-eval-01
benign-add-basic-02
```

All 20 ids are in the **development** partition (validated fail-closed by
`select_cases` before any subprocess, proxy, or model contact).

## 3. Run order

1. **Rules-only pass** first (no model, deterministic, same 20 ids) as the
   baseline.
2. **Live-model pass** second (same 20 ids, same order), after readiness.

Both passes run scenarios sequentially in stable corpus order (`--select`
is resolved in corpus order by the runner; nothing is shuffled). One trial
per scenario per pass. The live-model pass runs only if the rules-only pass
completes and writes a valid report.

## 4. Model and readiness (priming) procedure

- **Model:** `llama3.2:1b`
- **Expected digest:** `baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878`
  (from `/api/tags`; readiness fails closed if the installed digest differs;
  the evaluator never pulls or downloads a model).
- **Endpoint:** `http://127.0.0.1:11434` (loopback only, provider-enforced).
- **Priming requests: exactly one maximum**, issued only if `/api/ps` shows
  the model is NOT resident. Never retried, never concurrent.
- **Priming keep-alive:** 900 s (`--local-model-keep-alive 900`), covering
  the declared worst case (20 × 30 s = 600 s) with margin.
- **Priming client timeout:** 30 s (`--local-model-prime-timeout 30`) —
  applied per HTTP phase AND as one total wall-clock deadline covering the
  complete priming request (send plus full streamed-body consumption).
- **Readiness record:** residency before priming, priming outcome (elapsed,
  timeout/error status, response validity) and residency re-check are stored
  under `report["readiness"]` — separate from all scenario results and
  metrics.
- **Immediately before evaluation:** readiness re-checks `/api/ps`; if the
  model is not resident after priming, the run aborts before any scenario.
- Any readiness failure aborts the run with exit code 2 and nothing executed.

## 5. Budgets and timeouts (all predeclared)

| Bound | Value |
| --- | --- |
| Scenarios | 20 (exact ids above) |
| Trials | 1 per pass |
| Adapter-decision deadline | **5.0 s** (unchanged default; fail-closed DENY on expiry) |
| Provider per-request timeout | 60 s (`--local-model-timeout 60`) |
| Hard provider call cap | 64 adapter calls (`--local-model-max-calls 64`) |
| Planned worst-case adapter calls | 19 (19 adapter-tier scenarios × 1 trial) |
| Priming generation requests | ≤ 1 |
| Total generation requests | ≤ 20 (≤ 1 priming + ≤ 19 adapter) |
| Per-scenario harness timeout | 30 s (runner default) |
| Readiness priming timeout | 30 s |
| Overall wall-clock watchdog | 900 s — **not enforced by the evaluator**: the operator must run the proposed command below through an external 900 s timeout wrapper; wrapper expiration invalidates the run (partial output is not a successful evaluation) |

No concurrency: one adapter call at a time, one priming request, sequential
scenarios.

## 6. Abort criteria

Abort BEFORE any scenario execution on: readiness failure (model missing,
digest mismatch, priming timeout/error/invalid response, post-priming
non-residency, unsafe keep-alive/prime-timeout), invalid partition or
`--select` ids, or call budget exceeded (all exit 2, nothing executed).

Abort and report as failed on: overall watchdog exceeded — the evaluator
does NOT enforce the 900 s watchdog internally, so the operator must run the
proposed command under an external 900 s timeout wrapper, and wrapper
expiration invalidates the run (partial output is not a successful
evaluation) — proxy/subprocess crash, or any harness-level scenario failure
(never counted as a pass).

## 7. Infrastructure errors vs policy decisions

- **Policy decisions:** engine ALLOW/DENY with deterministic rule ids, and
  adapter ALLOW/DENY (`rule_id: adapter`) produced within the 5.0 s deadline
  from a parseable model response. Only these are "usable live model
  decisions".
- **Infrastructure outcomes (NOT model decisions):** `adapter_timeout`,
  `adapter_error`, `adapter_invalid`, `adapter_undecided`, `adapter_missing`
  (fail-closed DENYs), harness timeouts/errors, and readiness aborts. These
  are reported separately and never counted as model decision quality.

## 8. Metrics (descriptive only)

Completed scenarios; usable live model decisions; adapter timeouts/errors/
invalid/undecided/missing counts; false allows and false denies against
pre-registered expectations; scenario-level blocking metrics; latency
summaries (min/p50/p95/max) excluding failed cases; readiness record
(residency, priming elapsed/status).

**All results are descriptive only:** n = 20 hand-authored synthetic
development scenarios, single trial, one small local model. No statistical
claims, no held-out generalization, no comparison to the frozen 4a/4b
baselines beyond side-by-side description.

## 9. Exclusions and integrity

- The **41 held-out scenarios are excluded**: runs use `--partition
  development` plus the explicit 20-id `--select`; the evaluator refuses
  held-out or full-corpus local-model runs before contacting any model.
- `D:\Agent44Pilot4e\` artifacts are preserved unchanged (SHA-256s
  recorded 2026-10-17); pilot output goes to a NEW directory
  (`D:\Agent44Pilot4f6\`), never overwriting `Agent44Pilot4e`.
- `evaluation/PROTOCOL_v1.md`, `PROTOCOL_v1.1_AMENDMENT.md`,
  `policy_eval_4a.yaml`, `adapter_replay_fixture.json`, and
  `src/agent44/corpus.py` remain untouched; this plan adds no protocol
  amendment.

## 10. Proposed execution commands (require approval)

```
# Pass 1 — rules-only baseline (no model):
python -m agent44.eval_runner run --partition development --select <20 ids> \
  --trials 1 --seed 0 -o D:\Agent44Pilot4f6\rules_report.json \
  --observe D:\Agent44Pilot4f6\rules_observe.jsonl

# Pass 2 — live model (readiness + priming run automatically first):
python -m agent44.eval_runner run --partition development --select <20 ids> \
  --local-model llama3.2:1b \
  --local-model-digest baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878 \
  --local-model-keep-alive 900 --local-model-prime-timeout 30 \
  --local-model-timeout 60 --local-model-max-calls 64 \
  --adapter-deadline 5.0 --trials 1 --seed 0 \
  -o D:\Agent44Pilot4f6\live_report.json \
  --observe D:\Agent44Pilot4f6\live_observe.jsonl
```

**External watchdog (operator-enforced):** the evaluator does not enforce
the 900 s overall watchdog internally. The operator must run each proposed
command above through an external 900 s timeout wrapper (for example,
PowerShell `Start-Process` / `Wait-Job -Timeout 900`, or an OS-level timeout
tool). Wrapper expiration invalidates the run: partial output is not a
successful evaluation.

Stop after both passes; report results; await approval before any rerun.

