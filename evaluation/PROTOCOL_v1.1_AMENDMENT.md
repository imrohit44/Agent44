# PROTOCOL_v1.1 — AMENDMENT

**Status:** Addendum to the frozen `PROTOCOL_v1.md`. v1 is preserved
byte-for-byte and remains authoritative for everything it defines. This
amendment documents vocabulary and statistical conventions that the
implementation and corpus had already adopted *before* this amendment existed,
so that results produced under them are reproducible and their units are
unambiguous.

**Date:** 2026-10-13
**Applies to:** Milestone 4c corpus (`CORPUS_VERSION = 4c.0.0`) and the
`agent44.eval_runner` implementation from the same date forward.

**This amendment does not retroactively relabel earlier results.** Any report
produced before this date is a v1 report. Only reports produced on/after this
date that carry `protocol: "PROTOCOL_v1.1_AMENDMENT"` are v1.1-aligned.

## 1. Backward compatibility

- v1 remains the base contract: a policy DENY is per-call blocking, never
  end-to-end attack prevention; failures fail closed; the harness never makes
  live model or network calls in deterministic CI.
- v1.1 only **pins down** choices the implementation already made (category and
  provenance vocabulary, label semantics, statistical unit, CI method, trial
  aggregation) and adds partition/manifest freeze tooling. Nothing in v1 is
  weakened or reinterpreted.
- Where v1 and the implementation already diverged (the controlled vocabulary
  in v1 §5 vs. the corpus's richer sub-categories), v1.1 records the
  implementation vocabulary as authoritative and states the mapping below.

## 2. Category vocabulary (implementation is authoritative)

v1 §5 lists `{benign, adversarial, ambiguous}`. The corpus uses finer
sub-categories that roll up into those three buckets. The full set is
`corpus.VALID_CATEGORIES`:

- `benign-basic`, `ambiguous-legitimate`, `policy-violation`, `hard-deny`,
  `argument-constraint`, `adapter-eligible`, `adapter-malformed`,
  `adapter-failure`, `prompt-injection`, `policy-bypass`, `conflicting-rules`,
  `ambiguous-adversarial`, `hard-deny-invariance`.

Roll-up mapping to v1 buckets:

| v1 bucket   | sub-categories rolled up |
|-------------|--------------------------|
| benign      | benign-basic |
| ambiguous   | ambiguous-legitimate, argument-constraint, adapter-eligible, ambiguous-adversarial |
| adversarial | policy-violation, hard-deny, adapter-malformed, adapter-failure, prompt-injection, policy-bypass, conflicting-rules, hard-deny-invariance |

Labels are a separate, independent axis: `corpus.VALID_LABELS =
{benign, ambiguous, malicious, invalid}`.

## 3. Expected labels

`expected ∈ {ALLOW, DENY}` (`corpus.VALID_EXPECTED`). Ground truth is authored
independently of the implementation's observed decision. An observed decision
that disagrees with `expected` is counted as an evaluation error
(false-allow / false-deny); it never redefines ground truth. A policy decision
that contradicts `expected` is a genuine miss, not a relabeling.

- **Expected ALLOW / observed DENY** → false-deny (over-block).
- **Expected DENY / observed ALLOW** → false-allow (under-block).

## 4. Provenance

All scenarios in `CORPUS_VERSION = 4c.0.0` are `hand-authored-synthetic`.
There are **no independently authored or externally sourced cases** in this
corpus. This is an explicit limitation: external validity and any
"independent review" claim would be unsupported. Independent cases, if ever
added, must be tagged distinctly and must not be mixed silently into the
synthetic label.

## 5. Statistical unit and repeated trials

- **Primary statistical unit = the distinct scenario.** Repeated trials of the
  same scenario are reproducibility evidence, not new independent samples.
  They are never counted as independent scenarios and never inflate an
  effective sample size.
- **Deterministic modes** (rules-only, replay): every trial of a scenario must
  yield an identical decision. Scenario-level false-allow/false-deny rates are
  reported with **Wilson 95% score intervals** using scenario counts as the
  denominator. Trial-level results are retained for the reproducibility check.
- **Stochastic adapters** (future live model): per-scenario decision rates are
  computed first (fraction of a scenario's trials that match expected), then a
  **scenario-level percentile bootstrap** (explicit seed, default 0) yields
  intervals over the per-scenario distribution. Within-scenario trial
  variability is reported separately and is never folded into the between-
  scenario interval.
- **Zero denominators** return `null` intervals (never 0.0, never omitted); the
  numerator/denominator pair is always reported alongside every rate.

## 6. Required reporting

Every v1.1 report must include: total and executed scenarios; failed/skipped
scenarios with reasons; allow/deny counts; false-allow and false-deny counts
**with explicit numerators, denominators, and Wilson intervals**; per-category
results; adapter error/timeout/invalid/unresolved tallies; scenario-level vs
trial-level accounting; and a `completed` boolean. Adapter-outcome results are
never conflated with deterministic-tier results.
