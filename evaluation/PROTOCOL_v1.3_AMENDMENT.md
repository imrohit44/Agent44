# PROTOCOL_v1.3 — AMENDMENT (Held-Out Evaluation Protocol)

## A. Status and authority

- **Amendment identifier:** PROTOCOL_v1.3_AMENDMENT
- **Date:** 2026-10-22
- **Relationship to existing protocol:** Addendum to the frozen PROTOCOL_v1.md. v1 and all prior amendments (v1.1, v1.2) remain byte-for-byte authoritative for everything they define. This amendment defines the held-out evaluation protocol experiment only; nothing here weakens or reinterprets the frozen protocol.
- **Relationship to configuration freeze:** Addendum to CONFIGURATION_FREEZE_v1.md. The frozen configuration (prompt version, thresholds, policy file, judge model, corpus version 4c.0.0, runner configuration) remains unchanged. No held-out corpus construction or evaluation is authorized by this amendment.
- **Approved decisions versus proposed requirements:**
  - **Approved:** Ground-truth labelling via independent human review with adjudication for disagreements. Initial sample-size planning target of 50 held-out scenarios. Two-layer evaluation: Layer A (policy-engine decision quality) followed by Layer B (full proxy enforcement). Creation of a versioned protocol amendment to document the approved design while preserving all existing frozen protocols.
  - **Proposed requirements:** Full corpus construction, label assignment, policy-engine evaluation, proxy enforcement measurement, and experiment authorization — none of which are authorized by this amendment alone.
- **Explicit statement:** This amendment does not modify existing frozen protocols. It does not authorize held-out corpus construction or evaluation. It does not change the frozen configuration.
- **Explicit statement held-out corpus not authorized:** Held-out scenario construction, label assignment, policy-engine evaluation, proxy enforcement measurement, or any experiment run is not authorized by this task. The only artifact produced is this protocol amendment document.

Reference existing documents by their actual repository-relative paths:
- PROTOCOL_v1.md — frozen base protocol
- PROTOCOL_v1.1_AMENDMENT.md — vocabulary/statistics amendment
- PROTOCOL_v1.2_AMENDMENT.md — Phase 10 Backend Evaluation amendment
- CONFIGURATION_FREEZE_v1.md — frozen configuration manifest
- HOLDOUT_DATASET_PLAN_v1.md — held-out dataset plan (separate document, not modified by this amendment)
- PHASE_10_BACKEND_EVALUATION_REPORT.md — Phase 10 report (not modified by this amendment)

## B. Experiment scope

### Layer A — Policy-engine decision quality

- **Purpose:** Evaluate policy decisions on unseen held-out scenarios using the deterministic policy engine only. Compare the rules-only baseline against the frozen rules-plus-local-judge condition using the configured adapter eligibility and deterministic enforcement precedence.
- **Procedure:** Run the policy engine over the held-out scenario set and record the decision (ALLOW/DENY/UNDECIDED) for each scenario. The rules-only baseline uses policy_eval_4a.yaml with no backend consulted. The frozen rules-plus-local-judge condition uses the configured judge model and prompt version (llama3.2:1b, judge-prompt-v1).
- **Metrics to record:** decision accuracy, false allows, false denies, false-block rate, adapter invocation rate, backend failure rate, trial-level versus scenario-level aggregation.
- **Key constraint:** Policy-engine decisions alone do not prove downstream enforcement. Layer A evaluates the policy engine's decision output only; it does not verify that allowed calls reach downstream tools or that denied calls are blocked end-to-end.
- **Precedence:** Layer A must precede Layer B. Layer B is a separately measured evaluation layer, not an inference from Layer A results.
### Layer B — Full proxy enforcement

- **Purpose:** Evaluate the complete supported proxy path separately. Verify the complete end-to-end behavior of the gateway including downstream call forwarding, fail-closed enforcement, provenance, delegation, and correlation.
- **Procedure:** For each held-out scenario where Layer A produced a decision, verify the following assertions:
  1. Allowed calls reach downstream tools as expected — the downstream tool is invoked when the policy permits.
  2. Denied calls are not forwarded — the downstream tool is never invoked when the policy denies.
  3. Fail-closed behavior on applicable backend failures — a backend failure or timeout results in DENY, never ALLOW.
  4. Provenance and delegation — tool call provenance and delegation chains are correctly recorded and honored.
  5. Correlation and transfer behavior — where applicable, correlation IDs and transfer contexts are preserved or appropriately terminated.
  6. Observed downstream execution agrees with the policy engine's declared decision — the actual tool invocation matches the policy engine's ALLOW/DENY output.
  7. Integration failures — any integration-level failures (schema validation, parse errors, timeouts) are recorded and counted separately.
  8. Backend availability — any backend reported as unavailable has its condition excluded from quantitative comparison; it is never silently substituted.
- **Separation from Layer A:** Observed downstream execution is recorded independently of the policy engine's declared decision. Layer B does not assume Layer A results; it is a separately measured evaluation layer, with its own assertions and metrics.
- **Required assertions not yet supported:** Several assertions listed above require test instrumentation that does not yet exist in the repository. These are identified as unresolved and must be implemented before Layer B can be quantitatively evaluated.
## C. Held-out corpus design

- **Planning target:** 50 held-out scenarios. This is a planning target, not a statistically justified sample size or a guarantee of adequate power. The final sample size and category allocation still require a defensible rationale and explicit approval.
- **Corpus distinctness:** The held-out corpus must be distinct from the 94-scenario development corpus (CORPUS_VERSION = 4c.0.0, PARTITION_DEVELOPMENT). No scenario from the development corpus may be included in the held-out set.
- **Scenario origin:** Newly authored synthetic scenarios, not copied or lightly paraphrased development cases. The corpus must use scenarios authored specifically for the held-out purpose.
- **Category coverage:** The corpus should include appropriate categories where supported by the implementation: benign, adversarial, ambiguous, malformed-input, provenance, delegation, prompt-injection, and adapter-failure. Do not invent category counts or claim that 50 scenarios provide statistically adequate coverage. Category allocation and final sample-size justification are unresolved until approved.
- **Labeling:** Ground-truth labels must be assigned before execution. Labels are tied to the Agent44 decision contract (expected in {ALLOW, DENY}) and must be assigned independently of the implementation's observed decision.
- **Provenance and label decisions:** Each scenario must have recorded provenance and label decisions. Label provenance must be tracked separately from the implementation's predictions.
- **Duplicate and near-duplicate check:** The corpus must be checked for exact duplicates and likely near-duplicates against development scenarios. No exact duplicate IDs should be present; near-duplicates that trigger the same policy rules must be documented and excluded or flagged.
- **Schema validation:** Each scenario must conform to the CorpusCase schema (id, tool_name, arguments, category, label, expected, rationale, provenance) before approval.
- **Do not generate:** Do not generate any scenarios or labels during this task. Do not claim category counts or statistical adequacy for the 50-scenario planning target.

## D. Independent labelling and adjudication
## D. Independent labelling and adjudication

- **Required approach:** Independent human review with a documented adjudication process for disagreements.
- **Rubric:** A written labelling rubric tied to the actual Agent44 decision contract. The rubric maps categories to typical expected values (ALLOW or DENY) as described in the ground-truth labelling rubric (see HOLDOUT_DATASET_PLAN_v1.md Section 4).
- **Independent labelling before execution:** Labels must be assigned by independent human reviewers before any evaluation execution. The labels are ground truth; the implementation's observed decision is compared against them.
- **Disagreement process:** If label assigners disagree on a scenario's expected outcome:
  1. The scenario is flagged for review.
  2. The dispute is resolved by referencing the decision contract (the policy rules as written).
  3. If still unresolved, the scenario is excluded from the held-out set and documented, not arbitrarily re-labeled.
  4. All disputes and their resolutions are recorded in the held-out manifest.
- **Separation between expected labels and Agent44's predictions:** Expected labels (ground truth) are independent of Agent44's predictions. An observed decision that disagrees with expected is counted as an evaluation error (false-allow / false-deny); it never redefines ground truth.
- **No use of evaluation results to determine ground truth:** Evaluation results must never be used to determine or modify ground truth labels.
- **Unresolved operational details (require owner/approval):**
  - Reviewer availability and independence — who are the reviewers; how is independence verified; are reviewers drawn from outside the core development team?
  - Reviewer count and adjudication procedure — how many reviewers per scenario; who is the adjudicator when reviewers disagree.
  - Final sample-size rationale and category allocation — the 50-scenario planning target must be justified by category diversity, expected uncertainty, and evaluation budget.
  - Storage location and actual access controls — where are scenario definitions and labels stored; who has read/write access.
  - Protocol amendment approval — this amendment (PROTOCOL_v1.3_AMENDMENT.md) must be reviewed and approved before corpus construction begins.

Do not invent reviewer identities, approvals, or completed labelling work.

## E. Leakage prevention and corpus protection

- **Separation from development data and tuning workflows:** Held-out scenario definitions and labels must be stored and accessed separately from the 94-scenario development corpus and any tuning workflows. No held-out data should be accessible in developer working directories, notebooks, or commit histories outside the designated storage location.
- **Access to scenario definitions and labels before evaluation:** Access to held-out scenario definitions and ground-truth labels before evaluation must be restricted to the experiment lead and designated reviewers. All access must be logged.
- **Storage and access permissions:** Held-out scenario definitions, labels, and the manifest must be stored in a designated protected location. Access permissions must be set to prevent unintended read/write by unauthorized parties.
- **Corpus and label hashes:** SHA-256 hashes of all held-out scenario files, label files, and the manifest must be recorded. Hashes must be verified before and after any access or transfer.
- **Configuration identity and freeze verification:** The frozen configuration (prompt version, thresholds, policy file, judge model, corpus version, runner configuration) must be verified against CONFIGURATION_FREEZE_v1.md before any held-out run. Any change to the frozen configuration requires a new experiment version and a freshly protected held-out set.
- **Handling accidental exposure or leakage:**
  - If held-out labels are discovered in any developer's working directory, notebook, or commit history outside the designated storage location, the experiment must be paused immediately.
  - The experiment lead must be notified immediately.
  - A new experiment version is issued, and a fresh held-out corpus is generated with new labels.
  - The previous run's results are annulled for any tuning-related purpose.
- **Change control after results are observed:** If policies, prompts, model settings, thresholds, labels, or scoring rules change after results are observed, a new experiment version is issued. A confirmatory evaluation after tuning must use a newly protected held-out set. The prior held-out results cannot be carried forward.
- **Distinction between planned controls and enforced controls:** Planned controls are specified in this amendment. Controls actually enforced by the repository or operating environment (e.g., git branch protection, access control lists) may differ. Do not claim a local file is confidential, access-controlled, or tamper-proof without evidence.

Do not claim a local file is confidential, access-controlled, or tamper-proof without evidence.

## F. Evaluation metrics and reporting

## H. Unresolved decisions register

| Decision | Current status | Why it matters | Required owner or approval | Blocks |
|---|---|---|---|---|
| Reviewer availability and independence | Unresolved — reviewer pool not yet identified | Determines whether independent human labelling can proceed; without reviewers, labels cannot be assigned, and corpus construction is blocked. | Experiment lead / hiring/outreach lead | Corpus construction, Layer A |
| Reviewer count and adjudication procedure | Unresolved — number of reviewers, adjudicator not documented | Affects label assignment throughput and dispute resolution; unclear procedure leads to inconsistent labels. | Experiment lead / reviewer coordinator | Corpus construction, Layer A |
| Final sample-size rationale and category allocation | Unresolved — 50 scenarios is a planning target only; no defensible rationale approved | Statistical validity of evaluation results depends on adequate sample size and category coverage; without approval, Layer A and Layer B cannot be justified. | Experiment lead / statistician | Layer A, Layer B |
| Storage location and actual access controls | Unresolved — designated storage location and permission scheme not yet configured | Leakage prevention depends on proper storage and access controls; misconfigured access could expose labels or scenarios prematurely. | Experiment lead / infrastructure lead | Corpus construction, Layer A, Layer B |
| Protocol amendment approval | Unresolved — this amendment (PROTOCOL_v1.3_AMENDMENT.md) under review | All subsequent steps (corpus construction, label assignment, evaluation) are contingent on amendment approval. | Experiment lead | All milestones |
| Metric formulas and acceptance criteria | Unresolved — detailed formulas, denominators, and Wilson interval requirements not yet finalized | Without accepted formulas, results cannot be compared across conditions or versions; ambiguity leads to disputes. | Experiment lead / statistician | Layer A, Layer B |
| Required proxy integration instrumentation | Unresolved — several Layer B assertions (e.g., downstream non-forwarding, provenance) require test instrumentation not yet in the repository | Layer B cannot be quantitatively evaluated until instrumentation exists; workarounds would not be authoritative. | Implementation lead / instrumentation owner | Layer B |
## I. Explicit non-execution statement

This amendment task did not:

- Create a held-out corpus
- Assign held-out labels
- Run policy-engine or proxy evaluation
- Run model inference
- Make live backend calls
- Modify the frozen configuration
- Modify existing protocol files, historical results, or hash baselines

The only repository change introduced by this task is the addition of this protocol amendment document (PROTOCOL_v1.3_AMENDMENT.md). No other files were created, edited, or committed.

No scenarios were generated, no labels were assigned, no evaluations were run, no model inference was executed, no live backend calls were made, no frozen artifacts were modified, no commits or pushes were performed.
| Execution environment and reproducibility checks | Unresolved — exact execution commands, environment variables, RNG seed not yet confirmed for held-out runs | Reproducibility is a core requirement; without confirmed environment, results cannot be verified or built upon. | Experiment lead / DevOps | Layer A, Layer B |
| Authorization to construct the corpus | Unresolved — no held-out corpus may be constructed without explicit user authorization after amendment approval | Prevents premature corpus construction before all gating conditions are met. | Experiment lead / user | Corpus construction |
| Separate authorization for Layer A and Layer B | Unresolved — Layer B requires its own readiness check and explicit authorization after Layer A | Ensures Layer B is not assumed from Layer A results; Layer B has independent assertions and metrics. | Experiment lead | Layer B (after Layer A) |

Do not mark these resolved without evidence or explicit approval.

- **Decision accuracy:** (scenarios where observed decision matches expected) / (total scenarios), with Wilson 95% score interval using scenario counts as the denominator.
- **False allows:** (scenarios where observed ALLOW but expected DENY) / (scenarios where expected DENY), with Wilson interval.
- **False denies:** (scenarios where observed DENY but expected ALLOW) / (scenarios where expected ALLOW), with Wilson interval.
- **False-block rate:** same as false-deny rate; explicitly state which terminology is used.
- **Adapter eligibility and actual invocation:** fraction of scenarios where adapter_tools was consulted and the rate of adapter invocation versus skip.
- **Backend failures and fail-closed outcomes:** count and rate of backend failures, timeouts, and fail-closed DENY outcomes.
- **Trial-level versus scenario-level aggregation:** scenario-level rates use scenario counts as the denominator; trial-level results are retained for reproducibility check but never inflate effective sample size. Deterministic modes (rules-only, replay): every trial of a scenario must yield an identical decision; scenario-level rates are reported with Wilson intervals.
- **UNDECIDED treatment:** UNDECIDED outcomes are excluded from decision-accuracy, false-allow, and false-denominator rates per the rubric. They are reported separately as a distinct category.
- **50-scenario planning target caveat:** The 50-scenario planning target must not be presented as sufficient for precise estimates of rare false allows without an appropriate justification. The planning target is a starting point, not a statistically powered sample size.

### Layer B metrics

- **Final policy decision:** the policy engine's ALLOW/DENY/UNDECIDED output for each scenario.
- **Actual downstream invocation:** whether the downstream tool was actually invoked for each scenario; count and rate.
- **Denied-call non-forwarding:** count and rate of scenarios where the policy denied but the downstream tool was nonetheless forwarded (should be 0; any non-zero count is a failure).
- **Allowed-call forwarding:** count and rate of scenarios where the policy allowed and the downstream tool was forwarded as expected.
- **Fail-closed enforcement:** count and rate of backend failures or timeouts that result in DENY (fail-closed behavior).
- **Integration failures:** count and rate of schema validation errors, parse failures, timeout exceptions, and other integration-level failures.
- **Latency and cost where measurable:** record where measurable, but do not invent baseline results or confidence intervals.
- **UNDECIDED and failed executions:** explicitly document how UNDECIDED and failed executions are treated in each metric's numerator and denominator.

### Reporting requirements for both layers

- Total and executed scenarios; failed/skipped scenarios with reasons.
- Allow/deny counts with explicit numerators, denominators, and Wilson intervals.
- Per-category results (category, numerator, denominator, rate, Wilson interval).
- Adapter error/timeout/invalid/unresolved tallies.
- Scenario-level versus trial-level accounting (never fold trial-level variability into between-scenario intervals).
- A completed boolean indicating whether the evaluation layer has been fully executed and reported.
- Adapter-outcome results must never be conflated with deterministic-tier results.

Document how uncertainty will be reported. The 50-scenario planning target must not be presented as sufficient for precise estimates of rare false allows without an appropriate justification.
## E. Leakage prevention and corpus protection