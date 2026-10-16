import sys

path = r"d:\Agent44\src\agent44\eval_runner.py"
with open(path, encoding="utf-8") as fh:
    src = fh.read()

edits = []

# R1: docstring paragraph after the select_ids paragraph (no triple quotes in old)
r1_old = """    ``select_ids`` further bounds the run to an explicit scenario-id subset
    (a bounded pilot). Every id must exist and belong to ``partition`` or the
    run fails closed through :func:`select_cases` before any subprocess,
    proxy, or model call; the resolved ids are recorded in the report under
    ``partition_selection.explicit_selection``.
"""
r1_new = """    ``select_ids`` further bounds the run to an explicit scenario-id subset
    (a bounded pilot). Every id must exist and belong to ``partition`` or the
    run fails closed through :func:`select_cases` before any subprocess,
    proxy, or model call; the resolved ids are recorded in the report under
    ``partition_selection.explicit_selection``.
    The adapter deadline (``adapter_deadline``, seconds) defaults to 5.0,
    the module default ``ADAPTER_TIMEOUT_SECONDS``. It is validated by the
    same rules as the CLI (``agent44.policy``): finite, strictly positive,
    and no larger than the provider/downsream timeout (60 s). Every engine
    constructed in this run (the runner's local-model engine and the
    proxy's per-connection engine) receives this value.
    """
edits.append((r1_old, r1_new, "R1"))

# R2: evaluate() signature
r2_old = """    timeout_seconds: float = 30.0,
    trials: int = 1,
    bootstrap_seed: int = 0,
) -> dict[str, Any]:
"""
r2_new = r2_old + "    adapter_deadline: float = 5.0,\n"
edits.append((r2_old, r2_new, "R2"))

# R3: local-model engine construction
r3_old = """        engine = policy_module.PolicyEngine.from_path(policy)
"""
r3_new = """        engine = policy_module.PolicyEngine.from_path(
            policy, adapter_timeout_seconds=adapter_deadline
        )
"""
edits.append((r3_old, r3_new, "R3"))

# R4: run_bounds adapter decision timeout
r4_old = """        "adapter_decision_timeout_seconds": float(policy_module.ADAPTER_TIMEOUT_SECONDS),
"""
r4_new = """        # Effective per-adapter deadline configured for this run: it is
        # forwarded verbatim into every engine (the runner's local-model
        # engine above, and the proxy's per-connection engine via
        # --adapter-deadline).
        "adapter_decision_timeout_seconds": float(adapter_deadline),
"""
edits.append((r4_old, r4_new, "R4"))

# R5: --adapter-deadline CLI argument (inserted before --local-model)
r5_old = """    parser.add_argument(
        "--local-model",
        default=None,
        metavar="TAG",
        help=(
            "Opt in to a local Ollama model (e.g. 'llama3.2:1b'). Calls only "
            "http://127.0.0.1:11434. Off by default; default/CI runs stay "
            "offline on the rules-only/replay paths. A model must already be "
            "installed (run 'ollama pull <TAG>' manually); the evaluator "
            "never downloads a model."
        ),
    )
    parser.add_argument(
        "--local-model-host",
"""
r5_new = """    parser.add_argument(
        "--adapter-deadline",
        metavar="SECONDS",
        type=float,
        default=5.0,
        help=(
            "Per-adapter-call deadline passed to the policy engine (default: "
            "5.0, the module default ADAPTER_TIMEOUT_SECONDS). Must be finite "
            "and strictly positive and cannot exceed the provider and "
            "downstream call timeouts (60 s); see agent44.policy for the "
            "validation rules."
        ),
    )
    parser.add_argument(
        "--local-model",
        default=None,
        metavar="TAG",
        help=(
            "Opt in to a local Ollama model (e.g. 'llama3.2:1b'). Calls only "
            "http://127.0.0.1:11434. Off by default; default/CI runs stay "
            "offline on the rules-only/replay paths. A model must already be "
            "installed (run 'ollama pull <TAG>' manually); the evaluator "
            "never downloads a model."
        ),
    )
    parser.add_argument(
        "--local-model-host",
"""
edits.append((r5_old, r5_new, "R5"))

# R6: evaluate() call in main
r6_old = """            evaluate(
                observe_path=args.observe,
            adapter_replay=args.adapter_replay,
            local_model=local_model,
            partition=args.partition,
            select_ids=select_ids,
            trials=args.trials,
            bootstrap_seed=args.seed,
            )
"""
r6_new = r6_old + "            adapter_deadline=args.adapter_deadline,\n"
edits.append((r6_old, r6_new, "R6"))

# R7: build_manifest signature
r7_old = """def build_manifest(
    policy_path: str | Path | None = None,
    local_model: dict[str, Any] | None = None,
    select_ids: list[str] | None = None,
    select_partition: str | None = None,
) -> dict[str, Any]:
"""
r7_new = r7_old + "    adapter_deadline_seconds: float | None = None,\n"
edits.append((r7_old, r7_new, "R7"))

# R8: build_manifest returned dict
r8_old = """    return {
        "protocol": "PROTOCOL_v1.1_AMENDMENT",
        "generated_by": "agent44.eval_runner manifest",
"""
r8_new = r8_old + '        "adapter_deadline_seconds": adapter_deadline_seconds,\n'
edits.append((r8_old, r8_new, "R8"))

# R9: build_manifest call in main
r9_old = """        manifest = build_manifest(
            local_model=local_model,
            select_ids=select_ids,
            select_partition=args.partition if select_ids is not None else None,
        )
"""
r9_new = r9_old + "            adapter_deadline_seconds=args.adapter_deadline,\n"
edits.append((r9_old, r9_new, "R9"))

for old, new, tag in edits:
    count = src.count(old)
    print(f"{tag}: count={count}", file=sys.stderr)
    if count != 1:
        print(f"FAIL {tag}: found {count} occurrences", file=sys.stderr)
        sys.exit(1)
    src = src.replace(old, new)

with open(path, "w", encoding="utf-8") as fh:
    fh.write(src)

print("ALL EDITS APPLIED")
for _, _, tag in edits:
    print(" -", tag)