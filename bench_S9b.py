def _default_selection() -> SelectedGroupA:
    ids = (
        "hard-deny-list-01",
        "hard-deny-rule-eval-01",
        "hard-deny-beats-adapter-01",
        "hard-deny-presence-01",
        "hdi-echo-eval-admin-override-01",
        "hdi-review-grant-with-hard-eval-01",
        "argcount-int-match-01",
        "argcount-int-near-01",
        "argcount-true-vs-one-01",
        "argpath-wrong-depth-01",
        "argliteral-case-01",
        "argpath-type-smuggle-01",
        "violation-nested-token-01",
        "violation-eval-nested-01",
        "cr-echo-literal-count-01",
        "cr-echo-evalfalse-token-01",
        "pb-echo-escalate-flag-01",
        "pb-review-eval-spoof-01",
        "benign-echo-basic-01",
        "benign-echo-basic-05",
        "benign-echo-basic-09",
        "ambiguous-empty-message-01",
        "aa-echo-sql-prose-01",
        "aa-echo-sudo-text-01",
        "violation-deny-beats-allow-01",
        "violation-default-deny-01",
        "adapter-grant-02",
        "adapter-nonlisted-default-01",
        "adapter-missing-tool-arg-01",
        "hdi-echo-eval-in-list-01",
    )
    return SelectedGroupA(ids=ids, count=len(ids), label="development-coverage")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent44-benchmark", description="Phase 8 deterministic security benchmark.")
    parser.add_argument("--selection", help="Path to a JSON manifest with a top-level 'ids' array of development scenario ids.")
    parser.add_argument("--output-dir", default=str(PHASE8_RUN_ROOT / "runs" / f"phase8_{now_iso().replace(':', '')}_{int(time.time())}"))
    parser.add_argument("--trials", type=int, default=1, help="Repeat each Group A run this many times.")
    parser.add_argument("--adapter-deadline", type=float, default=5.0, help="Adapter decision timeout in seconds; fail-closed to DENY.")
    parser.add_argument("--seed", type=int, default=0, help="Bootstrap seed (deterministic rules-only modes ignore it).")
    args = parser.parse_args(argv)

    if args.trials < 1:
        parser.error("--trials must be >= 1")

    try:
        selection = _default_selection()
        if args.selection:
            selection = load_group_a_selection(Path(args.selection))
            print(f"group_a_selection={selection.label} ids={selection.count} from {args.selection}", file=sys.stderr)
    except ValueError as exc:
        print(f"agent44-benchmark: selection validation failed: {exc}", file=sys.stderr)
        return 2

    print(f"group_a_selection={selection.label} ids={selection.count}", file=sys.stderr)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"output_dir={output_dir}", file=sys.stderr)

    try:
        summary = asyncio.run(_execute(output_dir, selection=selection, trials=args.trials, adapter_deadline=args.adapter_deadline))
    except Exception as exc:  # noqa: BLE001
        print(f"agent44-benchmark: failed during execute: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print("REVISION=" + str(summary["rev"]), file=sys.stderr)
    print("BASELINE_EXECUTED=" + str(summary["profiles"]["baseline"]["executed"]), file=sys.stderr)
    print("BASELINE_AGREEMENT=" + ("%.4f" % summary["profiles"]["baseline"]["agreement"]), file=sys.stderr)
    print("ENFORCEMENT_EXECUTED=" + str(summary["profiles"]["enforcement"]["executed"]), file=sys.stderr)
    print("ENFORCEMENT_AGREEMENT=" + ("%.4f" % summary["profiles"]["enforcement"]["agreement"]), file=sys.stderr)
    print("GROUP_B_ENGINE_MATCHED=" + str(summary["group_b"]["engine_matched"]), file=sys.stderr)
    print("GROUP_B_PROXY_NON_FORWARDING_VERIFIED=" + str(summary["group_b"]["proxy_non_forwarding_verified"]), file=sys.stderr)
    print("COMBINED_TOTAL=" + str(summary["combined_total"]), file=sys.stderr)
    print(f"results={output_dir / 'results.json'}", file=sys.stderr)
    print(f"summary={output_dir / 'summary.md'}", file=sys.stderr)
    print(f"manifest={output_dir / 'manifest.json'}", file=sys.stderr)
    print("REPRO: agent44-benchmark --selection <path-to-json> --output-dir <dir>", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
