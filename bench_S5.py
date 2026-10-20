# --------------------------------------------------------------------------- #
# Proxy-driven Group A evaluation  (reuses eval_runner)
# --------------------------------------------------------------------------- #


async def _run_profile_once(
    profile_name: str,
    profile_dir: Path,
    select_ids: tuple[str, ...],
    *,
    trials: int = 1,
    adapter_deadline: float = 5.0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import agent44.eval_runner as eval_runner

    policy_filename = "policy.yaml" if profile_name == "enforcement" else "baseline_policy.yaml"
    report = await eval_runner.evaluate(
        observe_path=None,
        policy_path=str(profile_dir / policy_filename),
        local_model=None,
        adapter_replay=None,
        partition="development",
        select_ids=list(select_ids),
        trials=trials,
        bootstrap_seed=0,
        adapter_deadline=adapter_deadline,
    )
    return list(report["results"]), dict(report["summary"])


async def _warm_up_proxy(policy_path: str | Path, delegation_manifest: str | Path | None) -> None:
    import asyncio

    import agent44.eval_runner as eval_runner
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    args = [
        *eval_runner.PROXY_MODULE,
        "--policy",
        str(policy_path),
        "--observe",
        str(Path(tempfile.gettempdir()) / f"bench_warm_{time.time_ns()}.jsonl"),
    ]
    if delegation_manifest is not None:
        args += ["--delegation", str(delegation_manifest)]
    args += ["--", sys.executable, *eval_runner.DEMO_MODULE]
    params = StdioServerParameters(command=sys.executable, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()


# --------------------------------------------------------------------------- #
# Group B engine-level resolvers  (Phase 7 models, in-process)
# --------------------------------------------------------------------------- #


def _build_engine(policy_text: str | None = None) -> PolicyEngine:
    policy_text = policy_text or build_enforcement_policy_text()
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as fh:
        fh.write(policy_text)
        fh.flush()
    return PolicyEngine.from_path(fh.name)


def _delegation_context_for(now: float) -> DelegationContext:
    manifest = build_delegation_manifest(now)
    return parse_delegation_manifest(json.dumps(manifest), now=now)


def _default_for(engine: PolicyEngine, tool: str) -> str:
    return engine._default_decision(tool).action.value
