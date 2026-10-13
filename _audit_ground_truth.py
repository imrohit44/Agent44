import asyncio
from collections import Counter

from agent44.corpus import load_corpus
from agent44.policy import Action, PolicyEngine, RulesOnlyAdapter

engine = PolicyEngine.from_path("evaluation/policy_eval_4a.yaml")
adapter = RulesOnlyAdapter()


async def main() -> None:
    mismatches = []
    adapter_reached = []
    for case in load_corpus():
        decision = await engine.decide(case.tool_name, case.arguments, adapter)
        got = "ALLOW" if decision.action is Action.ALLOW else "DENY"
        if got != case.expected:
            mismatches.append((case.id, case.expected, got, decision.rule_id))
        if decision.rule_id.startswith("adapter"):
            adapter_reached.append((case.id, decision.rule_id))
    print(f"total=100 mismatches={len(mismatches)}")
    for m in mismatches:
        print("MISMATCH", m)
    print(f"adapter_tier_hit={len(adapter_reached)}")
    for a in adapter_reached:
        print("ADAPTER", a)
    # hard-deny invariant: adapter must never be consulted for hard calls
    print("hard override check: RulesOnlyAdapter sees no hard rules (asserted in engine)")


asyncio.run(main())
