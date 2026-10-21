"""Phase 10 scratch verification (not committed)."""
from agent44 import judge_backend as j

d = j.parse_judge_decision('{"action": "UNDECIDED", "reason": "ambiguous evidence"}')
print("parsed:", d.action.value, "-", d.reason)
print(
    "config hash:",
    j.judge_config_sha256(
        model_name="llama3.2:1b",
        prompt_version=j.JUDGE_PROMPT_VERSION,
        parser_version=j.JUDGE_PARSER_VERSION,
    )[:16],
)
try:
    j.parse_judge_decision('{"action": "MAYBE", "reason": "x"}')
except Exception as exc:
    print("reject invalid action:", type(exc).__name__)
prompt = j.build_judge_prompt("review_tool", {"note": "hello"}, [])
print("prompt chars:", len(prompt), "| has untrusted rule:", "untrusted content" in prompt)


