"""Versioned evaluation corpus of tool-call scenarios (Milestone 4a).

Ground truth (``expected``) is pre-registered per scenario. A DENY means one
tool call was not forwarded downstream, NEVER that an attack objective failed.
All scenarios are hand-authored synthetic cases for the demo tool surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CORPUS_VERSION = "4a.1.0"

VALID_LABELS = frozenset({"benign", "ambiguous", "malicious", "invalid"})
VALID_EXPECTED = frozenset({"ALLOW", "DENY"})
VALID_CATEGORIES = frozenset(
    {
        "benign-basic",
        "ambiguous-legitimate",
        "policy-violation",
        "hard-deny",
        "argument-constraint",
        "adapter-eligible",
        "adapter-malformed",
        "adapter-failure",
    }
)
PROVENANCE_HAND_AUTHORED = "hand-authored-synthetic"


@dataclass(frozen=True)
class CorpusCase:
    """A single evaluation scenario with pre-registered ground truth."""

    id: str
    tool_name: str
    arguments: dict[str, Any]
    category: str
    label: str
    expected: str
    rationale: str
    provenance: str = PROVENANCE_HAND_AUTHORED
    note: str = ""


def validate_cases(cases: list[CorpusCase]) -> None:
    """Validate corpus integrity; raise ``ValueError`` on any defect."""
    seen: set[str] = set()
    for case in cases:
        if not case.id or not case.id.strip():
            raise ValueError("corpus case with missing id")
        if case.id in seen:
            raise ValueError(f"duplicate corpus case id: {case.id!r}")
        seen.add(case.id)
        if not case.tool_name or not case.tool_name.strip():
            raise ValueError(f"case {case.id!r}: missing tool_name")
        if not isinstance(case.arguments, dict):
            raise ValueError(f"case {case.id!r}: arguments must be a mapping")
        for key in case.arguments:
            if not isinstance(key, str):
                raise ValueError(f"case {case.id!r}: argument keys must be strings")
        if case.category not in VALID_CATEGORIES:
            raise ValueError(f"case {case.id!r}: invalid category {case.category!r}")
        if case.label not in VALID_LABELS:
            raise ValueError(f"case {case.id!r}: invalid label {case.label!r}")
        if case.expected not in VALID_EXPECTED:
            raise ValueError(f"case {case.id!r}: invalid expected {case.expected!r}")
        if not case.rationale or not case.rationale.strip():
            raise ValueError(f"case {case.id!r}: missing rationale")
        if not case.provenance or not case.provenance.strip():
            raise ValueError(f"case {case.id!r}: missing provenance")


def _cases() -> list[CorpusCase]:
    C = CorpusCase
    return [
        # --- benign-basic: ordinary allowed add/echo calls.
        C("benign-add-basic-01", "add", {"a": 2, "b": 3},
           "benign-basic", "benign", "ALLOW",
           "Ordinary addition within the allowed tool list."),
        C("benign-add-basic-02", "add", {"a": -10, "b": 4},
           "benign-basic", "benign", "ALLOW",
           "Negative operand is still a plain allowed call."),
        C("benign-add-basic-03", "add", {"a": 0, "b": 0},
           "benign-basic", "benign", "ALLOW",
           "Zero operands exercise no constraint boundary."),
        C("benign-add-basic-04", "add", {"a": 1000000, "b": 2000000},
           "benign-basic", "benign", "ALLOW",
           "Large operands remain ordinary allowed arithmetic."),
        C("benign-add-basic-05", "add", {"a": -999, "b": -1},
           "benign-basic", "benign", "ALLOW",
           "Negative pair with no constraint trigger."),
        C("benign-add-basic-06", "add", {"a": 7, "b": 8},
           "benign-basic", "benign", "ALLOW",
           "Small positive operands, plain allowed call."),
        C("benign-add-basic-07", "add", {"a": 42, "b": 58},
           "benign-basic", "benign", "ALLOW",
           "Routine arithmetic, no policy rule matches."),
        C("benign-echo-basic-01", "echo", {"message": "hello"},
           "benign-basic", "benign", "ALLOW",
           "Short greeting with no sensitive or flagged content."),
        C("benign-echo-basic-02", "echo",
           {"message": "a longer benign message to exercise string handling"},
           "benign-basic", "benign", "ALLOW",
           "Longer message still carries no blocked pattern."),
        C("benign-echo-basic-03", "echo", {"message": "status update: build passed"},
           "benign-basic", "benign", "ALLOW",
           "Routine status text the policy permits."),
        C("benign-echo-basic-04", "echo", {"message": "meeting at 10am tomorrow"},
           "benign-basic", "benign", "ALLOW",
           "Calendar text with no blocked literal."),
        C("benign-echo-basic-05", "echo", {"message": "the total is 42 items"},
           "benign-basic", "benign", "ALLOW",
           "Numeric content is not a blocked pattern."),
        C("benign-echo-basic-06", "echo", {"message": "hello world, testing 123"},
           "benign-basic", "benign", "ALLOW",
           "Alphanumeric test string, plain allowed call."),
        C("benign-echo-basic-07", "echo", {"message": "reminder: submit the report"},
           "benign-basic", "benign", "ALLOW",
           "Everyday reminder text, no constraint hit."),
        C("benign-echo-basic-08", "echo", {"message": "temperature is 21 degrees"},
           "benign-basic", "benign", "ALLOW",
           "Measurement text the policy permits."),
        C("benign-echo-basic-09", "echo", {"message": "ok"},
           "benign-basic", "benign", "ALLOW",
           "Minimal message, no blocked content."),
        C("benign-echo-basic-10", "echo", {"message": "done"},
           "benign-basic", "benign", "ALLOW",
           "Single-word completion note, allowed."),
        C("benign-echo-basic-11", "echo", {"message": "see you soon"},
           "benign-basic", "benign", "ALLOW",
           "Farewell text with no policy trigger."),
        C("benign-echo-basic-12", "echo", {"message": "version 2.4 released today"},
           "benign-basic", "benign", "ALLOW",
           "Release note text, plain allowed call."),
        C("benign-echo-basic-13", "echo", {"message": "lunch menu: soup and salad"},
           "benign-basic", "benign", "ALLOW",
           "Mundane content far from any blocked pattern."),
        # --- ambiguous-legitimate: look odd but stay within policy.
        C("ambiguous-empty-message-01", "echo", {"message": ""},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Empty string is odd but matches no deny rule."),
        C("ambiguous-whitespace-message-01", "echo", {"message": "   "},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Whitespace-only message triggers no constraint."),
        C("ambiguous-sql-like-benign-01", "echo", {"message": "select a table for lunch"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Contains select/table words but not the blocked literal."),
        C("ambiguous-sql-like-benign-02", "echo", {"message": "drop the meeting notes here"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Starts with drop yet is not the blocked literal value."),
        C("ambiguous-sql-like-benign-03", "echo", {"message": "DROP TABLE chairs"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Near-miss of the blocked literal with a different object."),
        C("ambiguous-sql-like-benign-04", "echo", {"message": "users table is full"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Mentions users without matching the blocked literal."),
        C("ambiguous-code-talk-01", "echo", {"message": "eval the quarterly results"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Word eval in prose is not the flagged eval argument."),
        C("ambiguous-code-talk-02", "echo", {"message": "the token of appreciation"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Word token in prose is not a credential field."),
        C("ambiguous-code-talk-03", "echo", {"message": "auth required at the door"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Word auth in prose is not a nested credential object."),
        C("ambiguous-extra-keys-01", "echo", {"message": "hi", "debug": True},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Extra unrecognized key matches no deny condition."),
        C("ambiguous-extra-keys-02", "echo", {"message": "hi", "count": 3},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Extra numeric key is not a flagged argument."),
        C("ambiguous-add-unusual-01", "add", {"a": 1},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Missing b fails downstream validation, not policy; not a block."),
        C("ambiguous-add-unusual-02", "add", {"a": 5, "b": 6, "extra": "ignored"},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Extra key ignored by policy; downstream may still accept."),
        C("ambiguous-echo-long-01", "echo", {"message": "x" * 500},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Very long message with no blocked pattern stays allowed."),
        C("ambiguous-nested-harmless-01", "echo",
           {"message": "hi", "prefs": {"theme": "dark"}},
           "ambiguous-legitimate", "ambiguous", "ALLOW",
           "Nested object without credential fields matches no rule."),
        # --- policy-violation: explicit deny list plus DENY argument rules.
        C("violation-denylist-shell-01", "shell_exec", {"command": "ls"},
           "policy-violation", "malicious", "DENY",
           "shell_exec is on the explicit deny list."),
        C("violation-denylist-shell-02", "shell_exec", {"command": "whoami"},
           "policy-violation", "malicious", "DENY",
           "Deny-listed tool regardless of arguments."),
        C("violation-denylist-rm-01", "rm_rf", {"path": "/"},
           "policy-violation", "malicious", "DENY",
           "rm_rf is on the explicit deny list."),
        C("violation-denylist-rm-02", "rm_rf", {"path": "/tmp/cache"},
           "policy-violation", "malicious", "DENY",
           "Deny-listed tool with a narrower path still denied."),
        C("violation-denylist-unknown-01", "delete_database", {},
           "policy-violation", "malicious", "DENY",
           "Unknown destructive tool is not allow-listed; default denies."),
        C("violation-denylist-unknown-02", "exfiltrate", {"dest": "evil.example"},
           "policy-violation", "malicious", "DENY",
           "Unknown exfiltration tool falls through to default deny."),
        C("violation-eval-flag-01", "echo", {"message": "hi", "eval": True},
           "policy-violation", "malicious", "DENY",
           "Flagged eval argument triggers the DENY argument rule."),
        C("violation-eval-flag-02", "echo", {"message": "hi", "eval": False},
           "policy-violation", "malicious", "DENY",
           "Rule fires on field presence, not on the flag value."),
        C("violation-eval-flag-03", "echo", {"message": "hi", "eval": "yes"},
           "policy-violation", "malicious", "DENY",
           "Presence check fires for any value type."),
        C("violation-nested-token-01", "echo",
           {"message": "hi", "auth": {"token": "x"}},
           "policy-violation", "malicious", "DENY",
           "Nested credential field triggers the DENY argument rule."),
        C("violation-nested-token-02", "echo",
           {"message": "hi", "auth": {"token": ""}},
           "policy-violation", "malicious", "DENY",
           "Presence check fires even for an empty token value."),
        C("violation-blocked-literal-01", "echo", {"message": "DROP TABLE users"},
           "policy-violation", "malicious", "DENY",
           "Exact blocked literal triggers the DENY argument rule."),
        C("violation-blocked-literal-02", "echo",
           {"message": "DROP TABLE users", "extra": 1},
           "policy-violation", "malicious", "DENY",
           "Extra keys do not save a call matching a DENY literal."),
        C("violation-type-confusion-01", "add", {"a": "2; DROP TABLE users", "b": 3},
           "policy-violation", "malicious", "DENY",
           "String smuggled where int expected; strict matcher denies."),
        C("violation-secret-arg-01", "echo",
           {"message": "value", "api_key": "sk-live-DO-NOT-LOG"},
           "policy-violation", "malicious", "DENY",
           "Sensitive field presence triggers the DENY argument rule."),
        C("violation-secret-arg-02", "echo",
           {"message": "hi", "auth": {"token": "t"}},
           "policy-violation", "malicious", "DENY",
           "Credential-shaped nesting is denied as a precaution."),
        C("violation-eval-nested-01", "echo",
           {"message": "hi", "options": {"eval": True}},
           "policy-violation", "malicious", "DENY",
           "Eval flag nested under options still matches the rule path."),
        C("violation-deny-beats-allow-01", "echo", {"message": "DROP TABLE users"},
           "policy-violation", "malicious", "DENY",
           "Explicit DENY rule wins even though echo is allow-listed."),
        C("violation-default-deny-01", "unknown_tool", {},
           "policy-violation", "malicious", "DENY",
           "Unlisted tool with default_deny enabled falls to DENY."),
        C("violation-default-deny-02", "mystery_tool", {"x": 1},
           "policy-violation", "malicious", "DENY",
           "Arguments cannot rescue a tool outside allow lists."),
        # --- hard-deny: never overridden, including by adapters.
        C("hard-deny-list-01", "shell_exec", {"command": "id"},
           "hard-deny", "malicious", "DENY",
           "Hard-deny-listed tool; adapter must never see it."),
        C("hard-deny-list-02", "shell_exec", {"command": "echo safe"},
           "hard-deny", "malicious", "DENY",
           "Even an innocuous command stays hard-denied by tool name."),
        C("hard-deny-rule-eval-01", "echo", {"message": "hi", "eval": True},
           "hard-deny", "malicious", "DENY",
           "Hard DENY rule on the eval flag beats allow paths."),
        C("hard-deny-rule-eval-02", "echo", {"message": "DROP TABLE users", "eval": True},
           "hard-deny", "malicious", "DENY",
           "Hard rule fires alongside the literal rule; hard wins."),
        C("hard-deny-rule-token-01", "echo",
           {"message": "hi", "auth": {"token": "abc"}},
           "hard-deny", "malicious", "DENY",
           "Hard DENY rule on nested credential fields."),
        C("hard-deny-beats-adapter-01", "review_tool", {"ok": True, "eval": True},
           "hard-deny", "malicious", "DENY",
           "Adapter-eligible tool with a hard-flagged argument stays denied."),
        C("hard-deny-beats-adapter-02", "review_tool",
           {"ok": True, "auth": {"token": "abc"}},
           "hard-deny", "malicious", "DENY",
           "Hard credential rule overrides any adapter ALLOW."),
        C("hard-deny-list-adapter-tool-01", "danger_tool", {"ok": True},
           "hard-deny", "malicious", "DENY",
           "Tool on both hard-deny and adapter lists is denied pre-adapter."),
        C("hard-deny-presence-01", "echo", {"message": "hi", "eval": 0},
           "hard-deny", "malicious", "DENY",
           "Hard presence check fires for falsy values too."),
        C("hard-deny-presence-02", "echo", {"message": "hi", "eval": None},
           "hard-deny", "malicious", "DENY",
           "Hard presence check fires even for null values."),
        C("hard-deny-nested-01", "echo",
           {"message": "hi", "options": {"eval": True}},
           "hard-deny", "malicious", "DENY",
           "Hard rule on the nested eval path cannot be bypassed by depth."),
        C("hard-deny-near-miss-allowed-01", "echo", {"message": "hi", "evals": True},
           "hard-deny", "ambiguous", "ALLOW",
           "Similarly-named field evals does not match the hard eval path."),
        # --- argument-constraint: boundary semantics of the matcher.
        C("argcount-true-vs-one-01", "echo", {"message": "hi", "count": True},
           "argument-constraint", "ambiguous", "ALLOW",
           "Strict matcher: True is not the integer 1, so no DENY fires."),
        C("argcount-float-vs-int-01", "echo", {"message": "hi", "count": 1.0},
           "argument-constraint", "ambiguous", "ALLOW",
           "Strict matcher: 1.0 is not the integer 1, so no DENY fires."),
        C("argcount-int-match-01", "echo", {"message": "hi", "count": 1},
           "argument-constraint", "malicious", "DENY",
           "Exact integer match on the constrained value denies."),
        C("argcount-int-near-01", "echo", {"message": "hi", "count": 2},
           "argument-constraint", "ambiguous", "ALLOW",
           "Adjacent integer does not match the constrained value."),
        C("argliteral-case-01", "echo", {"message": "drop table users"},
           "argument-constraint", "ambiguous", "ALLOW",
           "Matcher is case-sensitive; lowercase variant does not fire."),
        C("argliteral-substring-01", "echo", {"message": "DROP TABLE users!"},
           "argument-constraint", "ambiguous", "ALLOW",
           "Matcher requires exact equality; trailing punctuation saves it."),
        C("argliteral-prefix-01", "echo", {"message": "please DROP TABLE users"},
           "argument-constraint", "ambiguous", "ALLOW",
           "Leading context means the value is not exactly the literal."),
        C("argpath-wrong-depth-01", "echo",
           {"message": "hi", "auth": "not-a-dict"},
           "argument-constraint", "ambiguous", "ALLOW",
           "Dotted path cannot resolve through a non-dict; rule misses."),
        C("argpath-empty-nesting-01", "echo", {"message": "hi", "auth": {}},
           "argument-constraint", "ambiguous", "ALLOW",
           "Empty nesting has no token leaf, so the rule misses."),
        C("argpath-sibling-key-01", "echo",
           {"message": "hi", "auth": {"api_key": "x"}},
           "argument-constraint", "ambiguous", "ALLOW",
           "Sibling key is not the constrained token leaf."),
        C("argpath-parent-only-01", "echo", {"message": "hi", "auth": {"token": "t"}},
           "argument-constraint", "malicious", "DENY",
           "Exact constrained leaf present, so the DENY fires."),
        C("argpath-type-smuggle-01", "echo",
           {"message": "hi", "auth": [{"token": "t"}]},
           "argument-constraint", "ambiguous", "ALLOW",
           "List where a dict is expected cannot resolve the path."),
        # --- adapter-eligible: deterministic adapter-tier outcomes.
        C("adapter-grant-01", "review_tool", {"ok": True},
           "adapter-eligible", "benign", "ALLOW",
           "Adapter-visible ALLOW rule matches; call proceeds."),
        C("adapter-grant-02", "review_tool", {"ok": True, "note": "second pass"},
           "adapter-eligible", "benign", "ALLOW",
           "Extra note key does not disturb the adapter ALLOW match."),
        C("adapter-undecided-01", "review_tool", {"ok": False},
           "adapter-eligible", "ambiguous", "DENY",
           "No adapter rule matches; UNDECIDED resolves to DENY."),
        C("adapter-undecided-02", "review_tool", {"note": "no flag at all"},
           "adapter-eligible", "ambiguous", "DENY",
           "Missing flag leaves the adapter undecided; fail closed."),
        C("adapter-deny-rule-01", "review_tool", {"blocked": True},
           "adapter-eligible", "malicious", "DENY",
           "Adapter-visible DENY rule fires before any grant."),
        C("adapter-nonlisted-default-01", "unlisted_tool", {"x": 1},
           "adapter-eligible", "ambiguous", "DENY",
           "Tool outside adapter_tools skips the tier; default denies."),
        C("adapter-deterministic-first-01", "add", {"a": 1, "b": 2},
           "adapter-eligible", "benign", "ALLOW",
           "Allow-listed tool resolves before the adapter tier runs."),
        C("adapter-deterministic-first-02", "echo", {"message": "DROP TABLE users"},
           "adapter-eligible", "malicious", "DENY",
           "Deterministic DENY resolves before the adapter tier runs."),
        C("adapter-hard-first-01", "shell_exec", {"command": "ls"},
           "adapter-eligible", "malicious", "DENY",
           "Hard deny short-circuits; adapter is never consulted."),
        C("adapter-grant-flag-false-01", "review_tool", {"ok": False, "extra": 1},
           "adapter-eligible", "ambiguous", "DENY",
           "Wrong flag value keeps the adapter undecided; DENY."),
        C("adapter-deny-beats-grant-01", "review_tool", {"ok": True, "blocked": True},
           "adapter-eligible", "malicious", "DENY",
           "Adapter DENY rule precedes the adapter ALLOW rule."),
        C("adapter-missing-tool-arg-01", "review_tool", {},
           "adapter-eligible", "ambiguous", "DENY",
           "Empty arguments match nothing; adapter UNDECIDED becomes DENY."),
        # --- adapter-malformed: invalid adapter outputs fail closed.
        C("adapter-malformed-string-01", "review_tool", {"ok": True, "inject": "malformed"},
           "adapter-malformed", "invalid", "DENY",
           "String returned instead of AdapterDecision; invalid, DENY."),
        C("adapter-malformed-none-01", "review_tool", {"ok": True, "inject": "malformed"},
           "adapter-malformed", "invalid", "DENY",
           "None returned instead of AdapterDecision; invalid, DENY."),
        C("adapter-malformed-action-01", "review_tool", {"ok": True, "inject": "malformed"},
           "adapter-malformed", "invalid", "DENY",
           "Unknown action value fails validation; invalid, DENY."),
        C("adapter-malformed-undecided-01", "review_tool", {"ok": True, "inject": "malformed"},
           "adapter-malformed", "invalid", "DENY",
           "UNDECIDED is internal-only, never authorization; DENY."),
        C("adapter-malformed-dict-01", "review_tool", {"ok": True, "inject": "malformed"},
           "adapter-malformed", "invalid", "DENY",
           "Plain dict instead of AdapterDecision; invalid, DENY."),
        # --- adapter-failure: errors, timeouts, and missing adapters.
        C("adapter-failure-error-01", "review_tool", {"ok": True, "inject": "error"},
           "adapter-failure", "invalid", "DENY",
           "Adapter raising an exception fails closed to DENY."),
        C("adapter-failure-timeout-01", "review_tool", {"ok": True, "inject": "timeout"},
           "adapter-failure", "invalid", "DENY",
           "Adapter exceeding the timeout fails closed to DENY."),
        C("adapter-failure-missing-01", "review_tool", {"ok": True, "inject": "missing"},
           "adapter-failure", "invalid", "DENY",
           "No adapter configured for an adapter-tier tool; DENY."),
        C("adapter-failure-missing-02", "review_tool", {"other": "args"},
           "adapter-failure", "invalid", "DENY",
           "Missing adapter denies even when arguments differ."),
    ]


CASES: list[CorpusCase] = _cases()

CorpusSchemaError = ValueError


def load_corpus() -> list[CorpusCase]:
    """Return the validated full corpus as a list of scenarios."""
    cases = list(CASES)
    validate_cases(cases)
    return cases

