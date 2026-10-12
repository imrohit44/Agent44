"""Versioned corpus of benign and simulated-adversarial tool-call scenarios.

These are *test scenarios* used to exercise the demo tools and the observation
layer. They are NOT a claim of comprehensive attack coverage. Each scenario is
labeled ``benign`` or ``adversarial`` so an evaluation run can report the mix
while making clear that in observation-only mode nothing is blocked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CORPUS_VERSION = "0.1.0"


@dataclass(frozen=True)
class CorpusCase:
    """A single corpus scenario targeting a demo tool."""

    id: str
    tool_name: str
    arguments: dict[str, Any]
    category: str  # "benign" | "adversarial"
    note: str = ""


def _cases() -> list[CorpusCase]:
    return [
        # --- Benign ---
        CorpusCase("benign-add-1", "add", {"a": 2, "b": 3}, "benign", "simple sum"),
        CorpusCase("benign-add-2", "add", {"a": -10, "b": 4}, "benign", "negative operand"),
        CorpusCase("benign-echo-1", "echo", {"message": "hello"}, "benign", "short message"),
        CorpusCase(
            "benign-echo-2",
            "echo",
            {"message": "a longer benign message to exercise string handling"},
            "benign",
            "longer message",
        ),
        # --- Simulated adversarial ---
        # Argument-smuggling style: a tool name that does not exist downstream.
        CorpusCase(
            "adv-unknown-tool",
            "rm_rf",
            {"path": "/"},
            "adversarial",
            "unknown tool; downstream returns tool-level error",
        ),
        # Type confusion / injection of unexpected argument types.
        CorpusCase(
            "adv-type-confusion",
            "add",
            {"a": "2; DROP TABLE users", "b": 3},
            "adversarial",
            "string where int expected; downstream validation rejects",
        ),
        # Missing required argument.
        CorpusCase(
            "adv-missing-arg",
            "add",
            {"a": 1},
            "adversarial",
            "required argument omitted",
        ),
        # Sensitive field in arguments (should be redacted in observations).
        CorpusCase(
            "adv-secret-arg",
            "echo",
            {"message": "value", "api_key": "sk-live-DO-NOT-LOG"},
            "adversarial",
            "sensitive field name present; extra key ignored by echo",
        ),
    ]


CASES: list[CorpusCase] = _cases()


def load_corpus() -> list[CorpusCase]:
    """Return the full corpus as a list of scenarios."""
    return list(CASES)
