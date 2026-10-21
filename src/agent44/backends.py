"""Stable provider-independent backend contract (Phase 10).

Builds *on* the existing :class:`agent44.policy.DecisionAdapter` seam — it is
not a parallel policy engine or adapter abstraction. Every backend is a
``DecisionAdapter`` that ultimately produces ``ALLOW`` / ``DENY`` /
``UNDECIDED`` through the existing engine fail-closed contract. This module
adds only reproducibility and attribution metadata around that seam:

- :class:`BackendIdentity` — name, version, decision-relevant config hash,
  stochasticity flag, optional probability metadata.
- :func:`config_sha256` — SHA-256 over canonical JSON of everything
  decision-relevant (prompt template, thresholds, model tag, parser version).
- :class:`RecordingAdapter` — wraps any backend adapter and records one
  bounded, secret-free :class:`BackendCallRecord` per consultation so runs can
  attribute outcomes to the actual decision source
  (``deterministic_rule`` / ``backend_decision`` / ``fail_closed_fallback`` /
  ``execution_failure``) and never credit a backend for a call the
  deterministic tiers already decided.
- :class:`BackendStatus` / :class:`BackendAvailability` — explicit
  unavailable/unverified provider reporting without fabricating results.

Hard-deny and deterministic precedence are unchanged: the engine consults an
adapter only after all applicable deterministic tiers returned UNDECIDED and
only for ``adapter_tools``; a backend can never grant authority, bypass
argument constraints, elevate provenance, or override delegation. There are
no retries. Records never contain prompts, credentials, raw responses, or raw
argument values.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agent44.policy import AdapterDecision, DecisionAdapter, PolicyRule

CONTRACT_VERSION = "phase10-backend-contract-1"
"""Version of this metadata contract (bump on breaking metadata changes)."""

MAX_RECORD_REASON_LEN = 200
"""Bounded copy of a backend reason retained in per-call records."""


def config_sha256(config: dict[str, Any]) -> str:
    """Return SHA-256 over canonical JSON of decision-relevant ``config``.

    Keys are sorted and separators are compact so equal configs hash equal
    across platforms. Non-JSON-serializable values are rejected loudly: a
    config that cannot be hashed deterministically must not silently produce
    a hash.
    """
    try:
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), default=None)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"config is not canonical-JSON serializable: {type(exc).__name__}"
        ) from exc
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BackendIdentity:
    """Reproducibility metadata for one configured backend."""

    name: str
    version: str
    config_sha256: str
    stochastic: bool
    contract_version: str = CONTRACT_VERSION
    probability_metadata: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "name": self.name,
            "version": self.version,
            "config_sha256": self.config_sha256,
            "stochastic": self.stochastic,
            "probability_metadata": (
                dict(self.probability_metadata) if self.probability_metadata else None
            ),
        }


class BackendStatus(StrEnum):
    """Availability of a backend, decided without making live calls."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class BackendAvailability:
    """Explicit provider availability report (never fabricates access)."""

    status: BackendStatus
    reason: str
    documentation: str | None = None
    verification: str = "unverified"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reason": self.reason,
            "documentation": self.documentation,
            "verification": self.verification,
        }


# Decision-source taxonomy (PROTOCOL_v1.2 §9). Exactly one applies per
# scenario evaluation.
SOURCE_DETERMINISTIC_RULE = "deterministic_rule"
SOURCE_BACKEND_DECISION = "backend_decision"
SOURCE_FAIL_CLOSED_FALLBACK = "fail_closed_fallback"
SOURCE_EXECUTION_FAILURE = "execution_failure"
SOURCE_HARNESS_ERROR = "harness_error"
SOURCE_UNSUPPORTED_CONDITION = "unsupported_condition"
DECISION_SOURCES = frozenset(
    {
        SOURCE_DETERMINISTIC_RULE,
        SOURCE_BACKEND_DECISION,
        SOURCE_FAIL_CLOSED_FALLBACK,
        SOURCE_EXECUTION_FAILURE,
        SOURCE_HARNESS_ERROR,
        SOURCE_UNSUPPORTED_CONDITION,
    }
)

FAIL_CLOSED_RULE_IDS = frozenset(
    {
        "adapter_timeout",
        "adapter_invalid",
        "adapter_error",
        "adapter_undecided",
        "adapter_missing",
    }
)
"""Engine fail-closed buckets, from the unchanged Phase 9 contract."""


def classify_decision_source(rule_id: str | None, *, backend_consulted: bool) -> str:
    """Map an engine decision to its actual decision source.

    - No backend consulted → the deterministic tiers decided (this covers
      hard-deny, argument constraints, allow/deny lists, soft rules, the
      policy default, and every non-adapter tier). A backend is never credited
      for a call it did not decide.
    - Backend consulted but the engine reports a fail-closed bucket →
      ``fail_closed_fallback`` (timeout/invalid/error/undecided/missing).
    - Backend consulted and its ALLOW/DENY was used → ``backend_decision``.
    """
    if rule_id in FAIL_CLOSED_RULE_IDS:
        return SOURCE_FAIL_CLOSED_FALLBACK
    if backend_consulted:
        return SOURCE_BACKEND_DECISION
    return SOURCE_DETERMINISTIC_RULE


@dataclass
class BackendCallRecord:
    """One bounded, secret-free record of a backend consultation.

    Durations, labels, and bounded printable reasons only — never prompt
    text, raw responses, credentials, or raw argument values.
    """

    tool_name: str
    action: str | None = None
    rule_id: str | None = None
    duration_ms: float | None = None
    outcome: str = "error"
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "action": self.action,
            "rule_id": self.rule_id,
            "duration_ms": self.duration_ms,
            "outcome": self.outcome,
            "detail": self.detail,
        }


class RecordingAdapter(DecisionAdapter):
    """Wrap a backend adapter and record one secret-free record per call.

    The inner adapter's behavior is passed through unchanged: returns,
    :class:`~agent44.policy.AdapterParseError` raises, other exceptions, and
    cancellation all behave exactly as if the wrapper were absent (the engine
    keeps applying the existing fail-closed contract). The wrapper only adds
    ``records`` — a list appended in call order, one entry per consultation —
    plus a call counter used by tests to prove that deterministically decided
    calls never reach a backend.
    """

    def __init__(self, inner: DecisionAdapter, identity: BackendIdentity | None = None) -> None:
        self._inner = inner
        self.identity = identity
        self.records: list[BackendCallRecord] = []
        self.consultations = 0

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        self.consultations += 1
        record = BackendCallRecord(tool_name=tool_name)
        started = time.monotonic()
        try:
            decision = await self._inner.decide(tool_name, arguments, rules)
        except (Exception, asyncio.CancelledError) as exc:  # noqa: BLE001 - re-raised below
            record.duration_ms = (time.monotonic() - started) * 1000.0
            record.outcome = "cancelled" if isinstance(exc, asyncio.CancelledError) else "error"
            # Class name only: exception messages are untrusted and may embed data.
            record.detail = type(exc).__name__
            self.records.append(record)
            raise
        record.duration_ms = (time.monotonic() - started) * 1000.0
        record.action = decision.action.value
        record.rule_id = decision.rule_id
        record.outcome = "decision"
        reason = decision.reason or ""
        printable = "".join(ch if ch.isprintable() else " " for ch in reason)
        record.detail = " ".join(printable.split())[:MAX_RECORD_REASON_LEN]
        self.records.append(record)
        return decision

    @property
    def backend_calls(self) -> int:
        return len(self.records)

    @property
    def failed_calls(self) -> int:
        return sum(1 for r in self.records if r.outcome != "decision")

