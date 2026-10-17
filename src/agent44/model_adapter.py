"""Model-based decision adapters for Agent44 (Milestone 4b).

This module provides adapters that implement the deterministic
:class:`~agent44.policy.DecisionAdapter` protocol while treating any
model output as **untrusted**:

- :func:`parse_model_decision` is a strict, documented parser that accepts
  only ``ALLOW`` or ``DENY`` with a bounded reason and permitted metadata,
  and rejects ``UNDECIDED``, unknown actions, extra fields, malformed JSON,
  empty output, and unexpected shapes.
- :class:`ModelDecisionAdapter` wraps an injectable async ``complete``
  callable (the provider boundary). No provider SDK or network call is
  bundled here; tests inject a deterministic ``complete``. Any provider
  exception, malformed output, or timeout propagates so the engine fails
  closed (the engine maps these to ``adapter_error``/``adapter_timeout``).
- :class:`FakeModelAdapter` returns fixed decisions for offline tests.
- :class:`ReplayAdapter` replays decisions from a JSON fixture keyed by a
  deterministic, secret-safe :func:`decision_key`.

Adapters never see hard-deny rules and never override deterministic tiers:
``PolicyEngine`` only consults an adapter after the deterministic tiers are
undecided, only for tools listed in ``adapter_tools``, and never for a call a
hard-deny rule already denied. Model output can never modify policy config.

Secrets: prompts and replay keys are built from ``observe.safe_arguments``
(type/length metadata only); raw argument values are never placed in a prompt,
a reason, or a replay key.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent44 import observe
from agent44.policy import (
    Action,
    AdapterDecision,
    AdapterParseError,
    DecisionAdapter,
    PolicyRule,
)

# Optional per-call adapter timings hook. ModelDecisionAdapter.decide()
# accepts a caller-owned ``timings_out`` list and appends exactly one
# AdapterTimings record (durations only, no prompt/response content).
# Kept local to this module to avoid a provider <-> adapter import cycle:
# model_adapter must not import local_provider.


class AdapterTimings:
    """Privacy-safe, bounded per-call timing record for adapter diagnosis.

    One float duration (monotonic seconds) per pipeline stage plus the
    total. Stage names and durations only — no prompt text, no response
    bytes, no credentials, no scenario payload. One small fixed-size
    object per call; no buffer, no background worker, no network.

    ``provider`` optionally nests the provider's own stage breakdown
    (e.g. ``OllamaProvider.complete`` send/read/extract stages) when the
    injected ``complete`` supplies it. Stored as an opaque object to
    avoid a provider <-> adapter import cycle; :meth:`as_dict` renders
    it via its own ``as_dict()`` when available. It never carries
    prompt/response content either — durations only.
    """

    __slots__ = (
        "build_prompt_s",
        "complete_s",
        "parse_s",
        "total_s",
        "provider",
    )

    def __init__(self) -> None:
        self.build_prompt_s: float | None = None
        self.complete_s: float | None = None
        self.parse_s: float | None = None
        self.total_s: float | None = None
        self.provider: Any | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return stage durations; ``None`` means the stage never ran."""
        provider_dict: Any = None
        if self.provider is not None:
            as_dict = getattr(self.provider, "as_dict", None)
            provider_dict = as_dict() if callable(as_dict) else repr(self.provider)
        return {
            "build_prompt_s": self.build_prompt_s,
            "complete_s": self.complete_s,
            "parse_s": self.parse_s,
            "total_s": self.total_s,
            "provider": provider_dict,
        }

# Strict parser limits (treat model output as untrusted).
MAX_OUTPUT_CHARS = 8192
MAX_REASON_LEN = 200
MAX_RULE_ID_LEN = 64
ALLOWED_KEYS = frozenset({"action", "reason", "rule_id"})
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# Async provider boundary: given a prompt, return the raw model text.
CompleteFn = Callable[[str], Awaitable[str]]


MAX_ERROR_DETAIL_LEN = 160
"""Upper bound (chars) for model-output excerpts embedded in error messages."""


class ModelOutputError(AdapterParseError):
    """Raised when model output cannot be parsed into a valid decision.

    Subclassing :class:`~agent44.policy.AdapterParseError` makes the engine
    map parse failures to the fail-closed ``adapter_invalid`` outcome (a
    DENY), kept distinct from provider/transport failures (``adapter_error``).
    """


def _bounded_text(text: str, limit: int = MAX_ERROR_DETAIL_LEN) -> str:
    """Return a printable, single-line excerpt of ``text`` capped at ``limit``.

    Model output is untrusted: error messages that echo it must never carry
    multi-kilobyte dumps or control characters into logs or reports.
    """
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > limit:
        cleaned = cleaned[: max(0, limit - 3)].rstrip() + "..."
    return cleaned


def sanitized_response_summary(text: str) -> dict[str, Any]:
    """Return a secret-safe diagnostic fingerprint of raw model output.

    Raw model responses must never be written to logs, observation files, or
    replay fixtures. When a parser failure must be recorded for diagnosis,
    use this helper instead: it preserves the SHA-256 of the exact raw text,
    its character count, and a short printable excerpt. The strict parser
    only ever receives model output derived from a secret-free prompt (safe
    argument metadata), so an excerpt cannot echo call secrets.
    """
    if not isinstance(text, str):
        raise ModelOutputError("response summary requires a string")
    return {
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "chars": len(text),
        "excerpt": _bounded_text(text.strip()),
    }


class ReplayError(ValueError):
    """Raised for an invalid replay fixture or a missing replay entry."""

def _sanitize_reason(value: Any) -> str:
    """Return a bounded, control-character-free reason, or ``''`` if invalid."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > MAX_REASON_LEN:
        cleaned = cleaned[:MAX_REASON_LEN].rstrip()
    return cleaned


def _require_rule_id(value: Any) -> str | None:
    """Validate an optional rule id; raise :class:`ModelOutputError` if invalid."""
    if value is None:
        return None
    if not isinstance(value, str) or not _RULE_ID_RE.match(value):
        raise ModelOutputError(f"invalid rule_id: {_bounded_text(repr(value))}")
    if len(value) > MAX_RULE_ID_LEN:
        raise ModelOutputError("rule_id exceeds maximum length")
    return value


def parse_model_decision(text: str) -> AdapterDecision:
    """Strictly parse untrusted model ``text`` into an :class:`AdapterDecision`.

    Accepts only a JSON object with exactly the keys in :data:`ALLOWED_KEYS`,
    an ``action`` of ``ALLOW`` or ``DENY``, a bounded non-empty ``reason``, and
    an optional safe ``rule_id``. Rejects ``UNDECIDED``, unknown actions, extra
    fields, malformed JSON, empty output, and oversized output by raising
    :class:`ModelOutputError`.
    """
    if not isinstance(text, str):
        raise ModelOutputError("model output must be a string")
    stripped = text.strip()
    if not stripped:
        raise ModelOutputError("empty model output")
    if len(stripped) > MAX_OUTPUT_CHARS:
        raise ModelOutputError("model output exceeds maximum size")
    try:
        data = json.loads(stripped)
    except ValueError as exc:  # includes json.JSONDecodeError
        raise ModelOutputError(f"model output is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelOutputError("model output must be a JSON object")

    extra = set(data) - ALLOWED_KEYS
    if extra:
        raise ModelOutputError(
            f"unexpected fields in model output: {_bounded_text(str(sorted(extra)))}"
        )

    action_raw = data.get("action")
    if action_raw not in ("ALLOW", "DENY"):
        raise ModelOutputError(f"invalid or missing action: {_bounded_text(repr(action_raw))}")

    reason = _sanitize_reason(data.get("reason"))
    if not reason:
        raise ModelOutputError("missing or empty reason")

    rule_id = _require_rule_id(data.get("rule_id"))
    return AdapterDecision(action=Action(action_raw), reason=reason, rule_id=rule_id)


def decision_key(tool_name: str, arguments: dict[str, Any] | None) -> str:
    """Return a deterministic, secret-safe key for a call.

    Non-sensitive argument values are included verbatim so genuinely distinct
    calls (e.g. ``{"ok": True}`` vs ``{"ok": False}``) get distinct keys and can
    replay different decisions. Sensitive fields are replaced by a constant
    marker (``observe.REDACTED``) before hashing, so secrets never enter a key
    or a replay fixture. Identical inputs always yield an identical key.
    """
    redacted = observe.redact_arguments(arguments or {})
    canonical = json.dumps(redacted, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{tool_name}:{digest}"


def _validate_record(record: Any) -> AdapterDecision:
    """Validate one replay record into an :class:`AdapterDecision`."""
    if not isinstance(record, dict):
        raise ReplayError("replay record must be a JSON object")
    extra = set(record) - ALLOWED_KEYS
    if extra:
        raise ReplayError(f"unexpected fields in replay record: {sorted(extra)}")
    action_raw = record.get("action")
    if action_raw not in ("ALLOW", "DENY"):
        raise ReplayError(f"invalid or missing action: {action_raw!r}")
    reason = _sanitize_reason(record.get("reason"))
    if not reason:
        raise ReplayError("missing or empty reason")
    try:
        rule_id = _require_rule_id(record.get("rule_id"))
    except ModelOutputError as exc:
        raise ReplayError(str(exc)) from exc
    return AdapterDecision(action=Action(action_raw), reason=reason, rule_id=rule_id)


class ModelDecisionAdapter(DecisionAdapter):
    """Adapter that defers to an injected async model ``complete`` callable.

    The provider boundary is a single ``complete(prompt) -> str`` coroutine, so
    no provider SDK, credentials, or network access live here. Tests inject a
    deterministic ``complete``. Provider exceptions and parse failures
    propagate, and the engine maps them to fail-closed ``DENY``.
    """

    def __init__(self, complete: CompleteFn, *, model_name: str = "unknown") -> None:
        self._complete = complete
        self.model_name = model_name

    def build_prompt(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> str:
        """Build a secret-free prompt (safe argument metadata only)."""
        safe = observe.safe_arguments(arguments or {})
        rule_lines = [f"- {r.id}: {r.action.value}" for r in rules]
        rules_block = "\n".join(rule_lines) if rule_lines else "(none)"
        return (
            "You are an authorization decision function for one MCP tool call.\n"
            "Respond with a single JSON object and nothing else.\n"
            'Schema: {"action": "ALLOW"|"DENY", "reason": string, '
            '"rule_id": string?}\n'
            "Decide ALLOW or DENY. Never output UNDECIDED.\n\n"
            f"tool: {tool_name}\n"
            f"arguments_summary: {json.dumps(safe, sort_keys=True)}\n"
            f"candidate_rules:\n{rules_block}"
        )

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
        *,
        timings_out: list[AdapterTimings] | None = None,
    ) -> AdapterDecision:
        """Run one adapter decision with bounded, privacy-safe stage timings.

        Stages: prompt construction, provider ``complete`` (whole provider
        call, whatever its inner stages are), response parsing, and the
        total. When the injected provider nests its own stage breakdown
        (``OllamaProvider.complete``), it is attached as
        ``timings.provider`` — a separate nested record, not a second
        timeout source.

        ``timings_out`` is a caller-owned list; at most one record is
        appended (even when cancelled). Cancellation from the engine's
        ``asyncio.wait_for`` deadline propagates unchanged: ``complete_s``
        and ``total_s`` are still stamped by the ``finally`` blocks, stages
        that never ran stay ``None``, and the ``CancelledError`` is
        re-raised (never converted to a provider error) so the engine
        records ``adapter_timeout``.
        """
        timings = AdapterTimings()
        total_started = time.monotonic()
        try:
            stage_started = time.monotonic()
            prompt = self.build_prompt(tool_name, arguments, rules)
            timings.build_prompt_s = time.monotonic() - stage_started
            stage_started = time.monotonic()
            # Forward the provider-stage slot only when the injected
            # ``complete`` accepts it (OllamaProvider.complete does; test
            # fakes taking just ``(prompt)`` keep working unchanged).
            provider_slot: list[Any] | None = None
            try:
                accepts_timings = "timings_out" in inspect.signature(self._complete).parameters
            except (TypeError, ValueError):
                accepts_timings = False
            try:
                if accepts_timings:
                    provider_slot = []
                    raw = await self._complete(prompt, timings_out=provider_slot)
                else:
                    raw = await self._complete(prompt)
            finally:
                timings.complete_s = time.monotonic() - stage_started
                if provider_slot:
                    timings.provider = provider_slot[0]
            stage_started = time.monotonic()
            decision = parse_model_decision(raw)
            timings.parse_s = time.monotonic() - stage_started
            return decision
        finally:
            timings.total_s = time.monotonic() - total_started
            if timings_out is not None:
                timings_out.append(timings)


class FakeModelAdapter(DecisionAdapter):
    """Deterministic offline adapter returning fixed decisions by tool name.

    ``decisions`` maps a tool name to ``"ALLOW"``, ``"DENY"``, or
    ``"UNDECIDED"``. A tool with no entry returns ``UNDECIDED`` (fail closed).
    """

    def __init__(self, decisions: dict[str, str]) -> None:
        self._decisions = dict(decisions)

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        action = self._decisions.get(tool_name, "UNDECIDED").upper()
        if action not in ("ALLOW", "DENY", "UNDECIDED"):
            action = "UNDECIDED"
        return AdapterDecision(
            action=Action(action),
            reason=f"fake decision for tool '{tool_name}': {action}",
            rule_id="fake",
        )


class ReplayAdapter(DecisionAdapter):
    """Replay recorded decisions from a JSON fixture for reproducible runs.

    The fixture maps :func:`decision_key` values to decision records. A missing
    entry or an invalid record raises :class:`ReplayError`, which the engine
    maps to a fail-closed ``DENY``. Identical inputs always yield identical
    decisions.
    """

    def __init__(self, table: dict[str, AdapterDecision]) -> None:
        self._table = dict(table)

    @classmethod
    def from_file(cls, path: str | Path) -> ReplayAdapter:
        """Load and validate a replay fixture; raise ``ReplayError`` on defects."""
        raw = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ReplayError(f"replay fixture is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ReplayError("replay fixture must be a JSON object")
        table: dict[str, AdapterDecision] = {}
        for key, record in data.items():
            if not isinstance(key, str) or not key:
                raise ReplayError("replay keys must be non-empty strings")
            table[key] = _validate_record(record)
        return cls(table)

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        key = decision_key(tool_name, arguments)
        decision = self._table.get(key)
        if decision is None:
            raise ReplayError(f"no replay entry for key {key!r}")
        return decision

