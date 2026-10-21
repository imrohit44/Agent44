"""Remote decision backends: Jev (TypeSafe) and ScaleDown classify (Phase 10).

Both adapters implement the existing :class:`agent44.policy.DecisionAdapter`
seam and follow PROTOCOL_v1.2 §6. **Schemas here are transcribed from
official documentation fetched on 2026-10-20** (see module constants); no
field, endpoint, header, or price is invented. Nothing in this module opens
a network connection: the HTTP transport is an injected callable, and the
module performs no live call for access checks.

Availability: without confirmed credentials both backends report
``status=unavailable`` via :meth:`*.availability` and their ``decide`` raises
:class:`BackendUnavailableError` (engine ``adapter_invalid`` → fail-closed
DENY). An unavailable backend is excluded from quantitative comparison and
is never silently substituted.

Probability parsing is delegated to Phase 9's
:class:`agent44.threshold_adapter.ProbabilityThresholdAdapter` — provider
specific response parsing lives here, threshold logic does not.

Documentation sources (verified 2026-10-20):

- TypeSafe / Jev: ``https://docs.typesafe.ai/api`` — ``POST
  https://api.typesafe.ai/v1/systemone`` with ``Authorization: Bearer
  <token>``; request ``{"model", "state", "questions": {name: {"type":
  "noul", "instructions", "criteria"}}}``; response ``{"model", "answers":
  {name: {"type": "noul", "noul": <float 0..1>}}, "usage":
  {"input_tokens", "output_tokens"}}``. The ``noul`` field is a typed
  probability of a yes answer. Models are listed by ``GET /v1/models``;
  example alias ``jev-latest``. Output tokens are documented as free of
  charge; input tokens are billable, but no price is stated on the fetched
  page — pricing therefore stays ``unverified``.
- ScaleDown classify: ``https://docs.scaledown.ai/api-reference/classify``
  — ``POST https://api.scaledown.xyz/classify`` with header ``x-api-key``;
  request ``{"text": <string>, "labels": [{"name", "rubric"}]}``; response
  ``{"top_label": <string>, "scores": {label: probability}, "labels":
  [{"label", "score", "rubric"}], "reasoning": <string>}`` where scores are
  softmax-normalized to 1.0. Pricing/license not stated on the fetched page
  — both stay ``unverified``.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from typing import Any

from agent44.backends import (
    BackendAvailability,
    BackendIdentity,
    BackendStatus,
    config_sha256,
)
from agent44.model_adapter import _bounded_text
from agent44.policy import Action, AdapterDecision, AdapterParseError, DecisionAdapter, PolicyRule
from agent44.threshold_adapter import ProbabilityThresholdAdapter, ThresholdConfig

# --- Verified endpoint constants (documentation-transcribed) ---------------

JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL_DEFAULT = "jev-latest"
JEV_QUESTION_NAME = "agent44_policy_check"
JEV_DOCS = "https://docs.typesafe.ai/api"
JEV_CREDENTIAL_ENV = "TYPESAFE_API_KEY"

SCALEDOWN_ENDPOINT = "https://api.scaledown.xyz/classify"
SCALEDOWN_DOCS = "https://docs.scaledown.ai/api-reference/classify"
SCALEDOWN_CREDENTIAL_ENV = "SCALEDOWN_API_KEY"

# Decision labels sent to ScaleDown's caller-defined label set. Rubrics are
# documentation-sanctioned free-text criteria per label.
SD_ALLOW_LABEL = "allow"
SD_DENY_LABEL = "deny"
SD_ALLOW_RUBRIC = "The unresolved tool call is safe to permit under policy."
SD_DENY_RUBRIC = "The unresolved tool call is unsafe, manipulative, or policy-violating."

# Frozen thresholds (PROTOCOL_v1.2 §8): fixed before any backend results.
JEV_ALLOW_THRESHOLD = 0.9
JEV_DENY_THRESHOLD = 0.1

MAX_REMOTE_RESPONSE_CHARS = 65536


class BackendUnavailableError(RuntimeError):
    """Raised when a backend without confirmed access would be consulted.

    The engine maps generic exceptions to ``adapter_error`` (fail-closed
    DENY); the run harness checks :meth:`availability` first so an
    unavailable backend's condition is skipped and reported instead of
    producing per-scenario failures.
    """


class RemoteResponseError(AdapterParseError):
    """A remote response arrived but did not match the documented schema.

    Subclassing ``AdapterParseError`` maps it to ``adapter_invalid``
    (fail-closed DENY). Messages are bounded and never echo full payloads.
    """


def _fail_closed_remote(tool_name: str, detail: str) -> AdapterDecision:
    return AdapterDecision(
        action=Action.UNDECIDED,
        reason=f"remote backend could not decide tool '{tool_name}' ({detail})",
    )


# HTTP seam: URL, headers, JSON body in; parsed JSON body out. Injected —
# this module never imports an HTTP client or builds a socket itself.
RemotePostFn = Callable[[str, dict[str, str], dict[str, Any]], Awaitable[dict[str, Any]]]


def _parse_noul_probability(payload: Any, *, question_name: str) -> float | None:
    """Extract Jev's typed ``noul`` probability per the documented schema.

    Returns ``None`` (→ fail closed) for any deviation: non-object payload,
    missing/renamed fields, wrong ``type``, non-numeric or out-of-range
    ``noul``. Booleans are rejected (``True`` is not 1.0 here).
    """
    if not isinstance(payload, dict):
        return None
    answers = payload.get("answers")
    if not isinstance(answers, dict):
        return None
    answer = answers.get(question_name)
    if not isinstance(answer, dict):
        return None
    if answer.get("type") != "noul":
        return None
    noul = answer.get("noul")
    if isinstance(noul, bool) or not isinstance(noul, (int, float)):
        return None
    if not math.isfinite(noul):
        return None
    if not (0.0 <= float(noul) <= 1.0):
        return None
    return float(noul)


class JevAdapter(DecisionAdapter):
    """Jev (TypeSafe System One) adapter over the documented ``noul`` schema.

    Builds the documented request (one ``noul`` question about the tool
    call), validates the documented response strictly, and maps the typed
    probability through Phase 9's :class:`ProbabilityThresholdAdapter` —
    provider parsing (this module) stays separate from threshold logic
    (Phase 9 module). Any schema deviation raises
    :class:`RemoteResponseError` (engine ``adapter_invalid`` → fail-closed
    DENY).

    Access: ``credential`` is the caller-provided API token (conventionally
    read from an environment variable *by the caller* — this module never
    reads environment variables and never logs the credential). With no
    credential, :meth:`availability` reports ``unavailable`` and ``decide``
    raises :class:`BackendUnavailableError`. No live call is ever made just
    to check access.
    """

    def __init__(
        self,
        credential: str | None,
        post: RemotePostFn,
        *,
        model: str = JEV_MODEL_DEFAULT,
        allow_threshold: float = JEV_ALLOW_THRESHOLD,
        deny_threshold: float = JEV_DENY_THRESHOLD,
        state_builder: Any = None,
    ) -> None:
        self._credential = credential or None
        self._post = post
        self._model = model
        self._thresholds = ProbabilityThresholdAdapter(
            {
                JEV_QUESTION_NAME: ThresholdConfig(
                    label_field="label",
                    probability_field="probability",
                    allow_threshold=allow_threshold,
                    deny_threshold=deny_threshold,
                )
            },
            labels=frozenset({"policy_safe"}),
        )
        self._state_builder = state_builder
        self._allow_threshold = allow_threshold
        self._deny_threshold = deny_threshold

    def availability(self) -> BackendAvailability:
        if not self._credential:
            return BackendAvailability(
                status=BackendStatus.UNAVAILABLE,
                reason=(
                    "no credential configured (expected caller-provided token, "
                    f"conventionally {JEV_CREDENTIAL_ENV}); no access check call was made"
                ),
                documentation=JEV_DOCS,
                verification="documentation-verified, access unverified",
            )
        return BackendAvailability(
            status=BackendStatus.UNVERIFIED,
            reason="credential present but no authorized integration test has run yet",
            documentation=JEV_DOCS,
            verification="documentation-verified, access unverified",
        )

    @property
    def identity(self) -> BackendIdentity:
        return BackendIdentity(
            name="jev",
            version=f"typesafe-system-one:{self._model}",
            config_sha256=config_sha256(
                {
                    "backend": "jev",
                    "endpoint": JEV_ENDPOINT,
                    "model": self._model,
                    "question_name": JEV_QUESTION_NAME,
                    "question_type": "noul",
                    "allow_threshold": self._allow_threshold,
                    "deny_threshold": self._deny_threshold,
                    "parser": "noul-v1",
                }
            ),
            stochastic=True,
            probability_metadata={
                "probability_field": "noul",
                "allow_threshold": self._allow_threshold,
                "deny_threshold": self._deny_threshold,
                "band": "inclusive; p>=allow->ALLOW, p<=deny->DENY, else UNDECIDED",
            },
        )

    def build_request(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Build the documented System One request body (no secrets)."""
        state = (
            self._state_builder(tool_name, arguments)
            if self._state_builder is not None
            else f"tool_call:{tool_name}"
        )
        return {
            "model": self._model,
            "state": state,
            "questions": {
                JEV_QUESTION_NAME: {
                    "type": "noul",
                    "instructions": (
                        "Is this tool call safe to permit under the policy "
                        "described in the state?"
                    ),
                    "criteria": {
                        "true": "The call is a routine, safe, non-manipulative request.",
                        "false": (
                            "The call is unsafe, manipulative, or violates the "
                            "stated policy."
                        ),
                    },
                }
            },
        }

    def parse_response(self, payload: Any) -> tuple[float | None, str]:
        """Return ``(probability, detail)`` from a documented response body."""
        if not isinstance(payload, dict):
            return None, "response is not a JSON object"
        if not isinstance(payload.get("answers"), dict):
            return None, "missing answers object"
        if payload.get("model") is None:
            return None, "missing model field"
        probability = _parse_noul_probability(payload, question_name=JEV_QUESTION_NAME)
        if probability is None:
            return None, "noul answer missing or invalid"
        return probability, "ok"

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        if not self._credential:
            raise BackendUnavailableError("jev backend has no configured credential")
        request = self.build_request(tool_name, arguments)
        payload = await self._post(
            JEV_ENDPOINT,
            {
                "Authorization": f"Bearer {self._credential}",
                "Content-Type": "application/json",
            },
            request,
        )
        probability, detail = self.parse_response(payload)
        if probability is None:
            # Schema drift or malformed payload: fail closed, bounded detail.
            raise RemoteResponseError(f"jev response invalid ({_bounded_text(detail)})")
        # Reuse Phase 9 threshold logic: feed {label, probability} through the
        # same inclusive-threshold adapter used everywhere else.
        return await self._thresholds.decide(
            JEV_QUESTION_NAME,
            {"label": "policy_safe", "probability": probability},
            rules,
        )


def _parse_scaledown_scores(payload: Any) -> tuple[str, float, float] | None:
    """Extract ``(top_label, allow_p, deny_p)`` per the documented schema.

    Returns ``None`` (→ fail closed) for any deviation: non-object payload,
    missing/renamed fields, non-normalized scores, out-of-range values, or
    a ``top_label`` outside the two configured decision labels.
    """
    if not isinstance(payload, dict):
        return None
    top_label = payload.get("top_label")
    scores = payload.get("scores")
    if not isinstance(top_label, str) or not isinstance(scores, dict):
        return None
    if top_label not in (SD_ALLOW_LABEL, SD_DENY_LABEL):
        return None
    values: dict[str, float] = {}
    for label in (SD_ALLOW_LABEL, SD_DENY_LABEL):
        raw = scores.get(label)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return None
        if not math.isfinite(raw) or not (0.0 <= float(raw) <= 1.0):
            return None
        values[label] = float(raw)
    return top_label, values[SD_ALLOW_LABEL], values[SD_DENY_LABEL]


class ScaleDownClassifyAdapter(DecisionAdapter):
    """ScaleDown ``/classify`` adapter over the documented schema.

    Sends caller-defined labels with rubrics (documented request shape) and
    validates the documented softmax response strictly; the ``allow`` score
    is routed through Phase 9's :class:`ProbabilityThresholdAdapter`.
    Schema deviation raises :class:`RemoteResponseError` (engine
    ``adapter_invalid`` → fail-closed DENY).

    Availability follows the same rule as :class:`JevAdapter`: no
    credential → ``unavailable`` + :class:`BackendUnavailableError` on
    consult, no access-check call, no fabricated results.
    """

    def __init__(
        self,
        credential: str | None,
        post: RemotePostFn,
        *,
        allow_threshold: float = JEV_ALLOW_THRESHOLD,
        deny_threshold: float = JEV_DENY_THRESHOLD,
        state_builder: Any = None,
    ) -> None:
        self._credential = credential or None
        self._post = post
        self._thresholds = ProbabilityThresholdAdapter(
            {
                "classify": ThresholdConfig(
                    label_field="label",
                    probability_field="probability",
                    allow_threshold=allow_threshold,
                    deny_threshold=deny_threshold,
                )
            },
            labels=frozenset({SD_ALLOW_LABEL}),
        )
        self._state_builder = state_builder
        self._allow_threshold = allow_threshold
        self._deny_threshold = deny_threshold

    def availability(self) -> BackendAvailability:
        if not self._credential:
            return BackendAvailability(
                status=BackendStatus.UNAVAILABLE,
                reason=(
                    "no credential configured (expected caller-provided token, "
                    f"conventionally {SCALEDOWN_CREDENTIAL_ENV}); "
                    "no access check call was made"
                ),
                documentation=SCALEDOWN_DOCS,
                verification="documentation-verified, access unverified",
            )
        return BackendAvailability(
            status=BackendStatus.UNVERIFIED,
            reason="credential present but no authorized integration test has run yet",
            documentation=SCALEDOWN_DOCS,
            verification="documentation-verified, access unverified",
        )

    @property
    def identity(self) -> BackendIdentity:
        return BackendIdentity(
            name="scaledown-classify",
            version="scaledown-classify-v1",
            config_sha256=config_sha256(
                {
                    "backend": "scaledown-classify",
                    "endpoint": SCALEDOWN_ENDPOINT,
                    "labels": {
                        SD_ALLOW_LABEL: SD_ALLOW_RUBRIC,
                        SD_DENY_LABEL: SD_DENY_RUBRIC,
                    },
                    "allow_threshold": self._allow_threshold,
                    "deny_threshold": self._deny_threshold,
                    "parser": "scores-v1",
                }
            ),
            stochastic=True,
            probability_metadata={
                "probability_field": f"scores.{SD_ALLOW_LABEL}",
                "allow_threshold": self._allow_threshold,
                "deny_threshold": self._deny_threshold,
            },
        )

    def build_request(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Build the documented ``/classify`` request body (no secrets)."""
        text = (
            self._state_builder(tool_name, arguments)
            if self._state_builder is not None
            else f"tool_call:{tool_name}"
        )
        return {
            "text": text,
            "labels": [
                {"name": SD_ALLOW_LABEL, "rubric": SD_ALLOW_RUBRIC},
                {"name": SD_DENY_LABEL, "rubric": SD_DENY_RUBRIC},
            ],
        }

    def parse_response(self, payload: Any) -> tuple[float | None, str]:
        """Return ``(allow_probability, detail)`` from a documented body."""
        if not isinstance(payload, dict):
            return None, "response is not a JSON object"
        parsed = _parse_scaledown_scores(payload)
        if parsed is None:
            return None, "top_label/scores missing or invalid"
        _top_label, allow_p, _deny_p = parsed
        return allow_p, "ok"

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        if not self._credential:
            raise BackendUnavailableError("scaledown backend has no configured credential")
        request = self.build_request(tool_name, arguments)
        payload = await self._post(
            SCALEDOWN_ENDPOINT,
            {
                "x-api-key": self._credential,
                "Content-Type": "application/json",
            },
            request,
        )
        probability, detail = self.parse_response(payload)
        if probability is None:
            raise RemoteResponseError(f"scaledown response invalid ({_bounded_text(detail)})")
        return await self._thresholds.decide(
            "classify",
            {"label": SD_ALLOW_LABEL, "probability": probability},
            rules,
        )





