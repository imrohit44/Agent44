"""Transparent model-readiness and priming for live local-model runs (4f.6).

Live local-model pilots can conflate Ollama cold-start model loading with
model decision quality: the first request after an idle unload pays the load
cost (measured on this machine at 5-10+ s), which exceeds the 5.0 s adapter
deadline and fails closed to DENY before the model can answer. This module
makes warm-up explicit, bounded, and auditable instead of hidden:

1. Confirm the Ollama endpoint is reachable (via the loopback-only provider).
2. Confirm the exact expected model digest is installed; never pull a model.
3. Inspect ``/api/ps`` and record whether the model is resident before
   priming.
4. If (and only if) it is not resident, issue exactly ONE priming generation
   request with an explicit keep-alive and its own bounded client timeout.
5. Record the priming outcome (elapsed time, timeout/error status, and
   response validity) separately from evaluation outcomes; priming is
   infrastructure warm-up, never a scenario decision.
6. Re-check residency immediately before evaluation and abort if the model
   is not resident.

Any failure raises :class:`ReadinessError` (a ``ValueError``) carrying the
aborted procedure record on its ``record`` attribute, so callers fail closed
*before* any scenario is executed. Priming is never retried, never silent,
and never concurrent; the provider additionally refuses a second priming
request on the same instance. The adapter deadline
(``agent44.policy.ADAPTER_TIMEOUT_SECONDS``, 5.0 s) and all policy semantics
are untouched: readiness runs outside the policy engine and cannot influence
any decision.

The loopback-only safeguards of :class:`agent44.local_provider.OllamaProvider`
(host validation, redirect rejection, size caps, timeouts, never-download
``/api/tags`` check) are reused rather than duplicated or weakened.

No network calls happen at import time or during tests; unit tests inject an
``httpx.MockTransport``-backed provider and therefore validate procedure
logic, not live Ollama behavior.
"""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from typing import Any

from agent44.local_provider import LocalProviderError, OllamaProvider

# Priming prompt: short, secret-free, and validity-checkable (non-empty text).
DEFAULT_PRIME_PROMPT = "Reply with exactly the word OK and nothing else."
# Default keep-alive: long enough to cover the declared pilot worst case
# (20 scenarios x 30 s harness timeout = 600 s) with margin.
DEFAULT_KEEP_ALIVE_SECONDS = 900.0
# Hard ceiling: beyond this the model would be pinned in memory for an
# unreasonably long time relative to a bounded pilot.
MAX_KEEP_ALIVE_SECONDS = 3600.0
# Default bound for the single priming request. Cold model load has been
# measured at 5-10+ s on this machine, so 30 s allows a cold prime to finish
# while still bounding the wait.
DEFAULT_PRIME_TIMEOUT_SECONDS = 30.0
MAX_PRIME_TIMEOUT_SECONDS = 120.0


class ReadinessError(ValueError):
    """The readiness procedure failed; the run must abort before scenarios.

    Subclasses ``ValueError`` so every existing fail-closed handling path in
    :mod:`agent44.eval_runner` (exit code 2, "nothing executed") applies
    unchanged. The procedure record is attached to the ``record`` attribute.
    """


def _validate_keep_alive(seconds: float) -> float:
    """Validate the priming keep-alive (seconds) and return it as a float.

    Rejected: non-numbers, booleans, non-finite values, zero, negative values
    (``-1`` would pin the model in memory forever), and anything beyond
    :data:`MAX_KEEP_ALIVE_SECONDS`.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("keep-alive must be a number of seconds")
    value = float(seconds)
    if not math.isfinite(value):
        raise ValueError("keep-alive must be a finite number of seconds")
    if value <= 0:
        raise ValueError("keep-alive must be strictly positive; use an explicit duration")
    if value > MAX_KEEP_ALIVE_SECONDS:
        raise ValueError(
            f"keep-alive {value:g}s exceeds the maximum of {MAX_KEEP_ALIVE_SECONDS:g}s"
        )
    return value


def _validate_prime_timeout(seconds: float) -> float:
    """Validate the single priming request's client timeout (seconds)."""
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("prime timeout must be a number of seconds")
    value = float(seconds)
    if not math.isfinite(value):
        raise ValueError("prime timeout must be a finite number of seconds")
    if value <= 0:
        raise ValueError("prime timeout must be strictly positive")
    if value > MAX_PRIME_TIMEOUT_SECONDS:
        raise ValueError(
            f"prime timeout {value:g}s exceeds the maximum of {MAX_PRIME_TIMEOUT_SECONDS:g}s"
        )
    return value


def _model_is_resident(names: list[str], model: str) -> bool:
    """Return True when ``model`` appears among resident model names."""
    return model in names


async def ensure_model_ready(
    local_model: Mapping[str, Any],
    *,
    provider: OllamaProvider | None = None,
) -> dict[str, Any]:
    """Run the readiness procedure; return its record, or raise ReadinessError.

    ``local_model`` is the runner's local-model configuration dict and MUST
    declare ``digest`` (the exact expected model digest); ``model`` is
    required, and ``host``/``port``/``timeout_seconds``/``max_calls`` are
    honored when a provider must be constructed (loopback enforced; a remote
    host raises before any request). ``keep_alive_seconds`` and
    ``prime_timeout_seconds`` default to :data:`DEFAULT_KEEP_ALIVE_SECONDS`
    and :data:`DEFAULT_PRIME_TIMEOUT_SECONDS`.

    ``provider`` is an injection seam for tests; when omitted a fresh
    :class:`~agent44.local_provider.OllamaProvider` is constructed and closed
    here. The returned record is JSON-serializable and contains only
    infrastructure fields — never scenario ids, decisions, or metrics — so
    priming can never be conflated with evaluation outcomes.
    """
    model = local_model.get("model")
    if not isinstance(model, str) or not model:
        raise ReadinessError("local_model['model'] must be a non-empty string")

    expected_digest = local_model.get("digest")
    if not isinstance(expected_digest, str) or not expected_digest:
        raise ReadinessError(
            "local_model must declare the exact expected model digest ('digest') "
            "so readiness can confirm the installed model; fail closed before "
            "contacting the model host (the evaluator never pulls a model)"
        )

    try:
        keep_alive = _validate_keep_alive(
            local_model.get("keep_alive_seconds", DEFAULT_KEEP_ALIVE_SECONDS)
        )
        prime_timeout = _validate_prime_timeout(
            local_model.get("prime_timeout_seconds", DEFAULT_PRIME_TIMEOUT_SECONDS)
        )
    except ValueError as exc:
        raise ReadinessError(f"invalid readiness configuration: {exc}") from exc

    record: dict[str, Any] = {
        "status": "aborted",
        "model": model,
        "expected_digest": expected_digest,
        "installed_digest": None,
        "digest_matched": None,
        "resident_before": None,
        "priming": None,
        "resident_after": None,
        "keep_alive_seconds": keep_alive,
        "prime_timeout_seconds": prime_timeout,
        "generation_requests_issued": 0,
        "error": None,
        "note": (
            "Readiness is infrastructure warm-up, not a scenario decision. "
            "The at-most-one priming generation request is counted here "
            "separately from adapter calls and is never part of the "
            "evaluation results or metrics."
        ),
    }

    def _abort(message: str) -> ReadinessError:
        record["status"] = "aborted"
        record["error"] = message
        err = ReadinessError(message)
        err.record = record
        return err

    if provider is None:
        try:
            prov = OllamaProvider(
                model,
                host=str(local_model.get("host", "127.0.0.1")),
                port=int(local_model.get("port", 11434)),
                timeout=float(local_model.get("timeout_seconds", 60.0)),
                max_calls=int(local_model.get("max_calls", 256)),
            )
        except LocalProviderError as exc:
            raise _abort(f"could not construct loopback model provider: {exc}") from exc
    else:
        prov = provider

    try:
        # 1) Reachability + installed model + digest (never downloads).
        try:
            info = await prov.ensure_model_available()
        except LocalProviderError as exc:
            raise _abort(f"model availability check failed: {exc}") from exc
        record["installed_digest"] = info.get("digest")
        if info.get("digest") != expected_digest:
            record["digest_matched"] = False
            raise _abort(
                f"installed digest {info.get('digest')!r} does not match the expected "
                f"digest {expected_digest!r} for model {model!r}; aborting so a "
                "different model can never answer evaluation prompts"
            )
        record["digest_matched"] = True

        # 2) Residency before priming (read-only).
        try:
            names_before = await prov.resident_models()
        except LocalProviderError as exc:
            raise _abort(f"residency check failed: {exc}") from exc
        record["resident_before"] = _model_is_resident(names_before, model)

        # 3) At most one explicitly budgeted priming request; never retried.
        if not record["resident_before"]:
            record["generation_requests_issued"] = 1
            started = time.monotonic()
            try:
                outcome = await prov.prime(
                    prompt=DEFAULT_PRIME_PROMPT,
                    keep_alive_seconds=keep_alive,
                    timeout_seconds=prime_timeout,
                )
            except LocalProviderError as exc:
                record["priming"] = {
                    "issued": True,
                    "completed": False,
                    "response_valid": False,
                    "timed_out": "timed out" in str(exc),
                    "elapsed_seconds": round(time.monotonic() - started, 4),
                    "error": str(exc),
                }
                raise _abort(f"priming request failed: {exc}") from exc
            record["priming"] = {
                "issued": True,
                "completed": bool(outcome.get("completed")),
                "response_valid": bool(outcome.get("response_valid")),
                "timed_out": False,
                "elapsed_seconds": outcome.get("elapsed_seconds"),
                "error": None,
            }
            if not outcome.get("response_valid"):
                raise _abort(
                    "priming response was invalid (empty model output); aborting "
                    "before scenario execution"
                )

        # 4) Residency re-check immediately before evaluation.
        try:
            names_after = await prov.resident_models()
        except LocalProviderError as exc:
            raise _abort(f"post-priming residency check failed: {exc}") from exc
        record["resident_after"] = _model_is_resident(names_after, model)
        if not record["resident_after"]:
            raise _abort(
                f"model {model!r} is not resident after priming; aborting before "
                "scenario execution so cold-start latency cannot be mistaken for "
                "decision quality"
            )

        record["status"] = "ready"
        return record
    finally:
        if provider is None:
            await prov.aclose()
