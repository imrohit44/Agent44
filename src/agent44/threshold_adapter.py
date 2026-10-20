"""Provider-independent probability-threshold decision adapter (Phase 9).

Maps a probability score read from call arguments to ALLOW/DENY/UNDECIDED
using inclusive thresholds with an UNDECIDED escalation band. Consulted by the
engine only after deterministic tiers leave UNDECIDED, only for adapter_tools,
and never for hard-denied calls. Never overrides deterministic tiers.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent44.policy import Action, AdapterDecision, DecisionAdapter, PolicyRule

_PROBABILITY_MIN = 0.0
_PROBABILITY_MAX = 1.0


class ThresholdConfig(BaseModel):
    """Threshold configuration for one tool.

    allow_threshold must exceed deny_threshold so the UNDECIDED band is
    non-empty. Probability in (deny_threshold, allow_threshold) -> UNDECIDED.
    """

    model_config = ConfigDict(extra="forbid")

    label_field: str = Field(default="label", min_length=1)
    probability_field: str = Field(default="probability", min_length=1)
    allow_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    deny_threshold: float = Field(default=0.1, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _allow_above_deny(self) -> ThresholdConfig:
        if not self.allow_threshold > self.deny_threshold:
            raise ValueError(
                "allow_threshold must exceed deny_threshold "
                "for a non-empty UNDECIDED band"
            )
        return self


class ProbabilityThresholdAdapter(DecisionAdapter):
    """Deterministic probability-threshold decision adapter.

    Reads label and probability from call arguments:

    - p >= allow_threshold -> ALLOW
    - p <= deny_threshold -> DENY
    - otherwise -> UNDECIDED (fail closed)

    labels optionally restricts recognized labels; a label outside the set
    yields UNDECIDED. Malformed/missing/out-of-range probability yields
    UNDECIDED.
    """

    def __init__(
        self,
        configs: dict[str, ThresholdConfig] | None = None,
        *,
        labels: frozenset[str] | None = None,
    ) -> None:
        self._configs = dict(configs or {})
        self._labels = frozenset(labels) if labels is not None else None

    async def decide(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        rules: list[PolicyRule],
    ) -> AdapterDecision:
        args = dict(arguments or {})
        config = self._configs.get(tool_name)
        if config is None:
            return AdapterDecision(
                action=Action.UNDECIDED,
                reason=f"no threshold config for tool '{tool_name}'",
            )

        label = args.get(config.label_field)
        if self._labels is not None and label not in self._labels:
            return AdapterDecision(
                action=Action.UNDECIDED,
                reason=(
                    f"label {label!r} not in configured label set "
                    f"for tool '{tool_name}'"
                ),
            )

        probability = _coerce_probability(args.get(config.probability_field))
        if probability is None:
            return AdapterDecision(
                action=Action.UNDECIDED,
                reason=(
                    f"missing or unparseable probability for tool '{tool_name}'"
                ),
            )

        if probability >= config.allow_threshold:
            return AdapterDecision(
                action=Action.ALLOW,
                reason=(
                    f"probability {probability} >= allow threshold "
                    f"{config.allow_threshold} for tool '{tool_name}'"
                ),
                rule_id="threshold:allow",
            )
        if probability <= config.deny_threshold:
            return AdapterDecision(
                action=Action.DENY,
                reason=(
                    f"probability {probability} <= deny threshold "
                    f"{config.deny_threshold} for tool '{tool_name}'"
                ),
                rule_id="threshold:deny",
            )
        return AdapterDecision(
            action=Action.UNDECIDED,
            reason=(
                f"probability {probability} in UNDECIDED band "
                f"for tool '{tool_name}'"
            ),
        )


def _coerce_probability(value: Any) -> float | None:
    """Coerce an argument value to a probability in [0, 1], or None if invalid.

    Booleans, None, strings, and non-finite numbers are rejected.
    """
    if isinstance(value, bool) or value is None:
        return None
    if not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):
        return None
    probability = float(value)
    if probability < _PROBABILITY_MIN or probability > _PROBABILITY_MAX:
        return None
    return probability