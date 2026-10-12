"""Observation foundation for Agent44 (Milestone 2).

Provides a typed, normalized view of an MCP tool call (``CallContext``) built
*only* from metadata the MCP protocol actually exposes, plus a redaction-safe
serialization layer (``ObservationEvent``) and a JSONL sink (``JsonlObserver``).

Design rules:
  * Observation is *never* allowed to change tool-call results, error
    semantics, or protocol behavior. Every hook swallows its own exceptions
    and logs to stderr only.
  * Raw argument *values* and raw tool *results* are not persisted by default.
    Only safe, value-free per-argument metadata is recorded.
  * Sensitive field names are explicitly redacted and their structure omitted.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("agent44.observe")

EVENT_SCHEMA_VERSION = "0.1.0"
REDACTED = "<redacted>"

DEFAULT_SENSITIVE_FIELDS: frozenset[str] = frozenset(
    {
        "password", "passwd", "secret", "token", "access_token", "refresh_token",
        "api_key", "apikey", "key", "authorization", "auth", "credential",
        "credentials", "private_key", "session_id",
    }
)


@dataclass(frozen=True)
class CallContext:
    """Normalized, typed context for a single observed MCP tool call.

    All fields are derived from metadata the MCP protocol actually provides.
    When a value is unavailable it is ``None``; nothing is invented.
    """

    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    client_name: str | None = None
    client_version: str | None = None
    protocol_version: str | None = None
    request_id: str | int | None = None
    progress_token: Any = None


def context_from_request_context(
    request_context: Any,
    tool_name: str,
    arguments: dict[str, Any],
    timestamp: float | None = None,
) -> CallContext:
    """Build a :class:`CallContext` from an MCP server ``RequestContext``.

    Client metadata (name/version/protocol) is read defensively from the
    underlying session's stored ``InitializeRequestParams``; anything not
    provided by the protocol stays ``None``. This never raises.
    """

    client_name: str | None = None
    client_version: str | None = None
    protocol_version: str | None = None

    session = getattr(request_context, "session", None)
    client_params = getattr(session, "_client_params", None) if session is not None else None
    if client_params is not None:
        client_info = getattr(client_params, "clientInfo", None)
        if client_info is not None:
            client_name = getattr(client_info, "name", None)
            client_version = getattr(client_info, "version", None)
        protocol_version = getattr(client_params, "protocolVersion", None)

    meta = getattr(request_context, "meta", None)
    progress_token = getattr(meta, "progressToken", None) if meta is not None else None

    return CallContext(
        tool_name=tool_name,
        arguments=dict(arguments or {}),
        timestamp=time.time() if timestamp is None else float(timestamp),
        client_name=client_name,
        client_version=client_version,
        protocol_version=protocol_version,
        request_id=getattr(request_context, "request_id", None),
        progress_token=progress_token,
    )


def _normalized_sensitive(fields: Any) -> set[str]:
    return {str(f).lower() for f in fields}


def redact_arguments(
    arguments: dict[str, Any],
    sensitive_fields: frozenset[str] | set[str] = DEFAULT_SENSITIVE_FIELDS,
) -> dict[str, Any]:
    """Return a copy of ``arguments`` with sensitive values replaced by a marker.

    Non-sensitive values are preserved unchanged. This is the *explicit*
    redaction primitive used when argument structure is needed without exposing
    secrets.
    """

    sensitive = _normalized_sensitive(sensitive_fields)
    return {
        key: (REDACTED if str(key).lower() in sensitive else value)
        for key, value in (arguments or {}).items()
    }


def _summarize_value(value: Any, *, redacted: bool) -> dict[str, Any]:
    """Produce a value-free description of a single argument value."""

    if redacted:
        # Omit type/size entirely for sensitive fields to avoid side channels.
        return {"redacted": True}
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "bool"}
    if isinstance(value, (int, float)):
        return {"type": type(value).__name__}
    if isinstance(value, str):
        return {"type": "str", "length": len(value)}
    if isinstance(value, (list, tuple, set)):
        return {"type": type(value).__name__, "length": len(value)}
    if isinstance(value, dict):
        return {"type": "dict", "keys": len(value)}
    return {"type": type(value).__name__}


def safe_arguments(
    arguments: dict[str, Any],
    sensitive_fields: frozenset[str] | set[str] = DEFAULT_SENSITIVE_FIELDS,
) -> dict[str, Any]:
    """Return per-argument safe metadata (no raw string values by default).

    Strings, numbers, and collections are summarized by type and length only.
    Fields whose names are sensitive are marked redacted with no further detail.
    """

    sensitive = _normalized_sensitive(sensitive_fields)
    result: dict[str, Any] = {}
    for key, value in (arguments or {}).items():
        is_sensitive = str(key).lower() in sensitive
        result[key] = _summarize_value(value, redacted=is_sensitive)
    return result


@dataclass(frozen=True)
class ObservationEvent:
    """A single serializable observation record.

    Carries only non-sensitive metadata: event type, tool name, timing,
    outcome, and safe argument summaries. It never embeds raw argument values
    or raw tool results.
    """

    event_type: str
    tool_name: str
    outcome: str
    latency_ms: float
    safe_arguments: dict[str, Any] = field(default_factory=dict)
    is_error: bool = False
    timestamp: float = 0.0
    schema_version: str = EVENT_SCHEMA_VERSION
    client_name: str | None = None
    client_version: str | None = None
    protocol_version: str | None = None
    request_id: str | int | None = None
    policy_action: str | None = None
    policy_rule_id: str | None = None
    policy_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "outcome": self.outcome,
            "is_error": self.is_error,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
            "safe_arguments": self.safe_arguments,
            "client_name": self.client_name,
            "client_version": self.client_version,
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "policy_action": self.policy_action,
            "policy_rule_id": self.policy_rule_id,
            "policy_reason": self.policy_reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_call(
        cls,
        context: CallContext,
        *,
        outcome: str,
        latency_ms: float,
        is_error: bool,
        sensitive_fields: frozenset[str] | set[str] = DEFAULT_SENSITIVE_FIELDS,
        event_type: str = "tool_call",
        policy_action: str | None = None,
        policy_rule_id: str | None = None,
        policy_reason: str | None = None,
    ) -> ObservationEvent:
        return cls(
            event_type=event_type,
            tool_name=context.tool_name,
            outcome=outcome,
            latency_ms=round(float(latency_ms), 3),
            safe_arguments=safe_arguments(context.arguments, sensitive_fields),
            is_error=is_error,
            timestamp=context.timestamp,
            client_name=context.client_name,
            client_version=context.client_version,
            protocol_version=context.protocol_version,
            request_id=context.request_id,
            policy_action=policy_action,
            policy_rule_id=policy_rule_id,
            policy_reason=policy_reason,
        )


class JsonlObserver:
    """Append observation events as JSON lines to a local file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        parent = self.path.parent
        if str(parent) and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

    def observe(self, event: ObservationEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.to_json() + "\n")

    def read_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events


def record_observation(
    observer: JsonlObserver | None,
    context: CallContext,
    *,
    started: float,
    outcome: str,
    is_error: bool,
    sensitive_fields: frozenset[str] | set[str] = DEFAULT_SENSITIVE_FIELDS,
    policy_action: str | None = None,
    policy_rule_id: str | None = None,
    policy_reason: str | None = None,
) -> None:
    """Record one observation, never raising.

    Observer failures are logged to stderr and otherwise ignored so that a
    successful tool call can never be turned into a failure by the observation
    layer.
    """

    if observer is None:
        return
    try:
        latency_ms = (time.perf_counter() - started) * 1000.0
        event = ObservationEvent.from_call(
            context,
            outcome=outcome,
            latency_ms=latency_ms,
            is_error=is_error,
            sensitive_fields=sensitive_fields,
            policy_action=policy_action,
            policy_rule_id=policy_rule_id,
            policy_reason=policy_reason,
        )
        observer.observe(event)
    except Exception:  # noqa: BLE001 - observation must never break the call
        logger.exception("observation failed; continuing without recording")
