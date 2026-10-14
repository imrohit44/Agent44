"""Strictly-local, zero-cost model provider for the decision adapter.

This module adds an **optional** Ollama-compatible provider that talks only
to a loopback endpoint (``http://127.0.0.1:11434`` by default). It is used to
build a :class:`~agent44.model_adapter.ModelDecisionAdapter` via its injected
``complete(prompt) -> str`` seam. It bundles no provider SDK, performs no
cloud calls, has no cloud fallback, and never downloads a model.

Safety properties enforced here:

- **Loopback only.** The host is validated to be a loopback name/address and
  every resolved address must be loopback. Remote hosts are rejected at
  construction. Redirects are never followed and are rejected.
- **Opt-in.** Default execution and CI never construct this provider; the
  deterministic rules-only / replay / fake paths are unchanged.
- **Bounded.** Requests carry an explicit timeout; responses are streamed and
  capped in size; prompts are the already-bounded prompt from the adapter.
- **Fail closed.** Any provider error (connection refused, timeout, oversized
  response, redirect, remote host) raises :class:`LocalProviderError`, which
  the engine maps to a fail-closed ``DENY`` (``adapter_error``). Malformed
  response *content* (invalid UTF-8, non-JSON lines, unknown shape) raises
  :class:`LocalProviderResponseError`, mapped to the distinct fail-closed
  ``adapter_invalid`` outcome. No failure mode is ever non-blocking.
- **No secrets out.** Prompts already contain only safe argument metadata
  (types/lengths); nothing here adds arguments, credentials, or results to any
  outbound request.

No network calls or model downloads happen at import time or during tests;
tests inject an ``httpx.MockTransport``.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Mapping
from typing import Any

import httpx

from agent44.model_adapter import ModelDecisionAdapter
from agent44.policy import AdapterParseError

# Loopback names that are allowed without further resolution checks.
_LOOPBACK_NAMES = frozenset({"localhost"})
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 11434
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_CALLS = 256
# Hard cap on a single model response body (bytes) to bound memory use.
MAX_RESPONSE_BYTES = 1 << 20  # 1 MiB


class LocalProviderError(RuntimeError):
    """Raised for any local-provider configuration or transport failure.

    Treated by the engine as a fail-closed adapter error (→ ``DENY``,
    rule id ``adapter_error``).
    """


class LocalProviderResponseError(LocalProviderError, AdapterParseError):
    """Raised when the local model returns malformed response *content*.

    The request itself succeeded (transport, HTTP status, redirect, and size
    checks passed) but the body is not a well-formed Ollama payload: invalid
    UTF-8, non-JSON lines, a missing/non-string ``response`` field, or an
    unexpected shape. Because a response arrived but could not be parsed, the
    engine maps this to the fail-closed ``adapter_invalid`` outcome (a DENY);
    transport/status/limit failures remain plain :class:`LocalProviderError`
    → ``adapter_error``.
    """


def _is_loopback_ip(text: str) -> bool:
    """Return True if ``text`` is a valid loopback IP literal."""
    candidate = text.split("%", 1)[0]  # strip IPv6 zone id if present
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def assert_loopback_host(host: str) -> str:
    """Validate that ``host`` is loopback by name and by resolved address.

    Raises :class:`LocalProviderError` if ``host`` is a remote name/address or
    resolves to any non-loopback address (defends against DNS tricks such as a
    ``localhost`` mapping to a remote IP).
    """
    if not host or not isinstance(host, str):
        raise LocalProviderError("local provider host must be a non-empty string")
    # A bare IP literal must itself be loopback.
    if _is_loopback_ip(host):
        return host
    if host not in _LOOPBACK_NAMES:
        raise LocalProviderError(
            f"refusing non-loopback model host {host!r}; only 127.0.0.1/localhost/::1 allowed"
        )
    # A loopback *name* must resolve only to loopback addresses.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise LocalProviderError(f"could not resolve local model host {host!r}: {exc}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses or not all(_is_loopback_ip(addr) for addr in addresses):
        raise LocalProviderError(
            f"local model host {host!r} resolves to non-loopback addresses: {sorted(addresses)}"
        )
    return host


def _build_base_url(scheme: str, host: str, port: int) -> str:
    """Compose and validate a loopback base URL (rejects odd scheme; brackets IPv6)."""
    if scheme not in ("http", "https"):
        raise LocalProviderError(f"unsupported URL scheme {scheme!r}; only http/https allowed")
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_part}:{port}"


def _extract_text(body: bytes) -> str:
    """Extract model text from a (possibly streaming) Ollama response body.

    Ollama ``stream: true`` returns newline-delimited JSON objects, each with a
    ``response`` fragment. A single non-streamed object is also accepted. Any
    unexpected shape raises :class:`LocalProviderResponseError` (fail closed;
    the engine reports it as ``adapter_invalid``). The returned text is bounded
    by :data:`MAX_RESPONSE_BYTES` at read time; the adapter's strict parser
    then bounds its length and rejects junk.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalProviderResponseError(
            f"local model response is not valid UTF-8: {exc}"
        ) from exc
    fragments: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise LocalProviderResponseError(
                f"local model response line is not JSON: {exc}"
            ) from exc
        if not isinstance(obj, dict):
            raise LocalProviderResponseError("local model response line is not a JSON object")
        fragment = obj.get("response")
        if fragment is None:
            # A terminal done marker may omit 'response'; that is acceptable.
            if obj.get("done"):
                continue
            raise LocalProviderResponseError(
                "local model response object has no 'response' field"
            )
        if not isinstance(fragment, str):
            raise LocalProviderResponseError(
                "local model response 'response' field is not a string"
            )
        fragments.append(fragment)
    return "".join(fragments)


class OllamaProvider:
    """Optional, strictly-local provider exposing the adapter ``complete`` seam.

    Speaks the Ollama HTTP API on a loopback endpoint only. Every resolved
    address must be loopback; redirects are never followed; requests are
    bounded by a timeout and responses are stream-capped; a hard call-count
    limit bounds a single experiment. No cloud endpoint, fallback, SDK, or
    automatic model download exists here. Any failure raises
    :class:`LocalProviderError`, which the engine turns into a fail-closed
    ``DENY``.
    """

    def __init__(
        self,
        model: str,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        scheme: str = "http",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_calls: int = DEFAULT_MAX_CALLS,
        transport: httpx.AsyncBaseTransport | None = None,
        check_host: bool = True,
    ) -> None:
        if not model or not isinstance(model, str):
            raise LocalProviderError("model tag must be a non-empty string")
        if not isinstance(port, int) or not (0 < port < 65536):
            raise LocalProviderError(f"invalid port {port!r}")
        if timeout <= 0:
            raise LocalProviderError("timeout must be positive")
        if max_calls <= 0:
            raise LocalProviderError("max_calls must be positive")
        # When a mock transport is injected (tests), skip live host resolution.
        self._host = assert_loopback_host(host) if check_host else host
        self._port = port
        self._scheme = scheme
        self._base_url = _build_base_url(scheme, self._host, port)
        self._model = model
        self._timeout = float(timeout)
        self._max_calls = int(max_calls)
        self._calls = 0
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            transport=transport,
        )

    @property
    def model(self) -> str:
        return self._model

    @property
    def calls_made(self) -> int:
        return self._calls

    def describe(self) -> dict[str, Any]:
        """Return secret-free provider config for the experiment manifest."""
        return {
            "provider": "ollama-local",
            "cloud": False,
            "base_url": self._base_url,
            "host": self._host,
            "port": self._port,
            "scheme": self._scheme,
            "model": self._model,
            "timeout_seconds": self._timeout,
            "max_calls": self._max_calls,
        }

    def _check_status(self, status_code: int, location: str | None) -> None:
        """Reject redirects and any non-2xx response (fail closed)."""
        if 300 <= status_code < 400:
            raise LocalProviderError(
                f"refusing redirect (HTTP {status_code}) to {location!r}; local-only provider"
            )
        if not (200 <= status_code < 300):
            raise LocalProviderError(f"local model host returned HTTP {status_code}")

    async def _read_capped(self, response: httpx.Response) -> bytes:
        """Stream a response body and reject anything over :data:`MAX_RESPONSE_BYTES`.

        A ``Location`` header is rejected even before reading the body, so a
        redirect can never cause prompt/data to reach a remote host.
        """
        self._check_status(response.status_code, response.headers.get("location"))
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise LocalProviderError(
                    f"local model response exceeded {MAX_RESPONSE_BYTES} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Request:
        """Build a POST request; the body carries only the prompt + model tag."""
        return self._client.build_request(
            "POST",
            f"{self._base_url}{path}",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    async def complete(self, prompt: str) -> str:
        """Return the raw model text for ``prompt`` via the local Ollama API.

        Bounded by the call-count limit, request timeout, and response-size
        cap. Any failure raises :class:`LocalProviderError` so the engine fails
        closed. The outbound body contains only the already-sanitized prompt
        (no raw arguments, results, or credentials).
        """
        if self._calls >= self._max_calls:
            raise LocalProviderError(
                f"local model call limit reached ({self._max_calls}); stopping"
            )
        if not isinstance(prompt, str) or not prompt:
            raise LocalProviderError("prompt must be a non-empty string")
        self._calls += 1
        # stream=True so _read_capped can enforce the size cap while reading.
        request = self._post(
            "/api/generate",
            {
                "model": self._model,
                "prompt": prompt,
                "stream": True,
                "options": {"temperature": 0},
            },
        )
        try:
            response = await self._client.send(request, stream=True)
            try:
                body = await self._read_capped(response)
            finally:
                await response.aclose()
        except LocalProviderError:
            raise
        except httpx.HTTPError as exc:
            raise LocalProviderError(f"local model request failed: {exc}") from exc
        except OSError as exc:
            raise LocalProviderError(f"local model transport failure: {exc}") from exc
        return _extract_text(body)

    async def ensure_model_available(self) -> dict[str, Any]:
        """Verify the model is installed locally; never download it.

        Calls ``GET /api/tags`` and raises :class:`LocalProviderError` if the
        model tag is absent. This is a read-only check — it does not pull a
        model. Returns secret-free model metadata (including a digest when the
        server provides one) for the experiment manifest.
        """
        request = self._client.build_request("GET", f"{self._base_url}/api/tags")
        try:
            response = await self._client.send(request, stream=True)
            try:
                body = await self._read_capped(response)
            finally:
                await response.aclose()
        except LocalProviderError:
            raise
        except httpx.HTTPError as exc:
            raise LocalProviderError(f"local model tags request failed: {exc}") from exc
        except OSError as exc:
            raise LocalProviderError(f"local model tags transport failure: {exc}") from exc
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise LocalProviderError(f"local model tags response is not JSON: {exc}") from exc
        if not isinstance(data, Mapping) or not isinstance(data.get("models"), list):
            raise LocalProviderError("unexpected /api/tags shape from local model host")
        for entry in data["models"]:
            if isinstance(entry, Mapping) and entry.get("name") == self._model:
                digest = entry.get("digest")
                return {
                    "name": self._model,
                    "digest": digest if isinstance(digest, str) else None,
                }
        raise LocalProviderError(
            f"model {self._model!r} is not installed locally; pull it manually before running"
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()


def local_model_adapter(provider: OllamaProvider) -> ModelDecisionAdapter:
    """Wrap an :class:`OllamaProvider` in the existing decision adapter.

    The adapter's strict parser continues to treat model output as untrusted;
    the provider only supplies raw text via the ``complete`` seam. Reusing the
    existing adapter keeps deterministic precedence, adapter-tool gating,
    timeout handling, hard-deny invariance, and secret-safe prompts identical
    to every other adapter.
    """
    return ModelDecisionAdapter(provider.complete, model_name=f"ollama-local:{provider.model}")


