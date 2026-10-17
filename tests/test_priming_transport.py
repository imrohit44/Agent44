"""Real-transport regression tests for the 4g.1.1 priming timeout fix.

Phase 4g.1 run B aborted pre-execution because ``prime()`` stored an
``httpx.Timeout`` OBJECT in ``request.extensions["timeout"]``, while the
httpcore connection pool contract expects the phased dict that httpx itself
writes (``timeout.as_dict()`` → ``{"connect", "read", "write", "pool"}``).
The pool crashed with ``AttributeError: 'Timeout' object has no attribute
'get'`` before any byte reached the wire.

These tests exercise the REAL httpx/httpcore transport stack end-to-end
against an in-process loopback HTTP server bound to an ephemeral port on
``127.0.0.1``. They never contact Ollama (``127.0.0.1:11434`` — hard-guarded
by fixture), never run the evaluation pilot (readiness-abort paths only,
with zero scenario execution), and never touch the external network.

Covered here (real-transport path):
- the timeout extension arrives at the transport boundary as the phased dict;
- a full readiness/priming procedure completes over the real stack;
- the total priming deadline cancels a slow-drip body and cleans up;
- transport failure and deadline timeout abort readiness BEFORE any
  evaluation scenario executes (observe file never created);
- no automatic retry: the priming budget remains exactly one.

Mocked procedure-logic coverage (``httpx.MockTransport``, no sockets) stays
in tests/test_readiness.py and tests/test_eval_runner.py and must keep
passing unchanged.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from agent44 import corpus
from agent44.eval_runner import evaluate
from agent44.local_provider import LocalProviderError, OllamaProvider
from agent44.readiness import ReadinessError, ensure_model_ready

MODEL = "llama3.2:1b"
DIGEST = "baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878"
STREAMED_OK = b'{"response":"OK", "done": false}\n{"done": true}\n'
# Ollama's real endpoint. Tests must NEVER bind it or send it a request.
OLLAMA_PORT = 11434


class _Handler(BaseHTTPRequestHandler):
    """Serves the minimal Ollama API surface for readiness/priming tests.

    State lives on the server object (``self.server.state``) and is shared
    with the test thread. Two body modes: ``ok`` (valid streamed Ollama
    body) and ``slow_drip`` (a chunk every 0.05 s — always inside the
    per-phase read timeout, so only a total wall-clock deadline can stop it).
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # silence per-request logging
        pass

    @property
    def state(self) -> dict[str, Any]:
        return self.server.state  # type: ignore[attr-defined]

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # http.server naming convention
        st = self.state
        st["requests"].append(("GET", self.path))
        if self.path == "/api/tags":
            body = json.dumps({"models": [{"name": MODEL, "digest": DIGEST}]}).encode()
            self._respond(200, body)
            return
        if self.path == "/api/ps":
            idx = min(st["ps_calls"], len(st["resident_flags"]) - 1)
            resident = st["resident_flags"][idx]
            st["ps_calls"] += 1
            models = [{"name": MODEL, "model": MODEL}] if resident else []
            self._respond(200, json.dumps({"models": models}).encode())
            return
        self.send_error(404)

    def do_POST(self) -> None:  # http.server naming convention
        st = self.state
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        st["requests"].append(("POST", self.path))
        if self.path != "/api/generate":
            self.send_error(404)
            return
        st["generate_calls"] += 1
        if st["generate_mode"] == "error500":
            self._respond(500, b"boom")
        elif st["generate_mode"] == "slow_drip":
            self._slow_drip()
        else:
            self._respond(200, STREAMED_OK)

    def _slow_drip(self) -> None:
        st = self.state
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(200):  # ~10 s of data; a working deadline cuts it at 0.2 s
            if i:
                time.sleep(0.05)
            chunk = b'{"response":"warming", "done": false}\n'
            try:
                self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            except OSError:
                st["client_disconnected"] = True  # client aborted mid-body (cleanup closed it)
                return
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except OSError:
            st["client_disconnected"] = True


class _LiveServer:
    """An in-process Ollama-shaped HTTP server on an ephemeral loopback port."""

    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port: int = self._server.server_address[1]
        if self.port == OLLAMA_PORT:  # never risk the real Ollama endpoint
            self._server.server_close()
            raise AssertionError("ephemeral test port collided with Ollama port 11434")
        self._server.state = {
            "requests": [],
            "ps_calls": 0,
            "generate_calls": 0,
            "generate_mode": "ok",
            "resident_flags": [False],
            "client_disconnected": False,
        }
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def state(self) -> dict[str, Any]:
        return self._server.state

    @property
    def generate_requests(self) -> int:
        return int(self.state["generate_calls"])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def live_server():
    server = _LiveServer()
    try:
        yield server
    finally:
        server.close()


class TransportProbe(httpx.AsyncBaseTransport):
    """Delegates to the REAL AsyncHTTPTransport, capturing the transport boundary.

    Records the timeout extension exactly as it crosses into the layer that
    hands it to httpcore (the spot where the 4g.1 run B crash happened), and
    keeps every response object so cleanup can be asserted after a deadline
    abort.
    """

    def __init__(self) -> None:
        self._inner = httpx.AsyncHTTPTransport(retries=0)
        self.captured: list[dict[str, Any]] = []
        self.responses: list[httpx.Response] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        ext = request.extensions.get("timeout")
        self.captured.append({"path": request.url.path, "timeout": ext})
        response = await self._inner.handle_async_request(request)
        self.responses.append(response)
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class FailingTransport(httpx.AsyncBaseTransport):
    """Always fails like a refused connection (no socket, no server, no retry)."""

    def __init__(self) -> None:
        self.attempts = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        raise httpx.ConnectError("connection refused (simulated, no socket)")


# --- real-stack priming: representation + full procedure ---------------------


def test_timeout_extension_reaches_transport_as_phase_dict(live_server: _LiveServer) -> None:
    """The 4g.1 crash line: the extension must be httpcore's phased dict.

    httpcore does ``request.extensions.get("timeout", {}).get("pool", None)``
    in ``AsyncConnectionPool.handle_async_request``. A bare ``httpx.Timeout``
    raised AttributeError there during Phase 4g.1 run B.
    """
    probe = TransportProbe()
    provider = OllamaProvider(MODEL, host="127.0.0.1", port=live_server.port, transport=probe)

    async def _scenario() -> dict[str, Any]:
        try:
            return await provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0)
        finally:
            # Close on the SAME loop that opened the connection: a second
            # asyncio.run() would close the ProactorEventLoop out from under
            # httpcore on Windows ("Event loop is closed").
            await provider.aclose()

    outcome = asyncio.run(_scenario())
    assert outcome["completed"] is True

    generate = [c for c in probe.captured if c["path"] == "/api/generate"]
    assert len(generate) == 1
    ext = generate[0]["timeout"]
    assert isinstance(ext, dict)  # NOT an httpx.Timeout object (the 4g.1 regression)
    assert ext == httpx.Timeout(5.0).as_dict()
    assert ext.get("pool") == 5.0  # the exact httpcore call that crashed in run B
    assert live_server.generate_requests == 1


def test_full_readiness_priming_over_real_stack(live_server: _LiveServer) -> None:
    """tags → ps → ONE prime → ps through the real httpx/httpcore pool."""
    live_server.state["resident_flags"] = [False, True]
    provider = OllamaProvider(MODEL, host="127.0.0.1", port=live_server.port)

    async def _scenario() -> dict[str, Any]:
        try:
            return await ensure_model_ready(
                {
                    "model": MODEL,
                    "digest": DIGEST,
                    "keep_alive_seconds": 60.0,
                    "prime_timeout_seconds": 5.0,
                },
                provider=provider,
            )
        finally:
            # Same-loop close: a separate asyncio.run() would race the
            # Windows ProactorEventLoop teardown ("Event loop is closed").
            await provider.aclose()

    record = asyncio.run(_scenario())
    assert record["status"] == "ready"
    assert record["resident_before"] is False
    assert record["priming"]["completed"] is True
    assert record["priming"]["response_valid"] is True
    assert record["resident_after"] is True
    assert record["generation_requests_issued"] == 1
    assert provider.primes_made == 1
    assert provider.calls_made == 0  # adapter-call budget untouched by priming
    assert live_server.generate_requests == 1  # exactly one attempt, no retry
    assert [path for _, path in live_server.state["requests"]] == [
        "/api/tags",
        "/api/ps",
        "/api/generate",
        "/api/ps",
    ]


# --- total deadline, readiness aborts, and the one-shot priming budget --------


def test_total_deadline_cancels_slow_drip_and_cleans_up(live_server: _LiveServer) -> None:
    """The total priming wall-clock deadline still cuts a slow body short.

    The server drips a valid chunk every 0.05 s — always inside the 0.2 s
    per-phase read timeout — so ONLY the total deadline can stop it. The
    response must be closed on the failure path (cleanup despite task
    cancellation), the wire must show the client disconnect, and the budget
    must stay at exactly one attempt.
    """
    live_server.state.update(resident_flags=[False], generate_mode="slow_drip")
    probe = TransportProbe()
    provider = OllamaProvider(MODEL, host="127.0.0.1", port=live_server.port, transport=probe)
    started = time.monotonic()

    async def _scenario() -> None:
        try:
            with pytest.raises(LocalProviderError, match="timed out"):
                await provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=0.2)
        finally:
            # Same-loop close (Windows ProactorEventLoop teardown hazard).
            await provider.aclose()

    asyncio.run(_scenario())
    elapsed = time.monotonic() - started
    assert elapsed < 1.5  # aborted at the 0.2 s total deadline, never completed
    # Exactly one request was issued, and its response was closed (cleanup ran).
    assert live_server.generate_requests == 1
    assert len(probe.responses) == 1
    assert probe.responses[0].is_closed is True
    assert provider.primes_made == 1
    assert provider.calls_made == 0
    # The wire confirms cleanup too: the server notices the client disconnect.
    deadline = time.monotonic() + 3.0
    while not live_server.state["client_disconnected"] and time.monotonic() < deadline:
        time.sleep(0.05)
    assert live_server.state["client_disconnected"] is True


def test_transport_failure_aborts_readiness_before_any_scenario(tmp_path: Path) -> None:
    """A refused connection aborts readiness BEFORE any scenario executes.

    The dead loopback port is held (bound, never listening) so the connect
    fails deterministically and no other process can take the port. This
    exercises the REAL transport error path — no Ollama, no mock transport.
    """
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    dead_port = blocker.getsockname()[1]
    assert dead_port != OLLAMA_PORT
    observe = tmp_path / "never.jsonl"
    try:
        with pytest.raises(ReadinessError, match="availability check failed"):
            asyncio.run(
                evaluate(
                    observe_path=str(observe),
                    local_model={
                        "model": MODEL,
                        "digest": DIGEST,
                        "host": "127.0.0.1",
                        "port": dead_port,
                        "timeout_seconds": 5.0,
                    },
                    partition=corpus.PARTITION_DEVELOPMENT,
                    select_ids=["benign-add-basic-02"],
                )
            )
    finally:
        blocker.close()
    # Nothing executed: the observer file never exists and zero scenarios ran.
    assert not observe.exists()


def test_deadline_timeout_aborts_readiness_before_any_scenario(
    tmp_path: Path, live_server: _LiveServer
) -> None:
    """A real-transport total-deadline expiry aborts before any scenario runs."""
    live_server.state.update(resident_flags=[False], generate_mode="slow_drip")
    observe = tmp_path / "never.jsonl"
    with pytest.raises(ReadinessError, match="timed out"):
        asyncio.run(
            evaluate(
                observe_path=str(observe),
                local_model={
                    "model": MODEL,
                    "digest": DIGEST,
                    "host": "127.0.0.1",
                    "port": live_server.port,
                    "keep_alive_seconds": 60.0,
                    "prime_timeout_seconds": 0.2,
                    "timeout_seconds": 5.0,
                },
                partition=corpus.PARTITION_DEVELOPMENT,
                select_ids=["benign-add-basic-02"],
            )
        )
    assert not observe.exists()  # no scenario ever executed
    assert live_server.generate_requests == 1  # one attempt, never retried


def test_failed_prime_is_never_retried_and_budget_stays_one() -> None:
    """A transport failure counts ONE attempt; no httpx retry; cap enforced."""
    transport = FailingTransport()
    provider = OllamaProvider(MODEL, host="127.0.0.1", port=9, transport=transport)

    async def _scenario() -> None:
        try:
            with pytest.raises(LocalProviderError, match="priming request failed"):
                await provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0)
            assert transport.attempts == 1  # httpx performed no automatic retry
            assert provider.primes_made == 1  # one priming attempt, ever
            assert provider.calls_made == 0  # adapter-call budget untouched
            # The one-priming cap refuses a second attempt before any request:
            with pytest.raises(LocalProviderError, match="second priming"):
                await provider.prime(prompt="OK.", keep_alive_seconds=60.0, timeout_seconds=5.0)
            assert transport.attempts == 1  # still exactly one attempt
        finally:
            await provider.aclose()

    asyncio.run(_scenario())