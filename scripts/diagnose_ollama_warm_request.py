"""Isolated Ollama warm-request diagnostic (Milestone 4f.4).

Purpose: determine whether a subsequent local Ollama generation request
responds faster after the previous request timed out. INFRASTRUCTURE
DIAGNOSIS ONLY — does not run the 20-scenario evaluation pilot, does not
touch held-out scenarios, does not modify any tracked file, and does not
alter the configured 5.0 s adapter deadline.

Safety bounds (stated before execution):
  * Request budget: 1 generation POST to /api/generate (plus read-only
    /api/tags and /api/ps checks).
  * Per-request client timeout: 15 s (explicit, bounded).
  * Overall watchdog: 30 s.
  * No concurrent generation requests; sequential only.
  * No model download/pull; read-only model-residency checks only.
  * Bind only to loopback 127.0.0.1:11434.
  * No warm-ups; the single generation request is counted.

Output: a JSON-serializable diagnostic summary printed to stdout.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx

BASE_URL = "http://127.0.0.1:11434"
MODEL = "llama3.2:1b"
EXPECTED_DIGEST = "baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878"
PROMPT = "Reply with exactly the word OK and nothing else."
GENERATE_TIMEOUT_SECONDS = 15.0
OVERALL_WATCHDOG_SECONDS = 30.0


class Diagnostic:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.records: list[dict[str, Any]] = []

    def _elapsed(self) -> float:
        return time.monotonic() - self.start

    async def _get_json(
        self, client: httpx.AsyncClient, path: str, label: str
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "method": "GET",
            "path": path,
            "label": label,
            "elapsed_seconds": None,
            "status_code": None,
            "error": None,
            "data": None,
        }
        t0 = time.monotonic()
        try:
            resp = await client.get(f"{BASE_URL}{path}")
            t1 = time.monotonic()
            record["elapsed_seconds"] = round(t1 - t0, 4)
            record["status_code"] = resp.status_code
            record["data"] = resp.json()
        except Exception as exc:  # noqa: BLE001 - surface diagnostic failures
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["error"] = f"{type(exc).__name__}: {exc}"
        self.records.append(record)
        return record

    async def _post_generate(self, client: httpx.AsyncClient) -> None:
        record: dict[str, Any] = {
            "method": "POST",
            "path": "/api/generate",
            "label": "generate_probe",
            "elapsed_seconds": None,
            "status_code": None,
            "time_to_first_chunk_seconds": None,
            "total_seconds": None,
            "completed_within_timeout": None,
            "response_chars": None,
            "response_preview": None,
            "error": None,
            "timeout": False,
        }
        first_chunk_time: float | None = None
        chunks: list[bytes] = []
        t0 = time.monotonic()
        try:
            payload = {
                "model": MODEL,
                "prompt": PROMPT,
                "stream": True,
                "options": {"temperature": 0},
            }
            request = client.build_request(
                "POST", f"{BASE_URL}/api/generate", json=payload
            )
            response = await client.send(request, stream=True)
            record["status_code"] = response.status_code
            try:
                async for chunk in response.aiter_bytes():
                    if first_chunk_time is None:
                        first_chunk_time = time.monotonic()
                        record["time_to_first_chunk_seconds"] = round(
                            first_chunk_time - t0, 4
                        )
                    chunks.append(chunk)
            finally:
                await response.aclose()
            t1 = time.monotonic()
            record["elapsed_seconds"] = round(t1 - t0, 4)
            record["total_seconds"] = round(t1 - t0, 4)
            body = b"".join(chunks)
            record["response_chars"] = len(body)
            record["completed_within_timeout"] = True
            try:
                text = body.decode("utf-8")
                record["response_preview"] = text[:200]
            except Exception:
                record["response_preview"] = "<non-utf8>"
        except httpx.TimeoutException as exc:
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["total_seconds"] = record["elapsed_seconds"]
            record["timeout"] = True
            record["completed_within_timeout"] = False
            record["error"] = (
                f"client timeout ({type(exc).__name__}) after {record['elapsed_seconds']}s"
            )
        except httpx.HTTPError as exc:
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["total_seconds"] = record["elapsed_seconds"]
            record["completed_within_timeout"] = False
            record["error"] = f"HTTP error ({type(exc).__name__}: {exc})"
        except Exception as exc:  # noqa: BLE001
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["total_seconds"] = record["elapsed_seconds"]
            record["completed_within_timeout"] = False
            record["error"] = f"{type(exc).__name__}: {exc}"
        self.records.append(record)


    async def run(self) -> dict[str, Any]:
        timeout = httpx.Timeout(GENERATE_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Read-only preflight: model installed?
            await self._get_json(client, "/api/tags", "residency_before")
            # Read-only preflight: models currently loaded?
            await self._get_json(client, "/api/ps", "loaded_before")
            # The single bounded generation request.
            await self._post_generate(client)
            # Read-only postflight: models loaded after the request?
            await self._get_json(client, "/api/ps", "loaded_after")
        return self._build_summary()

    def _build_summary(self) -> dict[str, Any]:
        total = self._elapsed()

        tags_before = next(
            (r for r in self.records if r.get("label") == "residency_before"),
            {},
        )
        ps_before = next(
            (r for r in self.records if r.get("label") == "loaded_before"),
            {},
        )
        ps_after = next(
            (r for r in self.records if r.get("label") == "loaded_after"),
            {},
        )
        generate = next(
            (r for r in self.records if r["path"] == "/api/generate"),
            {},
        )

        model_installed = False
        model_digest = None
        model_size = None
        if tags_before.get("data"):
            for m in tags_before["data"].get("models", []):
                if isinstance(m, dict) and m.get("name") == MODEL:
                    model_installed = True
                    model_digest = m.get("digest")
                    model_size = m.get("size")
                    break

        loaded_before = []
        if ps_before.get("data") and isinstance(ps_before["data"], dict):
            loaded_before = ps_before["data"].get("models", [])
        loaded_after = []
        if ps_after.get("data") and isinstance(ps_after["data"], dict):
            loaded_after = ps_after["data"].get("models", [])

        time_to_first = generate.get("time_to_first_chunk_seconds")
        total_gen = generate.get("total_seconds")
        completed = generate.get("completed_within_timeout")
        gen_error = generate.get("error")
        gen_timeout = generate.get("timeout", False)
        status_code = generate.get("status_code")
        response_chars = generate.get("response_chars")

        diagnosis = "inconclusive"
        if not model_installed:
            diagnosis = "model_not_installed"
        elif gen_timeout:
            diagnosis = "startup_or_loading_delay"
        elif gen_error is not None and not completed:
            diagnosis = "client_side_timeout_or_error"
        elif completed is False:
            diagnosis = "did_not_complete_within_diagnostic_timeout"
        elif time_to_first is not None and time_to_first > 5.0:
            diagnosis = "slow_startup_or_first_token"
        elif total_gen is not None and total_gen > 5.0:
            diagnosis = "slow_generation"
        else:
            diagnosis = "responsive_within_diagnostic_timeout"

        return {
            "bounds": {
                "generation_requests": 1,
                "per_request_timeout_seconds": GENERATE_TIMEOUT_SECONDS,
                "overall_watchdog_seconds": OVERALL_WATCHDOG_SECONDS,
                "model": MODEL,
                "expected_digest": EXPECTED_DIGEST,
                "base_url": BASE_URL,
            },
            "actual": {
                "total_elapsed_seconds": round(total, 4),
            },
            "preflight": {
                "model_installed": model_installed,
                "model_digest": model_digest,
                "model_size_bytes": model_size,
                "digest_matches_expected": model_digest == EXPECTED_DIGEST,
                "loaded_models_before": loaded_before,
                "loaded_models_after": loaded_after,
            },
            "generation": {
                "http_status": status_code,
                "time_to_first_chunk_seconds": time_to_first,
                "total_seconds": total_gen,
                "completed_within_timeout": completed,
                "response_chars": response_chars,
                "response_preview": generate.get("response_preview"),
                "error": gen_error,
                "timeout": gen_timeout,
            },
            "diagnosis": diagnosis,
            "records": self.records,
        }


async def _main() -> int:
    diag = Diagnostic()
    try:
        summary = await asyncio.wait_for(
            diag.run(), timeout=OVERALL_WATCHDOG_SECONDS
        )
    except TimeoutError:
        summary = {
            "bounds": {
                "generation_requests": 1,
                "per_request_timeout_seconds": GENERATE_TIMEOUT_SECONDS,
                "overall_watchdog_seconds": OVERALL_WATCHDOG_SECONDS,
                "model": MODEL,
                "expected_digest": EXPECTED_DIGEST,
                "base_url": BASE_URL,
            },
            "actual": {"total_elapsed_seconds": round(diag._elapsed(), 4)},
            "diagnosis": "overall_watchdog_expired",
            "error": f"diagnostic exceeded {OVERALL_WATCHDOG_SECONDS}s watchdog",
            "records": diag.records,
        }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))

