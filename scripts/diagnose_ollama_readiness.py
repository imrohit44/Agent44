"""Isolated Ollama runtime-readiness diagnostic (Milestone 4f.3).

Purpose: diagnose why the previous live Ollama pilot saw six adapter
timeouts, before deciding whether to run another evaluation.
INFRASTRUCTURE DIAGNOSIS ONLY — does not run the 20-scenario evaluation
pilot, does not touch held-out scenarios, does not modify any tracked file,
and does not alter the configured 5.0 s adapter deadline.

Safety bounds (stated before execution):
  * Request budget: 3 HTTP requests total (GET /api/tags × 2,
    POST /api/generate × 1).
  * Maximum total wall-clock duration: 60 s.
  * Per-request client timeout: 10 s (explicit, bounded).
  * No concurrent requests; sequential only.
  * No model download/pull; read-only model-residency check via /api/tags.
  * Bind only to loopback 127.0.0.1:11434.
  * No warm-ups; every request is counted in the budget.

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
DIAG_TIMEOUT_SECONDS = 10.0
MAX_TOTAL_SECONDS = 60.0
MAX_REQUESTS = 3
PROMPT = "Reply with exactly the word OK and nothing else."


class Diagnostic:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.requests = 0
        self.records: list[dict[str, Any]] = []

    def _elapsed(self) -> float:
        return time.monotonic() - self.start

    def _can_proceed(self) -> bool:
        return (
            self.requests < MAX_REQUESTS
            and self._elapsed() < MAX_TOTAL_SECONDS
        )

    async def _get_tags(self, client: httpx.AsyncClient, label: str) -> None:
        if not self._can_proceed():
            return
        self.requests += 1
        t0 = time.monotonic()
        record: dict[str, Any] = {
            "request": self.requests,
            "method": "GET",
            "path": "/api/tags",
            "label": label,
            "elapsed_seconds": None,
            "status_code": None,
            "models": None,
            "model_found": None,
            "model_digest": None,
            "model_size": None,
            "error": None,
            "timeout": False,
        }
        try:
            resp = await client.get(f"{BASE_URL}/api/tags")
            t1 = time.monotonic()
            record["elapsed_seconds"] = round(t1 - t0, 4)
            record["status_code"] = resp.status_code
            data = resp.json()
            models = [m.get("name") for m in data.get("models", [])]
            record["models"] = models
            for m in data.get("models", []):
                if isinstance(m, dict) and m.get("name") == MODEL:
                    record["model_found"] = True
                    record["model_digest"] = m.get("digest")
                    record["model_size"] = m.get("size")
                    break
            else:
                record["model_found"] = False
        except httpx.TimeoutException as exc:
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["timeout"] = True
            record["error"] = f"client timeout ({type(exc).__name__})"
        except httpx.HTTPError as exc:
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["error"] = f"HTTP error ({type(exc).__name__}: {exc})"
        except Exception as exc:  # noqa: BLE001 - surface any diagnostic failure
            record["elapsed_seconds"] = round(time.monotonic() - t0, 4)
            record["error"] = f"{type(exc).__name__}: {exc}"
        self.records.append(record)

    async def _post_generate(self, client: httpx.AsyncClient) -> None:
        if not self._can_proceed():
            return
        self.requests += 1
        t0 = time.monotonic()
        record: dict[str, Any] = {
            "request": self.requests,
            "method": "POST",
            "path": "/api/generate",
            "label": "generate_probe",
            "elapsed_seconds": None,
            "status_code": None,
            "time_to_first_chunk_seconds": None,
            "total_seconds": None,
            "completed_within_timeout": None,
            "response_chars": None,
            "error": None,
            "timeout": False,
        }
        first_chunk_time: float | None = None
        chunks: list[bytes] = []
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
            t2 = time.monotonic()
            record["elapsed_seconds"] = round(t2 - t0, 4)
            record["total_seconds"] = round(t2 - t0, 4)
            body = b"".join(chunks)
            record["response_chars"] = len(body)
            record["completed_within_timeout"] = True
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
        timeout = httpx.Timeout(DIAG_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout) as client:
            await self._get_tags(client, "residency_before")
            await self._post_generate(client)
            await self._get_tags(client, "residency_after")
        summary = self._build_summary()
        return summary

    def _build_summary(self) -> dict[str, Any]:
        total = self._elapsed()
        api_ready = any(
            r["status_code"] == 200 and r["error"] is None
            for r in self.records
            if r["path"] == "/api/tags"
        )
        model_resident_before = next(
            (r for r in self.records if r.get("label") == "residency_before"),
            {},
        ).get("model_found")
        model_resident_after = next(
            (r for r in self.records if r.get("label") == "residency_after"),
            {},
        ).get("model_found")
        generate = next(
            (r for r in self.records if r["path"] == "/api/generate"),
            {},
        )
        time_to_first = generate.get("time_to_first_chunk_seconds")
        total_gen = generate.get("total_seconds")
        completed = generate.get("completed_within_timeout")
        gen_error = generate.get("error")
        gen_timeout = generate.get("timeout", False)

        diagnosis = "inconclusive"
        if not api_ready:
            diagnosis = "ollama_api_not_ready"
        elif model_resident_before is False:
            diagnosis = "model_not_resident"
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
                "max_requests": MAX_REQUESTS,
                "max_total_seconds": MAX_TOTAL_SECONDS,
                "per_request_timeout_seconds": DIAG_TIMEOUT_SECONDS,
                "model": MODEL,
                "base_url": BASE_URL,
            },
            "actual": {
                "requests_made": self.requests,
                "total_elapsed_seconds": round(total, 4),
            },
            "readiness": {
                "api_ready": api_ready,
                "model_resident_before": model_resident_before,
                "model_resident_after": model_resident_after,
            },
            "latency": {
                "time_to_first_chunk_seconds": time_to_first,
                "total_generate_seconds": total_gen,
                "completed_within_diagnostic_timeout": completed,
            },
            "errors": {
                "generate_error": gen_error,
                "generate_timeout": gen_timeout,
            },
            "diagnosis": diagnosis,
            "records": self.records,
        }


async def _main() -> int:
    diag = Diagnostic()
    summary = await diag.run()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))