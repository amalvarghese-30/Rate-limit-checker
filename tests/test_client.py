from __future__ import annotations

import asyncio
import time
import httpx
import pytest

from app.client import RateControlledClient


@pytest.mark.asyncio
async def test_adaptive_client_retries_on_429():
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0.05"})
        return httpx.Response(200, json={"ok": True})

    ctrl = RateControlledClient(interval_sec=0.05, jitter_pct=0.0)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        resp = await ctrl.get(http, "https://example.test/data", max_retries=2)
    assert resp.status_code == 200
    assert attempts["n"] == 2


@pytest.mark.asyncio
async def test_adaptive_client_aimd_rate_adjustment():
    ctrl = RateControlledClient(
        interval_sec=1.0,  # 1.0 req/s
        additive_step_rps=0.2,
        multiplicative_decrease_factor=0.5,
    )
    assert ctrl.current_rate_rps == 1.0

    # Simulate 5 successful responses -> triggers additive increase
    for _ in range(5):
        ctrl._record_success()
    assert round(ctrl.current_rate_rps, 2) == 1.2

    # Simulate throttling -> triggers multiplicative decrease
    ctrl._record_throttling()
    assert round(ctrl.current_rate_rps, 2) == 0.6


@pytest.mark.asyncio
async def test_token_bucket_burst_concurrency_control():
    """
    Ensures that with safe_burst_size=2, firing 5 concurrent requests allows
    at most 2 immediately, and the remaining 3 must wait for token replenishment.
    """
    timestamps = []

    def handler(request: httpx.Request) -> httpx.Response:
        timestamps.append(time.monotonic())
        return httpx.Response(200, json={"ok": True})

    # Burst = 2, rate = 10 req/s (interval 0.1s)
    ctrl = RateControlledClient(interval_sec=0.1, safe_burst_size=2, jitter_pct=0.0)

    start_time = time.monotonic()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        tasks = [ctrl.get(http, f"https://example.test/{i}") for i in range(5)]
        await asyncio.gather(*tasks)

    duration = time.monotonic() - start_time
    # 5 requests with burst=2 at 0.1s interval should take at least (5 - 2) * 0.1 = 0.3s
    assert duration >= 0.25
    assert len(timestamps) == 5


@pytest.mark.asyncio
async def test_retry_after_pauses_concurrent_callers():
    """
    When one request hits 429 with Retry-After, other concurrent requests
    must also wait until the cooldown window finishes.
    """
    times = []

    def handler(request: httpx.Request) -> httpx.Response:
        now = time.monotonic()
        times.append(now)
        if len(times) == 1:
            return httpx.Response(429, headers={"Retry-After": "0.15"})
        return httpx.Response(200, json={"ok": True})

    ctrl = RateControlledClient(interval_sec=0.02, safe_burst_size=5, jitter_pct=0.0)
    start = time.monotonic()

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        tasks = [
            ctrl.get(http, "https://example.test/a", max_retries=1),
            ctrl.get(http, "https://example.test/b", max_retries=1),
        ]
        resps = await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start
    assert elapsed >= 0.14
    for r in resps:
        assert r.status_code == 200
