from __future__ import annotations

import asyncio
import math
import time
from typing import Dict, List
import httpx
import pytest

from app.analyzer import RateLimitAnalyzer
from app.models import AnalyzeRequest, RequestCounters
from app.storage import HistoryStore


@pytest.mark.asyncio
async def test_budget_10_concurrency_1():
    """Case 1: Budget 10, concurrency 1. Total dispatched must equal exactly 10, concurrency <= 1."""
    active_concurrency = 0
    max_concurrency_seen = 0
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_concurrency, max_concurrency_seen, dispatched_count
        active_concurrency += 1
        dispatched_count += 1
        if active_concurrency > max_concurrency_seen:
            max_concurrency_seen = active_concurrency
        await asyncio.sleep(0.01)
        active_concurrency -= 1
        return httpx.Response(200, json={"ok": True, "n": dispatched_count})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/no-limit",
        request_budget=10,
        burst_size=1,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.status == "completed"
    assert res.profile.request_counters.dispatched_requests == 10
    assert res.profile.request_counters.completed_requests == 10
    assert len(res.probes) == 10
    assert dispatched_count == 10
    assert max_concurrency_seen == 1
    assert "Analysis completed successfully" in res.profile.completion_message
    assert res.profile.pattern_classification.detected_pattern == "no_limit_observed"
    assert res.profile.pattern_classification.explanation == "No rate limit observed within the tested budget."


@pytest.mark.asyncio
async def test_budget_25_concurrency_3():
    """Case 2: Budget 25, concurrency 3. Total dispatched must equal 25, concurrency <= 3."""
    active_concurrency = 0
    max_concurrency_seen = 0
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_concurrency, max_concurrency_seen, dispatched_count
        active_concurrency += 1
        dispatched_count += 1
        if active_concurrency > max_concurrency_seen:
            max_concurrency_seen = active_concurrency
        await asyncio.sleep(0.02)
        active_concurrency -= 1
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/no-limit",
        request_budget=25,
        burst_size=3,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.status == "completed"
    assert res.profile.request_counters.dispatched_requests == 25
    assert res.profile.request_counters.completed_requests == 25
    assert len(res.probes) == 25
    assert dispatched_count == 25
    assert max_concurrency_seen <= 3
    assert max_concurrency_seen >= 2  # Proves concurrent dispatch in batches
    assert "Analysis completed successfully" in res.profile.completion_message


@pytest.mark.asyncio
async def test_budget_100_concurrency_6():
    """Case 3: Budget 100, concurrency 6. Must NOT prematurely abort at 10; dispatches all 100 requests."""
    active_concurrency = 0
    max_concurrency_seen = 0
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_concurrency, max_concurrency_seen, dispatched_count
        active_concurrency += 1
        dispatched_count += 1
        if active_concurrency > max_concurrency_seen:
            max_concurrency_seen = active_concurrency
        await asyncio.sleep(0.01)
        active_concurrency -= 1
        return httpx.Response(200, json={"ok": True, "n": dispatched_count})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/no-limit",
        request_budget=100,
        burst_size=6,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.status == "completed"
    assert res.profile.request_counters.dispatched_requests == 100
    assert res.profile.request_counters.completed_requests == 100
    assert len(res.probes) == 100
    assert dispatched_count == 100
    assert max_concurrency_seen <= 6
    assert max_concurrency_seen >= 4  # Proves burst concurrency occurred
    assert res.profile.pattern_classification.explanation == "No rate limit observed within the tested budget."


@pytest.mark.asyncio
async def test_one_request_timing_out():
    """Case 4: One request timing out. Handled gracefully, classified as timeout, recorded in counters."""
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched_count
        dispatched_count += 1
        if dispatched_count == 4:
            raise httpx.ReadTimeout("Request timed out", request=request)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/test-timeout",
        request_budget=10,
        burst_size=2,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.request_counters.timed_out_requests == 1
    assert res.profile.request_counters.timeouts == 1
    assert res.profile.request_counters.successful_requests == 9
    assert res.profile.request_counters.dispatched_requests == 10
    assert len(res.probes) == 10


@pytest.mark.asyncio
async def test_multiple_requests_returning_429():
    """Case 5: Multiple requests returning HTTP 429. Detected and counted in rate_limited_requests."""
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched_count
        dispatched_count += 1
        if dispatched_count > 4:
            return httpx.Response(
                429,
                json={"error": "Too Many Requests"},
                headers={"Retry-After": "1"},
            )
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/test-429",
        request_budget=15,
        burst_size=2,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.request_counters.rate_limited_requests >= 1
    assert res.profile.request_counters.confirmed_rate_limited >= 1
    assert res.profile.detected_pattern in ("fixed_window", "token_bucket", "header_guided")


@pytest.mark.asyncio
async def test_server_returning_retry_after():
    """Case 6: Server returning Retry-After header. Extracted and documented in cooldown stats."""
    dispatched_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched_count
        dispatched_count += 1
        if dispatched_count > 3:
            return httpx.Response(
                429,
                json={"error": "Rate limit exceeded"},
                headers={"Retry-After": "3", "X-RateLimit-Limit": "3"},
            )
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/test-retry",
        request_budget=8,
        burst_size=1,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    retry_probes = [p for p in res.probes if p.retry_after_sec is not None]
    assert len(retry_probes) > 0
    assert retry_probes[0].retry_after_sec == 3.0
    assert res.profile.cooldown_stats.server_retry_after_sec == 3.0


@pytest.mark.asyncio
async def test_user_cancelling_during_batch():
    """Case 7: User cancels during a running batch. Analysis stops cleanly without hanging."""
    dispatched_count = 0
    cancel_flag = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatched_count, cancel_flag
        dispatched_count += 1
        if dispatched_count >= 5:
            cancel_flag = True
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/test-cancel",
        request_budget=50,
        burst_size=2,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req, is_cancelled=lambda: cancel_flag)

    assert res.profile.status == "cancelled"
    assert "Analysis cancelled by user" in res.profile.completion_message
    assert res.profile.request_counters.dispatched_requests < 50


@pytest.mark.asyncio
async def test_analysis_deadline_reached_partial_status():
    """Case 8: Analysis deadline reached before budget completion. Result is marked 'partial'."""
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.08)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    # Configure a short deadline (0.25s) with a larger budget (20 requests with 0.05s intervals)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/test-deadline",
        request_budget=20,
        burst_size=1,
        probe_interval_sec=0.05,
        max_analysis_duration_sec=0.25,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.status == "partial"
    assert "Analysis partially completed" in res.profile.completion_message
    assert "Maximum analysis duration reached" in res.profile.completion_message
    assert res.profile.request_counters.dispatched_requests < 20
    assert res.profile.rate_recommendations.is_provisional is True


@pytest.mark.asyncio
async def test_worker_restart_and_job_persistence():
    """Case 9: Analysis persistence across store instances (worker restart simulation)."""
    import tempfile

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        from pathlib import Path
        db_path = Path(tmpdir) / "test_restart.db"
        store1 = HistoryStore(db_path=db_path)

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

        req = AnalyzeRequest(
            url="http://127.0.0.1:8001/test-persist",
            request_budget=8,
            burst_size=2,
            probe_interval_sec=0.01,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )

        res = await analyzer.run(req)
        store1.save(res)

        # Simulate worker restart by creating a new store instance pointing to same DB
        store2 = HistoryStore(db_path=db_path)
        loaded = store2.get(res.profile.job_id)

        assert loaded is not None
        assert loaded.profile.job_id == res.profile.job_id
        assert loaded.profile.status == "completed"
        assert loaded.profile.request_counters.dispatched_requests == 8
        assert loaded.profile.request_counters.completed_requests == 8
        assert len(loaded.probes) == 8
