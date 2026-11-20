from __future__ import annotations

import httpx
import pytest

from app.analyzer import RateLimitAnalyzer
from app.models import AnalyzeRequest
from mock_target import app as mock_app


@pytest.mark.asyncio
async def test_analyzer_against_mock_no_limit():
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/no-limit",
        request_budget=6,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "no_limit_observed"
    assert res.profile.request_counters.accepted == 6
    assert res.profile.request_counters.confirmed_rate_limited == 0


@pytest.mark.asyncio
async def test_analyzer_against_mock_waf_block():
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/waf-block",
        request_budget=5,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "immediate_access_block"
    assert res.profile.safe_burst_size == 0


@pytest.mark.asyncio
async def test_analyzer_against_mock_ambiguous_403():
    """
    Ensure ambiguous 403 (permission denied) is not misclassified as rate-limiting.
    """
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/ambiguous-403",
        request_budget=5,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    # Probes should record http_errors, not confirmed rate limiting
    assert res.profile.request_counters.confirmed_rate_limited == 0
    assert res.profile.request_counters.http_errors > 0


@pytest.mark.asyncio
async def test_analyzer_against_mock_header_limit():
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/header-limit",
        request_budget=10,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "header_guided"
    assert res.profile.request_counters.confirmed_rate_limited > 0
