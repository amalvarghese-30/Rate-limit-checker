from __future__ import annotations

import httpx
import pytest

from app.analyzer import RateLimitAnalyzer, classify_response, parse_ratelimit_reset, parse_retry_after
from app.models import AnalyzeRequest


def test_retry_after_parser():
    # Delta seconds
    assert parse_retry_after("10") == 10.0
    assert parse_retry_after(" 5.5 ") == 5.5
    assert parse_retry_after("-2") == 0.0
    assert parse_retry_after("invalid") is None
    assert parse_retry_after(None) is None

    # HTTP-date (RFC 2822 / RFC 7231)
    http_date = "Wed, 21 Oct 2026 07:28:00 GMT"
    # Should parse into a float >= 0.0
    res = parse_retry_after(http_date)
    assert res is not None


def test_ratelimit_reset_parser():
    headers = {"X-RateLimit-Reset": "30"}
    assert parse_ratelimit_reset(headers) == 30.0

    headers_epoch = {"RateLimit-Reset": "1900000000"}
    res = parse_ratelimit_reset(headers_epoch)
    assert res is not None and res > 0.0


def test_classify_response_differentiation():
    # 429 is always confirmed rate limit
    acc, conf, err_type, reason = classify_response(429, {}, "")
    assert not acc
    assert conf is True
    assert err_type == "http_429"

    # 403 without rate limit headers is ambiguous
    acc, conf, err_type, reason = classify_response(403, {}, "Forbidden")
    assert not acc
    assert conf is False
    assert err_type == "http_403_ambiguous"

    # 403 with WAF signature is confirmed rate limit / access block
    acc, conf, err_type, reason = classify_response(403, {"cf-ray": "xyz"}, "Attention Required! Cloudflare")
    assert not acc
    assert conf is True
    assert err_type == "http_403_rate_limit"

    # 503 without headers is unavail, not confirmed rate limit
    acc, conf, err_type, reason = classify_response(503, {}, "Service Unavailable")
    assert not acc
    assert conf is False
    assert err_type == "http_503_unavail"

    # Network / Timeout errors
    acc, conf, err_type, reason = classify_response(None, {}, "", error=httpx.TimeoutException("timeout"))
    assert not acc
    assert conf is False
    assert err_type == "timeout"


@pytest.mark.asyncio
async def test_fixed_window_detection():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        counter["n"] += 1
        # 3 baseline requests succeed, then 3 probe requests succeed, then 429
        if counter["n"] <= 6:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(429, json={"error": "rate limit"})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/api",
        request_budget=12,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "fixed_window"
    assert res.profile.first_block_at_request == 7
    assert res.profile.safe_burst_size >= 1
    assert res.profile.baseline_stats.is_healthy is True


@pytest.mark.asyncio
async def test_header_guided_detection():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        counter["n"] += 1
        if counter["n"] <= 4:
            return httpx.Response(200, headers={"X-RateLimit-Limit": "4"})
        return httpx.Response(429, headers={"Retry-After": "4", "X-RateLimit-Limit": "4"})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/api",
        request_budget=10,
        probe_interval_sec=0.05,
        check_cooldown=True,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "header_guided"
    assert res.profile.cooldown_stats.server_retry_after_sec == 4.0


@pytest.mark.asyncio
async def test_immediate_waf_block():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        return httpx.Response(403, text="Attention Required! Cloudflare", headers={"cf-ray": "abc"})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/api",
        request_budget=10,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "immediate_access_block"
    assert res.profile.safe_burst_size == 0


@pytest.mark.asyncio
async def test_token_bucket_alternating_detection():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        counter["n"] += 1
        # 3 baseline + 2 probe = 5 pass, then alternate 429, 200, 429, 200
        if counter["n"] <= 5 or counter["n"] % 2 == 1:
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(429, json={"error": "burst limit"})

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/api",
        request_budget=12,
        probe_interval_sec=0.05,
        check_cooldown=False,
        verify_safe_pace=False,
    )
    res = await analyzer.run(req)
    assert res.profile.detected_pattern == "token_bucket"
