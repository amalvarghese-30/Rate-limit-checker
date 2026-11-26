from __future__ import annotations

import json
import httpx
import pytest

from app.analyzer import RateLimitAnalyzer
from app.models import AnalyzeRequest
from mock_target import app as mock_app


async def _reset_mock():
    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport) as client:
        await client.post("http://127.0.0.1:8001/reset-state")


@pytest.mark.asyncio
async def test_dummy_site_html_page():
    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport) as client:
        resp = await client.get("http://127.0.0.1:8001/")
        assert resp.status_code == 200
        assert "Dummy Rate-Limit Test Site" in resp.text
        assert "/post-limit" in resp.text
        assert "/concurrency-limit" in resp.text


@pytest.mark.asyncio
async def test_dummy_fixed_window_and_token_bucket():
    await _reset_mock()
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    # Fixed window (6 req / 6s)
    res_fw = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/fixed-window",
            request_budget=12,
            burst_size=2,
            probe_interval_sec=0.05,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_fw.profile.detected_pattern == "fixed_window"
    assert res_fw.profile.request_counters.rate_limited_requests >= 1
    assert len(res_fw.profile.pattern_classification.sending_schedule_steps) >= 2

    # Token bucket (5 tokens, 0.8s refill)
    await _reset_mock()
    res_tb = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/token-bucket",
            request_budget=12,
            burst_size=2,
            probe_interval_sec=0.25,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_tb.profile.detected_pattern in ("token_bucket", "fixed_window")
    assert res_tb.profile.request_counters.rate_limited_requests >= 1


@pytest.mark.asyncio
async def test_dummy_leaky_bucket_and_concurrency_limit():
    await _reset_mock()
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    # Leaky bucket (2 req/s delay injection)
    res_lb = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/leaky-bucket",
            request_budget=10,
            burst_size=2,
            probe_interval_sec=0.02,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_lb.profile.detected_pattern in ("leaky_bucket", "no_limit_observed")
    assert res_lb.profile.request_counters.successful_requests == 10

    # Concurrency limit (max 2 simultaneous)
    await _reset_mock()
    res_cc = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/concurrency-limit",
            request_budget=10,
            burst_size=4,
            probe_interval_sec=0.02,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_cc.profile.request_counters.rate_limited_requests >= 1
    assert res_cc.profile.detected_pattern == "header_guided"


@pytest.mark.asyncio
async def test_dummy_post_kong_and_waf_endpoints():
    await _reset_mock()
    transport = httpx.ASGITransport(app=mock_app)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    # POST /post-limit
    res_post = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/post-limit",
            method="POST",
            request_body=json.dumps({"hello": "world"}),
            request_budget=8,
            burst_size=1,
            probe_interval_sec=0.05,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_post.profile.method == "POST"
    assert res_post.profile.detected_pattern == "header_guided"
    assert res_post.profile.request_counters.rate_limited_requests >= 1

    # Kong Gateway
    await _reset_mock()
    res_kong = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/kong-limit",
            request_budget=8,
            burst_size=1,
            probe_interval_sec=0.05,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_kong.profile.pattern_classification.detected_waf == "Kong API Gateway"
    assert res_kong.profile.detected_pattern == "header_guided"

    # AWS WAF Block
    await _reset_mock()
    res_aws = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/aws-waf-block",
            request_budget=4,
            burst_size=1,
            probe_interval_sec=0.05,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_aws.profile.detected_pattern == "immediate_access_block"
    assert res_aws.profile.pattern_classification.detected_waf == "AWS CloudFront / WAF"

    # HTTP 503 with Retry-After
    await _reset_mock()
    res_503 = await analyzer.run(
        AnalyzeRequest(
            url="http://127.0.0.1:8001/http-503-retry",
            request_budget=4,
            burst_size=1,
            probe_interval_sec=0.05,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
    )
    assert res_503.profile.detected_pattern == "immediate_access_block"
    assert res_503.profile.request_counters.confirmed_rate_limited >= 1
