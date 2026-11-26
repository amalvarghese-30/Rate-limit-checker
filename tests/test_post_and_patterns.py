from __future__ import annotations

import json
import tempfile
from pathlib import Path
import httpx
import pytest

from app.analyzer import RateLimitAnalyzer
from app.models import AnalyzeRequest, ExecutionRequest
from app.pacing import PacingEngine
from app.storage import HistoryStore


@pytest.mark.asyncio
async def test_post_method_with_json_body_and_waf_detection():
    """Verify POST method sends request_body, detects Cloudflare WAF, and generates sending schedule."""
    received_methods = []
    received_bodies = []
    received_ctypes = []
    counter = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404)
        counter["n"] += 1
        received_methods.append(request.method)
        received_bodies.append(request.content.decode("utf-8"))
        received_ctypes.append(request.headers.get("content-type"))

        if counter["n"] <= 4:
            return httpx.Response(
                200,
                json={"ok": True},
                headers={"CF-RAY": "8a1b2c3d4e5f-SIN", "X-RateLimit-Limit": "4", "X-RateLimit-Remaining": str(4 - counter["n"])},
            )
        return httpx.Response(
            429,
            json={"error": "Too Many Requests"},
            headers={"CF-RAY": "8a1b2c3d4e5f-SIN", "Retry-After": "1", "X-RateLimit-Limit": "4", "X-RateLimit-Remaining": "0"},
        )

    transport = httpx.MockTransport(handler)
    analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

    payload_str = json.dumps({"action": "search", "q": "rate-limit"})
    req = AnalyzeRequest(
        url="http://127.0.0.1:8001/api/search",
        method="POST",
        request_body=payload_str,
        content_type="application/json",
        request_budget=8,
        burst_size=1,
        probe_interval_sec=0.01,
        check_cooldown=False,
        verify_safe_pace=False,
        check_robots=False,
    )

    res = await analyzer.run(req)

    assert res.profile.method == "POST"
    assert res.profile.request_body == payload_str
    assert all(m == "POST" for m in received_methods)
    assert all(b == payload_str for b in received_bodies)
    assert all(ct == "application/json" for ct in received_ctypes)
    assert res.profile.pattern_classification.detected_pattern == "header_guided"
    assert res.profile.pattern_classification.detected_waf == "Cloudflare"
    assert res.profile.pattern_classification.sending_pattern == "header_quota_pacing"
    assert len(res.profile.pattern_classification.sending_schedule_steps) >= 2
    assert res.probes[0].rate_limit_limit == 4
    assert res.probes[0].rate_limit_remaining == 3


@pytest.mark.asyncio
async def test_pacing_engine_executes_post_with_body():
    """Verify Stage 2 PacingEngine forwards POST method and request_body from profile."""
    received = []

    async def handler(request: httpx.Request) -> httpx.Response:
        received.append((request.method, request.content.decode("utf-8")))
        return httpx.Response(200, json={"accepted": True})

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        store = HistoryStore(db_path=Path(tmpdir) / "test_post_exec.db")
        transport = httpx.MockTransport(handler)
        analyzer = RateLimitAnalyzer(transport=transport, allow_local=True)

        body_str = json.dumps({"event": "ping"})
        req = AnalyzeRequest(
            url="http://127.0.0.1:8001/webhook",
            method="POST",
            request_body=body_str,
            request_budget=4,
            burst_size=1,
            probe_interval_sec=0.01,
            check_cooldown=False,
            verify_safe_pace=False,
            check_robots=False,
        )
        res = await analyzer.run(req)
        received.clear()

        engine = PacingEngine(store=store, allow_local=True)
        exec_req = ExecutionRequest(job_id=res.profile.job_id, request_budget=3)
        execution = engine.create_execution(res.profile, exec_req)
        await engine.start_execution(execution, transport=transport)
        await execution.task

        assert execution.status.status == "completed"
        assert execution.status.accepted_requests == 3
        assert len(received) == 3
        assert all(m == "POST" and b == body_str for m, b in received)
