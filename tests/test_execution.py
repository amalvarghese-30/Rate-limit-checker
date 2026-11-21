from __future__ import annotations

import asyncio
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app, store
from app.models import (
    AnalysisResult,
    BaselineStats,
    CooldownStats,
    ExecutionRequest,
    PatternClassification,
    RateLimitProfile,
    RateRecommendations,
    RequestCounters,
)
from app.pacing import PacingEngine


def make_test_profile(job_id: str = "exec-test-profile") -> AnalysisResult:
    profile = RateLimitProfile(
        job_id=job_id,
        created_at="2026-11-21T12:00:00Z",
        target_url="http://127.0.0.1:8001/fixed-window",
        method="GET",
        baseline_stats=BaselineStats(requests_sent=3, successful_count=3, avg_latency_ms=10.0),
        request_counters=RequestCounters(total_sent=10, accepted=10),
        pattern_classification=PatternClassification(
            detected_pattern="fixed_window",
            confidence="high",
            confidence_score=0.9,
            explanation="Test fixed window",
        ),
        rate_recommendations=RateRecommendations(
            recommended_rps=10.0,
            recommended_interval_sec=0.05,
            recommended_interval_ms=50.0,
            recommended_rpm=600.0,
        ),
        cooldown_stats=CooldownStats(observed_cooldown_sec=5.0),
        safe_burst_size=2,
        frequency_summary="Pacing test",
        observed_headers={},
    )
    return AnalysisResult(profile=profile, probes=[])


@pytest.mark.asyncio
async def test_pacing_engine_execution_lifecycle():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json={"ok": True, "n": called["count"]})

    res = make_test_profile("exec-job-1")
    store.save(res)

    engine = PacingEngine(store=store, allow_local=True)
    req = ExecutionRequest(job_id="exec-job-1", request_budget=4)
    execution = engine.create_execution(res.profile, req)

    transport = httpx.MockTransport(handler)
    await engine.start_execution(execution, transport=transport)

    # Wait for completion
    for _ in range(20):
        if execution.status.status == "completed":
            break
        await asyncio.sleep(0.05)

    assert execution.status.status == "completed"
    assert execution.status.completed_requests == 4
    assert execution.status.accepted_requests == 4
    assert len(execution.records) == 4
    assert called["count"] == 4


@pytest.mark.asyncio
async def test_pacing_engine_pause_resume_stop():
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, json={"ok": True})

    res = make_test_profile("exec-job-2")
    # Set interval to 200ms so we have clear pacing windows to test pause/resume
    res.profile.rate_recommendations.recommended_interval_sec = 0.2
    store.save(res)

    engine = PacingEngine(store=store, allow_local=True)
    req = ExecutionRequest(job_id="exec-job-2", request_budget=20)
    execution = engine.create_execution(res.profile, req)

    transport = httpx.MockTransport(handler)
    await engine.start_execution(execution, transport=transport)

    # Allow request #1 to dispatch
    await asyncio.sleep(0.04)
    execution.pause()
    assert execution.is_paused() is True

    current_called = called["count"]
    # Wait while paused - no new requests should fire
    await asyncio.sleep(0.25)
    assert called["count"] == current_called

    execution.resume()
    assert execution.is_paused() is False
    # Wait for the next paced request
    await asyncio.sleep(0.25)
    assert called["count"] > current_called

    execution.stop()
    assert execution.is_stopped() is True
    assert execution.status.status == "stopped"


def test_api_execution_endpoints():
    client = TestClient(app)
    res = make_test_profile("exec-job-api")
    store.save(res)

    # 1. Create execution
    post_res = client.post("/api/executions", json={"job_id": "exec-job-api", "request_budget": 5})
    assert post_res.status_code == 200
    data = post_res.json()
    exec_id = data["execution_id"]

    # 2. Status
    st_res = client.get(f"/api/executions/{exec_id}")
    assert st_res.status_code == 200
    assert "status" in st_res.json()

    # 3. Pause
    p_res = client.post(f"/api/executions/{exec_id}/pause")
    assert p_res.status_code == 200

    # 4. Resume
    r_res = client.post(f"/api/executions/{exec_id}/resume")
    assert r_res.status_code == 200

    # 5. Stop
    s_res = client.post(f"/api/executions/{exec_id}/stop")
    assert s_res.status_code == 200

    # 6. List executions
    l_res = client.get("/api/executions")
    assert l_res.status_code == 200
    items = l_res.json()["items"]
    assert any(i["execution_id"] == exec_id for i in items)
