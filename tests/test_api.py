from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app, store
from app.models import (
    AnalysisResult,
    BaselineStats,
    CooldownStats,
    PatternClassification,
    RateLimitProfile,
    RateRecommendations,
    RequestCounters,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_health_and_stats_endpoints(client: TestClient):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["version"] == "2.0.0"

    resp = client.get("/api/stats")
    assert resp.status_code == 200
    s_data = resp.json()
    assert "total_analyses" in s_data


def test_job_creation_and_history(client: TestClient):
    # Pre-seed a record in store
    sample_profile = RateLimitProfile(
        job_id="testjob1",
        created_at="2026-11-20T12:00:00Z",
        target_url="http://127.0.0.1:8001/fixed-window",
        method="GET",
        baseline_stats=BaselineStats(requests_sent=3, successful_count=3, avg_latency_ms=10.0),
        request_counters=RequestCounters(total_sent=6, accepted=5, confirmed_rate_limited=1),
        pattern_classification=PatternClassification(
            detected_pattern="fixed_window",
            confidence="high",
            confidence_score=0.88,
            explanation="Test pattern",
        ),
        rate_recommendations=RateRecommendations(
            recommended_rps=2.0,
            recommended_interval_sec=0.5,
            recommended_rpm=120.0,
        ),
        cooldown_stats=CooldownStats(observed_cooldown_sec=6.0),
        safe_burst_size=2,
        frequency_summary="Test frequency summary",
        observed_headers={},
    )
    store.save(AnalysisResult(profile=sample_profile, probes=[]))

    # Retrieve history
    resp = client.get("/api/history")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert any(i["job_id"] == "testjob1" for i in items)

    # Export
    resp = client.get("/api/export/testjob1")
    assert resp.status_code == 200
    assert resp.json()["job_id"] == "testjob1"

    # Client code generation
    resp = client.get("/api/generate-client/testjob1")
    assert resp.status_code == 200
    assert "RateControlledClient" in resp.text
    assert "interval_sec=0.5" in resp.text

    # Delete
    del_resp = client.delete("/api/history/testjob1")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True
