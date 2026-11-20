from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from app.models import (
    AnalysisResult,
    BaselineStats,
    CooldownStats,
    PatternClassification,
    RateLimitProfile,
    RateRecommendations,
    RequestCounters,
)
from app.storage import HistoryStore


def make_sample_result(job_id: str = "test1") -> AnalysisResult:
    profile = RateLimitProfile(
        job_id=job_id,
        created_at="2026-11-20T12:00:00Z",
        target_url="https://example.com/api",
        method="GET",
        baseline_stats=BaselineStats(requests_sent=3, successful_count=3, avg_latency_ms=45.0),
        request_counters=RequestCounters(total_sent=15, accepted=12, confirmed_rate_limited=3),
        pattern_classification=PatternClassification(
            detected_pattern="fixed_window",
            confidence="high",
            confidence_score=0.85,
            explanation="Test explanation",
        ),
        rate_recommendations=RateRecommendations(
            recommended_rps=2.0,
            recommended_interval_sec=0.5,
            recommended_rpm=120.0,
        ),
        cooldown_stats=CooldownStats(observed_cooldown_sec=5.0, recovery_verified=True),
        safe_burst_size=3,
        frequency_summary="Sample frequency summary",
        observed_headers={"Authorization": "Bearer secret-token"},
    )
    return AnalysisResult(profile=profile, probes=[])


def test_storage_lifecycle_and_sanitization():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test_history.db"
        store = HistoryStore(db_path=db_path)

        res = make_sample_result("job123")
        store.save(res)

        # Retrieve
        loaded = store.get("job123")
        assert loaded is not None
        assert loaded.profile.job_id == "job123"
        assert loaded.profile.safe_burst_size == 3
        # Sensitive headers must be masked in stored DB
        assert loaded.profile.observed_headers.get("Authorization") == "******"

        # List
        items = store.list_recent(10)
        assert len(items) == 1
        assert items[0]["job_id"] == "job123"

        # Stats
        stats = store.get_dashboard_stats()
        assert stats["total_analyses"] == 1
        assert stats["total_requests_tested"] == 15
        assert stats["total_blocked_requests"] == 3

        # Delete
        assert store.delete("job123") is True
        assert store.get("job123") is None
        assert store.get_dashboard_stats()["total_analyses"] == 0
