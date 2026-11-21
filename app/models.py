from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class AnalyzeRequest(BaseModel):
    url: HttpUrl
    method: Literal["GET", "HEAD"] = "GET"
    request_budget: int = Field(default=15, ge=1, description="Max total requests to send during probing")
    probe_interval_sec: float = Field(default=0.3, ge=0.001, description="Baseline delay between requests in seconds")
    burst_size: int = Field(default=3, ge=1, description="Initial burst grouping size")
    max_analysis_duration_sec: Optional[float] = Field(default=None, ge=0.1, description="Hard cap on analysis runtime")
    timeout_sec: float = Field(default=10.0, ge=0.1)
    check_cooldown: bool = True
    verify_safe_pace: bool = True
    check_robots: bool = True
    custom_headers: Dict[str, str] = Field(default_factory=dict)

    # Backwards compatibility: allow max_requests as alias for request_budget
    @field_validator("request_budget", mode="before")
    @classmethod
    def handle_legacy_alias(cls, v: Any, info: Any) -> Any:
        return v

    def __init__(self, **data: Any):
        if "max_requests" in data and "request_budget" not in data:
            data["request_budget"] = data.pop("max_requests")
        super().__init__(**data)

    @property
    def max_requests(self) -> int:
        return self.request_budget


class BaselineStats(BaseModel):
    requests_sent: int = 0
    successful_count: int = 0
    error_count: int = 0
    avg_latency_ms: Optional[float] = None
    median_latency_ms: Optional[float] = None
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    success_rate_pct: float = 0.0
    is_healthy: bool = True
    health_warning: Optional[str] = None


class RequestCounters(BaseModel):
    configured_budget: int = 0
    dispatched_requests: int = 0
    completed_requests: int = 0
    successful_requests: int = 0
    rate_limited_requests: int = 0
    timed_out_requests: int = 0
    network_errors: int = 0
    remaining_budget: int = 0
    in_progress_requests: int = 0
    # Backward compatibility aliases
    total_sent: int = 0
    accepted: int = 0
    confirmed_rate_limited: int = 0  # HTTP 429 or 403 with confirmed rate-limit headers/body
    suspected_throttled: int = 0    # Latency spike > 2.5x baseline
    http_errors: int = 0            # Ordinary 4xx/5xx (e.g. 404, 500)
    network_failures: int = 0       # Connection/DNS/TLS errors
    timeouts: int = 0


class ProbeEvent(BaseModel):
    request_num: int
    phase: Literal["baseline", "probe", "burst", "cooldown", "verify"]
    timestamp: float
    elapsed_sec: float
    status_code: Optional[int] = None
    latency_ms: float
    accepted: bool
    blocked: bool
    throttled: bool = False
    confirmed_rate_limit: bool = False
    error_type: Optional[str] = None  # None, "http_429", "http_403_rate_limit", "http_403_ambiguous", "http_503_unavail", "http_error", "network_error", "dns_error", "timeout"
    block_reason: Optional[str] = None
    retry_after_sec: Optional[float] = None
    dispatch_timestamp: Optional[float] = None
    scheduled_interval_ms: Optional[float] = None
    actual_interval_ms: Optional[float] = None
    rate_limit_limit: Optional[int] = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[float] = None
    ratelimit_headers: Dict[str, str] = Field(default_factory=dict)


class PatternClassification(BaseModel):
    detected_pattern: str  # fixed_window, sliding_window, token_bucket, leaky_bucket, header_guided, immediate_access_block, no_limit_observed, unknown_or_hybrid
    confidence: Literal["high", "medium", "low", "insufficient"]
    confidence_score: float = Field(ge=0.0, le=1.0)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradictory_evidence: List[str] = Field(default_factory=list)
    observation_type: str = "empirical_observations"  # direct_headers, empirical_observations, inferred_with_uncertainty
    limitations: List[str] = Field(default_factory=list)
    explanation: str


class RateRecommendations(BaseModel):
    max_observed_rps: float = 0.0
    estimated_sustainable_rps: float = 0.0
    recommended_rps: float = 0.0
    recommended_interval_sec: float = 1.0
    recommended_interval_ms: float = 1000.0
    recommended_rpm: float = 60.0
    safety_margin_pct: float = 25.0
    verified_rps: Optional[float] = None
    verified_interval_sec: Optional[float] = None
    verification_passed: Optional[bool] = None
    verification_rounds: int = 0
    verification_sample_size: int = 0
    verification_summary: Optional[str] = None
    is_provisional: bool = False


class CooldownStats(BaseModel):
    first_block_req: Optional[int] = None
    first_block_sec: Optional[float] = None
    first_recovery_sec: Optional[float] = None
    observed_cooldown_sec: Optional[float] = None
    server_retry_after_sec: Optional[float] = None
    recovery_verified: bool = False
    verification_attempts: int = 0


class RateLimitProfile(BaseModel):
    schema_version: str = "2.0.0"
    job_id: str
    created_at: str
    target_url: str
    method: str
    status: Literal["completed", "partial", "cancelled", "failed"] = "completed"
    completion_message: str = "Analysis completed successfully."
    configured_budget: int = 0
    dispatched_requests: int = 0
    execution_deadline_sec: float = 60.0
    actual_duration_sec: float = 0.0
    robots_crawl_delay_sec: Optional[float] = None
    baseline_stats: BaselineStats
    request_counters: RequestCounters
    pattern_classification: PatternClassification
    rate_recommendations: RateRecommendations
    cooldown_stats: CooldownStats
    safe_burst_size: int
    frequency_summary: str
    observed_headers: Dict[str, str] = Field(default_factory=dict)
    known_limitations: List[str] = Field(default_factory=list)

    # Convenience properties for backward compatibility with existing tests and UI
    @property
    def detected_pattern(self) -> str:
        return self.pattern_classification.detected_pattern

    @property
    def pattern_confidence(self) -> str:
        return self.pattern_classification.confidence

    @property
    def pattern_explanation(self) -> str:
        return self.pattern_classification.explanation

    @property
    def recommended_interval_sec(self) -> float:
        return self.rate_recommendations.recommended_interval_sec

    @property
    def recommended_rps(self) -> float:
        return self.rate_recommendations.recommended_rps

    @property
    def recommended_rpm(self) -> float:
        return self.rate_recommendations.recommended_rpm

    @property
    def verification_passed(self) -> Optional[bool]:
        return self.rate_recommendations.verification_passed

    @property
    def verification_note(self) -> Optional[str]:
        return self.rate_recommendations.verification_summary

    @property
    def estimated_cooldown_sec(self) -> Optional[float]:
        return self.cooldown_stats.observed_cooldown_sec or self.cooldown_stats.server_retry_after_sec

    @property
    def first_block_at_request(self) -> Optional[int]:
        return self.cooldown_stats.first_block_req

    @property
    def first_block_at_sec(self) -> Optional[float]:
        return self.cooldown_stats.first_block_sec

    @property
    def total_requests(self) -> int:
        return self.request_counters.total_sent

    @property
    def burst_requests_sent(self) -> int:
        return self.request_counters.total_sent

    @property
    def blocked_requests(self) -> int:
        return self.request_counters.confirmed_rate_limited

    @property
    def block_rate_pct(self) -> float:
        if self.request_counters.total_sent == 0:
            return 0.0
        return round((self.request_counters.confirmed_rate_limited / self.request_counters.total_sent) * 100, 2)

    @property
    def baseline_latency_ms(self) -> Optional[float]:
        return self.baseline_stats.median_latency_ms or self.baseline_stats.avg_latency_ms

    @property
    def p95_latency_ms(self) -> Optional[float]:
        return self.baseline_stats.max_latency_ms

    @property
    def test_duration_sec(self) -> float:
        return self.cooldown_stats.first_recovery_sec or 0.0

    @property
    def estimated_window_sec(self) -> Optional[float]:
        return self.cooldown_stats.observed_cooldown_sec


class AnalysisResult(BaseModel):
    profile: RateLimitProfile
    probes: List[ProbeEvent]


class JobStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    current_phase: str = "init"
    progress_pct: int = 0
    probes_count: int = 0
    configured_budget: int = 0
    dispatched_requests: int = 0
    completed_requests: int = 0
    in_progress_requests: int = 0
    remaining_budget: int = 0
    elapsed_sec: float = 0.0
    estimated_remaining_sec: Optional[float] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None


class ExecutionRequest(BaseModel):
    job_id: str
    request_budget: int = Field(default=50, ge=1, description="Number of subsequent requests to execute")
    custom_headers: Dict[str, str] = Field(default_factory=dict)


class ExecutionRecord(BaseModel):
    request_number: int
    timestamp: str
    scheduled_interval_ms: float
    actual_interval_ms: float
    status_code: Optional[int] = None
    latency_ms: float
    accepted: bool
    rate_limited: bool
    retry_after: Optional[float] = None
    rate_limit_limit: Optional[int] = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[float] = None
    error_type: Optional[str] = None


class ExecutionStatus(BaseModel):
    execution_id: str
    job_id: str
    target_url: str
    status: Literal["running", "paused", "cooldown", "completed", "stopped", "failed"]
    request_budget: int
    completed_requests: int = 0
    accepted_requests: int = 0
    rate_limited_requests: int = 0
    other_errors: int = 0
    avg_latency_ms: float = 0.0
    current_interval_ms: float = 500.0
    next_request_in_sec: Optional[float] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
