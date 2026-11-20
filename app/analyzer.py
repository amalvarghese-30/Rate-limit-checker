from __future__ import annotations

import asyncio
import email.utils
import math
import re
import socket
import statistics
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from app.config import ALLOW_LOCAL_TARGETS, DEFAULT_TIMEOUT_SEC, MAX_ANALYSIS_DURATION_SEC, MAX_RESPONSE_BODY_BYTES
from app.models import (
    AnalyzeRequest,
    AnalysisResult,
    BaselineStats,
    CooldownStats,
    PatternClassification,
    ProbeEvent,
    RateLimitProfile,
    RateRecommendations,
    RequestCounters,
)
from app.security import mask_sensitive_headers, sanitize_custom_headers, validate_target_url

BLOCK_STATUS_CODES = {429, 403, 503}

RATE_LIMIT_BODY_KEYWORDS = (
    "rate limit",
    "rate-limit",
    "ratelimit",
    "too many requests",
    "quota exceeded",
    "request threshold",
    "temporarily blocked",
    "retry after",
)

WAF_SIGNATURES = (
    "cf-ray",
    "cloudflare",
    "attention required",
    "bot detected",
    "akamai",
    "incapsula",
    "datadome",
    "perimeterx",
    "challenge required",
)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def parse_retry_after(raw: Optional[str]) -> Optional[float]:
    """
    Parses Retry-After header supporting both delta-seconds and RFC 2822 / RFC 7231 HTTP-dates.
    Returns delta seconds as float or None if invalid.
    """
    if not raw:
        return None
    raw = raw.strip()
    try:
        val = float(raw)
        return max(0.0, round(val, 2))
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, round(delta, 2))
    except Exception:
        return None


def parse_ratelimit_reset(headers: Dict[str, str]) -> Optional[float]:
    """
    Parses reset headers (ratelimit-reset, x-ratelimit-reset), supporting both
    delta-seconds and epoch unix timestamps.
    """
    for key in ("ratelimit-reset", "x-ratelimit-reset", "x-rate-limit-reset"):
        for hk, hv in headers.items():
            if hk.lower() == key:
                try:
                    num = float(hv.strip())
                    if num > 1_000_000_000:
                        now_ts = time.time()
                        return max(0.0, round(num - now_ts, 2))
                    return max(0.0, round(num, 2))
                except ValueError:
                    continue
    return None


def parse_ratelimit_limit(headers: Dict[str, str]) -> Optional[int]:
    for key in ("ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"):
        for hk, hv in headers.items():
            if hk.lower() == key:
                match = re.search(r"\d+", hv)
                if match:
                    return int(match.group(0))
    return None


def extract_interesting_headers(resp_headers: httpx.Headers) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for k, v in resp_headers.items():
        kl = k.lower()
        if any(
            token in kl
            for token in (
                "ratelimit",
                "rate-limit",
                "retry-after",
                "x-rate",
                "cf-ray",
                "x-cache",
                "server",
            )
        ):
            result[k] = v
    return result


def classify_response(
    status_code: Optional[int],
    headers: Dict[str, str],
    body_sample: str,
    error: Optional[Exception] = None,
) -> Tuple[bool, bool, Optional[str], Optional[str]]:
    """
    Classifies a response into:
      (accepted, confirmed_rate_limit, error_type, block_reason)
    """
    if error is not None:
        if isinstance(error, httpx.TimeoutException):
            return False, False, "timeout", f"Request timed out: {type(error).__name__}"
        if isinstance(error, (socket.gaierror, httpx.ConnectError)):
            return False, False, "dns_error", f"Network/DNS connection failure: {type(error).__name__}"
        return False, False, "network_error", f"Network error: {type(error).__name__}"

    if status_code is None:
        return False, False, "network_error", "No response received"

    # HTTP 429: Direct, confirmed rate limit signal
    if status_code == 429:
        reason = "HTTP 429 Too Many Requests"
        retry_val = headers.get("retry-after")
        if retry_val:
            reason += f" (Retry-After: {retry_val})"
        return False, True, "http_429", reason

    # HTTP 403: Must check for supporting evidence
    if status_code == 403:
        has_rl_header = any("ratelimit" in k.lower() or "retry-after" in k.lower() for k in headers)
        body_lower = body_sample.lower()
        header_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        has_rl_body = any(kw in body_lower for kw in RATE_LIMIT_BODY_KEYWORDS)
        matched_waf = next((sig for sig in WAF_SIGNATURES if sig in body_lower or sig in header_str), None)

        if has_rl_header or has_rl_body:
            return False, True, "http_403_rate_limit", "HTTP 403 Forbidden with explicit rate-limit message/headers"
        if matched_waf:
            return False, True, "http_403_rate_limit", f"HTTP 403 WAF/Access Challenge ({matched_waf})"
        return False, False, "http_403_ambiguous", "HTTP 403 Forbidden (ambiguous access restriction, no rate-limit evidence)"

    # HTTP 503: Must check for supporting evidence
    if status_code == 503:
        has_rl_header = any("retry-after" in k.lower() or "ratelimit" in k.lower() for k in headers)
        body_lower = body_sample.lower()
        has_rl_body = any(kw in body_lower for kw in RATE_LIMIT_BODY_KEYWORDS)
        if has_rl_header or has_rl_body:
            return False, True, "http_503_unavail", "HTTP 503 Service Unavailable with Retry-After / throttling indicators"
        return False, False, "http_503_unavail", "HTTP 503 Service Unavailable (temporary server outage or maintenance)"

    # Other 4xx / 5xx
    if status_code >= 400:
        return False, False, "http_error", f"HTTP {status_code}"

    # 2xx / 3xx
    return True, False, None, None


class RateLimitAnalyzer:
    """
    Evidence-based multi-phase rate-limit discovery and verification engine:
      Phase 1: Baseline health & latency measurement
      Phase 2: Controlled, progressive threshold probing
      Phase 3: Rate-limit pattern classification (Fixed/Sliding Window, Token/Leaky Bucket, Header-Guided)
      Phase 4: Cooldown & recovery verification (honoring Retry-After)
      Phase 5: Conservative safe pacing calculation & bounded verification
    """

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None, allow_local: Optional[bool] = None):
        self.transport = transport
        self.allow_local = ALLOW_LOCAL_TARGETS if allow_local is None else allow_local

    async def _fetch_robots_crawl_delay(self, client: httpx.AsyncClient, url: str) -> Optional[float]:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            resp = await client.get(robots_url, headers=DEFAULT_HEADERS, follow_redirects=True)
            if resp.status_code != 200:
                return None
            applies = False
            for line in resp.text.splitlines():
                clean = line.split("#", 1)[0].strip()
                if not clean or ":" not in clean:
                    continue
                field, val = [x.strip() for x in clean.split(":", 1)]
                fl = field.lower()
                if fl == "user-agent":
                    applies = val == "*"
                elif fl == "crawl-delay" and applies:
                    try:
                        return float(val)
                    except ValueError:
                        return None
        except Exception:
            return None
        return None

    async def _send_single_probe(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: Dict[str, str],
        req_num: int,
        phase: str,
        test_start: float,
        baseline_latency_ms: Optional[float] = None,
    ) -> ProbeEvent:
        start_mono = time.monotonic()
        ts = time.time()

        try:
            resp = await client.request(
                method,
                url,
                headers=headers,
                follow_redirects=True,
            )
            elapsed_sec = round(time.monotonic() - test_start, 2)
            latency_ms = round((time.monotonic() - start_mono) * 1000, 2)
            raw_headers = dict(resp.headers)
            body_sample = ""
            try:
                body_sample = resp.text[:1500]
            except Exception:
                pass

            accepted, confirmed_rl, err_type, reason = classify_response(
                resp.status_code, raw_headers, body_sample
            )

            throttled = (
                accepted
                and baseline_latency_ms is not None
                and baseline_latency_ms > 0
                and latency_ms >= max(baseline_latency_ms * 2.5, baseline_latency_ms + 400)
            )

            return ProbeEvent(
                request_num=req_num,
                phase=phase,  # type: ignore[arg-type]
                timestamp=ts,
                elapsed_sec=elapsed_sec,
                status_code=resp.status_code,
                latency_ms=latency_ms,
                accepted=accepted,
                blocked=not accepted,
                throttled=throttled,
                confirmed_rate_limit=confirmed_rl,
                error_type=err_type,
                block_reason=reason,
                retry_after_sec=parse_retry_after(resp.headers.get("retry-after")),
                ratelimit_headers=extract_interesting_headers(resp.headers),
            )
        except Exception as exc:
            elapsed_sec = round(time.monotonic() - test_start, 2)
            latency_ms = round((time.monotonic() - start_mono) * 1000, 2)
            accepted, confirmed_rl, err_type, reason = classify_response(None, {}, "", error=exc)

            return ProbeEvent(
                request_num=req_num,
                phase=phase,  # type: ignore[arg-type]
                timestamp=ts,
                elapsed_sec=elapsed_sec,
                status_code=None,
                latency_ms=latency_ms,
                accepted=False,
                blocked=True,
                throttled=False,
                confirmed_rate_limit=False,
                error_type=err_type,
                block_reason=reason,
                retry_after_sec=None,
                ratelimit_headers={},
            )

    async def run(
        self,
        req: AnalyzeRequest,
        on_event: Optional[Callable[[dict], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> AnalysisResult:
        def emit(payload: dict) -> None:
            if on_event:
                on_event(payload)

        # 1. SSRF and URL validation
        target_url = str(req.url)
        is_valid_url, url_err = validate_target_url(target_url, allow_local=self.allow_local)
        if not is_valid_url:
            raise ValueError(f"Security validation rejected target URL: {url_err}")

        # 2. Header sanitization
        sanitized_custom, rejected_headers = sanitize_custom_headers(req.custom_headers)
        if rejected_headers:
            emit({
                "type": "warning",
                "message": f"Stripped prohibited hop-by-hop headers: {', '.join(rejected_headers)}",
            })

        headers = {**DEFAULT_HEADERS, **sanitized_custom}
        job_id = uuid.uuid4().hex[:10]
        created_at = datetime.now(timezone.utc).isoformat()
        test_start = time.monotonic()
        probes: List[ProbeEvent] = []
        observed_headers: Dict[str, str] = {}
        req_counter = 0

        counters = RequestCounters()
        client_kwargs = {
            "timeout": req.timeout_sec,
            "limits": httpx.Limits(max_keepalive_connections=5, max_connections=10),
        }
        if self.transport is not None:
            client_kwargs["transport"] = self.transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            # Check robots.txt Crawl-delay
            robots_delay: Optional[float] = None
            if req.check_robots:
                emit({"type": "status", "phase": "baseline", "message": "Phase 0: Checking robots.txt for crawl guidelines..."})
                robots_delay = await self._fetch_robots_crawl_delay(client, target_url)
                if robots_delay:
                    emit({"type": "info", "message": f"Found robots.txt Crawl-delay: {robots_delay}s"})

            # PHASE 1: Baseline Measurement (3 baseline requests)
            emit({"type": "status", "phase": "baseline", "message": "Phase 1: Establishing baseline latency and target health (3 probes)..."})
            baseline_probes: List[ProbeEvent] = []
            for b_idx in range(3):
                if is_cancelled and is_cancelled():
                    break
                req_counter += 1
                b_ev = await self._send_single_probe(
                    client, target_url, req.method, headers, req_counter, "baseline", test_start
                )
                probes.append(b_ev)
                baseline_probes.append(b_ev)
                observed_headers.update(b_ev.ratelimit_headers)
                self._update_counters(counters, b_ev)
                emit({"type": "probe", "probe": b_ev.model_dump()})
                if b_idx < 2:
                    await asyncio.sleep(0.2)

            baseline_stats = self._calculate_baseline(baseline_probes)
            if not baseline_stats.is_healthy:
                emit({
                    "type": "warning",
                    "message": f"Target health warning: {baseline_stats.health_warning}. Rate-limit analysis may be unreliable.",
                })

            baseline_latency_ms = baseline_stats.median_latency_ms or baseline_stats.avg_latency_ms

            # PHASE 2: Controlled Threshold Discovery
            first_block_idx: Optional[int] = None
            first_block_sec: Optional[float] = None
            first_block_mono: Optional[float] = None
            consecutive_blocks = 0
            burst_probes: List[ProbeEvent] = list(baseline_probes)

            # Check if baseline was blocked already
            for p in baseline_probes:
                if p.confirmed_rate_limit or p.blocked:
                    if first_block_idx is None:
                        first_block_idx = p.request_num
                        first_block_sec = p.elapsed_sec
                        first_block_mono = time.monotonic()
                        consecutive_blocks += 1

            remaining_budget = max(0, req.request_budget - len(baseline_probes))
            if baseline_stats.is_healthy and remaining_budget > 0 and consecutive_blocks == 0:
                emit({
                    "type": "status",
                    "phase": "probe",
                    "message": f"Phase 2: Controlled threshold discovery ({remaining_budget} probes budgeted)...",
                })

                for _ in range(remaining_budget):
                    if is_cancelled and is_cancelled():
                        break
                    # Enforce max analysis duration safety
                    if (time.monotonic() - test_start) >= req.max_analysis_duration_sec:
                        emit({"type": "warning", "message": "Maximum analysis duration reached. Stopping probes."})
                        break

                    await asyncio.sleep(req.probe_interval_sec)
                    req_counter += 1
                    ev = await self._send_single_probe(
                        client,
                        target_url,
                        req.method,
                        headers,
                        req_counter,
                        "probe",
                        test_start,
                        baseline_latency_ms=baseline_latency_ms,
                    )
                    probes.append(ev)
                    burst_probes.append(ev)
                    observed_headers.update(ev.ratelimit_headers)
                    self._update_counters(counters, ev)
                    emit({"type": "probe", "probe": ev.model_dump()})

                    if ev.confirmed_rate_limit or ev.blocked:
                        consecutive_blocks += 1
                        if first_block_idx is None:
                            first_block_idx = ev.request_num
                            first_block_sec = ev.elapsed_sec
                            first_block_mono = time.monotonic()
                        if consecutive_blocks >= 3:
                            emit({"type": "info", "message": f"Sustained rate limit wall ({consecutive_blocks} consecutive blocks). Stopping probe burst."})
                            break
                    else:
                        consecutive_blocks = 0

            # PHASE 4: Cooldown & Recovery Detection
            cooldown_stats = CooldownStats(
                first_block_req=first_block_idx,
                first_block_sec=first_block_sec,
            )

            retry_hints = [p.retry_after_sec for p in burst_probes if p.retry_after_sec is not None]
            server_retry = max(retry_hints) if retry_hints else None
            reset_hint = parse_ratelimit_reset(observed_headers)
            cooldown_stats.server_retry_after_sec = server_retry

            if req.check_cooldown and first_block_idx is not None:
                emit({"type": "status", "phase": "cooldown", "message": "Phase 3: Measuring cooldown & recovery timing..."})
                planned_wait = server_retry or reset_hint

                if planned_wait is not None and planned_wait > 0:
                    cooldown_stats.observed_cooldown_sec = planned_wait
                    # Check if waiting exceeds duration budget
                    remaining_time = req.max_analysis_duration_sec - (time.monotonic() - test_start)
                    if planned_wait > remaining_time:
                        emit({
                            "type": "warning",
                            "message": f"Server Retry-After ({planned_wait}s) exceeds remaining duration budget ({round(remaining_time, 1)}s). Recovery verification skipped.",
                        })
                    else:
                        emit({"type": "info", "message": f"Respecting server requested cooldown: waiting {planned_wait}s before recovery probe..."})
                        await asyncio.sleep(planned_wait)
                        req_counter += 1
                        cooldown_stats.verification_attempts += 1
                        rec_ev = await self._send_single_probe(
                            client, target_url, req.method, headers, req_counter, "cooldown", test_start, baseline_latency_ms
                        )
                        probes.append(rec_ev)
                        observed_headers.update(rec_ev.ratelimit_headers)
                        self._update_counters(counters, rec_ev)
                        emit({"type": "probe", "probe": rec_ev.model_dump()})

                        if rec_ev.accepted:
                            cooldown_stats.recovery_verified = True
                            cooldown_stats.first_recovery_sec = rec_ev.elapsed_sec
                            if first_block_mono:
                                cooldown_stats.observed_cooldown_sec = round(time.monotonic() - first_block_mono, 2)
                            emit({"type": "info", "message": f"Target accepted recovery probe after {cooldown_stats.observed_cooldown_sec}s."})
                        else:
                            emit({"type": "warning", "message": "Target still throttled after server Retry-After period."})
                else:
                    # Empirical stepped backoff recovery probes (bounded)
                    for wait_step in (1.5, 3.0, 5.0):
                        if (time.monotonic() - test_start) + wait_step > req.max_analysis_duration_sec:
                            break
                        await asyncio.sleep(wait_step)
                        req_counter += 1
                        cooldown_stats.verification_attempts += 1
                        rec_ev = await self._send_single_probe(
                            client, target_url, req.method, headers, req_counter, "cooldown", test_start, baseline_latency_ms
                        )
                        probes.append(rec_ev)
                        observed_headers.update(rec_ev.ratelimit_headers)
                        self._update_counters(counters, rec_ev)
                        emit({"type": "probe", "probe": rec_ev.model_dump()})

                        if rec_ev.accepted:
                            cooldown_stats.recovery_verified = True
                            cooldown_stats.first_recovery_sec = rec_ev.elapsed_sec
                            if first_block_mono:
                                cooldown_stats.observed_cooldown_sec = round(time.monotonic() - first_block_mono, 2)
                            emit({"type": "info", "message": f"Target recovered cleanly after empirical wait of ~{cooldown_stats.observed_cooldown_sec}s."})
                            break

            # PHASE 3: Rate-Limit Pattern Detection
            classification, rec_rates, safe_burst = self._classify_pattern(
                burst_probes=burst_probes,
                probe_interval=req.probe_interval_sec,
                first_block_idx=first_block_idx,
                cooldown_stats=cooldown_stats,
                observed_headers=observed_headers,
                robots_delay=robots_delay,
                baseline_stats=baseline_stats,
            )

            # PHASE 5: Bounded Safe Frequency Verification
            if req.verify_safe_pace and classification.detected_pattern != "immediate_access_block" and rec_rates.recommended_interval_sec <= 5.0:
                emit({
                    "type": "status",
                    "phase": "verify",
                    "message": f"Phase 4: Verifying recommended pacing (sampling at {rec_rates.recommended_interval_sec:.2f}s spacing)...",
                })
                v_rounds = 0
                v_sample_size = min(4, max(2, req.request_budget // 5))
                v_success = 0
                v_failed = 0
                current_v_interval = rec_rates.recommended_interval_sec

                while v_rounds < 2 and (time.monotonic() - test_start) < req.max_analysis_duration_sec:
                    v_rounds += 1
                    round_blocks = 0
                    for _ in range(v_sample_size):
                        if (time.monotonic() - test_start) >= req.max_analysis_duration_sec:
                            break
                        await asyncio.sleep(current_v_interval)
                        req_counter += 1
                        v_ev = await self._send_single_probe(
                            client, target_url, req.method, headers, req_counter, "verify", test_start, baseline_latency_ms
                        )
                        probes.append(v_ev)
                        observed_headers.update(v_ev.ratelimit_headers)
                        self._update_counters(counters, v_ev)
                        emit({"type": "probe", "probe": v_ev.model_dump()})
                        if v_ev.accepted:
                            v_success += 1
                        else:
                            v_failed += 1
                            round_blocks += 1

                    if round_blocks == 0:
                        rec_rates.verification_passed = True
                        rec_rates.verified_interval_sec = current_v_interval
                        rec_rates.verified_rps = round(1.0 / current_v_interval, 2)
                        rec_rates.verification_summary = f"{v_success}/{v_success} verification requests succeeded at {current_v_interval:.2f}s spacing."
                        break
                    else:
                        # Widen interval and retry once if budget allows
                        current_v_interval = round(current_v_interval * 1.5, 2)
                        safe_burst = max(1, safe_burst // 2)
                        rec_rates.verification_passed = False
                        rec_rates.verification_summary = f"{round_blocks}/{v_sample_size} verification probes encountered resistance; widened interval to {current_v_interval:.2f}s."
                        if v_rounds < 2 and v_ev.retry_after_sec:
                            wait_s = min(v_ev.retry_after_sec, 5.0)
                            await asyncio.sleep(wait_s)

                rec_rates.verification_rounds = v_rounds
                rec_rates.verification_sample_size = v_success + v_failed
                rec_rates.recommended_interval_sec = current_v_interval
                rec_rates.recommended_interval_ms = round(current_v_interval * 1000.0, 1)
                rec_rates.recommended_rps = round(1.0 / current_v_interval, 2)
                rec_rates.recommended_rpm = round(60.0 / current_v_interval, 1)

        # Generate summary
        if classification.detected_pattern == "immediate_access_block":
            freq_summary = (
                "Blocked on the baseline request. Do not send automated requests without resolving "
                "WAF challenges, IP restrictions, or missing authorization credentials."
            )
        elif safe_burst > 1:
            freq_summary = (
                f"Send up to {safe_burst} requests concurrently (burst), then pace subsequent requests at "
                f"1 request every {rec_rates.recommended_interval_sec:.2f}s (~{rec_rates.recommended_rpm:.0f} req/min) with ±15% jitter."
            )
        else:
            freq_summary = (
                f"Avoid bursts. Send 1 request at a time, spaced {rec_rates.recommended_interval_sec:.2f}s apart "
                f"(~{rec_rates.recommended_rpm:.0f} req/min) with ±15% jitter."
            )

        profile = RateLimitProfile(
            schema_version="2.0.0",
            job_id=job_id,
            created_at=created_at,
            target_url=target_url,
            method=req.method,
            robots_crawl_delay_sec=robots_delay,
            baseline_stats=baseline_stats,
            request_counters=counters,
            pattern_classification=classification,
            rate_recommendations=rec_rates,
            cooldown_stats=cooldown_stats,
            safe_burst_size=safe_burst,
            frequency_summary=freq_summary,
            observed_headers=mask_sensitive_headers(observed_headers),
            known_limitations=classification.limitations,
        )

        result = AnalysisResult(profile=profile, probes=probes)
        emit({"type": "complete", "result": result.model_dump()})
        return result

    def _update_counters(self, counters: RequestCounters, ev: ProbeEvent) -> None:
        counters.total_sent += 1
        if ev.accepted:
            counters.accepted += 1
            if ev.throttled:
                counters.suspected_throttled += 1
        else:
            if ev.confirmed_rate_limit:
                counters.confirmed_rate_limited += 1
            elif ev.error_type == "timeout":
                counters.timeouts += 1
            elif ev.error_type in ("dns_error", "network_error"):
                counters.network_failures += 1
            elif ev.error_type in ("http_403_ambiguous", "http_503_unavail", "http_error"):
                counters.http_errors += 1
            else:
                counters.http_errors += 1

    def _calculate_baseline(self, probes: List[ProbeEvent]) -> BaselineStats:
        if not probes:
            return BaselineStats(is_healthy=False, health_warning="No baseline requests completed")

        latencies = [p.latency_ms for p in probes if p.status_code is not None]
        successes = sum(1 for p in probes if p.accepted)
        errors = len(probes) - successes
        rate = round((successes / len(probes)) * 100, 1)

        avg_lat = round(statistics.mean(latencies), 2) if latencies else None
        med_lat = round(statistics.median(latencies), 2) if latencies else None
        min_lat = round(min(latencies), 2) if latencies else None
        max_lat = round(max(latencies), 2) if latencies else None

        is_healthy = successes >= 2
        warning = None
        if not is_healthy:
            reasons = [p.block_reason for p in probes if p.block_reason]
            warning = f"Baseline failure rate is high ({errors}/{len(probes)} failed). Issues: {', '.join(set(filter(None, reasons)))}"

        return BaselineStats(
            requests_sent=len(probes),
            successful_count=successes,
            error_count=errors,
            avg_latency_ms=avg_lat,
            median_latency_ms=med_lat,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            success_rate_pct=rate,
            is_healthy=is_healthy,
            health_warning=warning,
        )

    def _classify_pattern(
        self,
        burst_probes: List[ProbeEvent],
        probe_interval: float,
        first_block_idx: Optional[int],
        cooldown_stats: CooldownStats,
        observed_headers: Dict[str, str],
        robots_delay: Optional[float],
        baseline_stats: BaselineStats,
    ) -> Tuple[PatternClassification, RateRecommendations, int]:
        total = len(burst_probes)
        confirmed_rl = [p for p in burst_probes if p.confirmed_rate_limit]
        throttled = [p for p in burst_probes if p.throttled]
        header_limit = parse_ratelimit_limit(observed_headers)
        header_reset = parse_ratelimit_reset(observed_headers)

        supporting: List[str] = []
        contradictory: List[str] = []
        limitations: List[str] = [
            "Rate limits can vary dynamically based on client IP, authenticated credentials, geographic region, and server load.",
            "Inferred thresholds reflect empirical observations within the test budget, not server-side implementation guarantees.",
        ]

        # Case 1: Blocked immediately on request #1
        if first_block_idx == 1:
            supporting.append("Target rejected request #1 unconditionally.")
            if any(sig in str(observed_headers).lower() for sig in WAF_SIGNATURES):
                supporting.append("WAF / security filtering signature found in headers/body.")
            return (
                PatternClassification(
                    detected_pattern="immediate_access_block",
                    confidence="high",
                    confidence_score=0.95,
                    supporting_evidence=supporting,
                    contradictory_evidence=[],
                    observation_type="direct_headers",
                    limitations=limitations,
                    explanation="Blocked on request #1. Indicates WAF filtering, IP ban, or missing authentication rather than an ongoing rate counter.",
                ),
                RateRecommendations(
                    max_observed_rps=0.0,
                    estimated_sustainable_rps=0.0,
                    recommended_rps=0.1,
                    recommended_interval_sec=10.0,
                    recommended_interval_ms=10000.0,
                    recommended_rpm=6.0,
                    safety_margin_pct=50.0,
                ),
                0,
            )

        # Case 2: No confirmed blocks encountered
        if not confirmed_rl:
            # Latency Throttling (Leaky Bucket / Progressive Spiking)
            if len(throttled) >= max(2, int(total * 0.25)):
                supporting.append(f"{len(throttled)}/{total} requests exhibited >2.5x baseline latency increases.")
                supporting.append("No explicit HTTP 429 received, but server enforced progressive delay queuing.")
                safe_int = max(probe_interval * 2.5, robots_delay or 0.0, 0.75)
                burst = max(1, min(3, total // 4))
                return (
                    PatternClassification(
                        detected_pattern="leaky_bucket",
                        confidence="medium",
                        confidence_score=0.70,
                        supporting_evidence=supporting,
                        contradictory_evidence=["Server did not emit explicit 429 status codes."],
                        observation_type="empirical_observations",
                        limitations=limitations,
                        explanation=f"No hard blocks were returned, but {len(throttled)} requests experienced heavy latency queuing under burst.",
                    ),
                    self._make_recommendations(safe_int, max_obs=1.0 / max(0.05, probe_interval)),
                    burst,
                )

            # Header-Guided Rate Limiting (headers present, no blocks triggered)
            if header_limit and header_reset and header_reset > 0:
                supporting.append(f"Server advertised RateLimit-Limit: {header_limit} and Reset: ~{header_reset}s.")
                safe_int = max((header_reset / max(header_limit, 1)) * 1.3, robots_delay or 0.0, 0.25)
                burst = max(1, int(header_limit * 0.75))
                return (
                    PatternClassification(
                        detected_pattern="header_guided",
                        confidence="high",
                        confidence_score=0.90,
                        supporting_evidence=supporting,
                        contradictory_evidence=[],
                        observation_type="direct_headers",
                        limitations=limitations,
                        explanation=f"Probes remained below the server's advertised ceiling of {header_limit} requests per ~{header_reset}s.",
                    ),
                    self._make_recommendations(safe_int, max_obs=1.0 / max(0.05, probe_interval)),
                    burst,
                )

            # No limit observed within budget
            safe_int = max(probe_interval * 1.5, robots_delay or 0.0, 0.35)
            burst = max(1, min(total, 10))
            supporting.append(f"All {total} budgeted requests passed cleanly at {probe_interval}s interval.")
            if robots_delay:
                supporting.append(f"Incorporated robots.txt Crawl-delay ({robots_delay}s).")
            return (
                PatternClassification(
                    detected_pattern="no_limit_observed",
                    confidence="medium",
                    confidence_score=0.65,
                    supporting_evidence=supporting,
                    contradictory_evidence=["Probe volume was limited to configured budget; higher throughput might trigger limits."],
                    observation_type="empirical_observations",
                    limitations=limitations,
                    explanation=f"All {total} requests succeeded with no throttling detected within the tested budget.",
                ),
                self._make_recommendations(safe_int, max_obs=1.0 / max(0.05, probe_interval)),
                burst,
            )

        # Case 3: Confirmed rate limiting observed
        allowed_count = max(1, (first_block_idx or 2) - 1)
        safe_burst = max(1, int(allowed_count * 0.75))
        retry_values = [p.retry_after_sec for p in confirmed_rl if p.retry_after_sec is not None]

        # Sub-case 3A: Header-Guided (explicit Retry-After or RateLimit headers returned on block)
        if retry_values or header_limit:
            max_retry = max(retry_values) if retry_values else (header_reset or 5.0)
            window_est = max(max_retry, header_reset or 0.0)
            supporting.append(f"Received explicit Retry-After: {max_retry}s on rate-limit response.")
            if header_limit:
                supporting.append(f"Server declared RateLimit-Limit: {header_limit}.")
            safe_int = max((window_est / allowed_count) * 1.3, robots_delay or 0.0, 0.5)
            return (
                PatternClassification(
                    detected_pattern="header_guided",
                    confidence="high",
                    confidence_score=0.92,
                    supporting_evidence=supporting,
                    contradictory_evidence=[],
                    observation_type="direct_headers",
                    limitations=limitations,
                    explanation=f"Throttled after {allowed_count} requests and returned explicit Retry-After: {max_retry}s.",
                ),
                self._make_recommendations(safe_int, max_obs=allowed_count / max(0.1, (first_block_idx or 2) * probe_interval)),
                safe_burst,
            )

        # Sub-case 3B: Analyze pattern of post-block responses
        post_first = [p for p in burst_probes if p.request_num >= (first_block_idx or 1)]
        accepted_after_first_block = any(p.accepted for p in post_first)
        cooldown_duration = cooldown_stats.observed_cooldown_sec or 10.0

        if accepted_after_first_block:
            # Alternating allowed and blocked -> Token Bucket or Sliding Window
            supporting.append(f"Initial burst of {allowed_count} requests permitted.")
            supporting.append("Subsequent requests alternated between blocked and accepted as capacity was replenished.")
            safe_int = max((cooldown_duration / allowed_count) * 1.25, robots_delay or 0.0, 0.5)
            return (
                PatternClassification(
                    detected_pattern="token_bucket",
                    confidence="high" if len(post_first) >= 4 else "medium",
                    confidence_score=0.82 if len(post_first) >= 4 else 0.65,
                    supporting_evidence=supporting,
                    contradictory_evidence=[],
                    observation_type="empirical_observations",
                    limitations=limitations,
                    explanation=f"Allowed burst of {allowed_count} requests, then alternated with token replenishment. Consistent with a token bucket rate limiter.",
                ),
                self._make_recommendations(safe_int, max_obs=allowed_count / max(0.1, (first_block_idx or 2) * probe_interval)),
                safe_burst,
            )

        # Sub-case 3C: Solid wall of blocks -> Fixed Window
        supporting.append(f"Allowed {allowed_count} requests, then encountered an unbroken wall of 429 blocks.")
        if cooldown_stats.recovery_verified:
            supporting.append(f"Verified full window recovery after {cooldown_stats.observed_cooldown_sec}s.")
        else:
            contradictory.append("Recovery timing could not be verified within duration budget.")

        safe_int = max((cooldown_duration / allowed_count) * 1.3, robots_delay or 0.0, 0.5)
        conf = "high" if cooldown_stats.recovery_verified else "medium"
        return (
            PatternClassification(
                detected_pattern="fixed_window",
                confidence=conf,
                confidence_score=0.85 if conf == "high" else 0.65,
                supporting_evidence=supporting,
                contradictory_evidence=contradictory,
                observation_type="empirical_observations",
                limitations=limitations,
                explanation=f"Allowed {allowed_count} requests cleanly, then blocked subsequent requests in a solid window until cooldown.",
            ),
            self._make_recommendations(safe_int, max_obs=allowed_count / max(0.1, (first_block_idx or 2) * probe_interval)),
            safe_burst,
        )

    def _make_recommendations(self, interval_sec: float, max_obs: float = 1.0) -> RateRecommendations:
        interval_sec = round(max(0.1, interval_sec), 2)
        interval_ms = round(interval_sec * 1000.0, 1)
        rec_rps = round(1.0 / interval_sec, 2)
        rec_rpm = round(60.0 / interval_sec, 1)
        sustainable_rps = round(rec_rps * 1.15, 2)

        return RateRecommendations(
            max_observed_rps=round(max_obs, 2),
            estimated_sustainable_rps=sustainable_rps,
            recommended_rps=rec_rps,
            recommended_interval_sec=interval_sec,
            recommended_interval_ms=interval_ms,
            recommended_rpm=rec_rpm,
            safety_margin_pct=25.0,
            verification_passed=None,
        )
