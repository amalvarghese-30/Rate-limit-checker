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
        scheduled_interval_ms: Optional[float] = None,
        actual_interval_ms: Optional[float] = None,
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
                dispatch_timestamp=ts,
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
                scheduled_interval_ms=scheduled_interval_ms,
                actual_interval_ms=actual_interval_ms,
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
                dispatch_timestamp=ts,
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
                scheduled_interval_ms=scheduled_interval_ms,
                actual_interval_ms=actual_interval_ms,
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
        baseline_stats = BaselineStats()
        cooldown_stats = CooldownStats()
        burst_probes: List[ProbeEvent] = []
        first_block_idx: Optional[int] = None
        first_block_sec: Optional[float] = None
        first_block_mono: Optional[float] = None
        consecutive_blocks = 0
        classification: Optional[PatternClassification] = None
        rec_rates: Optional[RateRecommendations] = None
        safe_burst = 1
        robots_delay: Optional[float] = None

        configured_budget = req.request_budget
        concurrency = max(1, min(req.burst_size, configured_budget))
        counters = RequestCounters(
            configured_budget=configured_budget,
            remaining_budget=configured_budget,
        )

        # Budget-aware execution deadline accounting for baseline, discovery batches, interval, timeouts, and recovery
        if req.max_analysis_duration_sec is not None:
            deadline_sec = req.max_analysis_duration_sec
        else:
            baseline_est = min(3, configured_budget) * (min(req.timeout_sec, 2.0) + 0.2)
            disc_batches = math.ceil(max(0, configured_budget - 3) / concurrency)
            disc_est = disc_batches * (req.probe_interval_sec + min(req.timeout_sec, 2.5))
            cooldown_est = 25.0 if req.check_cooldown else 0.0
            verify_est = 15.0 if req.verify_safe_pace else 0.0
            total_est = baseline_est + disc_est + cooldown_est + verify_est + 25.0
            deadline_sec = max(45.0, total_est)

        emit({
            "type": "info",
            "message": f"Budget-aware execution deadline: {round(deadline_sec, 1)}s (Budget: {configured_budget}, Burst: {concurrency}, Interval: {req.probe_interval_sec}s).",
        })

        def emit_progress(phase: str) -> None:
            elapsed = round(time.monotonic() - test_start, 2)
            eta = None
            if counters.completed_requests >= 3 and counters.dispatched_requests < configured_budget:
                remaining_reqs = configured_budget - counters.completed_requests
                batches_left = math.ceil(remaining_reqs / concurrency)
                avg_batch_time = elapsed / math.ceil(counters.completed_requests / concurrency)
                eta = round(batches_left * avg_batch_time, 1)
            emit({
                "type": "progress",
                "budget": configured_budget,
                "dispatched": counters.dispatched_requests,
                "completed": counters.completed_requests,
                "in_progress": counters.in_progress_requests,
                "remaining": max(0, configured_budget - counters.dispatched_requests),
                "current_phase": phase,
                "elapsed_sec": elapsed,
                "estimated_remaining_sec": eta,
            })

        async def sleep_cancellable(duration_sec: float) -> None:
            if duration_sec <= 0:
                return
            end_t = time.monotonic() + duration_sec
            while time.monotonic() < end_t:
                if is_cancelled and is_cancelled():
                    break
                rem = end_t - time.monotonic()
                await asyncio.sleep(min(0.05, max(0.005, rem)))

        deadline_reached = False
        cancelled_during_run = False
        client_kwargs = {
            "timeout": req.timeout_sec,
            "limits": httpx.Limits(max_keepalive_connections=max(10, concurrency * 2), max_connections=max(20, concurrency * 3)),
        }
        if self.transport is not None:
            client_kwargs["transport"] = self.transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            # Check robots.txt Crawl-delay
            if req.check_robots:
                emit({"type": "status", "phase": "baseline", "message": "Phase 0: Checking robots.txt for crawl guidelines..."})
                robots_delay = await self._fetch_robots_crawl_delay(client, target_url)
                if robots_delay:
                    emit({"type": "info", "message": f"Found robots.txt Crawl-delay: {robots_delay}s"})

            # PHASE 1: Baseline Measurement (up to 3 baseline requests within budget)
            baseline_count = min(3, configured_budget)
            emit({"type": "status", "phase": "baseline", "message": f"Phase 1: Establishing baseline latency and target health ({baseline_count} probes)..."})
            baseline_probes: List[ProbeEvent] = []
            for b_idx in range(baseline_count):
                if is_cancelled and is_cancelled():
                    break
                if (time.monotonic() - test_start) >= deadline_sec:
                    deadline_reached = True
                    emit({"type": "warning", "message": "Maximum analysis duration reached. Stopping probes."})
                    break
                req_counter += 1
                counters.dispatched_requests += 1
                counters.in_progress_requests += 1
                emit_progress("baseline")
                b_ev = await self._send_single_probe(
                    client, target_url, req.method, headers, req_counter, "baseline", test_start
                )
                probes.append(b_ev)
                baseline_probes.append(b_ev)
                observed_headers.update(b_ev.ratelimit_headers)
                self._update_counters(counters, b_ev)
                emit({"type": "probe", "probe": b_ev.model_dump()})
                emit_progress("baseline")
                if b_idx < baseline_count - 1:
                    await sleep_cancellable(0.2)

            baseline_stats = self._calculate_baseline(baseline_probes)
            if not baseline_stats.is_healthy:
                emit({
                    "type": "warning",
                    "message": f"Target health warning: {baseline_stats.health_warning}. Rate-limit analysis may be unreliable.",
                })

            baseline_latency_ms = baseline_stats.median_latency_ms or baseline_stats.avg_latency_ms

            # PHASE 2: Controlled Threshold Discovery (Concurrent Batches)
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

            remaining_budget = max(0, configured_budget - counters.dispatched_requests)
            if baseline_stats.is_healthy and remaining_budget > 0 and consecutive_blocks == 0:
                emit({
                    "type": "status",
                    "phase": "probe",
                    "message": f"Phase 2: Controlled threshold discovery ({remaining_budget} probes budgeted, burst size {concurrency})...",
                })
                last_batch_mono: Optional[float] = None

                while counters.dispatched_requests < configured_budget:
                    if is_cancelled and is_cancelled():
                        break
                    if (time.monotonic() - test_start) >= deadline_sec:
                        deadline_reached = True
                        emit({"type": "warning", "message": "Maximum analysis duration reached. Stopping probes."})
                        break

                    batch_size = min(concurrency, configured_budget - counters.dispatched_requests)
                    if batch_size <= 0:
                        break

                    batch_scheduled_interval = req.probe_interval_sec * 1000.0
                    now_mono = time.monotonic()
                    batch_actual_interval = (now_mono - last_batch_mono) * 1000.0 if last_batch_mono else 0.0
                    last_batch_mono = now_mono

                    batch_req_nums = []
                    for _ in range(batch_size):
                        req_counter += 1
                        batch_req_nums.append(req_counter)

                    counters.dispatched_requests += batch_size
                    counters.in_progress_requests += batch_size
                    emit_progress("probe")

                    async def _send_probe_task(r_num: int) -> ProbeEvent:
                        ev = await self._send_single_probe(
                            client,
                            target_url,
                            req.method,
                            headers,
                            r_num,
                            "probe",
                            test_start,
                            baseline_latency_ms=baseline_latency_ms,
                            scheduled_interval_ms=batch_scheduled_interval,
                            actual_interval_ms=batch_actual_interval,
                        )
                        self._update_counters(counters, ev)
                        emit({"type": "probe", "probe": ev.model_dump()})
                        emit_progress("probe")
                        return ev

                    batch_results = await asyncio.gather(*[_send_probe_task(r_n) for r_n in batch_req_nums])
                    probes.extend(batch_results)
                    burst_probes.extend(batch_results)
                    for ev in batch_results:
                        observed_headers.update(ev.ratelimit_headers)

                    batch_blocks = [ev for ev in batch_results if ev.confirmed_rate_limit or ev.blocked]
                    if batch_blocks:
                        consecutive_blocks += 1
                        for ev in batch_blocks:
                            if first_block_idx is None:
                                first_block_idx = ev.request_num
                                first_block_sec = ev.elapsed_sec
                                first_block_mono = time.monotonic()

                        # Check for server Retry-After delay
                        retry_candidates = [ev.retry_after_sec for ev in batch_blocks if ev.retry_after_sec]
                        if retry_candidates:
                            retry_wait = max(retry_candidates)
                            time_left = deadline_sec - (time.monotonic() - test_start)
                            if retry_wait > 0 and time_left > retry_wait:
                                emit({"type": "info", "message": f"Server requested Retry-After ({retry_wait}s). Waiting before next probe batch..."})
                                await sleep_cancellable(retry_wait)

                        if consecutive_blocks >= 3:
                            emit({"type": "info", "message": f"Sustained rate limit wall ({consecutive_blocks} consecutive batches blocked). Stopping discovery."})
                            break
                    else:
                        consecutive_blocks = 0

                    # Delay between batches if budget permits
                    if counters.dispatched_requests < configured_budget:
                        if (time.monotonic() - test_start) >= deadline_sec:
                            deadline_reached = True
                            emit({"type": "warning", "message": "Maximum analysis duration reached. Stopping probes."})
                            break
                        await sleep_cancellable(req.probe_interval_sec)

            # PHASE 4: Cooldown & Recovery Detection
            cooldown_stats = CooldownStats(
                first_block_req=first_block_idx,
                first_block_sec=first_block_sec,
            )

            retry_hints = [p.retry_after_sec for p in burst_probes if p.retry_after_sec is not None]
            server_retry = max(retry_hints) if retry_hints else None
            reset_hint = parse_ratelimit_reset(observed_headers)
            cooldown_stats.server_retry_after_sec = server_retry

            if req.check_cooldown and first_block_idx is not None and counters.dispatched_requests < configured_budget:
                emit({"type": "status", "phase": "cooldown", "message": "Phase 3: Measuring cooldown & recovery timing..."})
                planned_wait = server_retry or reset_hint

                if planned_wait is not None and planned_wait > 0:
                    cooldown_stats.observed_cooldown_sec = planned_wait
                    remaining_time = deadline_sec - (time.monotonic() - test_start)
                    if planned_wait > remaining_time:
                        emit({
                            "type": "warning",
                            "message": f"Server Retry-After ({planned_wait}s) exceeds remaining duration budget ({round(remaining_time, 1)}s). Recovery verification skipped.",
                        })
                    else:
                        emit({"type": "info", "message": f"Respecting server requested cooldown: waiting {planned_wait}s before recovery probe..."})
                        await sleep_cancellable(planned_wait)
                        if counters.dispatched_requests < configured_budget:
                            req_counter += 1
                            cooldown_stats.verification_attempts += 1
                            counters.dispatched_requests += 1
                            counters.in_progress_requests += 1
                            emit_progress("cooldown")
                            rec_ev = await self._send_single_probe(
                                client, target_url, req.method, headers, req_counter, "cooldown", test_start, baseline_latency_ms
                            )
                            probes.append(rec_ev)
                            observed_headers.update(rec_ev.ratelimit_headers)
                            self._update_counters(counters, rec_ev)
                            emit({"type": "probe", "probe": rec_ev.model_dump()})
                            emit_progress("cooldown")

                            if rec_ev.accepted:
                                cooldown_stats.recovery_verified = True
                                cooldown_stats.first_recovery_sec = rec_ev.elapsed_sec
                                if first_block_mono:
                                    cooldown_stats.observed_cooldown_sec = round(time.monotonic() - first_block_mono, 2)
                                emit({"type": "info", "message": f"Target accepted recovery probe after {cooldown_stats.observed_cooldown_sec}s."})
                            else:
                                emit({"type": "warning", "message": "Target still throttled after server Retry-After period."})
                else:
                    for wait_step in (1.5, 3.0, 5.0):
                        if counters.dispatched_requests >= configured_budget:
                            break
                        if (time.monotonic() - test_start) + wait_step > deadline_sec:
                            break
                        await sleep_cancellable(wait_step)
                        req_counter += 1
                        cooldown_stats.verification_attempts += 1
                        counters.dispatched_requests += 1
                        counters.in_progress_requests += 1
                        emit_progress("cooldown")
                        rec_ev = await self._send_single_probe(
                            client, target_url, req.method, headers, req_counter, "cooldown", test_start, baseline_latency_ms
                        )
                        probes.append(rec_ev)
                        observed_headers.update(rec_ev.ratelimit_headers)
                        self._update_counters(counters, rec_ev)
                        emit({"type": "probe", "probe": rec_ev.model_dump()})
                        emit_progress("cooldown")

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
            available_for_verify = configured_budget - counters.dispatched_requests
            if (
                req.verify_safe_pace
                and classification.detected_pattern != "immediate_access_block"
                and rec_rates.recommended_interval_sec <= 5.0
                and available_for_verify > 0
            ):
                emit({
                    "type": "status",
                    "phase": "verify",
                    "message": f"Phase 4: Verifying recommended pacing (sampling at {rec_rates.recommended_interval_sec:.2f}s spacing)...",
                })
                v_rounds = 0
                v_sample_size = min(available_for_verify, 4)
                v_success = 0
                v_failed = 0
                current_v_interval = rec_rates.recommended_interval_sec

                while v_rounds < 2 and (time.monotonic() - test_start) < deadline_sec and counters.dispatched_requests < configured_budget:
                    v_rounds += 1
                    round_blocks = 0
                    probes_to_send = min(v_sample_size, configured_budget - counters.dispatched_requests)
                    if probes_to_send <= 0:
                        break
                    for _ in range(probes_to_send):
                        if (time.monotonic() - test_start) >= deadline_sec:
                            deadline_reached = True
                            break
                        await sleep_cancellable(current_v_interval)
                        req_counter += 1
                        counters.dispatched_requests += 1
                        counters.in_progress_requests += 1
                        emit_progress("verify")
                        v_ev = await self._send_single_probe(
                            client, target_url, req.method, headers, req_counter, "verify", test_start, baseline_latency_ms
                        )
                        probes.append(v_ev)
                        observed_headers.update(v_ev.ratelimit_headers)
                        self._update_counters(counters, v_ev)
                        emit({"type": "probe", "probe": v_ev.model_dump()})
                        emit_progress("verify")
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
                        current_v_interval = round(current_v_interval * 1.5, 2)
                        safe_burst = max(1, safe_burst // 2)
                        rec_rates.verification_passed = False
                        rec_rates.verification_summary = f"{round_blocks}/{v_sample_size} verification probes encountered resistance; widened interval to {current_v_interval:.2f}s."
                        if v_rounds < 2 and v_ev.retry_after_sec:
                            wait_s = min(v_ev.retry_after_sec, 5.0)
                            await sleep_cancellable(wait_s)

                rec_rates.verification_rounds = v_rounds
                rec_rates.verification_sample_size = v_success + v_failed
                rec_rates.recommended_interval_sec = current_v_interval
                rec_rates.recommended_interval_ms = round(current_v_interval * 1000.0, 1)
                rec_rates.recommended_rps = round(1.0 / current_v_interval, 2)
                rec_rates.recommended_rpm = round(60.0 / current_v_interval, 1)

        actual_duration = round(time.monotonic() - test_start, 2)
        if is_cancelled and is_cancelled():
            final_status = "cancelled"
            completion_msg = f"Analysis cancelled by user: {counters.dispatched_requests} of {configured_budget} requests dispatched."
        elif deadline_reached:
            final_status = "partial"
            completion_msg = f"Analysis partially completed: {counters.dispatched_requests} of {configured_budget} requests dispatched. Maximum analysis duration reached."
        elif consecutive_blocks >= 3 and counters.completed_requests < configured_budget:
            final_status = "partial"
            completion_msg = f"Analysis partially completed: {counters.dispatched_requests} of {configured_budget} requests dispatched. Sustained rate limit wall encountered."
        elif counters.completed_requests >= configured_budget:
            final_status = "completed"
            completion_msg = f"Analysis completed successfully: {counters.completed_requests} of {configured_budget} requests dispatched."
        else:
            final_status = "partial"
            completion_msg = f"Analysis partially completed: {counters.dispatched_requests} of {configured_budget} requests dispatched."

        if classification is None or rec_rates is None:
            classification, rec_rates, safe_burst = self._classify_pattern(
                burst_probes=burst_probes or probes,
                probe_interval=req.probe_interval_sec,
                first_block_idx=first_block_idx,
                cooldown_stats=cooldown_stats,
                observed_headers=observed_headers,
                robots_delay=robots_delay,
                baseline_stats=baseline_stats,
            )

        if final_status in ("partial", "cancelled"):
            rec_rates.is_provisional = True
            if classification.confidence == "high":
                classification.confidence = "medium"
                classification.confidence_score = min(classification.confidence_score, 0.65)
            if final_status == "cancelled":
                classification.limitations.append(
                    f"Analysis was cancelled by user ({counters.dispatched_requests}/{configured_budget} requests dispatched). Recommendations are provisional."
                )
            else:
                classification.limitations.append(
                    f"Analysis was partially completed ({counters.dispatched_requests}/{configured_budget} requests dispatched). Recommendations are provisional."
                )

        # Generate summary
        if classification.detected_pattern == "immediate_access_block":
            freq_summary = (
                "Blocked on the baseline request. Do not send automated requests without resolving "
                "WAF challenges, IP restrictions, or missing authorization credentials."
            )
        elif safe_burst > 1:
            prov_text = " (Provisional)" if rec_rates.is_provisional else ""
            freq_summary = (
                f"Send up to {safe_burst} requests concurrently (burst), then pace subsequent requests at "
                f"1 request every {rec_rates.recommended_interval_sec:.2f}s (~{rec_rates.recommended_rpm:.0f} req/min) with ±15% jitter.{prov_text}"
            )
        else:
            prov_text = " (Provisional)" if rec_rates.is_provisional else ""
            freq_summary = (
                f"Avoid bursts. Send 1 request at a time, spaced {rec_rates.recommended_interval_sec:.2f}s apart "
                f"(~{rec_rates.recommended_rpm:.0f} req/min) with ±15% jitter.{prov_text}"
            )

        profile = RateLimitProfile(
            schema_version="2.0.0",
            job_id=job_id,
            created_at=created_at,
            target_url=target_url,
            method=req.method,
            status=final_status,
            completion_message=completion_msg,
            configured_budget=configured_budget,
            dispatched_requests=counters.dispatched_requests,
            execution_deadline_sec=deadline_sec,
            actual_duration_sec=actual_duration,
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
        emit({
            "type": "complete",
            "status": final_status,
            "message": completion_msg,
            "result": result.model_dump(),
        })
        return result
        return result

    def _update_counters(self, counters: RequestCounters, ev: ProbeEvent) -> None:
        counters.completed_requests += 1
        counters.total_sent = counters.completed_requests
        counters.in_progress_requests = max(0, counters.in_progress_requests - 1)
        if ev.accepted:
            counters.successful_requests += 1
            counters.accepted += 1
            if ev.throttled:
                counters.suspected_throttled += 1
        else:
            if ev.confirmed_rate_limit:
                counters.rate_limited_requests += 1
                counters.confirmed_rate_limited += 1
            elif ev.error_type == "timeout":
                counters.timed_out_requests += 1
                counters.timeouts += 1
            elif ev.error_type in ("dns_error", "network_error"):
                counters.network_errors += 1
                counters.network_failures += 1
            elif ev.error_type in ("http_403_ambiguous", "http_503_unavail", "http_error"):
                counters.http_errors += 1
            else:
                counters.http_errors += 1
        counters.remaining_budget = max(0, counters.configured_budget - counters.dispatched_requests)

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
            safe_int = max(probe_interval, robots_delay or 0.0, 0.25)
            burst = max(1, min(total, 10))
            is_insufficient = total < 5
            conf = "insufficient" if is_insufficient else "medium"
            conf_score = 0.35 if is_insufficient else 0.70
            supporting.append(f"All {total} budgeted requests passed cleanly at {probe_interval}s interval.")
            if robots_delay:
                supporting.append(f"Incorporated robots.txt Crawl-delay ({robots_delay}s).")
            explanation = "No rate limit observed within the tested budget."
            if is_insufficient:
                limitations.append(f"Sample size ({total} requests) is too small to reliably determine maximum throughput.")
            return (
                PatternClassification(
                    detected_pattern="no_limit_observed",
                    confidence=conf,
                    confidence_score=conf_score,
                    supporting_evidence=supporting,
                    contradictory_evidence=["Probe volume was limited to configured budget; higher throughput might trigger limits."],
                    observation_type="empirical_observations",
                    limitations=limitations,
                    explanation=explanation,
                ),
                self._make_recommendations(safe_int, max_obs=1.0 / max(0.05, probe_interval), is_provisional=is_insufficient),
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

    def _make_recommendations(self, interval_sec: float, max_obs: float = 1.0, is_provisional: bool = False) -> RateRecommendations:
        interval_sec = round(max(0.05, interval_sec), 2)
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
            is_provisional=is_provisional,
        )
