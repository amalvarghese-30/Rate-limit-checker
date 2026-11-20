from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path
from typing import Dict, Optional

import httpx

from app.analyzer import DEFAULT_HEADERS, classify_response, parse_retry_after


class RateControlledClient:
    """
    Adaptive, concurrency-safe HTTP client enforcing:
      1. Local Token-Bucket request scheduler for strict burst capacity enforcement.
      2. Concurrency-safe global pacing shared across simultaneous callers.
      3. Strict Retry-After adherence (shared cooldown across all callers, never shortened).
      4. True AIMD (Additive Increase / Multiplicative Decrease) on request rate (req/s).
      5. Bounded exponential backoff for transient failures.
    """

    def __init__(
        self,
        interval_sec: float = 1.0,
        safe_burst_size: int = 1,
        jitter_pct: float = 0.15,
        min_rate_rps: float = 0.05,
        max_rate_rps: float = 50.0,
        additive_step_rps: float = 0.1,
        multiplicative_decrease_factor: float = 0.5,
        max_backoff_sec: float = 60.0,
        headers: Optional[Dict[str, str]] = None,
        timeout_sec: float = 15.0,
    ):
        base_interval = max(0.02, interval_sec)
        self.base_rate_rps = 1.0 / base_interval
        self.current_rate_rps = self.base_rate_rps
        self.min_rate_rps = min_rate_rps
        self.max_rate_rps = max_rate_rps
        self.additive_step_rps = additive_step_rps
        self.multiplicative_decrease_factor = multiplicative_decrease_factor

        self.safe_burst_size = max(1, safe_burst_size)
        self.jitter_pct = max(0.0, min(0.5, jitter_pct))
        self.max_backoff_sec = max_backoff_sec
        self.headers = {**DEFAULT_HEADERS, **(headers or {})}
        self.timeout_sec = timeout_sec

        # Token Bucket scheduler state
        self._tokens = float(self.safe_burst_size)
        self._last_refill_mono = time.monotonic()
        self._retry_after_until_mono = 0.0
        self._success_streak = 0

        self._lock = asyncio.Lock()

    @property
    def current_interval_sec(self) -> float:
        return 1.0 / max(self.min_rate_rps, self.current_rate_rps)

    @classmethod
    def from_profile_dict(cls, profile: dict, **kwargs) -> "RateControlledClient":
        rate_recs = profile.get("rate_recommendations", {})
        interval = float(rate_recs.get("recommended_interval_sec") or profile.get("recommended_interval_sec", 1.0))
        burst = int(profile.get("safe_burst_size", 1))
        return cls(
            interval_sec=interval,
            safe_burst_size=burst,
            **kwargs,
        )

    @classmethod
    def from_profile_file(cls, path: str | Path, **kwargs) -> "RateControlledClient":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        profile = data.get("profile", data)
        return cls.from_profile_dict(profile, **kwargs)

    async def _acquire_slot(self) -> None:
        """
        Token-bucket scheduler: acquires 1 token before dispatching a request.
        Blocks if token bucket is depleted or if a global Retry-After cooldown is active.
        """
        while True:
            sleep_needed = 0.0
            async with self._lock:
                now = time.monotonic()

                # 1. Global Retry-After cooldown check
                if now < self._retry_after_until_mono:
                    sleep_needed = self._retry_after_until_mono - now
                else:
                    # 2. Refill tokens based on current replenishment rate
                    elapsed = now - self._last_refill_mono
                    self._last_refill_mono = now
                    refill = elapsed * self.current_rate_rps
                    self._tokens = min(float(self.safe_burst_size), self._tokens + refill)

                    # 3. Check if token is available
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    else:
                        deficit = 1.0 - self._tokens
                        sleep_needed = deficit / self.current_rate_rps

            # Apply sleep outside lock to avoid starving other coroutines
            if sleep_needed > 0:
                await asyncio.sleep(sleep_needed)

    def _record_success(self) -> None:
        """Additive increase on sustained success"""
        self._success_streak += 1
        if self._success_streak >= 5:
            self._success_streak = 0
            self.current_rate_rps = min(
                self.max_rate_rps,
                self.current_rate_rps + self.additive_step_rps,
            )

    def _record_throttling(self, retry_after_sec: Optional[float] = None) -> None:
        """Multiplicative decrease and cooldown activation on throttling"""
        self._success_streak = 0
        self.current_rate_rps = max(
            self.min_rate_rps,
            self.current_rate_rps * self.multiplicative_decrease_factor,
        )
        self._tokens = 0.0  # Drain burst bucket upon block

        if retry_after_sec is not None and retry_after_sec > 0:
            earliest_allowed = time.monotonic() + retry_after_sec
            if earliest_allowed > self._retry_after_until_mono:
                self._retry_after_until_mono = earliest_allowed

    async def request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        max_retries: int = 3,
        **kwargs,
    ) -> httpx.Response:
        req_headers = {**self.headers, **kwargs.pop("headers", {})}
        last_resp: Optional[httpx.Response] = None

        for attempt in range(max_retries + 1):
            await self._acquire_slot()

            # Optional jitter applied after scheduling slot is secured
            if self.jitter_pct > 0:
                jitter_span = self.current_interval_sec * self.jitter_pct
                await asyncio.sleep(random.uniform(0, jitter_span))

            try:
                resp = await client.request(
                    method, url, headers=req_headers, follow_redirects=True, **kwargs
                )
                last_resp = resp
                body_sample = resp.text[:1000] if resp.text else ""
                accepted, confirmed_rl, err_type, reason = classify_response(
                    resp.status_code, dict(resp.headers), body_sample
                )

                if accepted:
                    self._record_success()
                    return resp

                if confirmed_rl or resp.status_code == 429:
                    retry_val = parse_retry_after(resp.headers.get("retry-after"))
                    self._record_throttling(retry_val)

                    if attempt < max_retries:
                        if retry_val is not None and retry_val > 0:
                            # Must wait the entire Retry-After duration
                            await asyncio.sleep(retry_val)
                        else:
                            backoff = min(
                                (2 ** attempt) * self.current_interval_sec,
                                self.max_backoff_sec,
                            )
                            await asyncio.sleep(backoff)
                        continue
                    return resp

                # Transient server errors (502, 503, 504) -> Exponential backoff
                if resp.status_code in (502, 503, 504):
                    if attempt < max_retries:
                        backoff = min(1.0 * (2 ** attempt), self.max_backoff_sec)
                        await asyncio.sleep(backoff)
                        continue
                    return resp

                # Non-retryable HTTP error (400, 401, 404, etc.)
                return resp

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt < max_retries:
                    backoff = min(1.0 * (2 ** attempt), self.max_backoff_sec)
                    await asyncio.sleep(backoff)
                    continue
                raise exc

        assert last_resp is not None
        return last_resp

    async def get(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        return await self.request(client, "GET", url, **kwargs)

    async def post(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        return await self.request(client, "POST", url, **kwargs)
