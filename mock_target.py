from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import email.utils
import random
import time
from typing import Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="Enhanced Mock Rate-Limited Target")

# Server state
sliding_history: List[float] = []

state = {
    "fixed_count": 0,
    "fixed_reset_at": 0.0,
    "sliding_requests": sliding_history,
    "header_count": 0,
    "header_reset_at": 0.0,
    "bucket_tokens": 5.0,
    "bucket_last": time.monotonic(),
    "throttle_count": 0,
    "leaky_last": time.monotonic(),
}


@app.post("/reset-state")
@app.get("/reset-state")
async def reset_state():
    """Resets all mock limiter counters to initial state."""
    state["fixed_count"] = 0
    state["fixed_reset_at"] = 0.0
    state["sliding_requests"] = []
    state["header_count"] = 0
    state["header_reset_at"] = 0.0
    state["bucket_tokens"] = 5.0
    state["bucket_last"] = time.monotonic()
    state["throttle_count"] = 0
    state["leaky_last"] = time.monotonic()
    return {"status": "reset_successful"}


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return "User-agent: *\nCrawl-delay: 0.5\n"


@app.get("/no-limit")
async def no_limit():
    """Always returns 200 OK without restrictions."""
    return {"ok": True, "message": "No rate limits configured"}


@app.get("/fixed-window")
async def fixed_window():
    """Allows 6 requests per 6s window, then blocks with 429 until reset."""
    now = time.monotonic()
    if now > state["fixed_reset_at"]:
        state["fixed_count"] = 0
        state["fixed_reset_at"] = now + 6.0

    state["fixed_count"] += 1
    if state["fixed_count"] > 6:
        return JSONResponse({"error": "Fixed window rate limit exceeded"}, status_code=429)
    return {"ok": True, "count": state["fixed_count"]}


@app.get("/sliding-window")
async def sliding_window():
    """Allows 5 requests per 5-second rolling window based on timestamps."""
    now = time.monotonic()
    # Expire requests older than 5.0 seconds
    state["sliding_requests"] = [t for t in state["sliding_requests"] if now - t < 5.0]

    if len(state["sliding_requests"]) >= 5:
        oldest = state["sliding_requests"][0]
        retry_needed = max(1, int(5.0 - (now - oldest)) + 1)
        return JSONResponse(
            {"error": "Sliding window limit exceeded"},
            status_code=429,
            headers={"Retry-After": str(retry_needed)},
        )

    state["sliding_requests"].append(now)
    return {"ok": True, "active_in_window": len(state["sliding_requests"])}


@app.get("/token-bucket")
async def token_bucket():
    """Capacity 5 tokens, replenishes 1 token every 0.8s."""
    now = time.monotonic()
    elapsed = now - state["bucket_last"]
    state["bucket_last"] = now
    state["bucket_tokens"] = min(5.0, state["bucket_tokens"] + elapsed / 0.8)

    if state["bucket_tokens"] < 1.0:
        return JSONResponse({"error": "Token bucket empty"}, status_code=429)

    state["bucket_tokens"] -= 1.0
    return {"ok": True, "tokens_left": round(state["bucket_tokens"], 2)}


@app.get("/leaky-bucket")
async def leaky_bucket():
    """Controlled throughput leaky bucket: injects delay to pace requests at 2 req/s."""
    now = time.monotonic()
    elapsed = now - state["leaky_last"]
    state["leaky_last"] = now
    if elapsed < 0.5:
        delay = 0.5 - elapsed
        await asyncio.sleep(delay)
    return {"ok": True, "processed": True}


@app.get("/header-limit")
async def header_limit():
    """Allows 5 requests per 6s window with explicit Retry-After and X-RateLimit headers."""
    now = time.monotonic()
    if now > state["header_reset_at"]:
        state["header_count"] = 0
        state["header_reset_at"] = now + 6.0

    state["header_count"] += 1
    remaining = max(0, 5 - state["header_count"])
    if state["header_count"] > 5:
        retry = max(1, int(state["header_reset_at"] - now))
        return JSONResponse(
            {"error": "Too many requests"},
            status_code=429,
            headers={
                "Retry-After": str(retry),
                "X-RateLimit-Limit": "5",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(retry),
            },
        )
    return JSONResponse(
        {"ok": True, "count": state["header_count"]},
        headers={
            "X-RateLimit-Limit": "5",
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(max(1, int(state["header_reset_at"] - now))),
        },
    )


@app.get("/retry-after-date")
async def retry_after_date():
    """Returns 429 with RFC 2822 HTTP-date Retry-After."""
    future = datetime.now(timezone.utc) + timedelta(seconds=5)
    date_str = email.utils.format_datetime(future)
    return JSONResponse(
        {"error": "Too many requests. Please wait."},
        status_code=429,
        headers={"Retry-After": date_str},
    )


@app.get("/waf-block")
async def waf_block():
    """Simulated Cloudflare WAF block (HTTP 403 with signature)."""
    return JSONResponse(
        {"error": "Attention Required! Cloudflare bot check blocked this request."},
        status_code=403,
        headers={"cf-ray": "8a1b2c3d4e5f-BOM"},
    )


@app.get("/ambiguous-403")
async def ambiguous_403():
    """Ordinary 403 Forbidden without any rate-limit indicators (e.g. permission denied)."""
    return JSONResponse(
        {"error": "Access Denied: You do not have permission to view this resource."},
        status_code=403,
    )


@app.get("/transient-503")
async def transient_503():
    """Temporary server maintenance (HTTP 503)."""
    return JSONResponse(
        {"error": "Backend Service Unavailable - Database under scheduled maintenance."},
        status_code=503,
    )


@app.get("/latency-throttle")
async def latency_throttle():
    """Simulates progressive latency throttling after 4 fast requests."""
    state["throttle_count"] += 1
    if state["throttle_count"] > 4 and state["throttle_count"] % 10 != 0:
        await asyncio.sleep(0.55)
    return {"ok": True, "req": state["throttle_count"]}


@app.get("/malformed-headers")
async def malformed_headers():
    """Emits 429 with invalid or unparseable Retry-After header."""
    return JSONResponse(
        {"error": "Rate limited with weird headers"},
        status_code=429,
        headers={
            "Retry-After": "invalid-timestamp-string-xyz",
            "RateLimit-Reset": "-999",
        },
    )
