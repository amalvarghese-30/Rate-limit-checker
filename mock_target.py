from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import email.utils
import time
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(title="Rate Limit Test Target (Dummy Site)")

# Server state
state: Dict[str, Any] = {
    "fixed_count": 0,
    "fixed_reset_at": 0.0,
    "sliding_requests": [],
    "header_count": 0,
    "header_reset_at": 0.0,
    "post_count": 0,
    "post_reset_at": 0.0,
    "kong_count": 0,
    "kong_reset_at": 0.0,
    "bucket_tokens": 5.0,
    "bucket_last": time.monotonic(),
    "throttle_count": 0,
    "leaky_last": time.monotonic(),
    "concurrent_active": 0,
}


@app.get("/", response_class=HTMLResponse)
async def dummy_home(request: Request):
    """Interactive directory of all dummy rate-limit endpoints."""
    base = str(request.base_url).rstrip("/")
    endpoints = [
        ("GET", "/no-limit", "No Limit", "Always returns 200 OK without any throttling."),
        ("GET", "/fixed-window", "Fixed Window", "Allows 6 requests per 6s window, then blocks with HTTP 429 until window resets."),
        ("GET", "/sliding-window", "Sliding Window", "Allows 5 requests per 5s rolling window with Retry-After header."),
        ("GET", "/token-bucket", "Token Bucket", "Capacity 5 tokens; refills 1 token every 0.8s (~1.25 req/s)."),
        ("GET", "/leaky-bucket", "Leaky Bucket", "Queues & delays requests to enforce 2 req/s (no 429s, high latency)."),
        ("GET", "/header-limit", "Header-Guided", "Allows 5 req / 6s and sends X-RateLimit-Limit, Remaining, Reset & Retry-After."),
        ("POST", "/post-limit", "POST JSON Limit", "Accepts POST JSON body; allows 4 requests / 6s, then HTTP 429."),
        ("GET", "/concurrency-limit", "Concurrency Limit", "Allows max 2 simultaneous requests; 3rd+ concurrent request gets 429."),
        ("GET", "/latency-throttle", "Latency Throttle", "First 4 requests are fast; subsequent requests slow down by ~550ms."),
        ("GET", "/kong-limit", "Kong Gateway", "Simulates Kong API Gateway (x-kong-upstream-latency + 429 after 5 reqs)."),
        ("GET", "/waf-block", "Cloudflare WAF", "Immediate 403 Forbidden with cf-ray & bot-check signature."),
        ("GET", "/aws-waf-block", "AWS WAF / CloudFront", "Immediate 403 Forbidden with x-amz-cf-id header."),
        ("GET", "/ambiguous-403", "Plain 403 Denied", "403 Forbidden without rate-limit or WAF indicators."),
        ("GET", "/http-503-retry", "503 + Retry-After", "HTTP 503 Service Unavailable with Retry-After: 3 throttling header."),
        ("GET", "/transient-503", "Plain 503 Outage", "HTTP 503 Maintenance error without Retry-After."),
        ("GET", "/retry-after-date", "HTTP-Date Retry-After", "429 with RFC 2822 date string in Retry-After header."),
        ("GET", "/malformed-headers", "Malformed Headers", "429 with invalid Retry-After & negative RateLimit-Reset."),
    ]
    rows = "".join(
        f"""<tr>
            <td><span class="badge">{m}</span></td>
            <td><code>{base}{p}</code></td>
            <td><strong>{name}</strong></td>
            <td>{desc}</td>
            <td><button onclick="copyUrl('{base}{p}')">Copy URL</button></td>
        </tr>"""
        for m, p, name, desc in endpoints
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dummy Rate-Limit Test Site</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 16px; }}
    .wrap {{ max-width: 1000px; margin: 0 auto; }}
    .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; margin-bottom: 16px; }}
    h1 {{ margin: 0 0 6px; font-size: 20px; }}
    p {{ margin: 0 0 12px; color: #475569; font-size: 13.5px; }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; }}
    button {{ padding: 8px 12px; border-radius: 6px; border: 1px solid #cbd5e1; background: #fff; cursor: pointer; font-size: 12.5px; font-weight: 500; }}
    button:hover {{ background: #f1f5f9; }}
    .btn-primary {{ background: #0f172a; color: #fff; border-color: #0f172a; }}
    .btn-primary:hover {{ background: #1e293b; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid #e2e8f0; }}
    th {{ font-size: 11px; text-transform: uppercase; color: #64748b; }}
    .badge {{ display: inline-block; padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 600; background: #eff6ff; color: #1d4ed8; }}
    code {{ font-size: 12px; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Dummy Rate-Limit Test Site</h1>
      <p>Use any endpoint below in the <strong>Rate Limit Checker</strong> to test how different blocking patterns and timings are detected.</p>
      <div class="actions">
        <button class="btn-primary" onclick="resetAll()">Reset All Limit Counters</button>
        <a href="/"><button type="button">← Back to Rate Limit Checker</button></a>
        <span id="reset-msg" style="font-size:12.5px; color:#059669; align-self:center;"></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Method</th><th>Endpoint URL</th><th>Type</th><th>Behavior</th><th>Action</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>
  </div>
  <script>
    function copyUrl(u) {{
      navigator.clipboard.writeText(u);
      document.getElementById('reset-msg').textContent = 'Copied: ' + u;
    }}
    async function resetAll() {{
      await fetch('{base}/reset-state', {{ method: 'POST' }});
      document.getElementById('reset-msg').textContent = 'All counters reset!';
    }}
  </script>
</body>
</html>"""


@app.post("/reset-state")
@app.get("/reset-state")
async def reset_state():
    """Resets all mock limiter counters to initial state."""
    state["fixed_count"] = 0
    state["fixed_reset_at"] = 0.0
    state["sliding_requests"] = []
    state["header_count"] = 0
    state["header_reset_at"] = 0.0
    state["post_count"] = 0
    state["post_reset_at"] = 0.0
    state["kong_count"] = 0
    state["kong_reset_at"] = 0.0
    state["bucket_tokens"] = 5.0
    state["bucket_last"] = time.monotonic()
    state["throttle_count"] = 0
    state["leaky_last"] = time.monotonic()
    state["concurrent_active"] = 0
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


@app.post("/post-limit")
async def post_limit(request: Request):
    """POST endpoint: accepts JSON body, allows 4 POSTs per 6s window, then returns 429."""
    body_bytes = await request.body()
    now = time.monotonic()
    if now > state["post_reset_at"]:
        state["post_count"] = 0
        state["post_reset_at"] = now + 6.0

    state["post_count"] += 1
    remaining = max(0, 4 - state["post_count"])
    if state["post_count"] > 4:
        retry = max(1, int(state["post_reset_at"] - now))
        return JSONResponse(
            {"error": "POST rate limit exceeded", "received_bytes": len(body_bytes)},
            status_code=429,
            headers={
                "Retry-After": str(retry),
                "X-RateLimit-Limit": "4",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(retry),
            },
        )
    return JSONResponse(
        {"ok": True, "method": "POST", "count": state["post_count"], "received_bytes": len(body_bytes)},
        headers={
            "X-RateLimit-Limit": "4",
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(max(1, int(state["post_reset_at"] - now))),
        },
    )


@app.get("/concurrency-limit")
async def concurrency_limit():
    """Allows max 2 simultaneous in-flight requests; 3rd+ concurrent request gets 429."""
    if state["concurrent_active"] >= 2:
        return JSONResponse(
            {"error": "Too many concurrent requests (max 2 at once)"},
            status_code=429,
            headers={"Retry-After": "1"},
        )
    state["concurrent_active"] += 1
    try:
        await asyncio.sleep(0.15)
        return {"ok": True, "active_during_request": state["concurrent_active"]}
    finally:
        state["concurrent_active"] = max(0, state["concurrent_active"] - 1)


@app.get("/kong-limit")
async def kong_limit():
    """Simulates Kong API Gateway rate limiting headers (5 req / 6s)."""
    now = time.monotonic()
    if now > state["kong_reset_at"]:
        state["kong_count"] = 0
        state["kong_reset_at"] = now + 6.0

    state["kong_count"] += 1
    remaining = max(0, 5 - state["kong_count"])
    kong_headers = {
        "x-kong-upstream-latency": "12",
        "x-kong-proxy-latency": "2",
        "X-RateLimit-Limit-Minute": "5",
        "X-RateLimit-Remaining-Minute": str(remaining),
    }
    if state["kong_count"] > 5:
        retry = max(1, int(state["kong_reset_at"] - now))
        return JSONResponse(
            {"message": "API rate limit exceeded"},
            status_code=429,
            headers={**kong_headers, "Retry-After": str(retry)},
        )
    return JSONResponse({"ok": True, "count": state["kong_count"]}, headers=kong_headers)


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
        headers={"cf-ray": "8a1b2c3d4e5f-BOM", "server": "cloudflare"},
    )


@app.get("/aws-waf-block")
async def aws_waf_block():
    """Simulated AWS CloudFront / WAF block."""
    return JSONResponse(
        {"error": "Request blocked by AWS WAF."},
        status_code=403,
        headers={"x-amz-cf-id": "abc123def456==", "server": "CloudFront"},
    )


@app.get("/ambiguous-403")
async def ambiguous_403():
    """Ordinary 403 Forbidden without any rate-limit indicators (e.g. permission denied)."""
    return JSONResponse(
        {"error": "Access Denied: You do not have permission to view this resource."},
        status_code=403,
    )


@app.get("/http-503-retry")
async def http_503_retry():
    """HTTP 503 with explicit Retry-After throttling indicator."""
    return JSONResponse(
        {"error": "Server busy, rate limit exceeded. Retry after 3 seconds."},
        status_code=503,
        headers={"Retry-After": "3"},
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
