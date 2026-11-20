# Rate Limit Checker & Adaptive Request Controller (v2.0)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com/)
[![Tests Passing](https://img.shields.io/badge/tests-22%20passed-brightgreen.svg)]()
[![Security Audited](https://img.shields.io/badge/SSRF%20Defense-Active-success.svg)]()

A standalone, website-agnostic engineering tool designed to empirically discover rate-limiting patterns, measure cooldown recovery windows, verify safe request pacing, and generate an adaptive, concurrency-safe `RateControlledClient` for Python scrapers and API integrations.

---

## 1. Core Capabilities & Architecture

- **5-Phase Rate Limit Discovery Engine (`app/analyzer.py`)**:
  - **Phase 0 (Robots & Protocol)**: Fetches and respects `robots.txt` (`Crawl-delay`).
  - **Phase 1 (Baseline Health & Latency)**: Sends 3 initial probes to calculate median, average, minimum, and maximum baseline latency. Flags target unhealthiness if failure rate exceeds safety thresholds.
  - **Phase 2 (Controlled Threshold Discovery)**: Dispatches bounded, progressive requests respecting configured request budgets and interval spacing. Differentiates between HTTP 429, evidence-supported 403/503, network/DNS errors, and timeouts. Stops on sustained walls.
  - **Phase 3 (Pattern Classification)**: Evidence-based pattern classification (`fixed_window`, `sliding_window`, `token_bucket`, `leaky_bucket`, `header_guided`, `immediate_access_block`, `no_limit_observed`, `unknown_or_hybrid`) with dynamic confidence scoring, supporting observations, and contradictory evidence.
  - **Phase 4 (Cooldown & Recovery Measurement)**: Honors `Retry-After` (both delta-seconds and RFC 2822 HTTP dates) and `RateLimit-Reset` headers. Evaluates recovery probes without retrying earlier than the server-mandated cooldown.
  - **Phase 5 (Safe Pacing Verification)**: Performs repeated, bounded verification cycles at the calculated interval with automatic safety backoff.

- **Adaptive Request Controller (`app/client.py`)**:
  - **Token Bucket Local Scheduler**: Enforces strict burst capacity across concurrent callers.
  - **Shared Concurrency Pacing**: Multiple async callers share token replenishment and cooldown states without race conditions.
  - **True AIMD**: Additive Increase on successful streaks, Multiplicative Decrease on throttling.
  - **Strict Retry-After & Exponential Backoff**: Pauses all callers across the instance during server cooldowns; applies exponential backoff for transient 502/503/network errors.

- **Defense-in-Depth Security (`app/security.py`)**:
  - **SSRF Protection**: Validates schemes (HTTP/HTTPS only), resolves hostnames via DNS, and blocks private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8, ::1), cloud metadata (`169.254.169.254`, `100.100.100.200`), link-local, and multicast ranges.
  - **Header Sanitization**: Strips prohibited hop-by-hop headers (`Host`, `Connection`, `Transfer-Encoding`) and masks sensitive credentials (`Authorization`, `Cookie`, `X-API-Key`) in logs and exported profiles.
  - **Resource Caps**: Restricts maximum response body size (64 KB) and execution duration (60s) to prevent memory exhaustion.

- **Resilient Background Job Management & SSE (`app/jobs.py` & `app/main.py`)**:
  - Full job lifecycle (`queued`, `running`, `completed`, `failed`, `cancelled`).
  - Independent execution: browser refresh or connection disconnect will not abort active analyses.
  - Event replay on SSE reconnection.

- **Persistence & History (`app/storage.py`)**:
  - SQLite with WAL (Write-Ahead Logging) mode, schema version tracking, and indexed queries.

---

## 2. Quick Start (Local Development)

### 2.1 Installation
```bash
git clone <repo-url>
cd rate-limit-checker
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2.2 Run Application
```bash
python run.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### 2.3 Run Local Mock Target Server (For Testing)
In a separate terminal:
```bash
python -m uvicorn mock_target:app --port 8001
```
Available mock test endpoints:
- `http://127.0.0.1:8001/fixed-window`: 6 req / 6s window, solid 429 wall.
- `http://127.0.0.1:8001/sliding-window`: 5 req / 5s rolling window.
- `http://127.0.0.1:8001/token-bucket`: Burst of 5, refilling at 1 token / 0.8s.
- `http://127.0.0.1:8001/header-limit`: 5 req / 6s with `Retry-After` and `X-RateLimit-*`.
- `http://127.0.0.1:8001/retry-after-date`: 429 with RFC 2822 HTTP-date `Retry-After`.
- `http://127.0.0.1:8001/latency-throttle`: Progressive latency queueing.
- `http://127.0.0.1:8001/waf-block`: Cloudflare WAF block (HTTP 403 with `cf-ray`).
- `http://127.0.0.1:8001/ambiguous-403`: Standard permission denied (not rate-limiting).
- `http://127.0.0.1:8001/no-limit`: Unlimited 200 OK.

---

## 3. Running Automated Tests

Run the complete test suite:
```bash
python -m pytest -v
```

The test suite covers:
- **`tests/test_analyzer.py`**: Baseline statistics, header parsers (delta and dates), error classification, fixed window, token bucket, header-guided, and WAF detection.
- **`tests/test_client.py`**: Concurrency burst safety, token bucket scheduling, AIMD rate increase/decrease, shared Retry-After cooldown, exponential backoff.
- **`tests/test_security.py`**: SSRF blocking, IP classification, scheme enforcement, header sanitization, credential masking.
- **`tests/test_api.py`**: Endpoints, health check, job creation, history CRUD, client generation, export.
- **`tests/test_mock_target.py`**: Direct end-to-end analyzer validation against mock limiter profiles.
- **`tests/test_storage.py`**: SQLite WAL initialization, schema migrations, and sanitized persistence.

---

## 4. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI Dashboard. |
| `GET` | `/api/health` | Service health status and database connectivity. |
| `GET` | `/api/stats` | Aggregated dashboard metrics. |
| `POST` | `/api/analyze` | Submit an analysis job (returns `job_id`). |
| `GET` | `/api/jobs/{id}` | Poll job status, progress, and phase. |
| `GET` | `/api/jobs/{id}/stream` | Server-Sent Events (SSE) live probe activity stream. |
| `POST` | `/api/jobs/{id}/cancel` | Abort a running analysis. |
| `GET` | `/api/jobs/{id}/result` | Full analysis profile and probe log. |
| `GET` | `/api/history` | List recent saved runs. |
| `DELETE` | `/api/history/{id}` | Delete a history entry. |
| `GET` | `/api/export/{id}` | Download sanitized JSON profile. |
| `GET` | `/api/generate-client/{id}` | Get runnable Python client code snippet. |

---

## 5. Using the Adaptive Request Controller

You can load any exported JSON profile directly into `RateControlledClient`:

```python
import asyncio
import httpx
from app.client import RateControlledClient

# Option A: Initialize from exported JSON profile file
client_ctrl = RateControlledClient.from_profile_file("ratelimit-profile-job123.json")

# Option B: Initialize programmatically
client_ctrl = RateControlledClient(
    interval_sec=0.35,     # Safe pacing interval
    safe_burst_size=3,      # Max simultaneous requests permitted
    jitter_pct=0.15,        # 15% random jitter to avoid thundering herds
)

async def worker(worker_id: int):
    async with httpx.AsyncClient(timeout=15.0) as http:
        for i in range(10):
            response = await client_ctrl.get(http, "https://api.example.com/items")
            print(f"Worker {worker_id} - Req {i}: HTTP {response.status_code}")

async def main():
    # Multiple workers share the same client and token bucket without race conditions
    await asyncio.gather(worker(1), worker(2), worker(3))

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 6. Production Deployment (Linux VPS & Docker)

### Option A: Docker & Docker Compose (Recommended)
1. Copy configuration:
   ```bash
   cp .env.example .env
   ```
2. Build and start containers:
   ```bash
   docker compose up -d --build
   ```
3. Check logs and status:
   ```bash
   docker compose logs -f
   curl http://localhost:8000/api/health
   ```

### Option B: Linux VPS Systemd Service
1. Clone to `/opt/rate-limit-checker`:
   ```bash
   cd /opt/rate-limit-checker
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Create systemd unit `/etc/systemd/system/ratelimit.service`:
   ```ini
   [Unit]
   Description=Rate Limit Checker FastAPI Service
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/opt/rate-limit-checker
   Environment="PATH=/opt/rate-limit-checker/venv/bin"
   Environment="HOST=127.0.0.1"
   Environment="PORT=8000"
   Environment="ALLOW_LOCAL_TARGETS=false"
   ExecStart=/opt/rate-limit-checker/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2

   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
3. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ratelimit
   ```

### Reverse Proxy (Nginx Configuration)
```nginx
server {
    server_name ratelimit.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE Streaming support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 120s;
    }
}
```

---

## 7. Known Limitations & Responsible Use

1. **Permission Required**: You must have explicit permission or ownership of systems tested.
2. **Context-Dependent Limits**: Observed rate limits can fluctuate dynamically based on client IP, authenticated user tier, geography, and current server load.
3. **No Permanent Guarantee**: Recommendations represent empirical measurements observed during testing; they are not an immutable server-side contract.
