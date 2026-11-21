from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import statistics
import time
import uuid
from typing import Callable, Dict, List, Optional
import httpx

from app.analyzer import (
    DEFAULT_HEADERS,
    classify_response,
    extract_interesting_headers,
    parse_ratelimit_limit,
    parse_ratelimit_reset,
    parse_retry_after,
)
from app.config import ALLOW_LOCAL_TARGETS
from app.models import ExecutionRecord, ExecutionRequest, ExecutionStatus, RateLimitProfile
from app.security import sanitize_custom_headers, validate_target_url
from app.storage import HistoryStore


class ActiveExecution:
    def __init__(
        self,
        execution_id: str,
        profile: RateLimitProfile,
        request: ExecutionRequest,
    ):
        self.execution_id = execution_id
        self.profile = profile
        self.request = request
        self.status = ExecutionStatus(
            execution_id=execution_id,
            job_id=profile.job_id,
            target_url=profile.target_url,
            status="running",
            request_budget=request.request_budget,
            current_interval_ms=profile.recommended_interval_sec * 1000.0,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.records: List[ExecutionRecord] = []
        self.subscribers: List[asyncio.Queue[Optional[dict]]] = []
        self.event_history: List[dict] = []
        self.latencies: List[float] = []

        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Unpaused initially
        self._stop_flag = False
        self.task: Optional[asyncio.Task] = None

    def pause(self) -> None:
        if self.status.status in ("running", "cooldown"):
            self._pause_event.clear()
            self.status.status = "paused"
            self.broadcast({
                "type": "execution_status",
                "message": "Execution paused by user.",
                "status": self.status.model_dump(),
            })

    def resume(self) -> None:
        if self.status.status == "paused":
            self.status.status = "running"
            self._pause_event.set()
            self.broadcast({
                "type": "execution_status",
                "message": "Execution resumed.",
                "status": self.status.model_dump(),
            })

    def stop(self) -> None:
        self._stop_flag = True
        self._pause_event.set()  # Unblock if currently paused
        if self.task and not self.task.done():
            self.task.cancel()
        self.status.status = "stopped"
        self.status.completed_at = datetime.now(timezone.utc).isoformat()
        self.broadcast({
            "type": "execution_status",
            "message": "Execution stopped by user.",
            "status": self.status.model_dump(),
        })
        self.broadcast(None)

    def is_stopped(self) -> bool:
        return self._stop_flag

    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    def broadcast(self, event: Optional[dict]) -> None:
        if event is not None:
            self.event_history.append(event)
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def add_subscriber(self) -> asyncio.Queue[Optional[dict]]:
        q: asyncio.Queue[Optional[dict]] = asyncio.Queue()
        for ev in self.event_history:
            q.put_nowait(ev)
        if self.status.status in ("completed", "stopped", "failed"):
            q.put_nowait(None)
        self.subscribers.append(q)
        return q

    def remove_subscriber(self, q: asyncio.Queue[Optional[dict]]) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)


class PacingEngine:
    """
    Automatic Pacing Engine (Module E):
    Schedules and executes requests at the verified/recommended rate profile,
    adapts conservatively to rate-limit headers/signals, and handles pause/resume/stop.
    """

    def __init__(self, store: HistoryStore, allow_local: Optional[bool] = None):
        self.store = store
        self.allow_local = ALLOW_LOCAL_TARGETS if allow_local is None else allow_local
        self.active_executions: Dict[str, ActiveExecution] = {}

    def create_execution(
        self, profile: RateLimitProfile, req: ExecutionRequest
    ) -> ActiveExecution:
        exec_id = f"exec-{uuid.uuid4().hex[:8]}"
        execution = ActiveExecution(
            execution_id=exec_id, profile=profile, request=req
        )
        self.active_executions[exec_id] = execution
        return execution

    def get_execution(self, exec_id: str) -> Optional[ActiveExecution]:
        return self.active_executions.get(exec_id)

    def stop_execution(self, exec_id: str) -> bool:
        execution = self.get_execution(exec_id)
        if not execution:
            return False
        execution.stop()
        self.store.save_execution(execution.status, execution.records)
        return True

    async def start_execution(
        self, execution: ActiveExecution, transport: Optional[httpx.AsyncBaseTransport] = None
    ) -> None:
        async def _run():
            profile = execution.profile
            target_url = profile.target_url

            # Validate target URL for SSRF protection
            is_valid, err_msg = validate_target_url(target_url, allow_local=self.allow_local)
            if not is_valid:
                execution.status.status = "failed"
                execution.status.error = f"SSRF security rejected: {err_msg}"
                execution.broadcast({"type": "error", "message": execution.status.error})
                execution.broadcast(None)
                self.store.save_execution(execution.status, execution.records)
                return

            sanitized_custom, _ = sanitize_custom_headers(execution.request.custom_headers)
            headers = {**DEFAULT_HEADERS, **sanitized_custom}

            execution.status.started_at = datetime.now(timezone.utc).isoformat()
            execution.broadcast({
                "type": "execution_status",
                "message": f"Starting automatic pacing for {execution.request.request_budget} requests...",
                "status": execution.status.model_dump(),
            })

            # Base scheduling parameters from profile
            recommended_interval = profile.recommended_interval_sec
            current_interval = max(0.05, recommended_interval)
            budget = execution.request.request_budget

            client_kwargs = {
                "timeout": 15.0,
                "limits": httpx.Limits(max_keepalive_connections=5, max_connections=10),
            }
            if transport is not None:
                client_kwargs["transport"] = transport

            last_request_time = time.monotonic()
            req_num = 0

            async with httpx.AsyncClient(**client_kwargs) as client:
                while req_num < budget:
                    if execution.is_stopped():
                        break

                    # Wait if paused by user
                    await execution._pause_event.wait()
                    if execution.is_stopped():
                        break

                    # Calculate interval sleep needed
                    scheduled_ms = round(current_interval * 1000.0, 1)
                    now_mono = time.monotonic()
                    if req_num == 0:
                        wait_sec = 0.0
                    else:
                        elapsed_since_last = now_mono - last_request_time
                        wait_sec = max(0.0, current_interval - elapsed_since_last)

                    execution.status.next_request_in_sec = round(wait_sec, 2)
                    execution.status.current_interval_ms = scheduled_ms

                    if wait_sec > 0:
                        await asyncio.sleep(wait_sec)

                    # Re-check pause and stop state before dispatching
                    await execution._pause_event.wait()
                    if execution.is_stopped():
                        break

                    actual_interval_ms = round((time.monotonic() - last_request_time) * 1000.0, 1) if req_num > 0 else scheduled_ms
                    last_request_time = time.monotonic()
                    req_num += 1

                    # Send request
                    start_mono = time.monotonic()
                    ts_iso = datetime.now(timezone.utc).isoformat()

                    try:
                        resp = await client.request(
                            profile.method, target_url, headers=headers, follow_redirects=True
                        )
                        latency_ms = round((time.monotonic() - start_mono) * 1000.0, 1)
                        raw_headers = dict(resp.headers)
                        body_sample = resp.text[:1000] if resp.text else ""

                        accepted, confirmed_rl, err_type, reason = classify_response(
                            resp.status_code, raw_headers, body_sample
                        )

                        retry_after = parse_retry_after(raw_headers.get("retry-after"))
                        rl_limit = parse_ratelimit_limit(raw_headers)
                        rl_reset = parse_ratelimit_reset(raw_headers)

                        # Extract rate-limit remaining
                        rl_rem = None
                        for r_key in ("x-ratelimit-remaining", "ratelimit-remaining"):
                            for hk, hv in raw_headers.items():
                                if hk.lower() == r_key:
                                    try:
                                        rl_rem = int(hv.strip())
                                    except ValueError:
                                        pass

                        rec = ExecutionRecord(
                            request_number=req_num,
                            timestamp=ts_iso,
                            scheduled_interval_ms=scheduled_ms,
                            actual_interval_ms=actual_interval_ms,
                            status_code=resp.status_code,
                            latency_ms=latency_ms,
                            accepted=accepted,
                            rate_limited=confirmed_rl,
                            retry_after=retry_after,
                            rate_limit_limit=rl_limit,
                            rate_limit_remaining=rl_rem,
                            rate_limit_reset=rl_reset,
                            error_type=err_type,
                        )

                        execution.records.append(rec)
                        execution.latencies.append(latency_ms)
                        execution.status.completed_requests = req_num
                        execution.status.avg_latency_ms = round(statistics.mean(execution.latencies), 1)

                        if accepted:
                            execution.status.accepted_requests += 1
                            # Check quota remaining: if quota is very low (<=2), widen interval conservatively
                            if rl_rem is not None and rl_rem <= 2 and rl_reset and rl_reset > 0:
                                current_interval = max(current_interval, rl_reset / max(1, rl_rem))
                        elif confirmed_rl or resp.status_code == 429:
                            execution.status.rate_limited_requests += 1
                            # Condition: HTTP 429 -> Stop dispatching and respect Retry-After
                            cooldown_wait = retry_after or (current_interval * 2.0)
                            execution.status.status = "cooldown"
                            execution.broadcast({
                                "type": "execution_status",
                                "message": f"HTTP 429 received. Pausing requests for {cooldown_wait}s cooldown...",
                                "status": execution.status.model_dump(),
                            })
                            await asyncio.sleep(cooldown_wait)
                            current_interval = max(current_interval * 1.5, 0.5)
                            execution.status.status = "running"
                        elif resp.status_code in (401, 403):
                            # Condition: HTTP 401/403 -> Pause for authentication or permission review
                            execution.status.other_errors += 1
                            execution.status.status = "paused"
                            execution._pause_event.clear()
                            execution.broadcast({
                                "type": "execution_status",
                                "message": f"HTTP {resp.status_code} received. Pacing paused for credentials/permissions review.",
                                "status": execution.status.model_dump(),
                            })
                        elif resp.status_code >= 500:
                            # Condition: HTTP 5xx -> Apply bounded backoff
                            execution.status.other_errors += 1
                            await asyncio.sleep(min(current_interval * 2.0, 10.0))
                        else:
                            execution.status.other_errors += 1

                        execution.broadcast({
                            "type": "execution_record",
                            "record": rec.model_dump(),
                            "status": execution.status.model_dump(),
                        })

                    except Exception as exc:
                        latency_ms = round((time.monotonic() - start_mono) * 1000.0, 1)
                        rec = ExecutionRecord(
                            request_number=req_num,
                            timestamp=ts_iso,
                            scheduled_interval_ms=scheduled_ms,
                            actual_interval_ms=actual_interval_ms,
                            status_code=None,
                            latency_ms=latency_ms,
                            accepted=False,
                            rate_limited=False,
                            error_type=f"network_error: {type(exc).__name__}",
                        )
                        execution.records.append(rec)
                        execution.status.completed_requests = req_num
                        execution.status.other_errors += 1
                        execution.broadcast({
                            "type": "execution_record",
                            "record": rec.model_dump(),
                            "status": execution.status.model_dump(),
                        })
                        # Back off on network error
                        await asyncio.sleep(min(current_interval * 2.0, 5.0))

                if not execution.is_stopped() and execution.status.status != "failed":
                    execution.status.status = "completed"
                    execution.status.completed_at = datetime.now(timezone.utc).isoformat()
                    execution.broadcast({
                        "type": "execution_complete",
                        "message": f"Automatic pacing completed: {execution.status.accepted_requests}/{budget} requests accepted.",
                        "status": execution.status.model_dump(),
                    })

                self.store.save_execution(execution.status, execution.records)
                execution.broadcast(None)

        execution.task = asyncio.create_task(_run())
