from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional
import uuid

from app.analyzer import RateLimitAnalyzer
from app.config import MAX_CONCURRENT_JOBS
from app.models import AnalyzeRequest, AnalysisResult, JobStatus
from app.storage import HistoryStore


class ActiveJob:
    def __init__(self, job_id: str, request: AnalyzeRequest):
        self.job_id = job_id
        self.request = request
        self.status = JobStatus(
            job_id=job_id,
            status="queued",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.result: Optional[AnalysisResult] = None
        self.subscribers: List[asyncio.Queue[Optional[dict]]] = []
        self.event_history: List[dict] = []
        self._cancel_flag = False
        self.task: Optional[asyncio.Task] = None

    def cancel(self) -> bool:
        if self.status.status in ("completed", "failed", "cancelled"):
            return False
        self._cancel_flag = True
        self.status.status = "cancelled"
        self.status.completed_at = datetime.now(timezone.utc).isoformat()
        self.status.error = "Job was cancelled by user"
        self.broadcast({"type": "status", "phase": "cancelled", "message": "Analysis cancelled by user."})
        return True

    def is_cancelled(self) -> bool:
        return self._cancel_flag

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
        # Replay event history for reconnecting clients
        for ev in self.event_history:
            q.put_nowait(ev)
        if self.status.status in ("completed", "failed", "cancelled"):
            q.put_nowait(None)
        self.subscribers.append(q)
        return q

    def remove_subscriber(self, q: asyncio.Queue[Optional[dict]]) -> None:
        if q in self.subscribers:
            self.subscribers.remove(q)


class JobManager:
    def __init__(self, store: HistoryStore):
        self.store = store
        self.active_jobs: Dict[str, ActiveJob] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_JOBS)

    def create_job(self, req: AnalyzeRequest) -> ActiveJob:
        job_id = uuid.uuid4().hex[:10]
        job = ActiveJob(job_id=job_id, request=req)
        self.active_jobs[job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[ActiveJob]:
        return self.active_jobs.get(job_id)

    async def start_job(self, job: ActiveJob, analyzer: Optional[RateLimitAnalyzer] = None) -> None:
        analyzer = analyzer or RateLimitAnalyzer()

        async def _run():
            async with self._semaphore:
                if job.is_cancelled():
                    return

                job.status.status = "running"
                job.status.started_at = datetime.now(timezone.utc).isoformat()
                job.status.configured_budget = job.request.request_budget
                job.status.remaining_budget = job.request.request_budget
                job.broadcast({"type": "status", "phase": "running", "message": "Starting analysis..."})

                def on_event(ev: dict) -> None:
                    if ev.get("type") == "progress":
                        job.status.configured_budget = ev.get("budget", job.request.request_budget)
                        job.status.dispatched_requests = ev.get("dispatched", 0)
                        job.status.completed_requests = ev.get("completed", 0)
                        job.status.in_progress_requests = ev.get("in_progress", 0)
                        job.status.remaining_budget = ev.get("remaining", 0)
                        job.status.elapsed_sec = ev.get("elapsed_sec", 0.0)
                        job.status.estimated_remaining_sec = ev.get("estimated_remaining_sec")
                        job.status.current_phase = ev.get("current_phase", job.status.current_phase)
                        if job.status.configured_budget > 0:
                            job.status.progress_pct = min(99, int((job.status.completed_requests / job.status.configured_budget) * 100))
                    elif ev.get("type") == "probe":
                        job.status.probes_count += 1
                    elif ev.get("type") == "status":
                        job.status.current_phase = ev.get("phase", job.status.current_phase)
                    job.broadcast(ev)

                try:
                    res = await analyzer.run(
                        req=job.request,
                        on_event=on_event,
                        is_cancelled=job.is_cancelled,
                    )
                    job.result = res
                    self.store.save(res)
                    job.status.status = res.profile.status  # "completed" or "partial"
                    job.status.progress_pct = 100 if res.profile.status == "completed" else min(99, int((res.profile.request_counters.completed_requests / max(1, res.profile.configured_budget or job.request.request_budget)) * 100))
                    job.status.completed_at = datetime.now(timezone.utc).isoformat()
                    job.status.summary = {
                        "status": res.profile.status,
                        "completion_message": res.profile.completion_message,
                        "pattern": res.profile.detected_pattern,
                        "recommended_interval_sec": res.profile.recommended_interval_sec,
                        "safe_burst_size": res.profile.safe_burst_size,
                        "verified_passed": res.profile.verification_passed,
                        "dispatched_requests": res.profile.request_counters.dispatched_requests,
                        "configured_budget": res.profile.request_counters.configured_budget,
                    }
                except asyncio.CancelledError:
                    job.status.status = "cancelled"
                    job.status.completed_at = datetime.now(timezone.utc).isoformat()
                    job.status.error = "Analysis cancelled"
                except Exception as exc:
                    job.status.status = "failed"
                    job.status.completed_at = datetime.now(timezone.utc).isoformat()
                    job.status.error = str(exc)
                    job.broadcast({"type": "error", "message": str(exc)})
                finally:
                    job.broadcast(None)

        job.task = asyncio.create_task(_run())
