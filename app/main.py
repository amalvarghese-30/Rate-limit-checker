from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse

from app.config import API_KEY, BASE_DIR
from app.jobs import JobManager
from app.models import AnalyzeRequest, ExecutionRequest
from app.pacing import PacingEngine
from app.storage import HistoryStore

FRONTEND_HTML = BASE_DIR / "frontend" / "index.html"

app = FastAPI(
    title="Rate Limit Checker",
    description="Multi-phase rate-limit pattern discovery, recovery verification, and adaptive client generation.",
    version="2.0.0",
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = HistoryStore()
job_manager = JobManager(store=store)
pacing_engine = PacingEngine(store=store)

try:
    from mock_target import app as dummy_app
    app.mount("/dummy", dummy_app)
except ImportError:
    pass


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Optional API Key Authentication
async def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    if not API_KEY:
        return
    token = x_api_key
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if token != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )


@app.get("/", response_class=HTMLResponse)
async def index():
    if not FRONTEND_HTML.exists():
        raise HTTPException(status_code=404, detail="Frontend index.html not found")
    return FRONTEND_HTML.read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    try:
        # Check SQLite connection
        stats = store.get_dashboard_stats()
        db_healthy = True
    except Exception:
        db_healthy = False

    return {
        "status": "healthy" if db_healthy else "degraded",
        "version": "2.0.0",
        "database": "connected" if db_healthy else "error",
        "active_jobs": len(job_manager.active_jobs),
    }


@app.get("/api/stats")
async def stats():
    return store.get_dashboard_stats()


@app.post("/api/analyze", dependencies=[Depends(verify_api_key)])
async def create_analysis(req: AnalyzeRequest):
    """
    Submits a new analysis job. The job runs in the background independent
    of client disconnects or browser refreshes.
    """
    job = job_manager.create_job(req)
    await job_manager.start_job(job)
    return {
        "job_id": job.job_id,
        "status": job.status.model_dump(),
    }


@app.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    job = job_manager.get_job(job_id)
    if not job:
        # Check historical runs in DB
        res = store.get(job_id)
        if res:
            return {
                "job_id": job_id,
                "status": "completed",
                "progress_pct": 100,
                "summary": {
                    "pattern": res.profile.detected_pattern,
                    "recommended_interval_sec": res.profile.recommended_interval_sec,
                    "safe_burst_size": res.profile.safe_burst_size,
                    "verified_passed": res.profile.verification_passed,
                },
            }
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "job_id": job_id,
        "status": job.status.model_dump(),
    }


@app.get("/api/jobs/{job_id}/stream")
async def stream_job_events(job_id: str):
    """
    SSE stream yielding real-time probe events and status changes.
    Supports reconnection and history replay for disconnected clients.
    """
    job = job_manager.get_job(job_id)
    if not job:
        # If already completed in store, yield cached result
        res = store.get(job_id)
        if res:
            async def single_event_gen():
                yield f"data: {json.dumps({'type': 'complete', 'result': res.model_dump()})}\n\n"
            return StreamingResponse(single_event_gen(), media_type="text/event-stream")
        raise HTTPException(status_code=404, detail="Job not found")

    queue = job.add_subscriber()

    async def event_generator():
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            job.remove_subscriber(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/jobs/{job_id}/cancel", dependencies=[Depends(verify_api_key)])
async def cancel_job(job_id: str):
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Active job not found")
    cancelled = job.cancel()
    return {"job_id": job_id, "cancelled": cancelled}


@app.get("/api/jobs/{job_id}/result")
async def get_job_result(job_id: str):
    # Check active jobs first
    job = job_manager.get_job(job_id)
    if job and job.result:
        return job.result.model_dump()

    # Check database
    res = store.get(job_id)
    if not res:
        raise HTTPException(status_code=404, detail="Analysis result not found")
    return res.model_dump()


# Legacy / direct SSE endpoint for backward compatibility
@app.post("/api/analyze/stream", dependencies=[Depends(verify_api_key)])
async def analyze_stream_legacy(req: AnalyzeRequest):
    job = job_manager.create_job(req)
    await job_manager.start_job(job)
    queue = job.add_subscriber()

    async def event_generator():
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            job.remove_subscriber(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/history", dependencies=[Depends(verify_api_key)])
async def history(limit: int = Query(25, ge=1)):
    return {"items": store.list_recent(limit=limit)}


@app.get("/api/history/{job_id}", dependencies=[Depends(verify_api_key)])
async def get_history_detail(job_id: str):
    result = store.get(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Run not found in history")
    return result.model_dump()


@app.delete("/api/history/{job_id}", dependencies=[Depends(verify_api_key)])
async def delete_history_entry(job_id: str):
    if not store.delete(job_id):
        raise HTTPException(status_code=404, detail="Run not found in history")
    return {"deleted": True, "job_id": job_id}


@app.get("/api/export/{job_id}")
async def export_profile(job_id: str):
    result = store.get(job_id)
    if not result:
        job = job_manager.get_job(job_id)
        if job and job.result:
            result = job.result
    if not result:
        raise HTTPException(status_code=404, detail="Run not found")

    profile_dict = result.profile.model_dump()
    return JSONResponse(
        content=profile_dict,
        headers={"Content-Disposition": f'attachment; filename="ratelimit-profile-{job_id}.json"'},
    )


@app.get("/api/generate-client/{job_id}")
async def generate_client_code(job_id: str):
    result = store.get(job_id)
    if not result:
        job = job_manager.get_job(job_id)
        if job and job.result:
            result = job.result
    if not result:
        raise HTTPException(status_code=404, detail="Run not found")

    p = result.profile
    interval = p.recommended_interval_sec
    burst = p.safe_burst_size
    target_url = p.target_url
    method = p.method
    sending_title = p.pattern_classification.sending_pattern_title

    body_snippet = ""
    call_kwargs = ""
    if method in ("POST", "PUT", "PATCH") and getattr(p, "request_body", None):
        body_snippet = f'\nPAYLOAD = {repr(p.request_body)}\nHEADERS = {{"Content-Type": {repr(getattr(p, "content_type", "application/json"))}}}\n'
        call_kwargs = ", content=PAYLOAD.encode('utf-8'), headers=HEADERS"

    code = f'''# Generated by Rate Limit Checker for {target_url}
# Method: {method} | Blocking Pattern: {p.detected_pattern} (Confidence: {p.pattern_confidence})
# Sending Pattern: {sending_title}
# Safe Burst Size: {burst} | Recommended Interval: {interval}s (~{p.recommended_rpm:.0f} req/min)
# NOTICE: This client enforces empirical rate-limiting based on observed test behaviour.

import asyncio
import httpx
from app.client import RateControlledClient

# Initialize controller with verified profile settings
client_ctrl = RateControlledClient(
    interval_sec={interval},
    safe_burst_size={burst},
    jitter_pct=0.15,
)
{body_snippet}
async def fetch_target(url: str):
    async with httpx.AsyncClient(timeout=15.0) as http:
        response = await client_ctrl.request(http, "{method}", url{call_kwargs})
        print(f"Status: {{response.status_code}} | Latency: {{response.elapsed.total_seconds() * 1000:.1f}}ms")
        return response

async def main():
    # Example: Send 5 paced {method} requests
    tasks = [fetch_target("{target_url}") for _ in range(5)]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
'''
    return PlainTextResponse(code, media_type="text/x-python")


# ==============================================================================
# Module E: Automatic Pacing Engine Endpoints
# ==============================================================================

@app.post("/api/executions", dependencies=[Depends(verify_api_key)])
async def create_execution(req: ExecutionRequest):
    """
    Starts an automatic request pacing execution based on an approved analysis profile.
    """
    res = store.get(req.job_id)
    if not res:
        job = job_manager.get_job(req.job_id)
        if job and job.result:
            res = job.result
    if not res:
        raise HTTPException(status_code=404, detail="Analysis profile not found for this job ID")

    execution = pacing_engine.create_execution(res.profile, req)
    await pacing_engine.start_execution(execution)
    return {
        "execution_id": execution.execution_id,
        "status": execution.status.model_dump(),
    }


@app.get("/api/executions/{exec_id}")
async def get_execution_status(exec_id: str):
    execution = pacing_engine.get_execution(exec_id)
    if execution:
        return {
            "execution_id": exec_id,
            "status": execution.status.model_dump(),
            "records": [r.model_dump() for r in execution.records],
        }
    saved = store.get_execution(exec_id)
    if saved:
        return saved
    raise HTTPException(status_code=404, detail="Execution not found")


@app.post("/api/executions/{exec_id}/pause", dependencies=[Depends(verify_api_key)])
async def pause_execution(exec_id: str):
    execution = pacing_engine.get_execution(exec_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Active execution not found")
    execution.pause()
    return {"execution_id": exec_id, "status": execution.status.status}


@app.post("/api/executions/{exec_id}/resume", dependencies=[Depends(verify_api_key)])
async def resume_execution(exec_id: str):
    execution = pacing_engine.get_execution(exec_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Active execution not found")
    execution.resume()
    return {"execution_id": exec_id, "status": execution.status.status}


@app.post("/api/executions/{exec_id}/stop", dependencies=[Depends(verify_api_key)])
async def stop_execution(exec_id: str):
    execution = pacing_engine.get_execution(exec_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Active execution not found")
    execution.stop()
    return {"execution_id": exec_id, "status": execution.status.status}


@app.get("/api/executions/{exec_id}/stream")
async def stream_execution_events(exec_id: str):
    execution = pacing_engine.get_execution(exec_id)
    if not execution:
        saved = store.get_execution(exec_id)
        if saved:
            async def single_saved_gen():
                yield f"data: {json.dumps({'type': 'execution_complete', 'status': saved})}\n\n"
            return StreamingResponse(single_saved_gen(), media_type="text/event-stream")
        raise HTTPException(status_code=404, detail="Execution not found")

    queue = execution.add_subscriber()

    async def event_generator():
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            execution.remove_subscriber(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/executions", dependencies=[Depends(verify_api_key)])
async def list_executions(limit: int = Query(20, ge=1, le=100)):
    active_list = [e.status.model_dump() for e in pacing_engine.active_executions.values()]
    saved_list = store.list_executions(limit=limit)
    seen = set()
    merged = []
    for item in active_list + saved_list:
        eid = item.get("execution_id")
        if eid and eid not in seen:
            seen.add(eid)
            merged.append(item)
    return {"items": merged[:limit]}


@app.delete("/api/executions/{exec_id}", dependencies=[Depends(verify_api_key)])
async def delete_execution(exec_id: str):
    if not store.delete_execution(exec_id):
        raise HTTPException(status_code=404, detail="Execution not found in history")
    return {"deleted": True, "execution_id": exec_id}

