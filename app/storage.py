from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import DATABASE_PATH
from app.models import AnalysisResult, RateLimitProfile
from app.security import mask_sensitive_headers

CURRENT_SCHEMA_VERSION = 2


class HistoryStore:
    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency & safe write performance
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            # Metadata table for schema versioning
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_info (
                    version INTEGER PRIMARY KEY
                )
                """
            )

            # Core analysis runs table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    job_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    method TEXT NOT NULL DEFAULT 'GET',
                    detected_pattern TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    recommended_interval_sec REAL NOT NULL,
                    recommended_rps REAL NOT NULL DEFAULT 1.0,
                    safe_burst_size INTEGER NOT NULL,
                    total_requests INTEGER NOT NULL DEFAULT 0,
                    blocked_requests INTEGER NOT NULL DEFAULT 0,
                    block_rate_pct REAL NOT NULL,
                    verified_passed INTEGER DEFAULT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )

            # Safe schema migrations for existing database columns
            existing_cols = {col["name"] for col in conn.execute("PRAGMA table_info(runs)").fetchall()}
            migrations = [
                ("method", "TEXT NOT NULL DEFAULT 'GET'"),
                ("confidence", "TEXT NOT NULL DEFAULT 'medium'"),
                ("recommended_rps", "REAL NOT NULL DEFAULT 1.0"),
                ("total_requests", "INTEGER NOT NULL DEFAULT 0"),
                ("blocked_requests", "INTEGER NOT NULL DEFAULT 0"),
                ("verified_passed", "INTEGER DEFAULT NULL"),
                ("status", "TEXT NOT NULL DEFAULT 'completed'"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE runs ADD COLUMN {col_name} {col_def}")
                    except Exception:
                        pass

            # Indexes for fast querying & sorting
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_target_url ON runs(target_url)")

            # Automatic Pacing executions table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_budget INTEGER NOT NULL,
                    completed_requests INTEGER NOT NULL DEFAULT 0,
                    accepted_requests INTEGER NOT NULL DEFAULT 0,
                    rate_limited_requests INTEGER NOT NULL DEFAULT 0,
                    other_errors INTEGER NOT NULL DEFAULT 0,
                    avg_latency_ms REAL NOT NULL DEFAULT 0.0,
                    current_interval_ms REAL NOT NULL DEFAULT 500.0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT DEFAULT NULL,
                    records_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exec_created_at ON executions(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_exec_job_id ON executions(job_id)")

            # Record or update schema version
            row = conn.execute("SELECT version FROM schema_info").fetchone()
            if not row:
                conn.execute("INSERT INTO schema_info (version) VALUES (?)", (CURRENT_SCHEMA_VERSION,))
            else:
                conn.execute("UPDATE schema_info SET version = ?", (CURRENT_SCHEMA_VERSION,))

    def save(self, result: AnalysisResult) -> None:
        p = result.profile
        # Sanitize sensitive headers in stored JSON
        sanitized_headers = mask_sensitive_headers(p.observed_headers)
        p.observed_headers = sanitized_headers

        verified_int = 1 if p.verification_passed is True else (0 if p.verification_passed is False else None)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    job_id, created_at, target_url, method, detected_pattern,
                    confidence, recommended_interval_sec, recommended_rps, safe_burst_size,
                    total_requests, blocked_requests, block_rate_pct, verified_passed, status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p.job_id,
                    p.created_at,
                    p.target_url,
                    p.method,
                    p.detected_pattern,
                    p.pattern_confidence,
                    p.recommended_interval_sec,
                    p.recommended_rps,
                    p.safe_burst_size,
                    p.total_requests,
                    p.blocked_requests,
                    p.block_rate_pct,
                    verified_int,
                    getattr(p, "status", "completed"),
                    result.model_dump_json(),
                ),
            )

    def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT job_id, created_at, target_url, method, detected_pattern,
                       confidence, recommended_interval_sec, recommended_rps, safe_burst_size,
                       total_requests, blocked_requests, block_rate_pct, verified_passed, status
                FROM runs
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get(self, job_id: str) -> Optional[AnalysisResult]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM runs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if not row:
                return None
            return AnalysisResult.model_validate_json(row["payload_json"])

    def delete(self, job_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM runs WHERE job_id = ?", (job_id,))
            return cur.rowcount > 0

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total_analyses,
                    SUM(CASE WHEN verified_passed = 1 OR (verified_passed IS NULL AND blocked_requests = 0) THEN 1 ELSE 0 END) as successful_analyses,
                    COALESCE(SUM(total_requests), 0) as total_requests_tested,
                    COALESCE(SUM(blocked_requests), 0) as total_blocked_requests,
                    AVG(recommended_interval_sec) as avg_interval_sec
                FROM runs
                """
            ).fetchone()

            if not row or row["total_analyses"] == 0:
                return {
                    "total_analyses": 0,
                    "successful_analyses": 0,
                    "total_requests_tested": 0,
                    "total_blocked_requests": 0,
                    "avg_interval_sec": 0.0,
                    "success_rate_pct": 0.0,
                }

            total = row["total_analyses"]
            success = row["successful_analyses"] or 0
            reqs = row["total_requests_tested"] or 0
            blocked = row["total_blocked_requests"] or 0
            avg_int = round(row["avg_interval_sec"] or 0.0, 2)
            succ_pct = round((success / total) * 100, 1)

            return {
                "total_analyses": total,
                "successful_analyses": success,
                "total_requests_tested": reqs,
                "total_blocked_requests": blocked,
                "avg_interval_sec": avg_int,
                "success_rate_pct": succ_pct,
            }

    def save_execution(self, exec_status: Any, records: List[Any]) -> None:
        with self._connect() as conn:
            records_data = [r.model_dump() if hasattr(r, "model_dump") else r for r in records]
            conn.execute(
                """
                INSERT OR REPLACE INTO executions (
                    execution_id, job_id, target_url, status, request_budget,
                    completed_requests, accepted_requests, rate_limited_requests,
                    other_errors, avg_latency_ms, current_interval_ms,
                    created_at, completed_at, records_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    exec_status.execution_id,
                    exec_status.job_id,
                    exec_status.target_url,
                    exec_status.status,
                    exec_status.request_budget,
                    exec_status.completed_requests,
                    exec_status.accepted_requests,
                    exec_status.rate_limited_requests,
                    exec_status.other_errors,
                    exec_status.avg_latency_ms,
                    exec_status.current_interval_ms,
                    exec_status.created_at,
                    exec_status.completed_at,
                    json.dumps(records_data),
                ),
            )

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()
            if not row:
                return None
            res = dict(row)
            res["records"] = json.loads(res.pop("records_json"))
            return res

    def list_executions(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT execution_id, job_id, target_url, status, request_budget,
                       completed_requests, accepted_requests, rate_limited_requests,
                       other_errors, avg_latency_ms, current_interval_ms,
                       created_at, completed_at
                FROM executions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_execution(self, execution_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM executions WHERE execution_id = ?", (execution_id,))
            return cur.rowcount > 0
