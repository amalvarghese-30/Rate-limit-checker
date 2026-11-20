from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application Configuration
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")

# Database
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(DATA_DIR / "history.db")))

# Security & Network Controls
# Defaults to true in local development to allow testing local mock servers (127.0.0.1:8001).
# In production, ALLOW_LOCAL_TARGETS is set to false in docker-compose.yml / .env to block SSRF against internal networks.
ALLOW_LOCAL_TARGETS = os.getenv("ALLOW_LOCAL_TARGETS", "true").lower() in ("true", "1", "yes")
MAX_CONCURRENT_JOBS = int(os.getenv("MAX_CONCURRENT_JOBS", "5"))
MAX_RESPONSE_BODY_BYTES = int(os.getenv("MAX_RESPONSE_BODY_BYTES", str(64 * 1024)))  # 64 KB limit
DEFAULT_TIMEOUT_SEC = float(os.getenv("DEFAULT_TIMEOUT_SEC", "10.0"))
MAX_ANALYSIS_DURATION_SEC = float(os.getenv("MAX_ANALYSIS_DURATION_SEC", "60.0"))

# Optional API authentication for internet-facing deployments
API_KEY = os.getenv("API_KEY", "")
