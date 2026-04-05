"""
tests/conftest.py
──────────────────
Session-wide pytest fixtures shared across all test modules.

Sets environment variables BEFORE any app module is imported so that
Pydantic-Settings picks up the test values on first import.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Ensure project root is importable ────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Override settings for the test environment ────────────────────────────────────
# Must be set before any app.core.config import happens.
os.environ.setdefault("APP_ENVIRONMENT",          "development")
os.environ.setdefault("DEBUG",                    "true")
os.environ.setdefault("DATABASE_URL",             "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY",           "test-secret-key-not-for-production-use-at-all")
os.environ.setdefault("BCRYPT_ROUNDS",            "4")   # fast hashing in tests
os.environ.setdefault("RATE_LIMIT_DEFAULT",       "10000/minute")  # don't throttle tests
os.environ.setdefault("RATE_LIMIT_AUTH",          "10000/minute")
os.environ.setdefault("RATE_LIMIT_WRITE",         "10000/minute")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL",    "admin@test.com")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "AdminPass123!")
os.environ.setdefault("LOG_LEVEL",                "WARNING")  # quiet test output
