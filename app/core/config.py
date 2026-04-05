"""
app/core/config.py
──────────────────
Central configuration loaded from environment variables via Pydantic-Settings.

All variables are explicitly typed, documented, and have safe defaults for local
development.  Production deployments MUST override every SECRET_* variable.

Environment variable precedence:
  1. OS environment variables
  2. .env file (loaded automatically)
  3. Pydantic field defaults (dev-only defaults)
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Environment Enum ─────────────────────────────────────────────────────────────

class Environment(StrEnum):
    DEVELOPMENT = "development"
    STAGING     = "staging"
    PRODUCTION  = "production"


# ── Settings Model ───────────────────────────────────────────────────────────────

class Settings(BaseSettings):
    """
    All application configuration in one place.
    Keep secrets out of source control – use a .env file or secrets manager.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="forbid",           # fail fast on typos in .env
    )

    # ── Application ──────────────────────────────────────────────────────────────
    APP_NAME:        str         = "Finance Dashboard API"
    APP_VERSION:     str         = "1.0.0"
    APP_ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG:           bool        = False

    # ── API ──────────────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    # Comma-separated list of allowed origins for CORS
    # Example: "https://app.example.com,https://admin.example.com"
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

    # ── Database ─────────────────────────────────────────────────────────────────
    # SQLite for dev, PostgreSQL for staging/prod.
    # Format (SQLite):    sqlite+aiosqlite:///./data/finance.db
    # Format (Postgres):  postgresql+asyncpg://user:pass@host:5432/dbname
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/finance.db"

    # Pool settings (ignored by SQLite)
    DATABASE_POOL_SIZE:     int = 10
    DATABASE_MAX_OVERFLOW:  int = 20
    DATABASE_POOL_TIMEOUT:  int = 30   # seconds

    # ── Authentication / JWT ─────────────────────────────────────────────────────
    # CRITICAL: Replace with a strong random secret in production.
    # Generate with: python -c "import secrets; print(secrets.token_hex(64))"
    JWT_SECRET_KEY:       str = Field(
        default_factory=lambda: secrets.token_hex(64),
        description="HS256 signing key – MUST be overridden in production",
    )
    JWT_ALGORITHM:        str = "HS256"
    JWT_ACCESS_TOKEN_TTL_MINUTES:  int = 30    # short-lived access token
    JWT_REFRESH_TOKEN_TTL_DAYS:    int = 7     # longer-lived refresh token

    # ── Password Policy ───────────────────────────────────────────────────────────
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_MAX_LENGTH: int = 128   # prevent bcrypt DoS via huge strings
    BCRYPT_ROUNDS:       int = 12    # work factor – increase over time

    # ── Rate Limiting ─────────────────────────────────────────────────────────────
    # Applied per-IP.  Expressed as "count/window" where window is
    # second | minute | hour | day | month | year.
    RATE_LIMIT_DEFAULT:   str = "100/minute"
    RATE_LIMIT_AUTH:      str = "10/minute"    # tighter limit on login / token endpoints
    RATE_LIMIT_WRITE:     str = "30/minute"    # create / update / delete endpoints

    # ── Security Headers ──────────────────────────────────────────────────────────
    # Content-Security-Policy – tighten per deployment
    CSP_POLICY: str = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    HSTS_MAX_AGE_SECONDS: int = 31_536_000   # 1 year

    # ── Pagination ────────────────────────────────────────────────────────────────
    PAGINATION_DEFAULT_PAGE_SIZE: int = 20
    PAGINATION_MAX_PAGE_SIZE:     int = 100

    # ── Soft-Delete ───────────────────────────────────────────────────────────────
    # When True, DELETE endpoints mark records as deleted_at instead of removing them.
    ENABLE_SOFT_DELETE: bool = True

    # ── Logging ───────────────────────────────────────────────────────────────────
    LOG_LEVEL:  str                             = "INFO"
    LOG_FORMAT: Literal["json", "console"]      = "console"

    # ── Validators ───────────────────────────────────────────────────────────────

    @field_validator("APP_ENVIRONMENT", mode="before")
    @classmethod
    def normalise_env(cls, v: str) -> str:
        return v.lower()

    @model_validator(mode="after")
    def warn_insecure_defaults_in_production(self) -> "Settings":
        if self.APP_ENVIRONMENT == Environment.PRODUCTION:
            if self.DEBUG:
                raise ValueError("DEBUG must be False in production")
        return self


# ── Singleton ─────────────────────────────────────────────────────────────────────

settings = Settings()
