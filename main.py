"""
main.py
────────
FastAPI application factory + startup/shutdown lifecycle.

Middleware registration order matters: each layer wraps the one below it.
Request travels inward (top → bottom); response travels outward (bottom → top).

  ProcessTimeMiddleware       ← outermost: measures total elapsed time
  RequestIDMiddleware         ← attaches/propagates X-Request-ID
  SecurityHeadersMiddleware   ← appends security headers to every response
  CSRFCookieMiddleware        ← issues csrf_token cookie when absent
  CORSMiddleware              ← handles preflight + CORS headers
  SlowAPI (rate limiter)      ← enforced per-IP before route logic runs
  [routes]                    ← innermost: actual business logic
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.middleware.security import (
    CSRFCookieMiddleware,
    ProcessTimeMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)

logger = get_logger(__name__)


# ── Rate Limiter ──────────────────────────────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    storage_uri="memory://",   # swap for "redis://..." in production
)


# ── Database Initialisation ───────────────────────────────────────────────────────

async def _initialise_database() -> None:
    """Create all tables and seed a default admin user if the DB is empty."""
    from app.db.session import engine
    from app.db.base import Base

    # Import all models so SQLAlchemy knows about them
    import app.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _seed_default_admin()


async def _seed_default_admin() -> None:
    """
    Create a bootstrap admin account if no users exist yet.

    Credentials are read from environment variables so they are never
    hardcoded in source.  Defaults are only for local development.
    """
    from app.db.session import AsyncSessionLocal
    from app.models import User, UserRole
    from app.core.security import hash_password
    from sqlalchemy import select

    admin_email    = os.getenv("BOOTSTRAP_ADMIN_EMAIL",    "admin@finance.local")
    admin_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe123!")

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User.id).limit(1))
        if result.scalar_one_or_none() is not None:
            return   # users already exist – skip seeding

        admin = User(
            email=admin_email,
            password_hash=hash_password(admin_password),
            full_name="Bootstrap Admin",
            role=UserRole.ADMIN,
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        logger.info(
            "bootstrap_admin_created",
            email=admin_email,
            note="Change this password immediately in production",
        )


# ── Application Lifespan ──────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic executed by FastAPI's lifespan protocol."""
    configure_logging()
    logger.info("application_starting", environment=settings.APP_ENVIRONMENT)

    await _initialise_database()

    logger.info(
        "application_ready",
        version=settings.APP_VERSION,
        api_prefix=settings.API_V1_PREFIX,
    )
    yield

    # Shutdown
    from app.db.session import engine
    await engine.dispose()
    logger.info("application_stopped")


# ── App Factory ───────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Finance Dashboard API – role-based access control, "
            "financial record management, and dashboard analytics."
        ),
        docs_url="/docs"      if settings.APP_ENVIRONMENT != "production" else None,
        redoc_url="/redoc"    if settings.APP_ENVIRONMENT != "production" else None,
        openapi_url="/openapi.json" if settings.APP_ENVIRONMENT != "production" else None,
        swagger_ui_parameters={"syntaxHighlight": False},
        lifespan=lifespan,
    )

    # ── Rate Limiter ──────────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # ── CORS ──────────────────────────────────────────────────────────────────────
    # Must be registered BEFORE SecurityHeadersMiddleware so that CORS headers
    # are present on preflight (OPTIONS) responses.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,            # required for cookie-based refresh tokens
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Process-Time"],
        max_age=600,                       # cache preflight for 10 minutes
    )

    # ── Security Middleware Stack ─────────────────────────────────────────────────
    # Registered in reverse order (FastAPI applies them last-registered-first)
    app.add_middleware(ProcessTimeMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CSRFCookieMiddleware)

    # ── Exception Handlers ────────────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routes ────────────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # Health check (no auth, no rate limit – used by load balancers)
    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health_check():
        return {"status": "ok", "version": settings.APP_VERSION}

    return app


app = create_app()
