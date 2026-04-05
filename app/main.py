"""
app/main.py
────────────
FastAPI application factory.

Responsibilities:
  • Create the FastAPI app instance with metadata
  • Register all middleware (order matters – outermost = first on request)
  • Configure CORS
  • Mount the v1 API router
  • Register global exception handlers
  • Lifespan handler: run DB migrations on startup

Middleware execution order (request → response):
  ProcessTimeMiddleware        (outermost)
  RequestIDMiddleware
  SecurityHeadersMiddleware
  CSRFCookieMiddleware
  SlowAPI rate limiting        (innermost, applied per-route)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import engine
from app.db.base import Base
from app.middleware.security import (
    CSRFCookieMiddleware,
    ProcessTimeMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)

# ── Logging ───────────────────────────────────────────────────────────────────────

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    ),
)
logger = structlog.get_logger()


# ── Rate Limiter ──────────────────────────────────────────────────────────────────

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
)


# ── Lifespan ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Runs once on startup and once on shutdown.
    Creates all database tables if they do not exist (dev convenience).
    In production, use Alembic migrations instead of create_all.
    """
    logger.info("startup", environment=settings.APP_ENVIRONMENT, version=settings.APP_VERSION)

    async with engine.begin() as conn:
        # Import all models so SQLAlchemy knows about them before create_all
        import app.models  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)

    logger.info("database_tables_ready")
    yield
    logger.info("shutdown")
    await engine.dispose()


# ── Application Factory ───────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Finance Dashboard API — role-based financial record management "
            "with dashboard analytics."
        ),
        docs_url="/docs"   if settings.APP_ENVIRONMENT != "production" else None,
        redoc_url="/redoc" if settings.APP_ENVIRONMENT != "production" else None,
        openapi_url="/openapi.json" if settings.APP_ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # ── Rate limiter state ────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── CORS ──────────────────────────────────────────────────────────────────────
    # Allow only explicitly listed origins.
    # credentials=True is required for the browser to send cookies (refresh token).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID", "X-Process-Time"],
    )

    # ── Custom security middleware ────────────────────────────────────────────────
    # Registered in reverse order: last registered = outermost wrapper.
    app.add_middleware(ProcessTimeMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CSRFCookieMiddleware)
    app.add_middleware(SlowAPIMiddleware)

    # ── Routers ───────────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # ── Exception Handlers ────────────────────────────────────────────────────────
    _register_exception_handlers(app)

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """
    Global handlers that translate common exceptions into structured JSON responses.
    This ensures all error shapes are consistent regardless of where the error occurs.
    """

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """
        Pydantic validation errors → 422 with a structured list of field errors.
        Strips internal detail noise so responses are safe to return to clients.
        """
        errors = [
            {
                "code":    "validation_error",
                "field":   " → ".join(str(loc) for loc in err["loc"]),
                "message": err["msg"],
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"errors": errors},
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: IntegrityError
    ) -> JSONResponse:
        """
        Database unique-constraint violations → 409 Conflict.
        The raw DB error is logged server-side but NOT returned to the client
        (it may contain schema details).
        """
        logger.warning("db_integrity_error", path=request.url.path, error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"code": "conflict", "message": "A conflicting record already exists."},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all: log the full traceback server-side, return a generic 500.
        Never expose internal error detail to the client (A05 Security Misconfiguration).
        """
        logger.exception(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": "internal_error", "message": "An unexpected error occurred."},
        )

    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health_check() -> dict:
        """Liveness probe endpoint for load balancers and container orchestration."""
        return {"status": "ok", "version": settings.APP_VERSION}


# ── Entry Point ───────────────────────────────────────────────────────────────────

app = create_app()
