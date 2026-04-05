"""
app/middleware/security.py
───────────────────────────
ASGI middleware stack for defence-in-depth HTTP security.

Each middleware layer is documented with the OWASP control it addresses.

Middleware executed in registration order (outermost = first on request, last on response).
"""

from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.security import generate_csrf_token


# ── Security Headers Middleware ───────────────────────────────────────────────────
#
# OWASP:
#   A05 Security Misconfiguration – Missing security headers
#   A03 Injection – Content-Security-Policy prevents injected script execution

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Append HTTP security headers to every response.

    Headers applied:
      X-Content-Type-Options     – prevents MIME-type sniffing (XSS vector)
      X-Frame-Options            – clickjacking protection
      X-XSS-Protection           – legacy XSS filter (belt + suspenders)
      Content-Security-Policy    – script execution policy
      Referrer-Policy            – controls referrer header leakage
      Permissions-Policy         – disable unused browser features
      Strict-Transport-Security  – enforce HTTPS (production only)
      Cache-Control              – prevent caching of API responses
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Content-Security-Policy"] = settings.CSP_POLICY
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"]        = "no-cache"

        if settings.APP_ENVIRONMENT != "development":
            response.headers["Strict-Transport-Security"] = (
                f"max-age={settings.HSTS_MAX_AGE_SECONDS}; includeSubDomains; preload"
            )

        return response


# ── CSRF Cookie Middleware ─────────────────────────────────────────────────────────
#
# OWASP A01 – Broken Access Control: CSRF exploits authenticated sessions.
#
# Pattern: double-submit cookie
#   1. Server sets csrf_token cookie (HttpOnly=False so JS can read it).
#   2. SPA copies cookie value into X-CSRF-Token header on mutating requests.
#   3. The verify_csrf_token dependency (in dependencies.py) validates they match.
#
# GET/HEAD/OPTIONS are safe methods and do NOT require a CSRF token.

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class CSRFCookieMiddleware(BaseHTTPMiddleware):
    """
    Issue a new CSRF token cookie on every response that does not already have one.
    The cookie value is random and non-predictable; it does not expire within the
    browser session so the SPA can read it after a hard refresh.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Only set the cookie if it is not already present
        if "csrf_token" not in request.cookies:
            token = generate_csrf_token()
            response.set_cookie(
                key="csrf_token",
                value=token,
                httponly=False,     # MUST be readable by JavaScript
                samesite="strict",  # defence-in-depth
                secure=settings.APP_ENVIRONMENT != "development",
                max_age=86_400,     # 1 day – re-issued automatically
            )

        return response


# ── Request ID Middleware ──────────────────────────────────────────────────────────
#
# Assigns a unique ID to each request for distributed tracing and log correlation.

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Attach X-Request-ID to every request and response.
    If the client supplies a request ID it is used; otherwise a new UUID is generated.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Make the request ID available to route handlers via request.state
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ── Process Time Middleware ────────────────────────────────────────────────────────

class ProcessTimeMiddleware(BaseHTTPMiddleware):
    """Append X-Process-Time (ms) header – useful for performance monitoring."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start    = time.perf_counter()
        response = await call_next(request)
        elapsed  = (time.perf_counter() - start) * 1000
        response.headers["X-Process-Time"] = f"{elapsed:.2f}ms"
        return response
