"""
app/core/exceptions.py
───────────────────────
Centralised exception handlers registered on the FastAPI app.

Goals:
  1. Never leak stack traces or internal details to the client (OWASP A05).
  2. Return consistently structured error bodies for all error types.
  3. Log the full error server-side with request context for debugging.

Error body shape (always):
    {
        "code":    "VALIDATION_ERROR",
        "message": "Human-readable summary",
        "details": [...]   // optional, field-level errors
    }
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from jose import JWTError
from sqlalchemy.exc import IntegrityError

from app.core.logging import get_logger

logger = get_logger(__name__)


def _error_response(
    status_code: int,
    code:        str,
    message:     str,
    details:     list | None = None,
) -> JSONResponse:
    body: dict = {"code": code, "message": message}
    if details:
        body["details"] = details
    return JSONResponse(status_code=status_code, content=body)


def register_exception_handlers(app: FastAPI) -> None:
    """Attach all exception handlers to *app*."""

    # ── Pydantic / FastAPI validation errors (422) ────────────────────────────────
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Translate Pydantic errors into a clean list; strip internal field paths
        details = [
            {
                "field":   " → ".join(str(loc) for loc in err["loc"] if loc != "body"),
                "message": err["msg"],
                "type":    err["type"],
            }
            for err in exc.errors()
        ]
        logger.warning(
            "validation_error",
            path=str(request.url.path),
            errors=details,
        )
        return _error_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code="VALIDATION_ERROR",
            message="One or more fields failed validation.",
            details=details,
        )

    # ── HTTPException (includes our explicit raises) ──────────────────────────────
    from fastapi.exceptions import HTTPException

    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: HTTPException
    ) -> JSONResponse:
        # Map HTTP status codes to short error codes
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            409: "CONFLICT",
            422: "UNPROCESSABLE_ENTITY",
            423: "LOCKED",
            429: "TOO_MANY_REQUESTS",
            500: "INTERNAL_SERVER_ERROR",
        }
        code = code_map.get(exc.status_code, "HTTP_ERROR")
        if exc.status_code >= 500:
            logger.error("http_error", status=exc.status_code, detail=exc.detail,
                         path=str(request.url.path))
        elif exc.status_code >= 400:
            logger.warning("http_error", status=exc.status_code, code=code,
                           path=str(request.url.path))
        return _error_response(
            status_code=exc.status_code,
            code=code,
            message=str(exc.detail),
        )

    # ── Database integrity errors (e.g. unique constraint) ────────────────────────
    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: IntegrityError
    ) -> JSONResponse:
        logger.error(
            "db_integrity_error",
            path=str(request.url.path),
            error=str(exc.orig),   # log the real error server-side only
        )
        # Return generic message – do NOT expose DB details to client
        return _error_response(
            status_code=status.HTTP_409_CONFLICT,
            code="CONFLICT",
            message="A resource with the provided data already exists.",
        )

    # ── JWT errors ────────────────────────────────────────────────────────────────
    @app.exception_handler(JWTError)
    async def jwt_error_handler(
        request: Request, exc: JWTError
    ) -> JSONResponse:
        return _error_response(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="UNAUTHORIZED",
            message="Invalid or expired token.",
        )

    # ── Catch-all (500) ───────────────────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception(
            "unhandled_exception",
            path=str(request.url.path),
            exc_type=type(exc).__name__,
        )
        # NEVER leak internal details to the client
        return _error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected error occurred. Please try again later.",
        )
