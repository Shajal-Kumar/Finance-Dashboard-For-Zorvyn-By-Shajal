"""
app/api/v1/endpoints/auth.py
──────────────────────────────
Authentication endpoints.

POST /auth/login   – exchange credentials for tokens
POST /auth/refresh – rotate refresh token, get new access token
POST /auth/logout  – revoke refresh token

Security choices:
  • Refresh token is returned as an HttpOnly, Secure, SameSite=Strict cookie
    so JavaScript cannot access it (mitigates XSS token theft).
  • Access token is returned in the JSON body (short-lived; SPA stores in memory
    only – NOT localStorage).
  • CSRF token is validated on /refresh and /logout (state-mutating endpoints).
"""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import verify_csrf_token
from app.db.session import get_db
from app.schemas import LoginRequest, TokenResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])

_REFRESH_COOKIE_NAME = "refresh_token"


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Obtain access + refresh tokens",
    status_code=status.HTTP_200_OK,
)
async def login(
    credentials: LoginRequest,
    request:     Request,
    response:    Response,
    db:          AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Exchange email/password for an access token (JSON body) and a refresh
    token (HttpOnly cookie).
    """
    token_response, refresh_token = await AuthService.login(credentials, db, request)

    _set_refresh_cookie(response, refresh_token)
    return token_response


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token",
    dependencies=[Depends(verify_csrf_token)],
)
async def refresh_token(
    request:                    Request,
    response:                   Response,
    db:                         AsyncSession = Depends(get_db),
    refresh_token_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
) -> TokenResponse:
    """
    Use the refresh token cookie to obtain a new access token.
    The old refresh token is revoked and a new one is issued (rotation).
    """
    if not refresh_token_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    token_response, new_refresh = await AuthService.refresh(refresh_token_cookie, db, request)
    _set_refresh_cookie(response, new_refresh)
    return token_response


@router.post(
    "/logout",
    summary="Revoke refresh token",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    dependencies=[Depends(verify_csrf_token)],
)
async def logout(
    response:             Response,
    db:                   AsyncSession = Depends(get_db),
    refresh_token_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
) -> None:
    """
    Revoke the current refresh token and clear the cookie.
    Returns 204 regardless of whether a token was found (idempotent).
    """
    if refresh_token_cookie:
        await AuthService.logout(refresh_token_cookie, db)

    _clear_refresh_cookie(response)


# ── Cookie helpers ────────────────────────────────────────────────────────────────

from app.core.config import settings, Environment


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,          # JavaScript cannot access this cookie (XSS protection)
        secure=settings.APP_ENVIRONMENT != Environment.DEVELOPMENT,
        samesite="strict",      # CSRF protection
        max_age=settings.JWT_REFRESH_TOKEN_TTL_DAYS * 86_400,
        path="/api/v1/auth",    # cookie only sent to auth endpoints
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=_REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
    )
