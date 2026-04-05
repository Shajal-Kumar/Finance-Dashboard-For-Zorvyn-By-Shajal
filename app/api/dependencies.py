"""
app/api/dependencies.py
────────────────────────
Reusable FastAPI dependencies injected via Depends().

Separating auth + RBAC logic here keeps route handlers clean and testable.

Covered:
  • get_current_user      – decode JWT, load user from DB
  • RequireRole           – role-based access control guard
  • verify_csrf_token     – CSRF double-submit validation
  • get_pagination        – parse & clamp pagination params
  • get_record_filters    – parse financial record filter params
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Query, Request, status
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import TokenType, decode_token, validate_csrf_token
from app.db.session import get_db
from app.models import TransactionType, User, UserRole
from app.schemas import FinancialRecordFilter, PaginationParams


# ── Token Extraction ──────────────────────────────────────────────────────────────

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    request: Request,
    db:      AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate the Bearer JWT from the Authorization header,
    then return the corresponding active User.

    Raises 401 if the token is missing, expired, or the user does not exist.
    Raises 403 if the user account is inactive.
    """
    auth_header: str | None = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise _CREDENTIALS_EXCEPTION

    token = auth_header.removeprefix("Bearer ").strip()

    try:
        payload = decode_token(token)
    except JWTError:
        raise _CREDENTIALS_EXCEPTION

    # Verify this is an access token (not a refresh token being misused)
    if payload.get("type") != TokenType.ACCESS:
        raise _CREDENTIALS_EXCEPTION

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise _CREDENTIALS_EXCEPTION

    result = await db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None)))
    user   = result.scalar_one_or_none()

    if user is None:
        raise _CREDENTIALS_EXCEPTION

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact your administrator.",
        )

    return user




# ── Role-Based Access Control ─────────────────────────────────────────────────────

class RequireRole:
    """
    Dependency class that enforces role membership.

    Usage:
        @router.post("/records", dependencies=[Depends(RequireRole([UserRole.ADMIN]))])
        async def create_record(...):
            ...

    Or inject the user directly:
        @router.get("/records")
        async def list_records(user: User = Depends(RequireRole([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN]))):
            ...
    """

    def __init__(self, allowed_roles: list[UserRole]) -> None:
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied. Required role(s): "
                    f"{[r.value for r in self.allowed_roles]}."
                ),
            )
        return current_user


# Convenience aliases for the three permission tiers
AnyAuthenticatedUser = RequireRole([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])
AnalystOrAbove       = RequireRole([UserRole.ANALYST, UserRole.ADMIN])
AdminOnly            = RequireRole([UserRole.ADMIN])


# ── CSRF Validation ───────────────────────────────────────────────────────────────

async def verify_csrf_token(
    csrf_cookie: Annotated[str | None, Cookie(alias="csrf_token")]  = None,
    csrf_header: Annotated[str | None, Header(alias="x-csrf-token")] = None,
) -> None:
    """
    Validate the CSRF double-submit cookie.

    Applied to all state-mutating endpoints (POST, PUT, PATCH, DELETE).
    GET/HEAD/OPTIONS are exempt because they must be safe (idempotent).

    Raises 403 if the cookie and header values do not match.
    """
    if not validate_csrf_token(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid.",
        )


# ── Pagination ────────────────────────────────────────────────────────────────────

def get_pagination(
    page:      int = Query(default=1,  ge=1,  description="Page number (1-based)"),
    page_size: int = Query(
        default=settings.PAGINATION_DEFAULT_PAGE_SIZE,
        ge=1,
        le=settings.PAGINATION_MAX_PAGE_SIZE,
        description="Records per page",
    ),
) -> PaginationParams:
    return PaginationParams(page=page, page_size=page_size)


# ── Record Filters ────────────────────────────────────────────────────────────────

def get_record_filters(
    type:      TransactionType | None = Query(None),
    category:  str | None             = Query(None, max_length=100),
    date_from: str | None             = Query(None, description="YYYY-MM-DD"),
    date_to:   str | None             = Query(None, description="YYYY-MM-DD"),
    search:    str | None             = Query(None, max_length=200, description="Search notes"),
) -> FinancialRecordFilter:
    from datetime import date

    def _parse_date(value: str | None) -> date | None:
        if not value:
            return None
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid date format: {value!r}. Use YYYY-MM-DD.",
            )

    return FinancialRecordFilter(
        type=type,
        category=category,
        date_from=_parse_date(date_from),
        date_to=_parse_date(date_to),
        search=search,
    )
