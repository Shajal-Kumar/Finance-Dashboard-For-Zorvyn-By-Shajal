"""
app/services/auth_service.py
──────────────────────────────
Authentication business logic.

Covers:
  • User login with brute-force lockout
  • Access + refresh token issuance
  • Refresh token rotation (old token invalidated on each use)
  • Logout (revoke refresh token)

OWASP controls:
  A07 Identification and Authentication Failures:
    – bcrypt password verification
    – incremental lockout after N failed attempts
    – refresh token rotation to limit replay window
  A02 Cryptographic Failures:
    – tokens stored as SHA-256 hashes (not plaintext)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.models import RefreshToken, User
from app.schemas import LoginRequest, TokenResponse

# Maximum consecutive failures before the account is temporarily locked
_MAX_FAILED_ATTEMPTS: int = 5
# Lock duration in minutes
_LOCKOUT_MINUTES:     int = 15


class AuthService:

    # ── Login ─────────────────────────────────────────────────────────────────────

    @staticmethod
    async def login(
        credentials: LoginRequest,
        db:          AsyncSession,
        request:     Request,
    ) -> tuple[TokenResponse, str]:
        """
        Validate credentials and return (access_token_response, refresh_token).

        Returns a tuple so the caller (route handler) can set the refresh token
        as an HttpOnly cookie rather than returning it in the JSON body.

        Raises 401 for invalid credentials (generic message – no user enumeration).
        Raises 423 if the account is locked.
        """
        user = await _fetch_user_by_email(credentials.email, db)

        # Use a constant-time generic message to avoid user enumeration
        _INVALID = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

        if user is None:
            raise _INVALID

        # Check lockout before verifying password (saves bcrypt work)
        _assert_not_locked(user)

        if not verify_password(credentials.password, user.password_hash):
            await _record_failed_attempt(user, db)
            raise _INVALID

        # Successful login – reset failure counter
        await _reset_failed_attempts(user, db)

        access_token  = create_access_token(subject=user.id, extra_claims={"role": user.role})
        refresh_token = create_refresh_token(subject=user.id)

        await _persist_refresh_token(
            token=refresh_token,
            user=user,
            db=db,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
        )

        token_response = TokenResponse(access_token=access_token)
        return token_response, refresh_token

    # ── Token Refresh ─────────────────────────────────────────────────────────────

    @staticmethod
    async def refresh(
        refresh_token_value: str,
        db:                  AsyncSession,
        request:             Request,
    ) -> tuple[TokenResponse, str]:
        """
        Validate a refresh token, revoke it, and issue a new pair.

        Implements refresh token rotation: every call invalidates the presented
        token and issues a fresh one.  This limits the window for a stolen token.
        """
        _INVALID_REFRESH = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or expired.",
        )

        # Verify the JWT signature first (cheap operation)
        try:
            payload = decode_token(refresh_token_value)
        except Exception:
            raise _INVALID_REFRESH

        from app.core.security import TokenType
        if payload.get("type") != TokenType.REFRESH:
            raise _INVALID_REFRESH

        # Look up the hashed token in the database
        token_hash = _hash_token(refresh_token_value)
        result     = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.is_revoked == False,  # noqa: E712
            )
        )
        stored_token = result.scalar_one_or_none()

        if stored_token is None:
            raise _INVALID_REFRESH

        # Check expiry
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(stored_token.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            raise _INVALID_REFRESH

        # Revoke the current token (rotation)
        stored_token.is_revoked = True
        await db.flush()

        # Load the user
        user_result = await db.execute(
            select(User).where(User.id == stored_token.user_id, User.deleted_at.is_(None))
        )
        user = user_result.scalar_one_or_none()
        if user is None or not user.is_active:
            raise _INVALID_REFRESH

        # Issue new tokens
        new_access_token  = create_access_token(subject=user.id, extra_claims={"role": user.role})
        new_refresh_token = create_refresh_token(subject=user.id)

        await _persist_refresh_token(
            token=new_refresh_token,
            user=user,
            db=db,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
        )

        return TokenResponse(access_token=new_access_token), new_refresh_token

    # ── Logout ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def logout(refresh_token_value: str, db: AsyncSession) -> None:
        """
        Revoke the supplied refresh token.
        Silently succeeds if the token is not found (idempotent).
        """
        token_hash = _hash_token(refresh_token_value)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .values(is_revoked=True)
        )


# ── Private helpers ───────────────────────────────────────────────────────────────

async def _fetch_user_by_email(email: str, db: AsyncSession) -> User | None:
    result = await db.execute(
        select(User).where(User.email == email, User.deleted_at.is_(None))
    )
    return result.scalar_one_or_none()


def _assert_not_locked(user: User) -> None:
    if not user.locked_until:
        return
    locked_until = datetime.fromisoformat(user.locked_until)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) < locked_until:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=(
                f"Account locked due to too many failed attempts. "
                f"Try again after {locked_until.strftime('%H:%M UTC')}."
            ),
        )


async def _record_failed_attempt(user: User, db: AsyncSession) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
        locked_until             = datetime.now(timezone.utc) + timedelta(minutes=_LOCKOUT_MINUTES)
        user.locked_until        = locked_until.isoformat()
    await db.flush()


async def _reset_failed_attempts(user: User, db: AsyncSession) -> None:
    user.failed_login_attempts = 0
    user.locked_until          = None
    await db.flush()


async def _persist_refresh_token(
    token:      str,
    user:       User,
    db:         AsyncSession,
    client_ip:  str | None,
    user_agent: str | None,
) -> None:
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=settings.JWT_REFRESH_TOKEN_TTL_DAYS)
    ).isoformat()

    stored = RefreshToken(
        token_hash=_hash_token(token),
        user_id=user.id,
        expires_at=expires_at,
        client_ip=client_ip,
        user_agent=(user_agent or "")[:512],   # truncate to column length
    )
    db.add(stored)
    await db.flush()


def _hash_token(token: str) -> str:
    """SHA-256 hex digest of the raw token string."""
    return hashlib.sha256(token.encode()).hexdigest()
