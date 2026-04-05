"""
app/core/security.py
─────────────────────
All cryptographic operations in one module so the implementation is
auditable in a single place.

Covers:
  • Password hashing  (bcrypt via passlib)
  • JWT access + refresh token creation / verification
  • CSRF double-submit cookie token generation & validation
  • Input sanitisation helpers (strip HTML to prevent stored XSS)

OWASP references addressed here:
  A02 – Cryptographic Failures   : bcrypt + strong JWT secret
  A03 – Injection                : parameterised queries live in services;
                                   this module sanitises free-text fields
  A07 – Identification & Auth    : short-lived JWT, refresh rotation
"""

from __future__ import annotations

import hashlib
import hmac
import html
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt as _bcrypt_lib
from jose import JWTError, jwt

from app.core.config import settings


# ── Password Hashing ─────────────────────────────────────────────────────────────
#
# Uses bcrypt directly (not via passlib) to avoid version-compatibility issues
# between passlib and bcrypt >= 4.x.

def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash of *plain_password*."""
    _assert_password_length(plain_password)
    # bcrypt silently truncates at 72 bytes – we do it explicitly so behaviour is
    # predictable and auditable.
    encoded = plain_password.encode("utf-8")[:72]
    salt    = _bcrypt_lib.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return _bcrypt_lib.hashpw(encoded, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time comparison of *plain_password* against *hashed_password*."""
    _assert_password_length(plain_password)
    encoded = plain_password.encode("utf-8")[:72]
    return _bcrypt_lib.checkpw(encoded, hashed_password.encode("utf-8"))


def _assert_password_length(password: str) -> None:
    """
    Reject passwords that are too long *before* they reach bcrypt.
    bcrypt silently truncates at 72 bytes, which can cause subtle auth bugs,
    and extremely large inputs create a DoS vector.
    """
    if len(password) > settings.PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"Password must not exceed {settings.PASSWORD_MAX_LENGTH} characters"
        )


# ── JWT Tokens ────────────────────────────────────────────────────────────────────

class TokenType:
    ACCESS  = "access"
    REFRESH = "refresh"


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    """
    Create a short-lived JWT access token.

    :param subject:      Typically the user UUID (not the email – avoids leaking PII
                         if the token is logged or decoded client-side).
    :param extra_claims: Optional dict merged into the token payload.
    """
    return _create_token(
        subject=subject,
        token_type=TokenType.ACCESS,
        ttl=timedelta(minutes=settings.JWT_ACCESS_TOKEN_TTL_MINUTES),
        extra_claims=extra_claims,
    )


def create_refresh_token(subject: str) -> str:
    """Create a longer-lived refresh token (no extra claims – minimal surface area)."""
    return _create_token(
        subject=subject,
        token_type=TokenType.REFRESH,
        ttl=timedelta(days=settings.JWT_REFRESH_TOKEN_TTL_DAYS),
    )


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT.

    Raises ``jose.JWTError`` (subclass of Exception) on any validation failure:
    expired, wrong signature, malformed, etc.  Callers should catch ``JWTError``
    and translate it to an HTTP 401.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def _create_token(
    subject:     str,
    token_type:  str,
    ttl:         timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub":  subject,
        "type": token_type,
        "iat":  now,
        "exp":  now + ttl,
        # jti is a unique token ID – enables token revocation via a blocklist
        "jti":  secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# ── CSRF Double-Submit Cookie ─────────────────────────────────────────────────────
#
# The double-submit cookie pattern:
#   1. Server generates a random CSRF token and sets it as an HttpOnly=False cookie
#      (so JS can read it).
#   2. The SPA reads the cookie and echoes it in the X-CSRF-Token request header.
#   3. The server validates that the header value matches the cookie value.
#
# This mitigates CSRF because a cross-origin attacker cannot read the cookie value.
# Reference: OWASP CSRF Prevention Cheat Sheet

CSRF_TOKEN_BYTES = 32


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_hex(CSRF_TOKEN_BYTES)


def validate_csrf_token(cookie_token: str | None, header_token: str | None) -> bool:
    """
    Constant-time comparison of the cookie value against the header value.
    Returns False if either value is missing or they do not match.
    """
    if not cookie_token or not header_token:
        return False
    # hmac.compare_digest prevents timing attacks
    return hmac.compare_digest(cookie_token.encode(), header_token.encode())


# ── Input Sanitisation ────────────────────────────────────────────────────────────
#
# Defence-in-depth against stored XSS (A03/A07).  The primary defence is that
# API responses are JSON, which browsers do not render as HTML.  This secondary
# layer strips HTML tags from free-text fields (notes, descriptions) before they
# are persisted, so they are safe even if ever rendered in a legacy context.

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def sanitise_text(value: str | None) -> str | None:
    """
    Strip HTML tags and escape HTML entities in free-text fields.
    Returns None unchanged.
    """
    if value is None:
        return None
    stripped  = _HTML_TAG_RE.sub("", value)
    escaped   = html.escape(stripped, quote=True)
    return escaped.strip()
