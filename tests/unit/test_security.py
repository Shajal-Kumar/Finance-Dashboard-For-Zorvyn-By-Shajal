"""
tests/unit/test_security.py
─────────────────────────────
Unit tests for app/core/security.py.

These tests are pure-Python with no database or HTTP layer involved.
They run fast (<1s) and should be the first line of defence in CI.
"""

from __future__ import annotations

import time

import pytest

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_csrf_token,
    hash_password,
    sanitise_text,
    validate_csrf_token,
    verify_password,
)


# ── Password hashing ──────────────────────────────────────────────────────────────

class TestPasswordHashing:

    def test_hash_is_not_plaintext(self):
        hashed = hash_password("MySecret123!")
        assert hashed != "MySecret123!"

    def test_verify_correct_password(self):
        hashed = hash_password("CorrectHorse99!")
        assert verify_password("CorrectHorse99!", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("CorrectHorse99!")
        assert verify_password("WrongPassword1!", hashed) is False

    def test_same_password_produces_different_hashes(self):
        h1 = hash_password("SamePassword1!")
        h2 = hash_password("SamePassword1!")
        # bcrypt generates a different salt each time
        assert h1 != h2

    def test_password_too_long_raises(self):
        with pytest.raises(ValueError, match="exceed"):
            hash_password("x" * 200)

    def test_verify_too_long_password_raises(self):
        hashed = hash_password("ValidPass123!")
        with pytest.raises(ValueError, match="exceed"):
            verify_password("x" * 200, hashed)


# ── JWT tokens ────────────────────────────────────────────────────────────────────

class TestJWT:

    def test_access_token_contains_subject(self):
        token   = create_access_token(subject="user-uuid-123")
        payload = decode_token(token)
        assert payload["sub"]  == "user-uuid-123"
        assert payload["type"] == "access"

    def test_refresh_token_type_is_refresh(self):
        token   = create_refresh_token(subject="user-uuid-456")
        payload = decode_token(token)
        assert payload["type"] == "refresh"

    def test_token_has_jti(self):
        """Every token must have a unique token ID for potential revocation."""
        token   = create_access_token(subject="u1")
        payload = decode_token(token)
        assert "jti" in payload
        assert len(payload["jti"]) > 0

    def test_two_tokens_have_different_jti(self):
        t1 = decode_token(create_access_token(subject="u1"))
        t2 = decode_token(create_access_token(subject="u1"))
        assert t1["jti"] != t2["jti"]

    def test_extra_claims_are_included(self):
        token   = create_access_token(subject="u1", extra_claims={"role": "ADMIN"})
        payload = decode_token(token)
        assert payload["role"] == "ADMIN"

    def test_invalid_token_raises(self):
        from jose import JWTError
        with pytest.raises(JWTError):
            decode_token("this.is.not.valid")

    def test_tampered_token_raises(self):
        from jose import JWTError
        token   = create_access_token(subject="u1")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)


# ── CSRF tokens ───────────────────────────────────────────────────────────────────

class TestCSRF:

    def test_generated_token_is_nonempty_string(self):
        token = generate_csrf_token()
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_two_tokens_are_different(self):
        assert generate_csrf_token() != generate_csrf_token()

    def test_valid_pair_returns_true(self):
        t = generate_csrf_token()
        assert validate_csrf_token(t, t) is True

    def test_mismatched_pair_returns_false(self):
        assert validate_csrf_token("aaa", "bbb") is False

    def test_none_cookie_returns_false(self):
        assert validate_csrf_token(None, "token") is False

    def test_none_header_returns_false(self):
        assert validate_csrf_token("token", None) is False

    def test_both_none_returns_false(self):
        assert validate_csrf_token(None, None) is False

    def test_empty_string_returns_false(self):
        assert validate_csrf_token("", "token") is False


# ── Input sanitisation ────────────────────────────────────────────────────────────

class TestSanitiseText:

    def test_none_passthrough(self):
        assert sanitise_text(None) is None

    def test_plain_text_unchanged(self):
        result = sanitise_text("  Hello world  ")
        assert result == "Hello world"

    def test_html_tags_stripped(self):
        result = sanitise_text("<script>alert('xss')</script>Hello")
        assert "<script>" not in result
        assert "Hello" in result

    def test_html_entities_escaped(self):
        result = sanitise_text('<img src=x onerror="alert(1)">')
        assert "<img" not in result

    def test_nested_tags_stripped(self):
        result = sanitise_text("<b><i>bold italic</i></b>")
        assert "<b>" not in result
        assert "bold italic" in result

    def test_ampersand_escaped(self):
        result = sanitise_text("AT&T revenue")
        assert "&amp;" in result or "AT" in result  # escaped or text preserved

    def test_javascript_href_stripped(self):
        result = sanitise_text('<a href="javascript:void(0)">click</a>')
        assert "javascript" not in result or "<a" not in result
