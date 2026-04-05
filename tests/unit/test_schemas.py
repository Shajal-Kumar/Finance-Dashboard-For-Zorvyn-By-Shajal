"""
tests/unit/test_schemas.py
───────────────────────────
Unit tests for Pydantic schemas — validates that input rules work correctly
without requiring a running server or database.
"""

from __future__ import annotations

from datetime import date

import pytest
from pydantic import ValidationError

from app.schemas import (
    FinancialRecordCreate,
    FinancialRecordFilter,
    FinancialRecordUpdate,
    LoginRequest,
    UserCreate,
    UserUpdate,
)
from app.models import TransactionType, UserRole


# ── LoginRequest ──────────────────────────────────────────────────────────────────

class TestLoginRequest:

    def test_valid(self):
        req = LoginRequest(email="User@Example.COM", password="pass")
        assert req.email == "user@example.com"  # normalised to lowercase

    def test_invalid_email(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="not-an-email", password="pass")

    def test_empty_password_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="a@b.com", password="")


# ── UserCreate ────────────────────────────────────────────────────────────────────

class TestUserCreate:

    def test_valid_user(self):
        u = UserCreate(email="new@example.com", password="StrongPass123!")
        assert u.role == UserRole.VIEWER  # default role

    def test_email_normalised(self):
        u = UserCreate(email="  HELLO@WORLD.COM  ", password="StrongPass123!")
        assert u.email == "hello@world.com"

    def test_password_too_short(self):
        with pytest.raises(ValidationError, match="at least"):
            UserCreate(email="a@b.com", password="Short1!")

    def test_password_no_digit(self):
        with pytest.raises(ValidationError, match="digit"):
            UserCreate(email="a@b.com", password="NoDigitsHere!!!!!")

    def test_password_no_letter(self):
        with pytest.raises(ValidationError, match="letter"):
            UserCreate(email="a@b.com", password="12345678901234")

    def test_password_too_long(self):
        with pytest.raises(ValidationError):
            UserCreate(email="a@b.com", password="A1" + "x" * 200)

    def test_admin_role_assignable(self):
        u = UserCreate(email="a@b.com", password="StrongPass123!", role=UserRole.ADMIN)
        assert u.role == UserRole.ADMIN


# ── UserUpdate ────────────────────────────────────────────────────────────────────

class TestUserUpdate:

    def test_all_fields_optional(self):
        # Should not raise — all fields are optional
        u = UserUpdate()
        assert u.full_name is None
        assert u.role     is None
        assert u.is_active is None

    def test_partial_update(self):
        u = UserUpdate(is_active=False)
        assert u.is_active is False
        assert u.role      is None

    def test_full_name_max_length(self):
        with pytest.raises(ValidationError):
            UserUpdate(full_name="x" * 200)


# ── FinancialRecordCreate ─────────────────────────────────────────────────────────

class TestFinancialRecordCreate:

    def test_valid_income(self):
        r = FinancialRecordCreate(
            amount=1500.00,
            type=TransactionType.INCOME,
            category="consulting",
            date=date(2024, 3, 15),
        )
        assert r.category == "Consulting"   # Title-cased by validator
        assert r.notes is None

    def test_valid_expense(self):
        r = FinancialRecordCreate(
            amount=99.99,
            type=TransactionType.EXPENSE,
            category="Food",
            date=date(2024, 1, 1),
            notes="Lunch with client",
        )
        assert r.amount == 99.99

    def test_zero_amount_rejected(self):
        with pytest.raises(ValidationError, match="greater than"):
            FinancialRecordCreate(
                amount=0,
                type=TransactionType.INCOME,
                category="Test",
                date=date(2024, 1, 1),
            )

    def test_negative_amount_rejected(self):
        with pytest.raises(ValidationError):
            FinancialRecordCreate(
                amount=-100.0,
                type=TransactionType.EXPENSE,
                category="Test",
                date=date(2024, 1, 1),
            )

    def test_empty_category_rejected(self):
        with pytest.raises(ValidationError):
            FinancialRecordCreate(
                amount=100.0,
                type=TransactionType.INCOME,
                category="",
                date=date(2024, 1, 1),
            )

    def test_notes_max_length(self):
        with pytest.raises(ValidationError):
            FinancialRecordCreate(
                amount=100.0,
                type=TransactionType.INCOME,
                category="Test",
                date=date(2024, 1, 1),
                notes="x" * 3000,
            )

    def test_category_whitespace_stripped(self):
        r = FinancialRecordCreate(
            amount=1.0,
            type=TransactionType.INCOME,
            category="  food  ",
            date=date(2024, 1, 1),
        )
        assert r.category == "Food"


# ── FinancialRecordFilter ─────────────────────────────────────────────────────────

class TestFinancialRecordFilter:

    def test_all_optional(self):
        f = FinancialRecordFilter()
        assert f.type       is None
        assert f.category   is None
        assert f.date_from  is None
        assert f.date_to    is None

    def test_valid_date_range(self):
        f = FinancialRecordFilter(
            date_from=date(2024, 1, 1),
            date_to=date(2024, 12, 31),
        )
        assert f.date_from < f.date_to

    def test_invalid_date_range_rejected(self):
        with pytest.raises(ValidationError, match="date_from must be before"):
            FinancialRecordFilter(
                date_from=date(2024, 12, 31),
                date_to=date(2024, 1, 1),
            )

    def test_same_date_range_valid(self):
        # date_from == date_to is allowed (single-day filter)
        f = FinancialRecordFilter(
            date_from=date(2024, 6, 15),
            date_to=date(2024, 6, 15),
        )
        assert f.date_from == f.date_to

    def test_search_max_length(self):
        with pytest.raises(ValidationError):
            FinancialRecordFilter(search="x" * 500)
