"""
app/schemas/
─────────────
Pydantic v2 schemas for request validation and response serialisation.

Naming convention:
  *Create  – fields accepted when creating a resource (no id/timestamps)
  *Update  – fields accepted when updating (all optional)
  *Out     – fields returned to the caller (never exposes secrets)
  *Filter  – query parameter model for list endpoints

Pydantic raises HTTP 422 Unprocessable Entity automatically when validation
fails, with a structured error body – no manual validation code required.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Generic, Optional, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

from app.core.config import settings
from app.models import TransactionType, UserRole


# ── Shared base ───────────────────────────────────────────────────────────────────

class _Base(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,   # enables .model_validate(orm_object)
        str_strip_whitespace=True,
        populate_by_name=True,
    )


# ── Pagination ────────────────────────────────────────────────────────────────────

T = TypeVar("T")

class PaginatedResponse(_Base, Generic[T]):
    """Generic paginated envelope returned by all list endpoints."""
    items:       list[T]
    total:       int
    page:        int
    page_size:   int
    total_pages: int


class PaginationParams(_Base):
    page:      Annotated[int, Field(ge=1, default=1)]
    page_size: Annotated[int, Field(
        ge=1,
        le=settings.PAGINATION_MAX_PAGE_SIZE,
        default=settings.PAGINATION_DEFAULT_PAGE_SIZE,
    )]

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


# ── Auth ──────────────────────────────────────────────────────────────────────────

class LoginRequest(_Base):
    email:    EmailStr
    password: str = Field(..., min_length=1, max_length=settings.PASSWORD_MAX_LENGTH)

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()


class TokenResponse(_Base):
    access_token:  str
    token_type:    str = "bearer"
    expires_in:    int = settings.JWT_ACCESS_TOKEN_TTL_MINUTES * 60   # seconds


class RefreshRequest(_Base):
    refresh_token: str


# ── User ──────────────────────────────────────────────────────────────────────────

class UserCreate(_Base):
    email:     EmailStr
    password:  str = Field(
        ...,
        min_length=settings.PASSWORD_MIN_LENGTH,
        max_length=settings.PASSWORD_MAX_LENGTH,
        description=(
            f"Must be {settings.PASSWORD_MIN_LENGTH}–{settings.PASSWORD_MAX_LENGTH} "
            "characters."
        ),
    )
    full_name: str | None = Field(None, max_length=120)
    role:      UserRole   = UserRole.VIEWER

    @field_validator("email", mode="before")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        """
        Enforce NIST 800-63B inspired complexity check.
        Length is the primary control; we also require at least one digit.
        """
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter.")
        return v


class UserUpdate(_Base):
    """Partial update – all fields optional.  Admins only."""
    full_name: str | None = Field(None, max_length=120)
    role:      UserRole | None = None
    is_active: bool | None = None


class UserOut(_Base):
    """
    Safe user representation returned by the API.
    password_hash is deliberately excluded.
    """
    id:         str
    email:      str
    full_name:  str | None
    role:       UserRole
    is_active:  bool
    created_at: datetime
    updated_at: datetime


# ── Financial Record ──────────────────────────────────────────────────────────────

class FinancialRecordCreate(_Base):
    amount:   Annotated[float, Field(gt=0, description="Must be a positive number.")]
    type:     TransactionType
    category: Annotated[str,   Field(min_length=1, max_length=100)]
    date:     date
    notes:    str | None = Field(None, max_length=2000)

    @field_validator("category", mode="before")
    @classmethod
    def normalise_category(cls, v: str) -> str:
        return v.strip().title()


class FinancialRecordUpdate(_Base):
    """Partial update – all fields optional."""
    amount:   Annotated[float, Field(gt=0)] | None = None
    type:     TransactionType | None = None
    category: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    date:     Optional[date] = None
    notes:    Optional[str] = Field(None, max_length=2000)


class FinancialRecordOut(_Base):
    id:                 str
    amount:             float
    type:               TransactionType
    category:           str
    date:               str
    notes:              str | None
    created_by_user_id: str
    created_at:         datetime
    updated_at:         datetime


class FinancialRecordFilter(_Base):
    """Query parameters for filtering the record list."""
    type:           TransactionType | None = None
    category:       str | None            = None
    date_from:      date | None           = None
    date_to:        date | None           = None
    search:         str | None            = Field(None, max_length=200)  # searches notes

    @model_validator(mode="after")
    def validate_date_range(self) -> "FinancialRecordFilter":
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must be before or equal to date_to")
        return self


# ── Dashboard ─────────────────────────────────────────────────────────────────────

class CategoryTotal(_Base):
    category:      str
    total_amount:  float
    record_count:  int


class MonthlyTrend(_Base):
    year_month:     str   # "2024-03"
    total_income:   float
    total_expense:  float
    net:            float


class DashboardSummary(_Base):
    total_income:    float
    total_expense:   float
    net_balance:     float
    record_count:    int
    category_totals: list[CategoryTotal]
    monthly_trends:  list[MonthlyTrend]
    recent_records:  list[FinancialRecordOut]


# ── Error responses ───────────────────────────────────────────────────────────────

class ErrorDetail(_Base):
    """Structured error body returned on 4xx/5xx responses."""
    code:    str
    message: str
    field:   str | None = None   # set for field-level validation errors
