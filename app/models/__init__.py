"""
app/models/
───────────
SQLAlchemy ORM models.  Each model maps 1-to-1 with a database table.

Relationships are declared here; business logic lives in services/.
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, SoftDeleteMixin, TimestampMixin

if TYPE_CHECKING:
    pass   # avoid circular imports in type hints


# ── Enumerations ──────────────────────────────────────────────────────────────────

class UserRole(StrEnum):
    """
    Three-tier role model.

    VIEWER   – read-only access to records and dashboard summaries
    ANALYST  – read access + export; cannot modify data
    ADMIN    – full CRUD on records and user management
    """
    VIEWER   = "VIEWER"
    ANALYST  = "ANALYST"
    ADMIN    = "ADMIN"


class TransactionType(StrEnum):
    """Whether a financial record represents money in or money out."""
    INCOME  = "INCOME"
    EXPENSE = "EXPENSE"


# ── User ──────────────────────────────────────────────────────────────────────────

class User(Base, TimestampMixin, SoftDeleteMixin):
    """
    Represents an authenticated system user.

    Security notes:
      • password_hash stores bcrypt output – never the plain password.
      • email is lower-cased at the application layer before persistence.
      • failed_login_attempts + locked_until support brute-force lockout.
    """
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, native_enum=False),
        nullable=False,
        default=UserRole.VIEWER,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Brute-force protection
    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[str | None]   = mapped_column(String(50), nullable=True)

    # Relationships
    financial_records: Mapped[list["FinancialRecord"]] = relationship(
        "FinancialRecord",
        back_populates="created_by_user",
        lazy="select",
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )


# ── Financial Record ──────────────────────────────────────────────────────────────

class FinancialRecord(Base, TimestampMixin, SoftDeleteMixin):
    """
    A single financial entry (income or expense).

    Design decisions:
      • amount is always stored as a positive Float; the type field carries direction.
      • category is a free-text string (not a FK to a Category table) to keep
        the schema simple.  A category table is a natural v2 enhancement.
      • notes is sanitised at the service layer to prevent stored XSS.
    """
    __tablename__ = "financial_records"

    __table_args__ = (
        # Composite index for the most common dashboard query pattern
        Index("ix_records_user_date", "created_by_user_id", "date"),
        Index("ix_records_category",  "category"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    type: Mapped[TransactionType] = mapped_column(
        SAEnum(TransactionType, native_enum=False),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    date: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by_user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by_user: Mapped["User"] = relationship(
        "User",
        back_populates="financial_records",
    )


# ── Refresh Token ─────────────────────────────────────────────────────────────────

class RefreshToken(Base, TimestampMixin):
    """
    Persisted refresh tokens enable:
      • Server-side revocation (logout, suspicious activity).
      • Refresh token rotation – each use invalidates the old token and issues a new one.
      • Audit trail of active sessions per user.

    token_hash stores SHA-256(token) – never the raw token – so a DB breach
    does not expose usable tokens.
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at: Mapped[str] = mapped_column(String(50), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Optional: record IP + user-agent for session management UI
    client_ip:       Mapped[str | None] = mapped_column(String(45),  nullable=True)
    user_agent:      Mapped[str | None] = mapped_column(String(512), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")
