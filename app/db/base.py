"""
app/db/base.py
──────────────
Declarative base + shared mixin with audit columns.

Every table inherits TimestampMixin so we always know when a record was
created, last modified, and (for soft-delete) when it was removed.

The SoftDeleteMixin adds deleted_at; the service layer filters it out
so deleted records are invisible to normal queries but recoverable for
audits or regulatory requirements.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Shared SQLAlchemy declarative base for all models."""
    pass


class TimestampMixin:
    """
    Adds created_at / updated_at columns to any model.
    updated_at is maintained automatically by the database via onupdate.
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        server_default=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """
    Adds deleted_at column.  When set, the record is treated as deleted.
    The actual row is retained for audit purposes.

    Services must explicitly filter: .where(Model.deleted_at.is_(None))
    """
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
        index=True,   # index speeds up the is-null filter
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None
