"""
app/services/record_service.py
──────────────────────────────
Financial record CRUD and filtering logic.

Design decisions:
  • All filters are applied via SQLAlchemy – no post-fetch filtering in Python
    (prevents loading unnecessary rows into memory).
  • category is normalised to Title Case before persistence so that
    "food", "Food", and "FOOD" are treated as the same category.
  • notes is sanitised against XSS before storage.
  • Soft-delete: records are not removed from the database; deleted_at is set.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import sanitise_text
from app.models import FinancialRecord, User
from app.schemas import (
    FinancialRecordCreate,
    FinancialRecordFilter,
    FinancialRecordOut,
    FinancialRecordUpdate,
    PaginatedResponse,
    PaginationParams,
)


class RecordService:

    # ── Create ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def create(
        payload:      FinancialRecordCreate,
        current_user: User,
        db:           AsyncSession,
    ) -> FinancialRecord:
        record = FinancialRecord(
            amount=payload.amount,
            type=payload.type,
            category=payload.category,          # already normalised by schema validator
            date=payload.date.isoformat(),
            notes=sanitise_text(payload.notes),  # strip any HTML before persistence
            created_by_user_id=current_user.id,
        )
        db.add(record)
        await db.flush()
        await db.refresh(record)
        return record

    # ── Read (single) ─────────────────────────────────────────────────────────────

    @staticmethod
    async def get_by_id(record_id: str, db: AsyncSession) -> FinancialRecord:
        result = await db.execute(
            select(FinancialRecord).where(
                FinancialRecord.id == record_id,
                FinancialRecord.deleted_at.is_(None),
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Financial record not found.",
            )
        return record

    # ── Read (list with filters + pagination) ─────────────────────────────────────

    @staticmethod
    async def list_records(
        filters:    FinancialRecordFilter,
        pagination: PaginationParams,
        db:         AsyncSession,
    ) -> PaginatedResponse[FinancialRecordOut]:
        base_query = (
            select(FinancialRecord)
            .where(FinancialRecord.deleted_at.is_(None))
        )
        base_query = _apply_filters(base_query, filters)

        # Total count (separate query – more reliable than subquery with complex filters)
        count_query  = select(func.count()).select_from(base_query.subquery())
        count_result = await db.execute(count_query)
        total        = count_result.scalar_one()

        # Paginated results
        data_query = (
            base_query
            .order_by(FinancialRecord.date.desc(), FinancialRecord.created_at.desc())
            .offset(pagination.offset)
            .limit(pagination.page_size)
        )
        result  = await db.execute(data_query)
        records = result.scalars().all()

        return PaginatedResponse(
            items=[FinancialRecordOut.model_validate(r) for r in records],
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=math.ceil(total / pagination.page_size) if total else 0,
        )

    # ── Update ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def update(
        record_id: str,
        payload:   FinancialRecordUpdate,
        db:        AsyncSession,
    ) -> FinancialRecord:
        record = await RecordService.get_by_id(record_id, db)

        update_data = payload.model_dump(exclude_none=True)

        # Sanitise notes if provided
        if "notes" in update_data:
            update_data["notes"] = sanitise_text(update_data["notes"])

        # Convert date to ISO string if provided
        if "date" in update_data:
            update_data["date"] = update_data["date"].isoformat()

        # Normalise category if provided
        if "category" in update_data:
            update_data["category"] = update_data["category"].strip().title()

        for field, value in update_data.items():
            setattr(record, field, value)

        await db.flush()
        await db.refresh(record)
        return record

    # ── Delete ────────────────────────────────────────────────────────────────────

    @staticmethod
    async def delete(record_id: str, db: AsyncSession) -> None:
        """Soft-delete: sets deleted_at timestamp rather than removing the row."""
        record = await RecordService.get_by_id(record_id, db)
        record.deleted_at = datetime.now(timezone.utc)
        await db.flush()


# ── Private: filter builder ───────────────────────────────────────────────────────

def _apply_filters(query, filters: FinancialRecordFilter):
    """
    Add WHERE clauses to *query* based on the provided filter values.
    Each filter clause is only added if the corresponding value is not None,
    keeping the generated SQL minimal.
    """
    conditions = []

    if filters.type:
        conditions.append(FinancialRecord.type == filters.type)

    if filters.category:
        conditions.append(
            func.lower(FinancialRecord.category) == filters.category.lower()
        )

    if filters.date_from:
        conditions.append(FinancialRecord.date >= filters.date_from.isoformat())

    if filters.date_to:
        conditions.append(FinancialRecord.date <= filters.date_to.isoformat())

    if filters.search:
        # Case-insensitive substring search on notes field
        search_term = f"%{filters.search.lower()}%"
        conditions.append(
            func.lower(FinancialRecord.notes).like(search_term)
        )

    if conditions:
        query = query.where(and_(*conditions))

    return query
