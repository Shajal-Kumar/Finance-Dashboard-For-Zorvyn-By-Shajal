"""
app/services/dashboard_service.py
────────────────────────────────────
Dashboard aggregation logic.

Key design principle: **all aggregation happens inside the database**.
We never load raw rows into Python memory just to sum them.  This is critical
for tables that grow to millions of rows.

Queries use SQLAlchemy's func module to push GROUP BY / SUM / COUNT down to
the RDBMS, which can use indexes and execute set-based operations far more
efficiently than Python loops.
"""

from __future__ import annotations

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import FinancialRecord, TransactionType
from app.schemas import (
    CategoryTotal,
    DashboardSummary,
    FinancialRecordOut,
    MonthlyTrend,
)

# Number of recent records to include in the summary response
_RECENT_RECORDS_LIMIT = 10


class DashboardService:

    @staticmethod
    async def get_summary(db: AsyncSession) -> DashboardSummary:
        """
        Return an aggregated financial summary.

        Executes four focused queries rather than one monster query so that
        each can be independently optimised and cached later.
        """
        totals          = await DashboardService._get_income_expense_totals(db)
        record_count    = await DashboardService._get_record_count(db)
        category_totals = await DashboardService._get_category_totals(db)
        monthly_trends  = await DashboardService._get_monthly_trends(db)
        recent_records  = await DashboardService._get_recent_records(db)

        total_income  = totals.get(TransactionType.INCOME,  0.0)
        total_expense = totals.get(TransactionType.EXPENSE, 0.0)

        return DashboardSummary(
            total_income=round(total_income,  2),
            total_expense=round(total_expense, 2),
            net_balance=round(total_income - total_expense, 2),
            record_count=record_count,
            category_totals=category_totals,
            monthly_trends=monthly_trends,
            recent_records=recent_records,
        )

    # ── Private aggregation helpers ───────────────────────────────────────────────

    @staticmethod
    async def _get_income_expense_totals(db: AsyncSession) -> dict[TransactionType, float]:
        """
        Single query: SUM(amount) GROUP BY type for non-deleted records.

        Returns a dict like:
            { TransactionType.INCOME: 50000.0, TransactionType.EXPENSE: 32000.0 }
        """
        result = await db.execute(
            select(
                FinancialRecord.type,
                func.coalesce(func.sum(FinancialRecord.amount), 0.0).label("total"),
            )
            .where(FinancialRecord.deleted_at.is_(None))
            .group_by(FinancialRecord.type)
        )
        rows = result.all()
        return {row.type: float(row.total) for row in rows}

    @staticmethod
    async def _get_record_count(db: AsyncSession) -> int:
        result = await db.execute(
            select(func.count(FinancialRecord.id))
            .where(FinancialRecord.deleted_at.is_(None))
        )
        return result.scalar_one()

    @staticmethod
    async def _get_category_totals(db: AsyncSession) -> list[CategoryTotal]:
        """
        SUM(amount) and COUNT(*) per category, ordered by total descending.
        This powers the category breakdown widget on the dashboard.
        """
        result = await db.execute(
            select(
                FinancialRecord.category,
                func.sum(FinancialRecord.amount).label("total_amount"),
                func.count(FinancialRecord.id).label("record_count"),
            )
            .where(FinancialRecord.deleted_at.is_(None))
            .group_by(FinancialRecord.category)
            .order_by(func.sum(FinancialRecord.amount).desc())
        )
        rows = result.all()
        return [
            CategoryTotal(
                category=row.category,
                total_amount=round(float(row.total_amount), 2),
                record_count=row.record_count,
            )
            for row in rows
        ]

    @staticmethod
    async def _get_monthly_trends(db: AsyncSession) -> list[MonthlyTrend]:
        """
        Monthly income vs expense totals for the last 12 months.

        Uses SQLAlchemy's func.substr to extract the YYYY-MM prefix from the
        ISO date string stored in the date column.  This avoids storing a
        separate year/month column while remaining DB-portable.

        For PostgreSQL in production, replace substr with date_trunc.
        """
        year_month_expr = func.substr(FinancialRecord.date, 1, 7).label("year_month")

        result = await db.execute(
            select(
                year_month_expr,
                func.sum(
                    case(
                        (FinancialRecord.type == TransactionType.INCOME, FinancialRecord.amount),
                        else_=0.0,
                    )
                ).label("total_income"),
                func.sum(
                    case(
                        (FinancialRecord.type == TransactionType.EXPENSE, FinancialRecord.amount),
                        else_=0.0,
                    )
                ).label("total_expense"),
            )
            .where(FinancialRecord.deleted_at.is_(None))
            .group_by(year_month_expr)
            .order_by(year_month_expr.desc())
            .limit(12)
        )
        rows = result.all()
        return [
            MonthlyTrend(
                year_month=row.year_month,
                total_income=round(float(row.total_income),  2),
                total_expense=round(float(row.total_expense), 2),
                net=round(float(row.total_income) - float(row.total_expense), 2),
            )
            for row in rows
        ]

    @staticmethod
    async def _get_recent_records(db: AsyncSession) -> list[FinancialRecordOut]:
        """Fetch the N most recent non-deleted records for the activity feed."""
        result = await db.execute(
            select(FinancialRecord)
            .where(FinancialRecord.deleted_at.is_(None))
            .order_by(FinancialRecord.date.desc(), FinancialRecord.created_at.desc())
            .limit(_RECENT_RECORDS_LIMIT)
        )
        records = result.scalars().all()
        return [FinancialRecordOut.model_validate(r) for r in records]
