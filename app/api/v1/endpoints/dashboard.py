from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import AnyAuthenticatedUser
from app.db.session import get_db
from app.models import User
from app.schemas import DashboardSummary
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/summary", response_model=DashboardSummary, summary="Financial dashboard summary (all roles)")
async def get_dashboard_summary(
    _user: User = Depends(AnyAuthenticatedUser),
    db: AsyncSession = Depends(get_db),
) -> DashboardSummary:
    return await DashboardService.get_summary(db)
